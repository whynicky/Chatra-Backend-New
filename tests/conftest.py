import os
import tempfile
from types import SimpleNamespace

_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.close(_test_db_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("REFRESH_SECRET_KEY", "test-refresh-secret-key")
# Возвращать OTP-код в ответе (dev/тесты) — SMTP в тестах не настроен.
os.environ["OTP_DEBUG"] = "1"
os.environ["BACKGROUND_JOBS_ENABLED"] = "0"
os.environ["APP_ENV"] = "test"

# Тесты не должны наследовать сервисные ключи из локального .env. Иначе
# обычный pytest отправляет OTP через Brevo, обращается к реальному R2 и может
# расходовать AI-бюджет разработчика. Пустые значения задаём ДО import main:
# load_dotenv(override=False) не перезапишет уже существующие переменные.
for _external_key in (
    "BREVO_API_KEY",
    "R2_ACCOUNT_ID",
    "R2_ENDPOINT_URL",
    "R2_BUCKET_NAME",
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
    "R2_PUBLIC_BASE_URL",
    "OPENAI_API_KEY",
    "DID_API_KEY",
    "ELEVENLABS_API_KEY",
    "FCM_SERVICE_ACCOUNT_FILE",
    "FCM_SERVICE_ACCOUNT_JSON",
):
    os.environ[_external_key] = ""

import pytest
from fastapi.testclient import TestClient

from db import SessionLocal, engine  # noqa: E402
from models import Base  # noqa: E402

# Schema creation is a deliberate test-fixture step. Application import itself
# must remain read-only and cannot be responsible for initializing databases.
Base.metadata.create_all(bind=engine)

import main  # noqa: E402  (import after env vars/schema so db.py uses the test DB)
from crud import users as crud_users
from security import hash_password, create_access_token
from services.storage.base import StorageService
import services.storage as storage_module


class _TestStorage(StorageService):
    """Герметичное in-memory хранилище для общих API-тестов.

    Тесты самого R2 создают R2StorageService напрямую и поэтому по-прежнему
    проверяют S3-контракт через mock-клиент; этот fake лишь не даёт остальной
    suite случайно выйти в сеть при создании обложек/файлов.
    """

    def __init__(self):
        self.objects: dict[str, tuple[bytes, str, str | None]] = {}

    def upload(self, content, key, content_type="application/octet-stream", cache_control=None):
        self.objects[key] = (content, content_type, cache_control)
        return self.get_url(key)

    def replace(self, content, key, content_type="application/octet-stream", cache_control=None):
        return self.upload(content, key, content_type, cache_control)

    def delete(self, key):
        return self.objects.pop(key, None) is not None

    def exists(self, key):
        return key in self.objects

    def get_url(self, key):
        return f"http://testserver/api/uploads/r2/{key}"

    def put_if_absent(self, content, key, content_type, cache_control):
        if key in self.objects:
            return False
        self.objects[key] = (content, content_type, cache_control)
        return True

    def get_object(self, key, range_header=None):
        stored = self.objects.get(key)
        if stored is None:
            return None
        content, content_type, cache_control = stored
        return SimpleNamespace(
            body=content,
            content_type=content_type,
            etag=None,
            cache_control=cache_control,
            content_length=len(content),
            content_range=None,
            partial=False,
        )


storage_module._service = _TestStorage()


@pytest.fixture()
def client():
    # Instantiated without `with` so the app's startup lifespan (background
    # deadline-checker loop) never starts during tests.
    return TestClient(main.app)


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_counter = {"n": 0}


def make_user(db, role="student", org_type="university"):
    _counter["n"] += 1
    email = f"user{_counter['n']}@example.com"
    hashed = hash_password("password123")
    user = crud_users.create_user(db, email, hashed, role=role, org_type=org_type)
    # Фикстурные пользователи считаются подтверждёнными (иначе login → 403).
    user.is_verified = True
    db.commit()
    db.refresh(user)
    return user


def auth_headers(user):
    token = create_access_token(subject=str(user.id))
    return {"Authorization": f"Bearer {token}"}
