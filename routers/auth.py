import hashlib
import os
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import update
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from db import get_db
import schemas
from crud import users as crud_users
from security import hash_password, verify_password, create_access_token, create_refresh_token, decode_refresh_token
from services.rate_limit import RateLimiter, client_ip
from services.otp import issue_code, verify_code
from services.mailer import send_code_email, otp_debug
from jose import JWTError
from deps import get_current_user
from models import RefreshSession
from utils.time import utcnow

router = APIRouter(prefix="/auth", tags=["auth"])

_REFRESH_COOKIE = "chatra_refresh"
_CSRF_COOKIE = "chatra_csrf"
_REFRESH_COOKIE_PATH = "/api/auth"
_REFRESH_MAX_AGE = 30 * 24 * 60 * 60


def _cookie_secure() -> bool:
    default = "true" if os.getenv("APP_ENV", "development").lower() == "production" else "false"
    return os.getenv("AUTH_COOKIE_SECURE", default).lower() in {"1", "true", "yes"}


def _cookie_samesite() -> str:
    value = os.getenv("AUTH_COOKIE_SAMESITE", "lax").strip().lower()
    return value if value in {"lax", "strict", "none"} else "lax"


def _cookie_domain() -> str | None:
    return os.getenv("AUTH_COOKIE_DOMAIN", "").strip() or None


def validate_cookie_configuration() -> None:
    """Fail closed on combinations browsers reject or that expose production cookies."""
    if _cookie_samesite() == "none" and not _cookie_secure():
        raise RuntimeError("AUTH_COOKIE_SAMESITE=none requires AUTH_COOKIE_SECURE=true")
    if os.getenv("APP_ENV", "development").lower() == "production" and not _cookie_secure():
        raise RuntimeError("Production requires AUTH_COOKIE_SECURE=true")


def _is_cookie_mode(session: str) -> bool:
    if session not in {"body", "cookie"}:
        raise HTTPException(status_code=400, detail="invalid_session_mode")
    return session == "cookie"


def _set_session_cookies(response: Response, refresh_token: str, csrf_token: str) -> None:
    common = {
        "secure": _cookie_secure(),
        "samesite": _cookie_samesite(),
        "domain": _cookie_domain(),
        "max_age": _REFRESH_MAX_AGE,
    }
    response.set_cookie(
        _REFRESH_COOKIE,
        refresh_token,
        httponly=True,
        path=_REFRESH_COOKIE_PATH,
        **common,
    )
    response.set_cookie(
        _CSRF_COOKIE,
        csrf_token,
        httponly=False,
        path="/",
        **common,
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(
        _REFRESH_COOKIE, path=_REFRESH_COOKIE_PATH, domain=_cookie_domain(),
        secure=_cookie_secure(), samesite=_cookie_samesite(), httponly=True,
    )
    response.delete_cookie(
        _CSRF_COOKIE, path="/", domain=_cookie_domain(),
        secure=_cookie_secure(), samesite=_cookie_samesite(), httponly=False,
    )


def _require_csrf(request: Request) -> None:
    cookie = request.cookies.get(_CSRF_COOKIE, "")
    header = request.headers.get("X-CSRF-Token", "")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="csrf_validation_failed")

# Ключ IP+username: смена email не обходит лимит, соседей по NAT не блокируем зря.
_login_limiter = RateLimiter(max_calls=5, window_seconds=60)
# Запрос кодов (forgot-password / resend-verification): антиспам по IP+email.
_code_limiter = RateLimiter(max_calls=3, window_seconds=60, namespace="otp")


def normalize_email(email: str) -> str:
    """Email регистронезависим: приводим к нижнему регистру и обрезаем пробелы,
    иначе 'User@x.com' и 'user@x.com' стали бы разными аккаунтами и логин по
    другому регистру не находил бы пользователя."""
    return email.strip().lower()


def _norm_org(org_type: str) -> str:
    return org_type if org_type in ("university", "school") else "university"


def _issue_tokens(
    user,
    db: Session,
    *,
    response: Response | None = None,
    cookie_mode: bool = False,
) -> dict:
    jti = uuid.uuid4().hex
    refresh_token = create_refresh_token(
        subject=str(user.id), token_version=user.token_version, jti=jti
    )
    db.add(RefreshSession(
        jti=jti,
        user_id=user.id,
        token_version=user.token_version,
        client_type="web" if cookie_mode else "native",
        expires_at=datetime.fromtimestamp(
            decode_refresh_token(refresh_token)["exp"], tz=timezone.utc
        ).replace(tzinfo=None),
    ))
    result = {
        "access_token": create_access_token(subject=str(user.id), token_version=user.token_version),
        "refresh_token": None if cookie_mode else refresh_token,
        "token_type": "bearer",
    }
    if cookie_mode:
        if response is None:
            raise RuntimeError("Cookie sessions require a response object")
        csrf_token = secrets.token_urlsafe(32)
        _set_session_cookies(response, refresh_token, csrf_token)
        result["csrf_token"] = csrf_token
    return result


def _consume_refresh(db: Session, payload: dict, raw_token: str) -> None:
    """Consume a tracked token exactly once, including a legacy-token bridge."""
    now = utcnow()
    jti = payload.get("jti")
    if jti:
        consumed = db.execute(
            update(RefreshSession)
            .where(
                RefreshSession.jti == str(jti),
                RefreshSession.revoked_at.is_(None),
                RefreshSession.expires_at > now,
            )
            .values(revoked_at=now)
        )
        if consumed.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=401, detail="Refresh token already used or revoked")
        return

    # Tokens issued before this migration had no jti. Record a non-reversible
    # digest as a consumed tombstone, allowing each legacy token to bridge only
    # once without storing the credential itself.
    legacy_jti = "legacy-" + hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires = datetime.fromtimestamp(payload["exp"], tz=timezone.utc).replace(tzinfo=None)
    try:
        db.add(RefreshSession(
            jti=legacy_jti,
            user_id=int(payload["sub"]),
            token_version=int(payload.get("tv", 0)),
            client_type="legacy",
            expires_at=expires,
            revoked_at=now,
        ))
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=401, detail="Refresh token already used or revoked")


def _revoke_user_sessions(db: Session, user_id: int) -> None:
    db.execute(
        update(RefreshSession)
        .where(RefreshSession.user_id == user_id, RefreshSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


@router.get("/csrf")
def issue_csrf(response: Response):
    """Issue a double-submit value for a subsequent cookie refresh/logout."""
    token = secrets.token_urlsafe(32)
    response.set_cookie(
        _CSRF_COOKIE,
        token,
        httponly=False,
        secure=_cookie_secure(),
        samesite=_cookie_samesite(),
        domain=_cookie_domain(),
        path="/",
        max_age=_REFRESH_MAX_AGE,
    )
    return {"csrf_token": token}


@router.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserRegister, db: Session = Depends(get_db)):
    org_type = user.org_type if user.org_type in ("university", "school") else "university"
    email = normalize_email(user.email)
    existing = crud_users.get_user_by_email(db, email, org_type)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    hashed = hash_password(user.password)
    # Роль при самостоятельной регистрации всегда student:
    # teacher/admin выдаёт только администратор через /admin.
    try:
        created = crud_users.create_user(
            db,
            email,
            hashed,
            role="student",
            full_name=user.full_name,
            org_type=org_type,
        )
    except IntegrityError:
        # Гонка: параллельная регистрация того же (email, org_type) проскочила
        # проверку existing и упёрлась в составной unique-констрейнт.
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")

    # Новый аккаунт не подтверждён (ORM default), сразу шлём код на email.
    # Вход будет заблокирован до подтверждения (login → 403 email_not_verified).
    code = issue_code(db, email, org_type, "verify")
    sent = send_code_email(email, code, "verify")
    # Аккаунт уже создан — откатывать регистрацию из-за почты нельзя, но клиент
    # должен знать, что кода не будет, и предложить запросить его повторно.
    resp = schemas.UserResponse.model_validate(created)
    resp.email_sent = sent
    return resp


@router.post("/login", response_model=schemas.Token, response_model_exclude_none=True)
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    org_type: str = Query("university"),
    session: str = Query("body"),
):
    email = normalize_email(form_data.username)
    rate_key = f"{client_ip(request)}:{email}"
    _login_limiter.check(rate_key, detail="Слишком много попыток входа. Подождите минуту.")
    user = crud_users.get_user_by_email(db, email, org_type)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="user_inactive")
    # По этому коду клиент уводит на экран ввода кода. Письмо тут не шлём, иначе
    # ретраи входа спамят почту — его запросит /auth/resend-verification.
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="email_not_verified")
    _login_limiter.reset(rate_key)
    result = _issue_tokens(
        user, db, response=response, cookie_mode=_is_cookie_mode(session)
    )
    db.commit()
    return result


@router.post("/refresh", response_model=schemas.Token, response_model_exclude_none=True)
def refresh_token(
    request: Request,
    response: Response,
    body: schemas.RefreshRequest | None = None,
    db: Session = Depends(get_db),
    session: str = Query("body"),
):
    cookie_mode = _is_cookie_mode(session)
    if cookie_mode:
        cookie_token = request.cookies.get(_REFRESH_COOKIE)
        # One-time migration bridge: a legacy web refresh token may arrive in
        # the request body before any cookie exists. Once a cookie exists, the
        # endpoint is cookie-authenticated and CSRF validation is mandatory.
        if cookie_token:
            _require_csrf(request)
            raw_token = cookie_token
        else:
            raw_token = body.refresh_token if body else None
    else:
        raw_token = body.refresh_token if body else None
    if not raw_token:
        raise HTTPException(status_code=401, detail="Refresh token required")
    try:
        payload = decode_refresh_token(raw_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = crud_users.get_user_by_id(db, int(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    # Отзыв: refresh-токен старой версии (после logout/смены пароля) недействителен.
    if int(payload.get("tv", 0)) != user.token_version:
        raise HTTPException(status_code=401, detail="Token revoked")

    _consume_refresh(db, payload, raw_token)
    result = _issue_tokens(user, db, response=response, cookie_mode=cookie_mode)
    db.commit()
    return result


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    session: str = Query("body"),
):
    """Серверный отзыв всех токенов пользователя. Инкремент token_version делает
    недействительными все ранее выданные access/refresh на всех устройствах."""
    if _is_cookie_mode(session):
        _require_csrf(request)
    current_user.token_version += 1
    _revoke_user_sessions(db, current_user.id)
    db.commit()
    _clear_session_cookies(response)


@router.post("/change-password", response_model=schemas.Token, response_model_exclude_none=True)
def change_password(
    response: Response,
    body: schemas.ChangePassword,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    session: str = Query("body"),
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="wrong_current_password")
    current_user.hashed_password = hash_password(body.new_password)
    # Отзываем все старые сессии и тут же выдаём свежую пару для текущего клиента,
    # чтобы юзера не выкинуло на экран входа после успешной смены пароля.
    current_user.token_version += 1
    _revoke_user_sessions(db, current_user.id)
    result = _issue_tokens(
        current_user, db, response=response, cookie_mode=_is_cookie_mode(session)
    )
    db.commit()
    db.refresh(current_user)
    return result


@router.post("/verify-email", response_model=schemas.Token, response_model_exclude_none=True)
def verify_email(
    response: Response,
    body: schemas.VerifyEmailRequest,
    db: Session = Depends(get_db),
    session: str = Query("body"),
):
    """Подтверждает email по коду из письма и сразу выдаёт токены (авто-вход)."""
    email = normalize_email(body.email)
    org_type = _norm_org(body.org_type)
    user = crud_users.get_user_by_email(db, email, org_type)
    if not user:
        raise HTTPException(status_code=400, detail="invalid_code")
    if user.is_verified:
        # Идемпотентность: уже подтверждён — просто впускаем.
        result = _issue_tokens(user, db, response=response, cookie_mode=_is_cookie_mode(session))
        db.commit()
        return result
    if not verify_code(db, email, org_type, "verify", body.code):
        raise HTTPException(status_code=400, detail="invalid_code")
    user.is_verified = True
    result = _issue_tokens(user, db, response=response, cookie_mode=_is_cookie_mode(session))
    db.commit()
    db.refresh(user)
    return result


@router.post("/resend-verification")
def resend_verification(body: schemas.EmailCodeRequest, request: Request, db: Session = Depends(get_db)):
    """Повторно шлёт код подтверждения. Всегда 200 (не раскрываем существование
    аккаунта). dev_code возвращается только при OTP_DEBUG=1."""
    email = normalize_email(body.email)
    org_type = _norm_org(body.org_type)
    _code_limiter.check(f"{client_ip(request)}:{email}", detail="Слишком часто. Подождите минуту.")
    resp: dict = {"sent": False}
    user = crud_users.get_user_by_email(db, email, org_type)
    if user and not user.is_verified:
        code = issue_code(db, email, org_type, "verify")
        # sent = реальная отправка: честнее сказать «не ушло», чем заставить ждать.
        # Анти-энумерация не страдает — ответ как для несуществующего аккаунта.
        resp["sent"] = send_code_email(email, code, "verify")
        if otp_debug():
            resp["dev_code"] = code
    return resp


@router.post("/forgot-password")
def forgot_password(body: schemas.EmailCodeRequest, request: Request, db: Session = Depends(get_db)):
    """Шлёт код для сброса пароля. Всегда 200 (анти-энумерация)."""
    email = normalize_email(body.email)
    org_type = _norm_org(body.org_type)
    _code_limiter.check(f"{client_ip(request)}:{email}", detail="Слишком часто. Подождите минуту.")
    resp: dict = {"sent": False}
    user = crud_users.get_user_by_email(db, email, org_type)
    if user and user.is_active:
        code = issue_code(db, email, org_type, "reset")
        resp["sent"] = send_code_email(email, code, "reset")
        if otp_debug():
            resp["dev_code"] = code
    return resp


@router.post("/reset-password", response_model=schemas.Token, response_model_exclude_none=True)
def reset_password(
    response: Response,
    body: schemas.ResetPasswordRequest,
    db: Session = Depends(get_db),
    session: str = Query("body"),
):
    """Сбрасывает пароль по коду из письма, отзывает старые сессии и впускает."""
    email = normalize_email(body.email)
    org_type = _norm_org(body.org_type)
    user = crud_users.get_user_by_email(db, email, org_type)
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="invalid_code")
    if not verify_code(db, email, org_type, "reset", body.code):
        raise HTTPException(status_code=400, detail="invalid_code")
    user.hashed_password = hash_password(body.new_password)
    # Успешный код из письма доказывает владение почтой — заодно подтверждаем email.
    user.is_verified = True
    # Отзываем все старые сессии (пароль изменился).
    user.token_version += 1
    _revoke_user_sessions(db, user.id)
    result = _issue_tokens(user, db, response=response, cookie_mode=_is_cookie_mode(session))
    db.commit()
    db.refresh(user)
    return result


@router.get("/me", response_model=schemas.UserResponse)
def me(current_user=Depends(get_current_user)):
    return current_user


@router.patch("/me", response_model=schemas.UserResponse)
def update_me(
    body: schemas.UpdateMe,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if body.full_name is not None:
        current_user.full_name = body.full_name.strip() or None

    db.commit()
    db.refresh(current_user)
    return current_user


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_me(
    body: schemas.DeleteAccount,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Самоудаление аккаунта (требование App Store / GDPR). Подтверждается
    паролем, чтобы украденный access-токен не позволил удалить аккаунт.
    Связанные записи (посты, чаты, сдачи и т.д.) удаляются каскадом на уровне
    ORM/БД — та же логика, что при удалении админом."""
    if not verify_password(body.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="wrong_current_password")
    # BE-10: файлы сдач/заданий/обложек классов пользователя не чистятся
    # каскадом на уровне БД — собираем их явно, но физически удаляем из
    # хранилища только ПОСЛЕ успешного commit() (см. crud/assignments.py::
    # delete_assignment — если бы удаление шло раньше и commit() затем упал,
    # откат вернул бы записи в БД, но их файлы были бы уже стёрты насовсем).
    from services.file_cleanup import delete_urls, user_file_urls
    urls = user_file_urls(current_user)
    db.delete(current_user)
    db.commit()
    delete_urls(urls)


def admin_required(current_user=Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin allowed")
    return current_user
