from fastapi.testclient import TestClient

from crud import classes
from tests.conftest import auth_headers, make_user


def test_pins_are_shared_between_sessions_and_isolated_by_account(client, db_session):
    teacher = make_user(db_session, role="teacher")
    student = make_user(db_session)
    other_student = make_user(db_session)
    subject = classes.create_class(db_session, "Physics", None, created_by=teacher.id)
    classes.add_member(db_session, subject.id, student.id)
    classes.add_member(db_session, subject.id, other_student.id)

    route = f"/api/classes/pins/{subject.id}"
    headers = auth_headers(student)
    second_client = TestClient(client.app)
    assert client.put(route, json={"pinned": True}, headers=headers).status_code == 204
    assert second_client.get("/api/classes/pins", headers=auth_headers(student)).json() == [subject.id]
    assert second_client.get("/api/classes/pins", headers=auth_headers(other_student)).json() == []
    assert second_client.put(route, json={"pinned": False}, headers=auth_headers(student)).status_code == 204
    assert client.get("/api/classes/pins", headers=headers).json() == []


def test_import_keeps_order_and_never_restores_unpinned_or_inaccessible_subjects(client, db_session):
    teacher = make_user(db_session, role="teacher")
    student = make_user(db_session)
    a, b, c, inaccessible = [
        classes.create_class(db_session, name, None, created_by=teacher.id)
        for name in ("A", "B", "C", "Private")
    ]
    for subject in (a, b, c):
        classes.add_member(db_session, subject.id, student.id)
    headers = auth_headers(student)

    assert client.put(f"/api/classes/pins/{inaccessible.id}", json={"pinned": True}, headers=headers).status_code == 403
    assert client.put(f"/api/classes/pins/{a.id}", json={"pinned": False}, headers=headers).status_code == 204
    imported = {"class_ids": [c.id, inaccessible.id, a.id, b.id, c.id]}
    for _ in range(2):
        assert client.post("/api/classes/pins/import", json=imported, headers=headers).status_code == 204
    assert client.get("/api/classes/pins", headers=headers).json() == [c.id, b.id]

    assert client.put(f"/api/classes/pins/{a.id}", json={"pinned": True}, headers=headers).status_code == 204
    assert client.put(f"/api/classes/pins/{c.id}", json={"pinned": True}, headers=headers).status_code == 204
    assert client.get("/api/classes/pins", headers=headers).json() == [c.id, b.id, a.id]
