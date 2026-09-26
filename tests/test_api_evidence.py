"""证据内容寻址与访问控制的接口测试。"""

from __future__ import annotations

import base64
import hashlib
import threading

from sqlalchemy import select

from app import services
from app.models import EvidenceAccessEvent, EvidenceBinding, EvidenceGrant, EvidenceObject
from tests.conftest import SHANGHAI_PLAN, TestSessionLocal


def _b64(content: bytes) -> str:
    return base64.b64encode(content).decode("ascii")


def _register(client, content: bytes, uploader: str = "mentor-1") -> dict:
    resp = client.post(
        "/api/evidence/objects",
        json={"content_b64": _b64(content), "uploader_id": uploader},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _bind(client, case_id: str, content_hash: str, bound_by: str = "mentor-1") -> dict:
    resp = client.post(
        f"/api/cases/{case_id}/evidence",
        json={"content_hash": content_hash, "bound_by": bound_by},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _grant(client, case_id: str, content_hash: str, subject: str) -> dict:
    resp = client.post(
        f"/api/cases/{case_id}/evidence/{content_hash}/grants",
        json={"subject_id": subject, "granted_by": "officer-1"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _read_content(client, case_id: str, content_hash: str, subject: str):
    return client.get(
        f"/api/cases/{case_id}/evidence/{content_hash}/content",
        params={"subject_id": subject},
    )


def test_duplicate_upload_reuses_same_object(client):
    first = _register(client, b"proof-of-internship")
    assert first["created"] is True
    assert first["upload_count"] == 1
    assert first["content_hash"] == hashlib.sha256(b"proof-of-internship").hexdigest()

    second = _register(client, b"proof-of-internship", uploader="mentor-2")
    assert second["created"] is False
    assert second["content_hash"] == first["content_hash"]
    assert second["upload_count"] == 2

    other = _register(client, b"different-proof")
    assert other["content_hash"] != first["content_hash"]

    meta = client.get(f"/api/evidence/objects/{first['content_hash']}")
    assert meta.status_code == 200
    assert meta.json()["upload_count"] == 2


def test_register_rejects_invalid_base64(client):
    resp = client.post(
        "/api/evidence/objects",
        json={"content_b64": "!!!not-base64!!!", "uploader_id": "mentor-1"},
    )
    assert resp.status_code == 422


def test_bind_requires_registered_object(client):
    resp = client.post(
        "/api/cases/case-1/evidence",
        json={"content_hash": "0" * 64, "bound_by": "mentor-1"},
    )
    assert resp.status_code == 404


def test_concurrent_binding_keeps_single_reference(client):
    obj = _register(client, b"concurrent-proof")
    digest = obj["content_hash"]

    results: list[bool] = []
    errors: list[Exception] = []

    def _bind_in_thread() -> None:
        session = TestSessionLocal()
        try:
            out = services.bind_evidence(
                session,
                case_id="case-concurrent",
                content_hash=digest,
                bound_by="mentor-1",
            )
            results.append(out["created"])
        except Exception as exc:  # pragma: no cover - 失败时由断言暴露
            errors.append(exc)
        finally:
            session.close()

    threads = [threading.Thread(target=_bind_in_thread) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert results.count(True) == 1
    assert results.count(False) == 7

    bindings = client.get("/api/cases/case-concurrent/evidence").json()
    assert len(bindings) == 1
    assert bindings[0]["content_hash"] == digest


def test_concurrent_duplicate_upload_keeps_single_object(client):
    digest = hashlib.sha256(b"shared-proof").hexdigest()

    created_flags: list[bool] = []
    errors: list[Exception] = []

    def _register_in_thread() -> None:
        session = TestSessionLocal()
        try:
            out = services.register_evidence(
                session, content=b"shared-proof", media_type="text/plain", uploader_id="u"
            )
            created_flags.append(out["created"])
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
        finally:
            session.close()

    threads = [threading.Thread(target=_register_in_thread) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert created_flags.count(True) == 1

    meta = client.get(f"/api/evidence/objects/{digest}").json()
    assert meta["upload_count"] == 6


def test_permissions_are_scoped_per_case(client):
    obj = _register(client, b"cross-case-proof")
    digest = obj["content_hash"]
    _bind(client, "case-A", digest)
    _bind(client, "case-B", digest)

    _grant(client, "case-A", digest, "auditor-1")

    ok = _read_content(client, "case-A", digest, "auditor-1")
    assert ok.status_code == 200
    assert base64.b64decode(ok.json()["content_b64"]) == b"cross-case-proof"

    # 相同内容在另一个案件中没有授权，不能读取。
    denied = _read_content(client, "case-B", digest, "auditor-1")
    assert denied.status_code == 403

    # 撤销后读取被拒绝，重新授权后恢复。
    resp = client.post(
        f"/api/cases/case-A/evidence/{digest}/grants/auditor-1/revoke",
        json={"revoked_by": "officer-1", "reason": "case closed"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "revoked"
    assert _read_content(client, "case-A", digest, "auditor-1").status_code == 403

    _grant(client, "case-A", digest, "auditor-1")
    assert _read_content(client, "case-A", digest, "auditor-1").status_code == 200

    grants = client.get(f"/api/cases/case-A/evidence/{digest}/grants").json()
    assert len(grants) == 1
    assert grants[0]["state"] == "granted"
    assert grants[0]["version"] == 3


def test_delete_request_revokes_access_but_preserves_history(client, db):
    obj = _register(client, b"deletion-proof")
    digest = obj["content_hash"]
    _bind(client, "case-del", digest)
    _grant(client, "case-del", digest, "auditor-1")
    _grant(client, "case-del", digest, "auditor-2")

    resp = client.request(
        "DELETE",
        f"/api/cases/case-del/evidence/{digest}",
        json={"revoked_by": "officer-1", "reason": "retention request"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["revoked_grants"] == 2
    assert body["object_preserved"] is True
    assert body["binding_preserved"] is True

    # 访问被撤销，但对象、引用和审计流水都还在。
    assert _read_content(client, "case-del", digest, "auditor-1").status_code == 403
    assert client.get(f"/api/evidence/objects/{digest}").status_code == 200
    assert len(client.get("/api/cases/case-del/evidence").json()) == 1

    grants = db.execute(select(EvidenceGrant)).scalars().all()
    assert {g.state for g in grants} == {"revoked"}
    assert all(g.revoked_by == "officer-1" for g in grants)

    history = client.get(f"/api/cases/case-del/evidence/{digest}/history").json()
    actions = [h["action"] for h in history]
    assert actions.count("grant") == 2
    assert actions.count("revoke") == 2

    integrity = client.post("/api/evidence/integrity").json()
    assert integrity["ok"] is True


def test_integrity_check_detects_tampering(client, db):
    obj = _register(client, b"tamper-target")
    digest = obj["content_hash"]
    _bind(client, "case-tamper", digest)

    clean = client.post("/api/evidence/integrity").json()
    assert clean["ok"] is True
    assert clean["checked_objects"] == 1

    stored = db.get(EvidenceObject, digest)
    stored.content = b"tampered-content"
    db.commit()

    report = client.post("/api/evidence/integrity").json()
    assert report["ok"] is False
    assert report["corrupted_objects"] == [digest]


def test_orphan_gc_removes_only_unreferenced_objects(client):
    bound_obj = _register(client, b"bound-proof")
    orphan = _register(client, b"orphan-proof")
    revoked_obj = _register(client, b"revoked-proof")

    _bind(client, "case-gc", bound_obj["content_hash"])
    _bind(client, "case-gc", revoked_obj["content_hash"])
    _grant(client, "case-gc", revoked_obj["content_hash"], "auditor-1")
    client.request(
        "DELETE",
        f"/api/cases/case-gc/evidence/{revoked_obj['content_hash']}",
        json={"revoked_by": "officer-1"},
    )

    resp = client.post("/api/evidence/gc")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["removed"] == [orphan["content_hash"]]
    assert body["removed_count"] == 1
    assert body["kept_count"] == 2

    # 孤立对象被清理；有引用的对象即使访问已撤销也保留指纹。
    assert client.get(f"/api/evidence/objects/{orphan['content_hash']}").status_code == 404
    assert client.get(f"/api/evidence/objects/{bound_obj['content_hash']}").status_code == 200
    assert client.get(f"/api/evidence/objects/{revoked_obj['content_hash']}").status_code == 200

    # 再次执行为空操作，保持幂等。
    again = client.post("/api/evidence/gc").json()
    assert again["removed_count"] == 0


def test_mentor_confirm_pins_evidence_versions(client):
    client.post("/api/plans", json=SHANGHAI_PLAN)
    obj = _register(client, b"mentor-confirmation-proof")
    digest = obj["content_hash"]

    plan = SHANGHAI_PLAN["plan_version"]
    client.post(
        f"/api/plans/{plan}/events",
        json={
            "events": [
                {
                    "event_id": "E-01",
                    "event_type": "checkin",
                    "student_id": "S1",
                    "payload": {
                        "activity_id": "A1",
                        "activity_type": "internship",
                        "check_in_at": "2024-03-15T08:00:00+08:00",
                        "check_out_at": "2024-03-15T12:00:00+08:00",
                    },
                }
            ]
        },
    )

    resp = client.post(
        f"/api/plans/{plan}/events",
        json={
            "events": [
                {
                    "event_id": "E-CONF-1",
                    "event_type": "mentor_confirm",
                    "student_id": "S1",
                    "payload": {
                        "checkin_event_id": "E-01",
                        "confirmed_by": "mentor-9",
                        "evidence_hashes": [digest],
                    },
                }
            ]
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["accepted"] == 1

    bindings = client.get("/api/cases/E-CONF-1/evidence").json()
    assert len(bindings) == 1
    assert bindings[0]["content_hash"] == digest
    assert bindings[0]["bound_by"] == "mentor-9"

    # 重复导入同一确认事件不会重复固定证据。
    again = client.post(
        f"/api/plans/{plan}/events",
        json={
            "events": [
                {
                    "event_id": "E-CONF-1",
                    "event_type": "mentor_confirm",
                    "student_id": "S1",
                    "payload": {
                        "checkin_event_id": "E-01",
                        "evidence_hashes": [digest],
                    },
                }
            ]
        },
    )
    assert again.json()["duplicates"] == ["E-CONF-1"]
    assert len(client.get("/api/cases/E-CONF-1/evidence").json()) == 1


def test_mentor_confirm_with_unregistered_evidence_is_rejected(client):
    client.post("/api/plans", json=SHANGHAI_PLAN)
    plan = SHANGHAI_PLAN["plan_version"]
    client.post(
        f"/api/plans/{plan}/events",
        json={
            "events": [
                {
                    "event_id": "E-01",
                    "event_type": "checkin",
                    "student_id": "S1",
                    "payload": {
                        "activity_id": "A1",
                        "activity_type": "internship",
                        "check_in_at": "2024-03-15T08:00:00+08:00",
                        "check_out_at": "2024-03-15T12:00:00+08:00",
                    },
                }
            ]
        },
    )

    resp = client.post(
        f"/api/plans/{plan}/events",
        json={
            "events": [
                {
                    "event_id": "E-CONF-2",
                    "event_type": "mentor_confirm",
                    "student_id": "S1",
                    "payload": {
                        "checkin_event_id": "E-01",
                        "evidence_hashes": ["f" * 64],
                    },
                }
            ]
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["accepted"] == 0
    assert body["rejected"][0]["event_id"] == "E-CONF-2"
    assert "unregistered evidence" in body["rejected"][0]["reason"]

    # 被拒绝的确认事件不产生绑定，签到仍处于待确认状态。
    assert client.get("/api/cases/E-CONF-2/evidence").json() == []
    progress = client.get(f"/api/plans/{plan}/students/S1/progress").json()
    assert progress["pending_seconds"] == 4 * 3600
    assert progress["confirmed_seconds"] == 0


def test_access_events_are_append_only_audit(client, db):
    obj = _register(client, b"audit-proof")
    digest = obj["content_hash"]
    _bind(client, "case-audit", digest)
    _grant(client, "case-audit", digest, "auditor-1")
    client.post(
        f"/api/cases/case-audit/evidence/{digest}/grants/auditor-1/revoke",
        json={"revoked_by": "officer-1", "reason": "rotation"},
    )

    events = db.execute(select(EvidenceAccessEvent)).scalars().all()
    assert [(e.action, e.subject_id) for e in events] == [
        ("grant", "auditor-1"),
        ("revoke", "auditor-1"),
    ]
    assert events[1].reason == "rotation"

    bindings = db.execute(select(EvidenceBinding)).scalars().all()
    assert len(bindings) == 1
