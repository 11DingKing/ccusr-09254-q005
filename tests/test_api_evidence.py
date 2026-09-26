"""证据内容指纹服务的接口测试。"""

from __future__ import annotations

import base64
import threading

from app import models
from tests.conftest import TestSessionLocal


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _register(client, case, ref, content, uploader="mentor-1", filename=None, status_code=201):
    resp = client.post(
        f"/api/cases/{case}/evidence/{ref}/register",
        json={
            "evidence_ref": ref,
            "content_base64": _b64(content),
            "uploader": uploader,
            "filename": filename,
        },
    )
    assert resp.status_code == status_code, resp.text
    return resp.json()


def _bind(client, case, ref, event_id="CONF-1", bound_by="mentor-1", status_code=201):
    resp = client.post(
        f"/api/cases/{case}/evidence/{ref}/bindings",
        json={
            "confirmation_event_id": event_id,
            "bound_by": bound_by,
            "note": "mentor confirmed",
        },
    )
    assert resp.status_code == status_code, resp.text
    return resp.json()


def _grant(client, case, ref, grantee, granted_by="mentor-1", status_code=201):
    resp = client.post(
        f"/api/cases/{case}/evidence/{ref}/grants",
        json={"grantee": grantee, "granted_by": granted_by, "role": "auditor"},
    )
    assert resp.status_code == status_code, resp.text
    return resp.json()


def _revoke(client, case, ref, revoked_by="mentor-1", reason="student request"):
    resp = client.post(
        f"/api/cases/{case}/evidence/{ref}/revoke",
        json={"revoked_by": revoked_by, "reason": reason},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _verify(client):
    resp = client.post("/api/evidence/integrity/verify")
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# 登记与重复上传
# ---------------------------------------------------------------------------


def test_register_returns_content_fingerprint(client):
    body = _register(client, "CASE-1", "EV-1", "certificate bytes", filename="c.pdf")
    assert body["sha256"]
    assert len(body["sha256"]) == 64
    assert body["status"] == "active"
    assert body["blob_reused"] is False
    assert body["deduplicated"] is False


def test_duplicate_upload_same_case_same_content_is_deduplicated(client):
    first = _register(client, "CASE-1", "EV-1", "same bytes")
    again = _register(client, "CASE-1", "EV-1", "same bytes")
    assert again["sha256"] == first["sha256"]
    assert again["deduplicated"] is True
    assert again["blob_reused"] is True
    assert again["changed"] is True  # 引用仍然存在、状态不变


def test_replacing_ref_with_different_content_is_rejected(client):
    first = _register(client, "CASE-1", "EV-1", "v1 content")
    resp = client.post(
        "/api/cases/CASE-1/evidence/EV-1/register",
        json={
            "evidence_ref": "EV-1",
            "content_base64": _b64("v2 content - different"),
            "uploader": "mentor-1",
        },
    )
    assert resp.status_code == 409, resp.text
    # 原指纹保持不变
    obj = client.get(f"/api/evidence/objects/{first['sha256']}").json()
    assert obj["sha256"] == first["sha256"]
    assert len(obj["links"]) == 1


def test_same_content_in_other_case_shares_blob_but_has_separate_link(client):
    first = _register(client, "CASE-1", "EV-1", "shared content")
    second = _register(
        client, "CASE-2", "EV-9", "shared content", uploader="mentor-2"
    )
    assert second["sha256"] == first["sha256"]
    assert second["blob_reused"] is True
    assert second["case_id"] == "CASE-2"
    obj = client.get(f"/api/evidence/objects/{first['sha256']}").json()
    assert {(lk["case_id"], lk["evidence_ref"]) for lk in obj["links"]} == {
        ("CASE-1", "EV-1"),
        ("CASE-2", "EV-9"),
    }


# ---------------------------------------------------------------------------
# 确认事件固定证据版本
# ---------------------------------------------------------------------------


def test_binding_pins_exact_version_and_is_idempotent(client):
    reg = _register(client, "CASE-1", "EV-1", "pinned bytes")
    bound = _bind(client, "CASE-1", "EV-1", event_id="CONF-7")
    assert bound["created"] is True
    assert bound["sha256"] == reg["sha256"]
    assert bound["confirmation_event_id"] == "CONF-7"

    again = _bind(client, "CASE-1", "EV-1", event_id="CONF-7")
    assert again["created"] is False
    assert again["sha256"] == reg["sha256"]

    listings = client.get("/api/cases/CASE-1/evidence/EV-1/bindings").json()
    assert len(listings["bindings"]) == 1


def test_concurrent_bindings_only_one_wins(client):
    from app.evidence import service

    _register(client, "CASE-1", "EV-1", "race bytes")
    created: list[bool] = []
    lock = threading.Lock()

    def _worker():
        session = TestSessionLocal()
        try:
            result = service.bind(
                session,
                case_id="CASE-1",
                evidence_ref="EV-1",
                confirmation_event_id="CONF-RACE",
                bound_by="mentor-1",
            )
            with lock:
                created.append(result["created"])
        finally:
            session.close()

    threads = [threading.Thread(target=_worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(created) == 1
    assert len(created) == 6
    listings = client.get("/api/cases/CASE-1/evidence/EV-1/bindings").json()
    assert len(listings["bindings"]) == 1

    # 并发追加审计后哈希链仍完整。
    report = _verify(client)
    assert report["ok"] is True, report["problems"]
    assert report["audit_entries_checked"] == 2  # register + 唯一一次 bind


# ---------------------------------------------------------------------------
# 授权与跨案件权限隔离
# ---------------------------------------------------------------------------


def test_access_requires_uploader_or_grant_and_revocation_takes_effect(client):
    _register(client, "CASE-1", "EV-1", "secret", uploader="mentor-1")

    denied = client.post(
        "/api/cases/CASE-1/evidence/EV-1/access", json={"actor": "auditor-9"}
    )
    assert denied.status_code == 403

    _grant(client, "CASE-1", "EV-1", "auditor-9")
    ok = client.post(
        "/api/cases/CASE-1/evidence/EV-1/access", json={"actor": "auditor-9"}
    ).json()
    assert ok["role"] == "auditor"
    assert base64.b64decode(ok["content_base64"]) == b"secret"

    revoked = client.post(
        "/api/cases/CASE-1/evidence/EV-1/grants/auditor-9/revoke",
        json={"revoked_by": "mentor-1", "reason": "audit window closed"},
    ).json()
    assert revoked["status"] == "revoked"
    assert revoked["changed"] is True

    denied_after = client.post(
        "/api/cases/CASE-1/evidence/EV-1/access", json={"actor": "auditor-9"}
    )
    assert denied_after.status_code == 403


def test_cross_case_grants_and_revocations_are_independent(client):
    _register(client, "CASE-1", "EV-1", "shared content", uploader="mentor-1")
    _register(client, "CASE-2", "EV-9", "shared content", uploader="mentor-2")
    _grant(client, "CASE-1", "EV-1", "auditor-9")

    # 只在 CASE-1 有授权，CASE-2 仍然拒绝。
    assert (
        client.post(
            "/api/cases/CASE-2/evidence/EV-9/access", json={"actor": "auditor-9"}
        ).status_code
        == 403
    )
    # 撤销 CASE-1 的访问不触及 CASE-2 的链接与 blob。
    _revoke(client, "CASE-1", "EV-1")
    still = client.post(
        "/api/cases/CASE-2/evidence/EV-9/access", json={"actor": "mentor-2"}
    )
    assert still.status_code == 200
    assert base64.b64decode(still.json()["content_base64"]) == b"shared content"


# ---------------------------------------------------------------------------
# 删除请求只撤销访问，历史指纹与绑定保留
# ---------------------------------------------------------------------------


def test_revocation_preserves_fingerprint_and_historical_binding(client):
    reg = _register(client, "CASE-1", "EV-1", "immutable bytes")
    _bind(client, "CASE-1", "EV-1", event_id="CONF-1")
    revoked = _revoke(client, "CASE-1", "EV-1", reason="replace requested")
    assert revoked["status"] == "revoked"
    assert revoked["sha256"] == reg["sha256"]

    # 访问被拒绝。
    denied = client.post(
        "/api/cases/CASE-1/evidence/EV-1/access", json={"actor": "mentor-1"}
    )
    assert denied.status_code == 403
    # 撤销后不能新增绑定。
    assert (
        _bind(
            client, "CASE-1", "EV-1", event_id="CONF-2", status_code=403
        )
        is not None
    )
    # 历史绑定仍可查询，指纹仍是当时看到的版本。
    listings = client.get("/api/cases/CASE-1/evidence/EV-1/bindings").json()
    assert listings["bindings"][0]["sha256"] == reg["sha256"]
    assert listings["bindings"][0]["confirmation_event_id"] == "CONF-1"

    report = _verify(client)
    assert report["ok"] is True


def test_regrant_after_grant_revoke_does_not_reopen_revoked_link(client):
    _register(client, "CASE-1", "EV-1", "bytes", uploader="mentor-1")
    _grant(client, "CASE-1", "EV-1", "auditor-9")
    client.post(
        "/api/cases/CASE-1/evidence/EV-1/grants/auditor-9/revoke",
        json={"revoked_by": "mentor-1", "reason": "temp"},
    )
    # 案件整体撤销后，即使重新授权也不能读取
    _revoke(client, "CASE-1", "EV-1")
    _grant(client, "CASE-1", "EV-1", "auditor-9")
    denied = client.post(
        "/api/cases/CASE-1/evidence/EV-1/access", json={"actor": "auditor-9"}
    )
    assert denied.status_code == 403


# ---------------------------------------------------------------------------
# 完整性检查
# ---------------------------------------------------------------------------


def test_integrity_detects_tampered_blob(client, db):
    reg = _register(client, "CASE-1", "EV-1", "original content")
    # 直接篡改存储内容（模拟底层损坏/越权改写）。
    obj = db.get(models.EvidenceObject, reg["sha256"])
    obj.content = b"tampered content does not match hash"
    db.commit()

    report = _verify(client)
    assert report["ok"] is False
    kinds = {p["kind"] for p in report["problems"]}
    assert "fingerprint_mismatch" in kinds


def test_integrity_detects_binding_version_drift(client, db):
    reg = _register(client, "CASE-1", "EV-1", "v1")
    _bind(client, "CASE-1", "EV-1", event_id="CONF-1")
    # 人为篡改链接指纹，模拟绕过服务的版本替换。
    link = db.query(models.EvidenceLink).one()
    link.sha256 = "a" * 64
    db.commit()

    report = _verify(client)
    assert report["ok"] is False
    assert any(p["kind"] == "dangling_link" for p in report["problems"])
    assert any(p["kind"] == "binding_version_drift" for p in report["problems"])


def test_integrity_detects_broken_audit_chain(client, db):
    _register(client, "CASE-1", "EV-1", "audit me")
    entry = db.query(models.EvidenceAudit).one()
    entry.detail = "rewritten after the fact"
    db.commit()
    report = _verify(client)
    assert report["ok"] is False
    assert any(p["kind"] == "audit_hash_mismatch" for p in report["problems"])


# ---------------------------------------------------------------------------
# 孤立对象清理
# ---------------------------------------------------------------------------


def test_cleanup_removes_unreferenced_blob_but_keeps_bound_history(client):
    # 输掉引用竞争 / 从未被案件引用的孤立 blob：直接写库模拟。
    orphan_sha = "b" * 64
    orphan = models.EvidenceObject(
        sha256=orphan_sha,
        content=b"orphan upload lost the race",
        size_bytes=len(b"orphan upload lost the race"),
        first_uploader="mentor-x",
    )
    client  # fixture 确保建表
    from tests.conftest import TestSessionLocal

    session = TestSessionLocal()
    session.add(orphan)
    session.commit()
    session.close()

    reg = _register(client, "CASE-1", "EV-1", "bound content")
    _bind(client, "CASE-1", "EV-1", event_id="CONF-1")
    # 撤销案件访问后清理：绑定仍在，blob 必须保留。
    _revoke(client, "CASE-1", "EV-1")

    result = client.post(
        "/api/evidence/integrity/cleanup-orphans", json={"actor": "janitor"}
    ).json()
    assert orphan_sha in result["sha256"]
    assert reg["sha256"] not in result["sha256"]

    # 绑定引用的对象仍可通过管理视图查看。
    overview = client.get(f"/api/evidence/objects/{reg['sha256']}").json()
    assert overview["sha256"] == reg["sha256"]
    assert client.get(f"/api/evidence/objects/{orphan_sha}").status_code == 404

    report = _verify(client)
    assert report["ok"] is True


def test_cleanup_keeps_blob_referenced_by_any_active_case(client):
    _register(client, "CASE-1", "EV-1", "alive content")
    result = client.post(
        "/api/evidence/integrity/cleanup-orphans", json={"actor": "janitor"}
    ).json()
    assert result["removed"] == 0
