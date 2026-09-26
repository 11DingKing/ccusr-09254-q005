"""服务端业务模块。"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from .core.snapshot import Snapshot, build_snapshot, diff_snapshots, explain_student
from .repository import (
    create_grant,
    delete_evidence_objects,
    get_binding,
    get_evidence_object,
    get_freeze,
    get_grant,
    get_plan,
    insert_access_event,
    insert_binding,
    insert_events,
    insert_evidence_object,
    insert_freeze,
    list_access_events,
    list_bindings,
    list_bound_hashes,
    list_evidence_objects,
    list_grants,
    load_events,
    load_events_up_to,
    max_event_id,
    save_grant,
    touch_evidence_upload,
    upsert_plan,
)


class PlanNotFoundError(Exception):
    pass


class FreezeConflictError(Exception):
    pass


class FreezeNotFoundError(Exception):
    pass


class EvidenceValidationError(Exception):
    pass


class EvidenceNotFoundError(Exception):
    pass


class BindingNotFoundError(Exception):
    pass


class GrantNotFoundError(Exception):
    pass


class EvidenceAccessDeniedError(Exception):
    pass


def get_plan_plain(db: Session, plan_version: str) -> dict[str, Any] | None:
    plan = get_plan(db, plan_version)
    if plan is None:
        return None
    return {
        "plan_version": plan.plan_version,
        "iana_timezone": plan.iana_timezone,
        "required_seconds": plan.required_seconds,
    }


def ensure_plan(
    db: Session,
    *,
    plan_version: str,
    iana_timezone: str,
    required_seconds: int,
) -> dict[str, Any]:
    plan = upsert_plan(
        db,
        plan_version=plan_version,
        iana_timezone=iana_timezone,
        required_seconds=required_seconds,
    )
    return {
        "plan_version": plan.plan_version,
        "iana_timezone": plan.iana_timezone,
        "required_seconds": plan.required_seconds,
    }


def _require_plan(db: Session, plan_version: str):
    plan = get_plan(db, plan_version)
    if plan is None:
        raise PlanNotFoundError(f"plan version '{plan_version}' is not registered")
    return plan


def _evidence_hashes_of(event: dict[str, Any]) -> list[str]:
    """导师确认事件可附带证据指纹，导入时固定到确认事件对应的案件。"""
    if event.get("event_type") != "mentor_confirm":
        return []
    payload = event.get("payload") or {}
    raw = payload.get("evidence_hashes") or []
    return sorted({str(h).strip().lower() for h in raw})


def import_events(
    db: Session, *, plan_version: str, events: list[dict[str, Any]]
) -> dict[str, Any]:
    _require_plan(db, plan_version)
    candidates: list[tuple[dict[str, Any], list[str]]] = []
    rejected: list[dict[str, Any]] = []
    for event in events:
        hashes = _evidence_hashes_of(event)
        unknown = [h for h in hashes if get_evidence_object(db, h) is None]
        if unknown:
            rejected.append(
                {
                    "event_id": event.get("event_id"),
                    "reason": "unregistered evidence: " + ", ".join(unknown),
                }
            )
            continue
        candidates.append((event, hashes))
    accepted, duplicates = insert_events(
        db, plan_version=plan_version, events=[e for e, _ in candidates]
    )
    accepted_ids = set(accepted)
    for event, hashes in candidates:
        if not hashes or event["event_id"] not in accepted_ids:
            continue
        payload = event.get("payload") or {}
        bound_by = str(payload.get("confirmed_by") or event["student_id"])
        for content_hash in hashes:
            insert_binding(
                db,
                case_id=event["event_id"],
                content_hash=content_hash,
                bound_by=bound_by,
                note="mentor_confirm",
            )
    return {
        "accepted": len(accepted),
        "duplicates": duplicates,
        "rejected": rejected,
    }


def current_snapshot(db: Session, plan_version: str) -> Snapshot:
    plan = _require_plan(db, plan_version)
    events = load_events(db, plan_version)
    return build_snapshot(
        events,
        plan_version=plan_version,
        timezone_name=plan.iana_timezone,
        required_seconds=plan.required_seconds,
    )


def student_progress(
    db: Session, plan_version: str, student_id: str
) -> dict[str, Any] | None:
    snap = current_snapshot(db, plan_version)
    return explain_student(snap, student_id)


def freeze_semester(
    db: Session, *, plan_version: str, freeze_id: str
) -> tuple[Snapshot, bool]:
    """执行确定性的业务处理。"""
    plan = _require_plan(db, plan_version)
    existing = get_freeze(db, plan_version, freeze_id)
    if existing is not None:
        return Snapshot.from_dict(existing.snapshot), False

    cutoff = max_event_id(db, plan_version)
    events = load_events(db, plan_version)
    snap = build_snapshot(
        events,
        plan_version=plan_version,
        timezone_name=plan.iana_timezone,
        required_seconds=plan.required_seconds,
        freeze_id=freeze_id,
        event_cutoff_id=cutoff,
    )
    row = insert_freeze(
        db,
        plan_version=plan_version,
        freeze_id=freeze_id,
        snapshot=snap.to_dict(),
        event_cutoff_id=cutoff,
    )
    if row is None:
        existing = get_freeze(db, plan_version, freeze_id)
        assert existing is not None
        return Snapshot.from_dict(existing.snapshot), False
    return snap, True


def get_frozen_snapshot(
    db: Session, plan_version: str, freeze_id: str
) -> Snapshot:
    _require_plan(db, plan_version)
    row = get_freeze(db, plan_version, freeze_id)
    if row is None:
        raise FreezeNotFoundError(
            f"freeze '{freeze_id}' for plan '{plan_version}' does not exist"
        )
    return Snapshot.from_dict(row.snapshot)


def explain_frozen_student(
    db: Session, plan_version: str, freeze_id: str, student_id: str
) -> dict[str, Any] | None:
    snap = get_frozen_snapshot(db, plan_version, freeze_id)
    return explain_student(snap, student_id)


def diff_freezes(
    db: Session, plan_version: str, old_freeze_id: str, new_freeze_id: str
) -> dict[str, Any]:
    old = get_frozen_snapshot(db, plan_version, old_freeze_id)
    new = get_frozen_snapshot(db, plan_version, new_freeze_id)
    return diff_snapshots(old, new)


# ---- 证据内容寻址与访问控制 ----

MAX_EVIDENCE_BYTES = 8 * 1024 * 1024

GRANT_GRANTED = "granted"
GRANT_REVOKED = "revoked"


def _normalize_hash(content_hash: str) -> str:
    digest = content_hash.strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise EvidenceValidationError(
            "content_hash must be a 64-character hex digest"
        )
    return digest


def _evidence_object_out(obj: Any, *, created: bool) -> dict[str, Any]:
    return {
        "content_hash": obj.content_hash,
        "media_type": obj.media_type,
        "size_bytes": obj.size_bytes,
        "uploader_id": obj.uploader_id,
        "upload_count": obj.upload_count,
        "created": created,
        "created_at": obj.created_at,
    }


def _binding_out(binding: Any, *, created: bool) -> dict[str, Any]:
    return {
        "case_id": binding.case_id,
        "content_hash": binding.content_hash,
        "bound_by": binding.bound_by,
        "note": binding.note,
        "created": created,
        "created_at": binding.created_at,
    }


def _grant_out(grant: Any) -> dict[str, Any]:
    return {
        "case_id": grant.case_id,
        "content_hash": grant.content_hash,
        "subject_id": grant.subject_id,
        "state": grant.state,
        "granted_by": grant.granted_by,
        "revoked_by": grant.revoked_by,
        "revoke_reason": grant.revoke_reason,
        "version": grant.version,
        "updated_at": grant.updated_at,
    }


def register_evidence(
    db: Session, *, content: bytes, media_type: str, uploader_id: str
) -> dict[str, Any]:
    """按内容指纹登记证据对象，重复上传只累计次数不产生新对象。"""
    uploader = uploader_id.strip()
    if not uploader:
        raise EvidenceValidationError("uploader_id must not be empty")
    if not content:
        raise EvidenceValidationError("evidence content must not be empty")
    if len(content) > MAX_EVIDENCE_BYTES:
        raise EvidenceValidationError("evidence content exceeds the size limit")
    digest = hashlib.sha256(content).hexdigest()
    inserted = insert_evidence_object(
        db,
        content_hash=digest,
        content=content,
        media_type=media_type.strip() or "application/octet-stream",
        size_bytes=len(content),
        uploader_id=uploader,
    )
    if not inserted:
        touch_evidence_upload(db, digest)
    obj = get_evidence_object(db, digest)
    assert obj is not None
    return _evidence_object_out(obj, created=inserted)


def get_evidence_metadata(db: Session, content_hash: str) -> dict[str, Any]:
    digest = _normalize_hash(content_hash)
    obj = get_evidence_object(db, digest)
    if obj is None:
        raise EvidenceNotFoundError(f"evidence object '{digest}' is not registered")
    return _evidence_object_out(obj, created=False)


def bind_evidence(
    db: Session,
    *,
    case_id: str,
    content_hash: str,
    bound_by: str,
    note: str = "",
) -> dict[str, Any]:
    """把已登记证据固定到案件，绑定不可变且并发安全。"""
    case = case_id.strip()
    binder = bound_by.strip()
    if not case or not binder:
        raise EvidenceValidationError("case_id and bound_by must not be empty")
    digest = _normalize_hash(content_hash)
    if get_evidence_object(db, digest) is None:
        raise EvidenceNotFoundError(f"evidence object '{digest}' is not registered")
    created = insert_binding(
        db, case_id=case, content_hash=digest, bound_by=binder, note=note.strip()
    )
    binding = get_binding(db, case, digest)
    assert binding is not None
    return _binding_out(binding, created=created)


def list_case_bindings(db: Session, case_id: str) -> list[dict[str, Any]]:
    return [
        _binding_out(b, created=False)
        for b in list_bindings(db, case_id=case_id.strip())
    ]


def grant_evidence_access(
    db: Session,
    *,
    case_id: str,
    content_hash: str,
    subject_id: str,
    granted_by: str,
) -> dict[str, Any]:
    """按案件授权访问证据，权限只作用于当前案件。"""
    case = case_id.strip()
    subject = subject_id.strip()
    actor = granted_by.strip()
    if not case or not subject or not actor:
        raise EvidenceValidationError(
            "case_id, subject_id and granted_by must not be empty"
        )
    digest = _normalize_hash(content_hash)
    if get_binding(db, case, digest) is None:
        raise BindingNotFoundError(
            f"evidence '{digest}' is not bound to case '{case}'"
        )
    grant = get_grant(db, case, digest, subject)
    if grant is None:
        grant = create_grant(
            db,
            case_id=case,
            content_hash=digest,
            subject_id=subject,
            granted_by=actor,
        )
        insert_access_event(
            db,
            case_id=case,
            content_hash=digest,
            subject_id=subject,
            action="grant",
            actor_id=actor,
        )
    elif grant.state != GRANT_GRANTED:
        grant.state = GRANT_GRANTED
        grant.granted_by = actor
        grant.revoked_by = None
        grant.revoke_reason = None
        grant.version += 1
        grant.updated_at = datetime.now(timezone.utc)
        grant = save_grant(db, grant)
        insert_access_event(
            db,
            case_id=case,
            content_hash=digest,
            subject_id=subject,
            action="grant",
            actor_id=actor,
        )
    return _grant_out(grant)


def revoke_evidence_access(
    db: Session,
    *,
    case_id: str,
    content_hash: str,
    subject_id: str,
    revoked_by: str,
    reason: str = "",
) -> dict[str, Any]:
    """撤销访问只改变授权状态，历史指纹与审计流水保持不变。"""
    case = case_id.strip()
    subject = subject_id.strip()
    actor = revoked_by.strip()
    if not actor:
        raise EvidenceValidationError("revoked_by must not be empty")
    digest = _normalize_hash(content_hash)
    grant = get_grant(db, case, digest, subject)
    if grant is None:
        raise GrantNotFoundError(
            f"no grant for subject '{subject}' on evidence '{digest}' in case '{case}'"
        )
    if grant.state != GRANT_REVOKED:
        grant.state = GRANT_REVOKED
        grant.revoked_by = actor
        grant.revoke_reason = reason.strip()
        grant.version += 1
        grant.updated_at = datetime.now(timezone.utc)
        grant = save_grant(db, grant)
        insert_access_event(
            db,
            case_id=case,
            content_hash=digest,
            subject_id=subject,
            action="revoke",
            actor_id=actor,
            reason=reason.strip(),
        )
    return _grant_out(grant)


def request_evidence_deletion(
    db: Session,
    *,
    case_id: str,
    content_hash: str,
    revoked_by: str,
    reason: str = "",
) -> dict[str, Any]:
    """删除请求只撤销该案件下的全部访问授权，对象与引用关系保留。"""
    case = case_id.strip()
    actor = revoked_by.strip()
    if not actor:
        raise EvidenceValidationError("revoked_by must not be empty")
    digest = _normalize_hash(content_hash)
    if get_binding(db, case, digest) is None:
        raise BindingNotFoundError(
            f"evidence '{digest}' is not bound to case '{case}'"
        )
    active = list_grants(db, case_id=case, content_hash=digest, state=GRANT_GRANTED)
    for grant in active:
        grant.state = GRANT_REVOKED
        grant.revoked_by = actor
        grant.revoke_reason = reason.strip()
        grant.version += 1
        grant.updated_at = datetime.now(timezone.utc)
        save_grant(db, grant)
        insert_access_event(
            db,
            case_id=case,
            content_hash=digest,
            subject_id=grant.subject_id,
            action="revoke",
            actor_id=actor,
            reason=reason.strip(),
        )
    return {
        "case_id": case,
        "content_hash": digest,
        "revoked_grants": len(active),
        "object_preserved": True,
        "binding_preserved": True,
    }


def list_case_grants(
    db: Session, case_id: str, content_hash: str
) -> list[dict[str, Any]]:
    digest = _normalize_hash(content_hash)
    return [
        _grant_out(g)
        for g in list_grants(db, case_id=case_id.strip(), content_hash=digest)
    ]


def list_access_history(
    db: Session, case_id: str, content_hash: str
) -> list[dict[str, Any]]:
    digest = _normalize_hash(content_hash)
    return [
        {
            "case_id": e.case_id,
            "content_hash": e.content_hash,
            "subject_id": e.subject_id,
            "action": e.action,
            "actor_id": e.actor_id,
            "reason": e.reason,
            "occurred_at": e.occurred_at,
        }
        for e in list_access_events(db, case_id=case_id.strip(), content_hash=digest)
    ]


def read_case_evidence(
    db: Session, *, case_id: str, content_hash: str, subject_id: str
) -> dict[str, Any]:
    """读取证据内容前校验当前案件下的有效授权。"""
    case = case_id.strip()
    subject = subject_id.strip()
    digest = _normalize_hash(content_hash)
    if get_binding(db, case, digest) is None:
        raise BindingNotFoundError(
            f"evidence '{digest}' is not bound to case '{case}'"
        )
    obj = get_evidence_object(db, digest)
    if obj is None:
        raise EvidenceNotFoundError(f"evidence object '{digest}' is not registered")
    grant = get_grant(db, case, digest, subject)
    if grant is None or grant.state != GRANT_GRANTED:
        raise EvidenceAccessDeniedError(
            f"subject '{subject}' has no active grant for this evidence"
        )
    return {
        "case_id": case,
        "content_hash": digest,
        "media_type": obj.media_type,
        "size_bytes": obj.size_bytes,
        "content_b64": base64.b64encode(obj.content).decode("ascii"),
    }


def check_evidence_integrity(db: Session) -> dict[str, Any]:
    """重算内容指纹并核对引用关系，发现篡改或悬空引用。"""
    objects = list_evidence_objects(db)
    corrupted: list[str] = []
    for obj in objects:
        if len(obj.content) != obj.size_bytes:
            corrupted.append(obj.content_hash)
            continue
        if hashlib.sha256(obj.content).hexdigest() != obj.content_hash:
            corrupted.append(obj.content_hash)
    known_hashes = {o.content_hash for o in objects}
    bindings = list_bindings(db)
    dangling_bindings = [
        {"case_id": b.case_id, "content_hash": b.content_hash}
        for b in bindings
        if b.content_hash not in known_hashes
    ]
    bound_pairs = {(b.case_id, b.content_hash) for b in bindings}
    dangling_grants = [
        {
            "case_id": g.case_id,
            "content_hash": g.content_hash,
            "subject_id": g.subject_id,
        }
        for g in list_grants(db)
        if (g.case_id, g.content_hash) not in bound_pairs
    ]
    ok = not corrupted and not dangling_bindings and not dangling_grants
    return {
        "ok": ok,
        "checked_objects": len(objects),
        "corrupted_objects": sorted(corrupted),
        "dangling_bindings": dangling_bindings,
        "dangling_grants": dangling_grants,
    }


def collect_orphan_evidence(db: Session) -> dict[str, Any]:
    """清理从未被任何案件引用的孤立对象，被引用对象的历史指纹保留。"""
    bound = list_bound_hashes(db)
    objects = list_evidence_objects(db)
    orphans = sorted(o.content_hash for o in objects if o.content_hash not in bound)
    delete_evidence_objects(db, orphans)
    return {
        "removed": orphans,
        "removed_count": len(orphans),
        "kept_count": len(objects) - len(orphans),
    }
