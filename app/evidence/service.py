"""证据对象的内容寻址登记、版本固定、授权与完整性校验。"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    EvidenceAudit,
    EvidenceBinding,
    EvidenceGrant,
    EvidenceLink,
    EvidenceObject,
)

GENESIS_HASH = "0" * 64


class EvidenceError(Exception):
    """证据域业务错误基类。"""


class EvidenceNotFoundError(EvidenceError):
    pass


class EvidenceConflictError(EvidenceError):
    pass


class EvidencePermissionError(EvidenceError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def hash_content(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _decode(content_b64: str) -> bytes:
    try:
        return base64.b64decode(content_b64, validate=True)
    except Exception as exc:  # noqa: BLE001 - pydantic 之外的输入防御
        raise EvidenceError("content 必须是 base64 编码") from exc


def _require_text(value: str, field: str) -> str:
    value = value.strip()
    if not value:
        raise EvidenceError(f"{field} 不能为空")
    return value


def _chain_hash(
    *,
    sequence: int,
    action: str,
    case_id: str | None,
    evidence_ref: str | None,
    sha256: str | None,
    actor_id: str,
    detail: str,
    prev_hash: str,
    created_at: datetime,
) -> str:
    payload = "|".join(
        [
            str(sequence),
            action,
            case_id or "",
            evidence_ref or "",
            sha256 or "",
            actor_id,
            detail,
            prev_hash,
            created_at.isoformat(),
        ]
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _append_audit(
    db: Session,
    *,
    action: str,
    actor_id: str,
    case_id: str | None = None,
    evidence_ref: str | None = None,
    sha256: str | None = None,
    detail: str = "",
) -> EvidenceAudit:
    """追加一条哈希链审计记录（同事务内串行）。"""
    created_at = _now()
    entry = EvidenceAudit(
        action=action,
        case_id=case_id,
        evidence_ref=evidence_ref,
        sha256=sha256,
        actor_id=actor_id,
        detail=detail,
        prev_hash=GENESIS_HASH,
        entry_hash="",
        created_at=created_at,
    )
    db.add(entry)
    db.flush()  # 先取得自增 sequence；SQLite 写锁保证此时更早记录均已提交

    predecessor = db.execute(
        select(EvidenceAudit)
        .where(EvidenceAudit.sequence < entry.sequence)
        .order_by(EvidenceAudit.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()
    prev_hash = predecessor.entry_hash if predecessor is not None else GENESIS_HASH
    entry.prev_hash = prev_hash
    entry.entry_hash = _chain_hash(
        sequence=entry.sequence,
        action=action,
        case_id=case_id,
        evidence_ref=evidence_ref,
        sha256=sha256,
        actor_id=actor_id,
        detail=detail,
        prev_hash=prev_hash,
        created_at=created_at,
    )
    db.flush()
    return entry


def _get_object(db: Session, sha256: str) -> EvidenceObject | None:
    return db.get(EvidenceObject, sha256)


def _get_link(
    db: Session, case_id: str, evidence_ref: str
) -> EvidenceLink | None:
    return db.execute(
        select(EvidenceLink).where(
            EvidenceLink.case_id == case_id,
            EvidenceLink.evidence_ref == evidence_ref,
        )
    ).scalar_one_or_none()


def _require_link(db: Session, case_id: str, evidence_ref: str) -> EvidenceLink:
    link = _get_link(db, case_id, evidence_ref)
    if link is None:
        raise EvidenceNotFoundError(
            f"案件 '{case_id}' 中不存在证据 '{evidence_ref}'"
        )
    return link


def register(
    db: Session,
    *,
    case_id: str,
    evidence_ref: str,
    content_b64: str,
    uploader: str,
    filename: str | None = None,
    media_type: str | None = None,
) -> dict[str, Any]:
    """登记证据对象并在案件下建立引用。

    同一内容重复上传时复用全局 blob（去重）；同一证据引用若已指向不同
    内容则拒绝——确认事件固定的是不可变版本，"替换"必须使用新引用登记。
    """
    case_id = _require_text(case_id, "case_id")
    evidence_ref = _require_text(evidence_ref, "evidence_ref")
    uploader = _require_text(uploader, "uploader")
    content = _decode(content_b64)
    digest = hash_content(content)

    blob_existed = _get_object(db, digest) is not None

    # 内容寻址：全局 blob 去重，冲突时复用已有行。
    obj_stmt = sqlite_insert(EvidenceObject).values(
        sha256=digest,
        content=content,
        size_bytes=len(content),
        media_type=media_type,
        first_uploader=uploader,
    )
    obj_stmt = obj_stmt.on_conflict_do_nothing(index_elements=["sha256"])
    db.execute(obj_stmt)

    existing = _get_link(db, case_id, evidence_ref)
    if existing is not None:
        if existing.sha256 == digest:
            payload = _link_payload(existing, deduplicated=True, reused=True)
            db.commit()
            return payload
        raise EvidenceConflictError(
            f"证据引用 '{evidence_ref}' 已固定为另一版本 "
            f"({existing.sha256[:12]})；不同内容请使用新的证据引用登记"
        )

    link = EvidenceLink(
        case_id=case_id,
        evidence_ref=evidence_ref,
        sha256=digest,
        filename=filename,
        uploader=uploader,
        status="active",
    )
    db.add(link)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        winner = _get_link(db, case_id, evidence_ref)
        if winner is not None and winner.sha256 == digest:
            return _link_payload(winner, deduplicated=True, reused=True)
        raise EvidenceConflictError(
            f"证据引用 '{evidence_ref}' 正被并发登记为另一版本"
        ) from exc

    _append_audit(
        db,
        action="register",
        case_id=case_id,
        evidence_ref=evidence_ref,
        sha256=digest,
        actor_id=uploader,
        detail=filename or "",
    )
    payload = _link_payload(link, deduplicated=False, reused=blob_existed)
    db.commit()
    return payload


def bind(
    db: Session,
    *,
    case_id: str,
    evidence_ref: str,
    confirmation_event_id: str,
    bound_by: str,
    note: str = "",
) -> dict[str, Any]:
    """把证据当前版本固定到确认事件；绑定不可变，重复绑定幂等。"""
    case_id = _require_text(case_id, "case_id")
    evidence_ref = _require_text(evidence_ref, "evidence_ref")
    confirmation_event_id = _require_text(
        confirmation_event_id, "confirmation_event_id"
    )
    bound_by = _require_text(bound_by, "bound_by")

    link = _require_link(db, case_id, evidence_ref)
    if link.status != "active":
        raise EvidencePermissionError(
            f"证据 '{evidence_ref}' 已被撤销访问，不能新增绑定"
        )

    stmt = sqlite_insert(EvidenceBinding).values(
        case_id=case_id,
        confirmation_event_id=confirmation_event_id,
        evidence_ref=evidence_ref,
        sha256=link.sha256,
        bound_by=bound_by,
        note=note,
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["case_id", "confirmation_event_id", "evidence_ref"]
    ).returning(EvidenceBinding.id)
    inserted_id = db.execute(stmt).scalar_one_or_none()
    created = inserted_id is not None
    if created:
        _append_audit(
            db,
            action="bind",
            case_id=case_id,
            evidence_ref=evidence_ref,
            sha256=link.sha256,
            actor_id=bound_by,
            detail=f"confirmation={confirmation_event_id}; {note}".strip("; "),
        )
    payload = {
        "created": created,
        "case_id": case_id,
        "evidence_ref": evidence_ref,
        "confirmation_event_id": confirmation_event_id,
        "sha256": link.sha256,
        "bound_by": bound_by,
        "note": note,
    }
    db.commit()
    return payload


def list_bindings(db: Session, *, case_id: str, evidence_ref: str) -> list[dict[str, Any]]:
    _require_link(db, case_id, evidence_ref)
    rows = db.execute(
        select(EvidenceBinding)
        .where(
            EvidenceBinding.case_id == case_id,
            EvidenceBinding.evidence_ref == evidence_ref,
        )
        .order_by(EvidenceBinding.id)
    ).scalars().all()
    return [
        {
            "case_id": r.case_id,
            "evidence_ref": r.evidence_ref,
            "confirmation_event_id": r.confirmation_event_id,
            "sha256": r.sha256,
            "bound_by": r.bound_by,
            "note": r.note,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


def grant(
    db: Session,
    *,
    case_id: str,
    evidence_ref: str,
    grantee: str,
    granted_by: str,
    role: str = "viewer",
) -> dict[str, Any]:
    """按案件授权；相同内容跨案件复用时授权各自独立。"""
    case_id = _require_text(case_id, "case_id")
    evidence_ref = _require_text(evidence_ref, "evidence_ref")
    grantee = _require_text(grantee, "grantee")
    granted_by = _require_text(granted_by, "granted_by")
    role = _require_text(role, "role")
    _require_link(db, case_id, evidence_ref)

    existing = db.execute(
        select(EvidenceGrant).where(
            EvidenceGrant.case_id == case_id,
            EvidenceGrant.evidence_ref == evidence_ref,
            EvidenceGrant.grantee == grantee,
        )
    ).scalar_one_or_none()

    reactivated = False
    if existing is not None and existing.status == "active":
        db.commit()
        return _grant_payload(existing, changed=False)
    if existing is not None:
        existing.status = "active"
        existing.role = role
        existing.granted_by = granted_by
        existing.revoked_by = None
        existing.revoke_reason = None
        existing.revoked_at = None
        reactivated = True
        row = existing
    else:
        row = EvidenceGrant(
            case_id=case_id,
            evidence_ref=evidence_ref,
            grantee=grantee,
            role=role,
            status="active",
            granted_by=granted_by,
        )
        db.add(row)

    _append_audit(
        db,
        action="grant" if not reactivated else "regrant",
        case_id=case_id,
        evidence_ref=evidence_ref,
        actor_id=granted_by,
        detail=f"grantee={grantee}; role={role}",
    )
    db.flush()
    payload = _grant_payload(row, changed=True)
    db.commit()
    return payload


def revoke_grant(
    db: Session,
    *,
    case_id: str,
    evidence_ref: str,
    grantee: str,
    revoked_by: str,
    reason: str,
) -> dict[str, Any]:
    """撤销单个被授权人的访问，不影响其他案件或其他被授权人。"""
    revoked_by = _require_text(revoked_by, "revoked_by")
    reason = _require_text(reason, "reason")
    row = db.execute(
        select(EvidenceGrant).where(
            EvidenceGrant.case_id == case_id,
            EvidenceGrant.evidence_ref == evidence_ref,
            EvidenceGrant.grantee == grantee,
        )
    ).scalar_one_or_none()
    if row is None:
        raise EvidenceNotFoundError(f"未找到对 '{grantee}' 的授权")
    changed = row.status == "active"
    if changed:
        row.status = "revoked"
        row.revoked_by = revoked_by
        row.revoke_reason = reason
        row.revoked_at = _now()
        _append_audit(
            db,
            action="revoke_grant",
            case_id=case_id,
            evidence_ref=evidence_ref,
            actor_id=revoked_by,
            detail=f"grantee={grantee}; {reason}",
        )
    db.flush()
    payload = _grant_payload(row, changed=changed)
    db.commit()
    return payload


def revoke(
    db: Session,
    *,
    case_id: str,
    evidence_ref: str,
    revoked_by: str,
    reason: str,
) -> dict[str, Any]:
    """删除请求：只软撤销案件访问，blob、指纹、历史绑定与审计均保留。"""
    revoked_by = _require_text(revoked_by, "revoked_by")
    reason = _require_text(reason, "reason")
    link = _require_link(db, case_id, evidence_ref)
    changed = link.status == "active"
    if changed:
        link.status = "revoked"
        link.revoked_by = revoked_by
        link.revoke_reason = reason
        link.revoked_at = _now()
        _append_audit(
            db,
            action="revoke",
            case_id=case_id,
            evidence_ref=evidence_ref,
            sha256=link.sha256,
            actor_id=revoked_by,
            detail=reason,
        )
    payload = _link_payload(link, deduplicated=False, reused=False, changed=changed)
    db.commit()
    return payload


def _active_grant(
    db: Session, case_id: str, evidence_ref: str, actor: str
) -> EvidenceGrant | None:
    return db.execute(
        select(EvidenceGrant).where(
            EvidenceGrant.case_id == case_id,
            EvidenceGrant.evidence_ref == evidence_ref,
            EvidenceGrant.grantee == actor,
            EvidenceGrant.status == "active",
        )
    ).scalar_one_or_none()


def access(
    db: Session,
    *,
    case_id: str,
    evidence_ref: str,
    actor: str,
) -> dict[str, Any]:
    """读取证据内容；上传人或本案件有效授权方可访问。"""
    actor = _require_text(actor, "actor")
    link = _require_link(db, case_id, evidence_ref)
    if link.status != "active":
        raise EvidencePermissionError(
            f"证据 '{evidence_ref}' 在案件 '{case_id}' 的访问已撤销"
        )
    is_uploader = link.uploader == actor
    grant_row = _active_grant(db, case_id, evidence_ref, actor)
    if not is_uploader and grant_row is None:
        raise EvidencePermissionError(f"'{actor}' 无权访问该证据")
    obj = _get_object(db, link.sha256)
    assert obj is not None  # FK 保证
    return {
        **_link_payload(link, deduplicated=False, reused=False),
        "role": "uploader" if is_uploader else grant_row.role,  # type: ignore[union-attr]
        "media_type": obj.media_type,
        "content_base64": base64.b64encode(obj.content).decode("ascii"),
    }


def object_overview(db: Session, sha256: str) -> dict[str, Any]:
    obj = _get_object(db, sha256)
    if obj is None:
        raise EvidenceNotFoundError(f"不存在内容指纹为 {sha256} 的证据对象")
    links = db.execute(
        select(EvidenceLink).where(EvidenceLink.sha256 == sha256)
    ).scalars().all()
    return {
        "sha256": obj.sha256,
        "size_bytes": obj.size_bytes,
        "media_type": obj.media_type,
        "first_uploader": obj.first_uploader,
        "created_at": obj.created_at.isoformat(),
        "links": [
            {
                "case_id": lk.case_id,
                "evidence_ref": lk.evidence_ref,
                "status": lk.status,
                "uploader": lk.uploader,
            }
            for lk in links
        ],
    }


def verify_integrity(db: Session) -> dict[str, Any]:
    """重算 blob 指纹、绑定版本与审计哈希链。"""
    problems: list[dict[str, str]] = []

    objects = db.execute(select(EvidenceObject)).scalars().all()
    for obj in objects:
        actual = hash_content(obj.content)
        if actual != obj.sha256:
            problems.append(
                {
                    "kind": "fingerprint_mismatch",
                    "sha256": obj.sha256,
                    "actual": actual,
                }
            )
        if obj.size_bytes != len(obj.content):
            problems.append(
                {
                    "kind": "size_mismatch",
                    "sha256": obj.sha256,
                    "stored": str(obj.size_bytes),
                    "actual": str(len(obj.content)),
                }
            )

    links = db.execute(select(EvidenceLink)).scalars().all()
    for link in links:
        if _get_object(db, link.sha256) is None:
            problems.append(
                {
                    "kind": "dangling_link",
                    "case_id": link.case_id,
                    "evidence_ref": link.evidence_ref,
                    "sha256": link.sha256,
                }
            )

    bindings = db.execute(select(EvidenceBinding)).scalars().all()
    link_index = {(lk.case_id, lk.evidence_ref): lk for lk in links}
    for binding in bindings:
        link = link_index.get((binding.case_id, binding.evidence_ref))
        if link is None:
            problems.append(
                {
                    "kind": "binding_without_link",
                    "case_id": binding.case_id,
                    "evidence_ref": binding.evidence_ref,
                }
            )
        elif link.sha256 != binding.sha256:
            problems.append(
                {
                    "kind": "binding_version_drift",
                    "case_id": binding.case_id,
                    "evidence_ref": binding.evidence_ref,
                    "bound_sha256": binding.sha256,
                    "current_sha256": link.sha256,
                }
            )

    entries = db.execute(
        select(EvidenceAudit).order_by(EvidenceAudit.sequence)
    ).scalars().all()
    prev_hash = GENESIS_HASH
    seen_hashes: set[str] = set()
    expected_sequence = 1
    for entry in entries:
        if entry.sequence != expected_sequence:
            problems.append(
                {
                    "kind": "audit_sequence_gap",
                    "sequence": str(entry.sequence),
                    "expected": str(expected_sequence),
                }
            )
        if entry.prev_hash != prev_hash:
            problems.append(
                {
                    "kind": "audit_chain_broken",
                    "sequence": str(entry.sequence),
                }
            )
        created_at = entry.created_at
        if created_at.tzinfo is None:  # SQLite 回读会丢失时区
            created_at = created_at.replace(tzinfo=UTC)
        expected_hash = _chain_hash(
            sequence=entry.sequence,
            action=entry.action,
            case_id=entry.case_id,
            evidence_ref=entry.evidence_ref,
            sha256=entry.sha256,
            actor_id=entry.actor_id,
            detail=entry.detail,
            prev_hash=entry.prev_hash,
            created_at=created_at,
        )
        if entry.entry_hash != expected_hash or entry.entry_hash in seen_hashes:
            problems.append(
                {
                    "kind": "audit_hash_mismatch",
                    "sequence": str(entry.sequence),
                }
            )
        seen_hashes.add(entry.entry_hash)
        prev_hash = entry.entry_hash
        expected_sequence += 1

    return {
        "ok": not problems,
        "objects_checked": len(objects),
        "links_checked": len(links),
        "bindings_checked": len(bindings),
        "audit_entries_checked": len(entries),
        "problems": problems,
        "checked_at": _now().isoformat(),
    }


def cleanup_orphans(db: Session, *, actor: str) -> dict[str, Any]:
    """清理没有任何案件引用、也没有历史绑定的 blob。

    并发登记输掉引用竞争的上传会留下仅按内容存在的 blob；已被任一案件
    （含已撤销链接）或任一绑定引用的对象一律保留，历史指纹不被破坏。
    """
    actor = _require_text(actor, "actor")
    referenced = set(
        db.execute(select(EvidenceLink.sha256).distinct()).scalars().all()
    )
    referenced.update(
        db.execute(select(EvidenceBinding.sha256).distinct()).scalars().all()
    )

    all_shas = db.execute(select(EvidenceObject.sha256)).scalars().all()
    removed: list[str] = []
    for sha in all_shas:
        if sha in referenced:
            continue
        obj = db.get(EvidenceObject, sha)
        if obj is not None:
            db.delete(obj)
            removed.append(sha)
    if removed:
        db.flush()
        _append_audit(
            db,
            action="cleanup_orphans",
            actor_id=actor,
            detail=f"removed={len(removed)}; "
            + ",".join(sha[:12] for sha in removed),
        )
    db.commit()
    return {"removed": len(removed), "sha256": removed}


def _link_payload(
    link: EvidenceLink,
    *,
    deduplicated: bool,
    reused: bool,
    changed: bool = True,
) -> dict[str, Any]:
    return {
        "case_id": link.case_id,
        "evidence_ref": link.evidence_ref,
        "sha256": link.sha256,
        "filename": link.filename,
        "uploader": link.uploader,
        "status": link.status,
        "revoke_reason": link.revoke_reason,
        "revoked_by": link.revoked_by,
        "deduplicated": deduplicated,
        "blob_reused": reused,
        "changed": changed,
        "created_at": link.created_at.isoformat(),
    }


def _grant_payload(row: EvidenceGrant, *, changed: bool) -> dict[str, Any]:
    return {
        "case_id": row.case_id,
        "evidence_ref": row.evidence_ref,
        "grantee": row.grantee,
        "role": row.role,
        "status": row.status,
        "granted_by": row.granted_by,
        "revoked_by": row.revoked_by,
        "revoke_reason": row.revoke_reason,
        "changed": changed,
    }
