"""服务端业务模块。"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from .core.replay import Event as CoreEvent
from .core.replay import EventType
from .models import (
    EvidenceAccessEvent,
    EvidenceBinding,
    EvidenceGrant,
    EvidenceObject,
)
from .models import Event as EventModel
from .models import Freeze, Plan


def get_plan(db: Session, plan_version: str) -> Plan | None:
    return db.get(Plan, plan_version)


def upsert_plan(
    db: Session,
    *,
    plan_version: str,
    iana_timezone: str,
    required_seconds: int,
) -> Plan:
    stmt = sqlite_insert(Plan).values(
        plan_version=plan_version,
        iana_timezone=iana_timezone,
        required_seconds=required_seconds,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["plan_version"],
        set_={
            "iana_timezone": iana_timezone,
            "required_seconds": required_seconds,
        },
    )
    db.execute(stmt)
    db.commit()
    plan = db.get(Plan, plan_version)
    assert plan is not None
    return plan


def _to_core_event(row: EventModel) -> CoreEvent:
    return CoreEvent(
        event_id=row.event_id,
        plan_version=row.plan_version,
        event_type=EventType(row.event_type),
        student_id=row.student_id,
        payload=dict(row.payload),
        created_at=row.created_at,
    )


def insert_events(
    db: Session,
    *,
    plan_version: str,
    events: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """执行确定性的业务处理。"""
    accepted: list[str] = []
    duplicates: list[str] = []
    for e in events:
        stmt = sqlite_insert(EventModel).values(
            event_id=e["event_id"],
            plan_version=plan_version,
            student_id=e["student_id"],
            event_type=e["event_type"],
            payload=e["payload"],
        )
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["event_id", "plan_version"]
        ).returning(EventModel.id)
        inserted_id = db.execute(stmt).scalar_one_or_none()
        if inserted_id is not None:
            accepted.append(e["event_id"])
        else:
            duplicates.append(e["event_id"])
    db.commit()
    return accepted, duplicates


def load_events(db: Session, plan_version: str) -> list[CoreEvent]:
    stmt = select(EventModel).where(EventModel.plan_version == plan_version)
    rows = db.execute(stmt).scalars().all()
    return [_to_core_event(r) for r in rows]


def load_events_up_to(
    db: Session, plan_version: str, max_event_id: str
) -> list[CoreEvent]:
    """执行确定性的业务处理。"""
    stmt = (
        select(EventModel)
        .where(EventModel.plan_version == plan_version)
        .where(EventModel.event_id <= max_event_id)
    )
    rows = db.execute(stmt).scalars().all()
    return [_to_core_event(r) for r in rows]


def max_event_id(db: Session, plan_version: str) -> str | None:
    stmt = (
        select(EventModel.event_id)
        .where(EventModel.plan_version == plan_version)
        .order_by(EventModel.event_id.desc())
        .limit(1)
    )
    return db.execute(stmt).scalar_one_or_none()


def get_freeze(
    db: Session, plan_version: str, freeze_id: str
) -> Freeze | None:
    return db.get(Freeze, (plan_version, freeze_id))


def insert_freeze(
    db: Session,
    *,
    plan_version: str,
    freeze_id: str,
    snapshot: dict[str, Any],
    event_cutoff_id: str | None,
) -> Freeze | None:
    """执行确定性的业务处理。"""
    stmt = sqlite_insert(Freeze).values(
        plan_version=plan_version,
        freeze_id=freeze_id,
        snapshot=snapshot,
        event_cutoff_id=event_cutoff_id,
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["plan_version", "freeze_id"]
    ).returning(Freeze.plan_version)
    inserted = db.execute(stmt).scalar_one_or_none()
    db.commit()
    if inserted is not None:
        return db.get(Freeze, (plan_version, freeze_id))
    return None


# ---- 证据内容寻址存储 ----


def get_evidence_object(db: Session, content_hash: str) -> EvidenceObject | None:
    return db.get(EvidenceObject, content_hash)


def insert_evidence_object(
    db: Session,
    *,
    content_hash: str,
    content: bytes,
    media_type: str,
    size_bytes: int,
    uploader_id: str,
) -> bool:
    """相同内容重复登记时静默忽略，返回是否真正新建。"""
    stmt = sqlite_insert(EvidenceObject).values(
        content_hash=content_hash,
        content=content,
        media_type=media_type,
        size_bytes=size_bytes,
        uploader_id=uploader_id,
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["content_hash"]
    ).returning(EvidenceObject.content_hash)
    inserted = db.execute(stmt).scalar_one_or_none()
    db.commit()
    return inserted is not None


def touch_evidence_upload(db: Session, content_hash: str) -> None:
    stmt = (
        update(EvidenceObject)
        .where(EvidenceObject.content_hash == content_hash)
        .values(
            upload_count=EvidenceObject.upload_count + 1,
            last_uploaded_at=datetime.now(timezone.utc),
        )
    )
    db.execute(stmt)
    db.commit()


def list_evidence_objects(db: Session) -> list[EvidenceObject]:
    stmt = select(EvidenceObject).order_by(EvidenceObject.content_hash)
    return list(db.execute(stmt).scalars().all())


def delete_evidence_objects(db: Session, content_hashes: list[str]) -> None:
    """物理删除仅用于无任何引用的孤立对象，历史指纹不在此列。"""
    if not content_hashes:
        return
    stmt = delete(EvidenceObject).where(
        EvidenceObject.content_hash.in_(content_hashes)
    )
    db.execute(stmt)
    db.commit()


def list_bound_hashes(db: Session) -> set[str]:
    stmt = select(EvidenceBinding.content_hash).distinct()
    return set(db.execute(stmt).scalars().all())


def get_binding(
    db: Session, case_id: str, content_hash: str
) -> EvidenceBinding | None:
    return db.get(EvidenceBinding, (case_id, content_hash))


def insert_binding(
    db: Session,
    *,
    case_id: str,
    content_hash: str,
    bound_by: str,
    note: str = "",
) -> bool:
    """并发绑定同一案件与证据时只保留一条引用，返回是否由本次调用创建。"""
    stmt = sqlite_insert(EvidenceBinding).values(
        case_id=case_id,
        content_hash=content_hash,
        bound_by=bound_by,
        note=note,
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["case_id", "content_hash"]
    ).returning(EvidenceBinding.case_id)
    inserted = db.execute(stmt).scalar_one_or_none()
    db.commit()
    return inserted is not None


def list_bindings(db: Session, *, case_id: str | None = None) -> list[EvidenceBinding]:
    stmt = select(EvidenceBinding)
    if case_id is not None:
        stmt = stmt.where(EvidenceBinding.case_id == case_id)
    stmt = stmt.order_by(EvidenceBinding.case_id, EvidenceBinding.content_hash)
    return list(db.execute(stmt).scalars().all())


def get_grant(
    db: Session, case_id: str, content_hash: str, subject_id: str
) -> EvidenceGrant | None:
    stmt = select(EvidenceGrant).where(
        EvidenceGrant.case_id == case_id,
        EvidenceGrant.content_hash == content_hash,
        EvidenceGrant.subject_id == subject_id,
    )
    return db.execute(stmt).scalar_one_or_none()


def create_grant(
    db: Session,
    *,
    case_id: str,
    content_hash: str,
    subject_id: str,
    granted_by: str,
) -> EvidenceGrant:
    stmt = sqlite_insert(EvidenceGrant).values(
        case_id=case_id,
        content_hash=content_hash,
        subject_id=subject_id,
        state="granted",
        granted_by=granted_by,
        version=1,
    )
    stmt = stmt.on_conflict_do_nothing(
        index_elements=["case_id", "content_hash", "subject_id"]
    )
    db.execute(stmt)
    db.commit()
    grant = get_grant(db, case_id, content_hash, subject_id)
    assert grant is not None
    return grant


def save_grant(db: Session, grant: EvidenceGrant) -> EvidenceGrant:
    db.add(grant)
    db.commit()
    db.refresh(grant)
    return grant


def list_grants(
    db: Session,
    *,
    case_id: str | None = None,
    content_hash: str | None = None,
    state: str | None = None,
) -> list[EvidenceGrant]:
    stmt = select(EvidenceGrant)
    if case_id is not None:
        stmt = stmt.where(EvidenceGrant.case_id == case_id)
    if content_hash is not None:
        stmt = stmt.where(EvidenceGrant.content_hash == content_hash)
    if state is not None:
        stmt = stmt.where(EvidenceGrant.state == state)
    stmt = stmt.order_by(EvidenceGrant.id)
    return list(db.execute(stmt).scalars().all())


def insert_access_event(
    db: Session,
    *,
    case_id: str,
    content_hash: str,
    subject_id: str,
    action: str,
    actor_id: str,
    reason: str = "",
) -> None:
    db.add(
        EvidenceAccessEvent(
            case_id=case_id,
            content_hash=content_hash,
            subject_id=subject_id,
            action=action,
            actor_id=actor_id,
            reason=reason,
        )
    )
    db.commit()


def list_access_events(
    db: Session, *, case_id: str, content_hash: str
) -> list[EvidenceAccessEvent]:
    stmt = (
        select(EvidenceAccessEvent)
        .where(
            EvidenceAccessEvent.case_id == case_id,
            EvidenceAccessEvent.content_hash == content_hash,
        )
        .order_by(EvidenceAccessEvent.id)
    )
    return list(db.execute(stmt).scalars().all())
