"""服务端业务模块。"""

from __future__ import annotations

import base64
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from . import services
from .db import get_db
from .schemas import (
    DiffOut,
    EventBatchIn,
    EvidenceAccessEventOut,
    EvidenceBindingOut,
    EvidenceBindIn,
    EvidenceContentOut,
    EvidenceDeletionOut,
    EvidenceGcOut,
    EvidenceGrantIn,
    EvidenceGrantOut,
    EvidenceIntegrityOut,
    EvidenceObjectOut,
    EvidenceRegisterIn,
    EvidenceRevokeIn,
    FreezeIn,
    ImportResult,
    PlanIn,
    PlanOut,
    SnapshotOut,
    StudentProgressOut,
)

router = APIRouter(prefix="/api")


@router.post("/plans", response_model=PlanOut, status_code=status.HTTP_201_CREATED)
def create_plan(body: PlanIn, db: Session = Depends(get_db)) -> Any:
    return services.ensure_plan(
        db,
        plan_version=body.plan_version,
        iana_timezone=body.iana_timezone,
        required_seconds=body.required_seconds,
    )


@router.get("/plans/{plan_version}", response_model=PlanOut)
def read_plan(plan_version: str, db: Session = Depends(get_db)) -> Any:
    plan = services.get_plan_plain(db, plan_version)
    if plan is None:
        raise HTTPException(status_code=404, detail="plan not found")
    return plan


@router.post(
    "/plans/{plan_version}/events",
    response_model=ImportResult,
    status_code=status.HTTP_201_CREATED,
)
def post_events(
    plan_version: str, body: EventBatchIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return services.import_events(
            db,
            plan_version=plan_version,
            events=[e.model_dump() for e in body.events],
        )
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/snapshot",
    response_model=SnapshotOut,
)
def get_snapshot(plan_version: str, db: Session = Depends(get_db)) -> Any:
    try:
        snap = services.current_snapshot(db, plan_version)
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/students/{student_id}/progress",
    response_model=StudentProgressOut,
)
def get_progress(
    plan_version: str, student_id: str, db: Session = Depends(get_db)
) -> Any:
    try:
        result = services.student_progress(db, plan_version, student_id)
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


@router.post(
    "/plans/{plan_version}/freezes/{freeze_id}",
    response_model=SnapshotOut,
    status_code=status.HTTP_201_CREATED,
)
def post_freeze(
    plan_version: str,
    freeze_id: str,
    body: FreezeIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        snap, _ = services.freeze_semester(
            db, plan_version=plan_version, freeze_id=freeze_id
        )
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}",
    response_model=SnapshotOut,
)
def get_freeze(
    plan_version: str, freeze_id: str, db: Session = Depends(get_db)
) -> Any:
    try:
        snap = services.get_frozen_snapshot(db, plan_version, freeze_id)
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except services.FreezeNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}/explain/{student_id}",
    response_model=StudentProgressOut,
)
def explain_freeze_student(
    plan_version: str,
    freeze_id: str,
    student_id: str,
    db: Session = Depends(get_db),
) -> Any:
    try:
        result = services.explain_frozen_student(
            db, plan_version, freeze_id, student_id
        )
    except (services.PlanNotFoundError, services.FreezeNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}/diff/{other_freeze_id}",
    response_model=DiffOut,
)
def get_diff(
    plan_version: str,
    freeze_id: str,
    other_freeze_id: str,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.diff_freezes(
            db, plan_version, freeze_id, other_freeze_id
        )
    except (services.PlanNotFoundError, services.FreezeNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---- 证据内容寻址与访问控制 ----


@router.post(
    "/evidence/objects",
    response_model=EvidenceObjectOut,
    status_code=status.HTTP_201_CREATED,
)
def register_evidence(body: EvidenceRegisterIn, db: Session = Depends(get_db)) -> Any:
    try:
        return services.register_evidence(
            db,
            content=base64.b64decode(body.content_b64, validate=True),
            media_type=body.media_type,
            uploader_id=body.uploader_id,
        )
    except services.EvidenceValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/evidence/objects/{content_hash}", response_model=EvidenceObjectOut)
def read_evidence_object(
    content_hash: str, db: Session = Depends(get_db)
) -> Any:
    try:
        return services.get_evidence_metadata(db, content_hash)
    except services.EvidenceValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except services.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/cases/{case_id}/evidence",
    response_model=EvidenceBindingOut,
    status_code=status.HTTP_201_CREATED,
)
def bind_evidence(
    case_id: str, body: EvidenceBindIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return services.bind_evidence(
            db,
            case_id=case_id,
            content_hash=body.content_hash,
            bound_by=body.bound_by,
            note=body.note,
        )
    except services.EvidenceValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except services.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceBindingOut])
def list_case_evidence(case_id: str, db: Session = Depends(get_db)) -> Any:
    return services.list_case_bindings(db, case_id)


@router.post(
    "/cases/{case_id}/evidence/{content_hash}/grants",
    response_model=EvidenceGrantOut,
    status_code=status.HTTP_201_CREATED,
)
def grant_evidence(
    case_id: str,
    content_hash: str,
    body: EvidenceGrantIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.grant_evidence_access(
            db,
            case_id=case_id,
            content_hash=content_hash,
            subject_id=body.subject_id,
            granted_by=body.granted_by,
        )
    except services.EvidenceValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except services.BindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/cases/{case_id}/evidence/{content_hash}/grants",
    response_model=list[EvidenceGrantOut],
)
def list_evidence_grants(
    case_id: str, content_hash: str, db: Session = Depends(get_db)
) -> Any:
    return services.list_case_grants(db, case_id, content_hash)


@router.post(
    "/cases/{case_id}/evidence/{content_hash}/grants/{subject_id}/revoke",
    response_model=EvidenceGrantOut,
)
def revoke_evidence(
    case_id: str,
    content_hash: str,
    subject_id: str,
    body: EvidenceRevokeIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.revoke_evidence_access(
            db,
            case_id=case_id,
            content_hash=content_hash,
            subject_id=subject_id,
            revoked_by=body.revoked_by,
            reason=body.reason,
        )
    except services.EvidenceValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except services.GrantNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete(
    "/cases/{case_id}/evidence/{content_hash}",
    response_model=EvidenceDeletionOut,
)
def request_evidence_deletion(
    case_id: str,
    content_hash: str,
    body: EvidenceRevokeIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.request_evidence_deletion(
            db,
            case_id=case_id,
            content_hash=content_hash,
            revoked_by=body.revoked_by,
            reason=body.reason,
        )
    except services.EvidenceValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except services.BindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/cases/{case_id}/evidence/{content_hash}/history",
    response_model=list[EvidenceAccessEventOut],
)
def evidence_access_history(
    case_id: str, content_hash: str, db: Session = Depends(get_db)
) -> Any:
    return services.list_access_history(db, case_id, content_hash)


@router.get(
    "/cases/{case_id}/evidence/{content_hash}/content",
    response_model=EvidenceContentOut,
)
def read_case_evidence(
    case_id: str,
    content_hash: str,
    subject_id: str = Query(...),
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.read_case_evidence(
            db,
            case_id=case_id,
            content_hash=content_hash,
            subject_id=subject_id,
        )
    except services.EvidenceValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (services.BindingNotFoundError, services.EvidenceNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except services.EvidenceAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/evidence/integrity", response_model=EvidenceIntegrityOut)
def evidence_integrity(db: Session = Depends(get_db)) -> Any:
    return services.check_evidence_integrity(db)


@router.post("/evidence/gc", response_model=EvidenceGcOut)
def garbage_collect_evidence(db: Session = Depends(get_db)) -> Any:
    return services.collect_orphan_evidence(db)
