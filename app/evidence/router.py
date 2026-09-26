"""证据指纹、版本固定与授权的 HTTP 接口。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..evidence import service
from ..schemas import (
    CleanupResult,
    EvidenceAccessIn,
    EvidenceAccessOut,
    EvidenceBindIn,
    EvidenceBindingOut,
    EvidenceGrantIn,
    EvidenceGrantOut,
    EvidenceLinkOut,
    EvidenceRegisterIn,
    EvidenceRevokeIn,
    IntegrityReport,
)

router = APIRouter(prefix="/api/cases/{case_id}/evidence", tags=["evidence"])

_admin_router = APIRouter(prefix="/api/evidence", tags=["evidence"])


@router.post(
    "/{evidence_ref}/register",
    response_model=EvidenceLinkOut,
    status_code=status.HTTP_201_CREATED,
)
def register_evidence(
    case_id: str,
    evidence_ref: str,
    body: EvidenceRegisterIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return service.register(
            db,
            case_id=case_id,
            evidence_ref=evidence_ref,
            content_b64=body.content_base64,
            uploader=body.uploader,
            filename=body.filename,
            media_type=body.media_type,
        )
    except service.EvidenceConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except service.EvidenceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/{evidence_ref}/bindings",
    response_model=EvidenceBindingOut,
    status_code=status.HTTP_201_CREATED,
)
def bind_evidence(
    case_id: str,
    evidence_ref: str,
    body: EvidenceBindIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        result = service.bind(
            db,
            case_id=case_id,
            evidence_ref=evidence_ref,
            confirmation_event_id=body.confirmation_event_id,
            bound_by=body.bound_by,
            note=body.note,
        )
        return result
    except service.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except service.EvidencePermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/{evidence_ref}/bindings")
def list_bindings(
    case_id: str,
    evidence_ref: str,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return {
            "case_id": case_id,
            "evidence_ref": evidence_ref,
            "bindings": service.list_bindings(
                db, case_id=case_id, evidence_ref=evidence_ref
            ),
        }
    except service.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/{evidence_ref}/grants",
    response_model=EvidenceGrantOut,
    status_code=status.HTTP_201_CREATED,
)
def grant_evidence(
    case_id: str,
    evidence_ref: str,
    body: EvidenceGrantIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return service.grant(
            db,
            case_id=case_id,
            evidence_ref=evidence_ref,
            grantee=body.grantee,
            granted_by=body.granted_by,
            role=body.role,
        )
    except service.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{evidence_ref}/grants/{grantee}/revoke", response_model=EvidenceGrantOut)
def revoke_grant_for(
    case_id: str,
    evidence_ref: str,
    grantee: str,
    body: EvidenceRevokeIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return service.revoke_grant(
            db,
            case_id=case_id,
            evidence_ref=evidence_ref,
            grantee=grantee,
            revoked_by=body.revoked_by,
            reason=body.reason,
        )
    except service.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{evidence_ref}/revoke", response_model=EvidenceLinkOut)
def revoke_evidence(
    case_id: str,
    evidence_ref: str,
    body: EvidenceRevokeIn,
    db: Session = Depends(get_db),
) -> Any:
    """删除请求：仅撤销本案件访问，指纹与历史绑定保留。"""
    try:
        return service.revoke(
            db,
            case_id=case_id,
            evidence_ref=evidence_ref,
            revoked_by=body.revoked_by,
            reason=body.reason,
        )
    except service.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{evidence_ref}/access", response_model=EvidenceAccessOut)
def access_evidence(
    case_id: str,
    evidence_ref: str,
    body: EvidenceAccessIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return service.access(
            db,
            case_id=case_id,
            evidence_ref=evidence_ref,
            actor=body.actor,
        )
    except service.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except service.EvidencePermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@_admin_router.get("/objects/{sha256}")
def read_object(sha256: str, db: Session = Depends(get_db)) -> Any:
    try:
        return service.object_overview(db, sha256)
    except service.EvidenceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@_admin_router.post("/integrity/verify", response_model=IntegrityReport)
def verify_integrity(db: Session = Depends(get_db)) -> Any:
    return service.verify_integrity(db)


@_admin_router.post(
    "/integrity/cleanup-orphans",
    response_model=CleanupResult,
)
def cleanup_orphans(body: EvidenceAccessIn, db: Session = Depends(get_db)) -> Any:
    return service.cleanup_orphans(db, actor=body.actor)
