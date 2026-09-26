"""服务端业务模块。"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class PlanIn(BaseModel):
    plan_version: str = Field(..., min_length=1, max_length=128)
    iana_timezone: str = Field(..., min_length=1, max_length=64)
    required_seconds: int = Field(0, ge=0)


class PlanOut(BaseModel):
    plan_version: str
    iana_timezone: str
    required_seconds: int


class CheckinPayload(BaseModel):
    activity_id: str = ""
    activity_type: str = "regular"
    check_in_at: datetime
    check_out_at: datetime

    @model_validator(mode="after")
    def _check_order(self) -> "CheckinPayload":
        if self.check_out_at <= self.check_in_at:
            raise ValueError("check_out_at must be after check_in_at")
        return self

    @field_validator("check_in_at", "check_out_at")
    @classmethod
    def _ensure_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware (RFC 3339)")
        return v


class MentorConfirmPayload(BaseModel):
    checkin_event_id: str


class LeaveCorrectionPayload(BaseModel):
    adjustment_seconds: int
    reason: str = ""


class EventIn(BaseModel):
    event_id: str = Field(..., min_length=1, max_length=128)
    event_type: Literal["checkin", "mentor_confirm", "leave_correction"]
    student_id: str = Field(..., min_length=1, max_length=128)
    payload: dict[str, Any]


class EventBatchIn(BaseModel):
    events: list[EventIn]


class EventOut(BaseModel):
    event_id: str
    plan_version: str
    event_type: str
    student_id: str
    payload: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class ImportResult(BaseModel):
    accepted: int
    duplicates: list[str]
    rejected: list[dict[str, Any]]


class DailyTotal(BaseModel):
    academic_day: str
    seconds: int


class CheckinExplanation(BaseModel):
    event_id: str
    activity_id: str
    activity_type: str
    status: str
    counts: bool
    check_in_at_utc: str
    check_out_at_utc: str
    raw_seconds: int
    academic_days: list[dict[str, Any]]


class AdjustmentOut(BaseModel):
    event_id: str
    seconds: int
    reason: str


class StudentProgressOut(BaseModel):
    student_id: str
    confirmed_seconds: int
    pending_seconds: int
    adjustment_seconds: int
    total_seconds: int
    lesson_units: int
    pending_lesson_units: int
    meets_requirement: bool
    daily: list[DailyTotal]
    checkins: list[CheckinExplanation]
    adjustments: list[AdjustmentOut]


class SnapshotOut(BaseModel):
    plan_version: str
    freeze_id: str | None
    timezone: str
    required_seconds: int
    generated_at: str
    event_cutoff_id: str | None
    students: list[dict[str, Any]]


class FreezeIn(BaseModel):
    pass


class DiffOut(BaseModel):
    plan_version: str
    old_freeze_id: str | None
    new_freeze_id: str | None
    old_generated_at: str
    new_generated_at: str
    old_event_cutoff_id: str | None
    new_event_cutoff_id: str | None
    student_changes: list[dict[str, Any]]
    students_affected: int


def _normalize_content_hash(v: str) -> str:
    digest = v.strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("content_hash must be a 64-character hex digest")
    return digest


class EvidenceRegisterIn(BaseModel):
    content_b64: str = Field(..., min_length=4, max_length=12_000_000)
    media_type: str = Field(
        "application/octet-stream", min_length=1, max_length=128
    )
    uploader_id: str = Field(..., min_length=1, max_length=128)

    @field_validator("content_b64")
    @classmethod
    def _check_base64(cls, v: str) -> str:
        try:
            base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("content_b64 must be valid base64") from exc
        return v


class EvidenceObjectOut(BaseModel):
    content_hash: str
    media_type: str
    size_bytes: int
    uploader_id: str
    upload_count: int
    created: bool
    created_at: datetime


class EvidenceBindIn(BaseModel):
    content_hash: str
    bound_by: str = Field(..., min_length=1, max_length=128)
    note: str = Field("", max_length=512)

    @field_validator("content_hash")
    @classmethod
    def _normalize_hash(cls, v: str) -> str:
        return _normalize_content_hash(v)


class EvidenceBindingOut(BaseModel):
    case_id: str
    content_hash: str
    bound_by: str
    note: str
    created: bool
    created_at: datetime


class EvidenceGrantIn(BaseModel):
    subject_id: str = Field(..., min_length=1, max_length=128)
    granted_by: str = Field(..., min_length=1, max_length=128)


class EvidenceRevokeIn(BaseModel):
    revoked_by: str = Field(..., min_length=1, max_length=128)
    reason: str = Field("", max_length=512)


class EvidenceGrantOut(BaseModel):
    case_id: str
    content_hash: str
    subject_id: str
    state: str
    granted_by: str
    revoked_by: str | None
    revoke_reason: str | None
    version: int
    updated_at: datetime


class EvidenceAccessEventOut(BaseModel):
    case_id: str
    content_hash: str
    subject_id: str
    action: str
    actor_id: str
    reason: str
    occurred_at: datetime


class EvidenceContentOut(BaseModel):
    case_id: str
    content_hash: str
    media_type: str
    size_bytes: int
    content_b64: str


class EvidenceDeletionOut(BaseModel):
    case_id: str
    content_hash: str
    revoked_grants: int
    object_preserved: bool
    binding_preserved: bool


class EvidenceIntegrityOut(BaseModel):
    ok: bool
    checked_objects: int
    corrupted_objects: list[str]
    dangling_bindings: list[dict[str, str]]
    dangling_grants: list[dict[str, str]]


class EvidenceGcOut(BaseModel):
    removed: list[str]
    removed_count: int
    kept_count: int
