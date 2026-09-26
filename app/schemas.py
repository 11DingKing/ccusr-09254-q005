"""服务端业务模块。"""

from __future__ import annotations

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


class EvidenceRegisterIn(BaseModel):
    evidence_ref: str = Field(..., min_length=1, max_length=128)
    content_base64: str
    uploader: str = Field(..., min_length=1, max_length=128)
    filename: str | None = Field(None, max_length=256)
    media_type: str | None = Field(None, max_length=128)


class EvidenceLinkOut(BaseModel):
    case_id: str
    evidence_ref: str
    sha256: str
    filename: str | None
    uploader: str
    status: str
    revoke_reason: str | None
    revoked_by: str | None
    deduplicated: bool
    blob_reused: bool
    changed: bool
    created_at: str


class EvidenceBindIn(BaseModel):
    confirmation_event_id: str = Field(..., min_length=1, max_length=128)
    bound_by: str = Field(..., min_length=1, max_length=128)
    note: str = Field("", max_length=512)


class EvidenceBindingOut(BaseModel):
    created: bool
    case_id: str
    evidence_ref: str
    confirmation_event_id: str
    sha256: str
    bound_by: str
    note: str


class EvidenceGrantIn(BaseModel):
    grantee: str = Field(..., min_length=1, max_length=128)
    granted_by: str = Field(..., min_length=1, max_length=128)
    role: str = Field("viewer", max_length=32)


class EvidenceGrantOut(BaseModel):
    case_id: str
    evidence_ref: str
    grantee: str
    role: str
    status: str
    granted_by: str
    revoked_by: str | None
    revoke_reason: str | None
    changed: bool


class EvidenceRevokeIn(BaseModel):
    revoked_by: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=512)


class EvidenceAccessIn(BaseModel):
    actor: str = Field(..., min_length=1, max_length=128)


class EvidenceAccessOut(EvidenceLinkOut):
    role: str
    media_type: str | None
    content_base64: str


class IntegrityProblem(BaseModel):
    kind: str

    model_config = {"extra": "allow"}


class IntegrityReport(BaseModel):
    ok: bool
    objects_checked: int
    links_checked: int
    bindings_checked: int
    audit_entries_checked: int
    problems: list[dict[str, Any]]
    checked_at: str


class CleanupResult(BaseModel):
    removed: int
    sha256: list[str]
