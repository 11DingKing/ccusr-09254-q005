"""服务端业务模块。"""

from __future__ import annotations

from fastapi import FastAPI

from .evidence.router import _admin_router as evidence_admin_router
from .evidence.router import router as evidence_router
from .routers import router

app = FastAPI(
    title="Practice Hours Guard",
    version="0.1.0",
    description=(
        "Event-sourced practice-hours compliance service. Check-ins, mentor "
        "confirmations and leave corrections are append-only; compliance is "
        "derived by replay and can be frozen into an immutable snapshot."
    ),
)

app.include_router(router)
app.include_router(evidence_router)
app.include_router(evidence_admin_router)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok"}
