from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/health")
def audit_health() -> dict[str, str]:
    return {
        "status": "ok",
        "module": "audit",
    }