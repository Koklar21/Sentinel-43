# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Authenticated, evidence-only ingress for the optional eBPF sensor."""

from __future__ import annotations

import os
import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from core.monitoring import get_monitoring_manager

router = APIRouter(prefix="/internal/ebpf", tags=["internal-ebpf"])
_MAX_TEXT = 512


class EbpfEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=64)
    host_ip: str = Field(min_length=1, max_length=64)
    pid: int = Field(ge=0, le=2_147_483_647)
    uid: int = Field(ge=0, le=4_294_967_295)
    comm: str = Field(default="", max_length=64)
    filename: str = Field(default="", max_length=_MAX_TEXT)
    severity: str = Field(default="informational", max_length=32)
    reason: str = Field(default="", max_length=256)


def _expected_token() -> str:
    return os.getenv("S43_EBPF_INGEST_TOKEN", "").strip()


def _enabled() -> bool:
    return os.getenv("S43_EBPF_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }


@router.post("/events", status_code=202)
def ingest_ebpf_event(
    event: EbpfEvent,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Accept one bounded sensor observation into the canonical monitor path."""
    if not _enabled():
        raise HTTPException(status_code=404, detail="eBPF ingestion disabled")

    token = _expected_token()
    if not token:
        raise HTTPException(status_code=503, detail="eBPF ingestion unconfigured")

    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="invalid eBPF service token")

    manager = get_monitoring_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="monitoring unavailable")

    payload = {
        "kind": "runtime",
        "event_id": event.event_id,
        "source": "sentinel-ebpf",
        "source_identity": "service:ebpf",
        "event_type": event.event_type,
        "runtime_event": event.event_type,
        "platform": "linux-ebpf",
        "runtime_role": "sensor",
        "instance_id": event.comm[:256],
        "runtime_metadata": {
            "pid": event.pid,
            "uid": event.uid,
            "comm": event.comm,
            "filename": event.filename,
            "severity": event.severity,
            "reason": event.reason,
        },
    }
    manager.analyze_event(
        payload,
        source_ip=event.host_ip,
        source_identity="service:ebpf",
        trusted_producer="ebpf",
    )
    return {"accepted": True, "event_id": event.event_id}
