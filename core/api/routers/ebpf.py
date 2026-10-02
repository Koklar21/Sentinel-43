# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Authenticated, evidence-only ingress for the optional eBPF sensor."""

from __future__ import annotations

import ipaddress
import os
import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.detection.ebpf_agent import classify_exec

from core.monitoring import get_monitoring_manager

router = APIRouter(prefix="/internal/ebpf", tags=["internal-ebpf"])
_MAX_TEXT = 512


class EbpfEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    host_ip: str = Field(min_length=1, max_length=64)
    pid: int = Field(ge=0, le=2_147_483_647)
    uid: int = Field(ge=0, le=4_294_967_295)
    comm: str = Field(default="", max_length=64)
    filename: str = Field(default="", max_length=_MAX_TEXT)
    @field_validator("host_ip")
    @classmethod
    def validate_host_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("host_ip must be an IPv4 or IPv6 address") from exc


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

    # Detection semantics are server-owned. The authenticated sensor reports
    # observation facts; it cannot choose its own threat label or severity.
    event_type, severity, reason = classify_exec(event.filename)

    payload = {
        "kind": "runtime",
        "event_id": event.event_id,
        "source": "sentinel-ebpf",
        "source_identity": "service:ebpf",
        "event_type": event_type,
        "runtime_event": event_type,
        "platform": "linux-ebpf",
        "runtime_role": "sensor",
        "instance_id": event.host_ip,
        "runtime_metadata": {
            "pid": event.pid,
            "uid": event.uid,
            "comm": event.comm,
            "filename": event.filename,
            "severity": severity,
            "reason": reason,
        },
    }
    manager.analyze_event(
        payload,
        source_ip=event.host_ip,
        source_identity="service:ebpf",
        trusted_producer="ebpf",
    )
    return {"accepted": True, "event_id": event.event_id}
