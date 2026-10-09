# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Authenticated, observation-only ingress for local router telemetry."""

from __future__ import annotations

import ipaddress
import os
import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.detection.router_event_classifier import classify_router_event
from core.monitoring import get_monitoring_manager


router = APIRouter(prefix="/internal/router", tags=["internal-router"])
_MAX_MESSAGE = 4096
_MAX_PROTOCOL = 32
_MAX_ACTION = 32


class RouterEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    router_ip: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=_MAX_MESSAGE)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = Field(default="", max_length=_MAX_PROTOCOL)
    action: str = Field(default="", max_length=_MAX_ACTION)

    @field_validator("router_ip", "source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError as exc:
            raise ValueError("must be an IPv4 or IPv6 address") from exc

    @field_validator("protocol", "action")
    @classmethod
    def normalize_short_text(cls, value: str) -> str:
        return value.strip().lower()


def _enabled() -> bool:
    return os.getenv("S43_ROUTER_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _expected_token() -> str:
    return os.getenv("S43_ROUTER_INGEST_TOKEN", "").strip()


def _expected_router_ips() -> frozenset[str]:
    raw = os.getenv("S43_EDGE_SOURCE_IPS", "").strip()
    if not raw:
        raw = os.getenv("S43_ROUTER_SOURCE_IP", "").strip()
    if not raw:
        return frozenset()

    values: set[str] = set()
    try:
        for item in raw.split(","):
            cleaned = item.strip()
            if cleaned:
                values.add(str(ipaddress.ip_address(cleaned)))
    except ValueError as exc:
        raise HTTPException(
            status_code=503,
            detail="router ingestion has an invalid configured source IP",
        ) from exc
    return frozenset(values)


def _authorize(authorization: str | None) -> None:
    token = _expected_token()
    if len(token) < 32 or not token.isascii():
        raise HTTPException(status_code=503, detail="router ingestion unconfigured")

    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not supplied.isascii() or not secrets.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="invalid router service token")


def _indicators(event: RouterEvent, *, classified_source_ip: str, reason: str) -> tuple[str, ...]:
    values: list[str] = [f"router:{event.router_ip}", f"reason:{reason}"]

    if classified_source_ip:
        values.append(f"src:{classified_source_ip}")
    if event.destination_ip:
        values.append(f"dst:{event.destination_ip}")
    if event.source_port is not None:
        values.append(f"sport:{event.source_port}")
    if event.destination_port is not None:
        values.append(f"dport:{event.destination_port}")
    if event.protocol:
        values.append(f"protocol:{event.protocol}")
    if event.action:
        values.append(f"action:{event.action}")

    return tuple(values[:20])


@router.post("/events", status_code=202)
def ingest_router_event(
    event: RouterEvent,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Accept one router observation without granting the router any authority."""
    if not _enabled():
        raise HTTPException(status_code=404, detail="router ingestion disabled")

    _authorize(authorization)

    expected_router_ips = _expected_router_ips()
    if not expected_router_ips:
        raise HTTPException(
            status_code=503,
            detail="router ingestion requires a configured trusted edge source",
        )
    if event.router_ip not in expected_router_ips:
        raise HTTPException(status_code=403, detail="unexpected router source")

    manager = get_monitoring_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="monitoring unavailable")

    classification = classify_router_event(
        message=event.message,
        source_ip=event.source_ip,
        action=event.action,
    )

    subject_ip = classification.source_ip or event.router_ip
    payload = {
        "kind": "security",
        "event_id": event.event_id,
        "source": "sentinel-router",
        "source_identity": "anonymous",
        "event_type": classification.event_type,
        "success": classification.success,
        "source_ip": subject_ip,
        "indicators": _indicators(
            event,
            classified_source_ip=classification.source_ip,
            reason=classification.reason,
        ),
    }

    trusted_producer = "router" if classification.detector_eligible else None
    result = manager.analyze_event(
        payload,
        source_ip=subject_ip,
        source_identity="anonymous",
        trusted_producer=trusted_producer,
    )

    return {
        "accepted": True,
        "event_id": event.event_id,
        "event_type": classification.event_type,
        "detector_ingested": bool(trusted_producer),
        "alert_count": result.alert_count,
    }


__all__ = ["RouterEvent", "router"]
