# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Authenticated evidence-only ingress for host network observations."""

from __future__ import annotations

import ipaddress
import os
import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.monitoring import get_monitoring_manager

router = APIRouter(prefix="/internal/host-network", tags=["internal-host-network"])


class HostNetworkEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    host_ip: str = Field(min_length=1, max_length=64)
    direction: str = Field(pattern=r"^(inbound|outbound)$")
    protocol: str = Field(pattern=r"^(tcp|udp)$")
    local_ip: str = Field(min_length=1, max_length=64)
    local_port: int = Field(ge=0, le=65535)
    remote_ip: str = Field(min_length=1, max_length=64)
    remote_port: int = Field(ge=0, le=65535)
    process_id: int = Field(default=0, ge=0, le=2_147_483_647)
    process_name: str = Field(default="", max_length=128)
    state: str = Field(default="", max_length=32)

    @field_validator("host_ip", "local_ip", "remote_ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("network addresses must be IPv4 or IPv6") from exc


def _enabled() -> bool:
    return os.getenv("S43_HOST_NETWORK_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }


def _expected_token() -> str:
    return os.getenv("S43_HOST_NETWORK_INGEST_TOKEN", "").strip()


@router.post("/events", status_code=202)
def ingest_host_network_event(
    event: HostNetworkEvent,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    if not _enabled():
        raise HTTPException(status_code=404, detail="host network ingestion disabled")

    token = _expected_token()
    if not token:
        raise HTTPException(status_code=503, detail="host network ingestion unconfigured")

    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="invalid host network service token")

    manager = get_monitoring_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="monitoring unavailable")

    # Sensor supplies facts only. Detection semantics remain server-owned.
    manager.analyze_event(
        {
            "kind": "runtime",
            "event_id": event.event_id,
            "source": "sentinel-host-network",
            "source_identity": "service:host-network",
            "event_type": "host_network_connection",
            "runtime_event": "host_network_connection",
            "platform": "windows-host",
            "runtime_role": "network-sensor",
            "instance_id": event.host_ip,
            "runtime_metadata": {
                "direction": event.direction,
                "protocol": event.protocol,
                "local_ip": event.local_ip,
                "local_port": event.local_port,
                "remote_ip": event.remote_ip,
                "remote_port": event.remote_port,
                "process_id": event.process_id,
                "process_name": event.process_name,
                "state": event.state,
            },
        },
        source_ip=event.host_ip,
        source_identity="service:host-network",
        trusted_producer="host_network",
    )
    return {"accepted": True, "event_id": event.event_id}
