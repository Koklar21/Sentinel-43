# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Authenticated evidence-only ingress for AI/agent runtime activity."""

from __future__ import annotations

import ipaddress
import os
import secrets
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.monitoring import get_monitoring_manager
from core.security_context import IdentityType

router = APIRouter(prefix="/internal/agent-runtime", tags=["internal-agent-runtime"])

AgentActivity = Literal[
    "agent_discovery",
    "agent_enumeration",
    "agent_secret_access",
    "agent_credential_access",
    "agent_external_transfer",
    "agent_data_export",
    "agent_policy_probe",
    "agent_permission_probe",
    "agent_privileged_action",
    "agent_permission_change",
]


class AgentActivityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    activity: AgentActivity
    subject_ip: str = Field(min_length=1, max_length=64)
    agent_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(default="", max_length=128)
    resource: str = Field(default="", max_length=256)

    @field_validator("subject_ip")
    @classmethod
    def validate_subject_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("subject_ip must be an IPv4 or IPv6 address") from exc


def _enabled() -> bool:
    return os.getenv("S43_AGENT_RUNTIME_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }


def _expected_token() -> str:
    return os.getenv("S43_AGENT_RUNTIME_INGEST_TOKEN", "").strip()


@router.post("/events", status_code=202)
def ingest_agent_activity(
    event: AgentActivityEvent,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    if not _enabled():
        raise HTTPException(status_code=404, detail="agent runtime ingestion disabled")

    token = _expected_token()
    if not token:
        raise HTTPException(status_code=503, detail="agent runtime ingestion unconfigured")

    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="invalid agent runtime service token")

    manager = get_monitoring_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="monitoring unavailable")

    payload = {
        "kind": "agent_runtime",
        "event_id": event.event_id,
        "source": "sentinel-agent-runtime",
        "source_identity": IdentityType.SERVICE_AGENT_RUNTIME.value,
        "event_type": event.activity,
        "runtime_event": event.activity,
        "runtime_role": "agent-observer",
        "instance_id": event.agent_id,
        "runtime_metadata": {
            "agent_id": event.agent_id,
            "tool_name": event.tool_name,
            "resource": event.resource,
        },
    }
    manager.analyze_event(
        payload,
        source_ip=event.subject_ip,
        source_identity=IdentityType.SERVICE_AGENT_RUNTIME.value,
        trusted_producer="agent_runtime",
    )
    return {"accepted": True, "event_id": event.event_id}
