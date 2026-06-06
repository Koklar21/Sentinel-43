# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 Watchgate API models.

Stable Pydantic schemas for the API layer.
No business logic. No DB access. No side effects.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


S43_API_NAME = "Sentinel-43 Watchgate API"
S43_API_VERSION = "1.0.0"


def utc_now_iso() -> str:
    """Return RFC3339 UTC timestamp."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class SentinelModel(BaseModel):
    """Strict base model for Sentinel-43 API schemas."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
        use_enum_values=False,
    )


class ApiStatus(str, Enum):
    ok = "ok"
    error = "error"


class AssessmentMode(str, Enum):
    shadow = "shadow"
    active = "active"


class ActionDecision(str, Enum):
    approved = "approved"
    vetoed = "vetoed"
    pending = "pending"
    unknown = "unknown"


class ErrorDetail(SentinelModel):
    """Structured Sentinel-43 API error."""

    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    details: dict[str, Any] | None = Field(
        default=None,
        description="Optional debug/context payload",
    )


class ApiResponse(SentinelModel):
    """Base Sentinel-43 API response."""

    status: ApiStatus = Field(default=ApiStatus.ok)
    request_id: str | None = Field(
        default=None,
        description="Correlation identifier",
    )
    ts: str = Field(default_factory=utc_now_iso)
    error: ErrorDetail | None = Field(default=None)


class HealthResponse(ApiResponse):
    """Sentinel-43 Watchgate health response."""

    service: str = Field(default=S43_API_NAME)
    version: str = Field(default=S43_API_VERSION)
    principle: str = Field(
        default=(
            "Advisory-first. Human-gated. "
            "Audit-backed. No autonomous enforcement in core."
        )
    )
    uptime_s: int | None = Field(default=None)


class ThreatSignal(SentinelModel):
    """Single observed signal/event."""

    source: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Sensor or source identifier",
    )
    kind: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Signal category/type",
    )
    ts: str | None = Field(
        default=None,
        description="Signal timestamp ISO string",
    )
    fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured signal payload",
    )


class ThreatAssessmentIn(SentinelModel):
    """Inbound Sentinel-43 assessment request."""

    mode: AssessmentMode = Field(default=AssessmentMode.shadow)
    actor_id: str | None = Field(default=None, max_length=128)
    tenant_id: str | None = Field(default=None, max_length=128)
    signals: list[ThreatSignal] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("signals")
    @classmethod
    def signals_nonempty(cls, value: list[ThreatSignal] | None) -> list[ThreatSignal]:
        return value or []


class ThreatAssessmentOut(ApiResponse):
    """Normalized Sentinel-43 assessment response."""

    assessment_id: str = Field(..., min_length=1)
    severity: int = Field(..., ge=0, le=100)
    confidence: int = Field(..., ge=0, le=100)
    summary: str = Field(..., min_length=1, max_length=4096)
    tags: list[str] = Field(default_factory=list)
    raw: Any | None = Field(default=None)


class ActionRequest(SentinelModel):
    """Approve/veto request payload."""

    action_id: str | None = Field(default=None, min_length=3, max_length=256)
    operator_id: str = Field(..., min_length=2, max_length=256)
    reason: str | None = Field(default="", max_length=4096)


class ActionStatus(SentinelModel):
    """Action decision state."""

    action_id: str = Field(...)
    decision: ActionDecision = Field(default=ActionDecision.unknown)
    decided_by: str | None = Field(default=None)
    decided_ts: str | None = Field(default=None)
    reason: str | None = Field(default=None)


class ActionResponse(ApiResponse):
    """Single action operation response."""

    result: bool = Field(..., description="Operation success state")
    action: ActionStatus | None = Field(default=None)


class ActionListResponse(ApiResponse):
    """Paginated Sentinel-43 action list response."""

    items: list[ActionStatus] = Field(default_factory=list)
    next_cursor: str | None = Field(default=None)
