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

Purpose:
- Stable API schemas for Sentinel-43.
- Strict request/response validation.
- Deterministic serialization behavior.
- Zero business logic.
- Zero DB access.
- Zero side effects.

Design Principles:
- Advisory-first.
- Human-gated escalation.
- Audit-backed responses.
- Strict schema enforcement.
- Backwards-compatible API evolution where possible.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


logger = logging.getLogger("sentinel43.watchgate.models")


# -----------------------------------------------------------------------------
# Sentinel-43 constants
# -----------------------------------------------------------------------------

S43_API_NAME = "Sentinel-43 Watchgate API"
S43_API_VERSION = "1.0.0"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return RFC3339 UTC timestamp."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


# -----------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------

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


# -----------------------------------------------------------------------------
# Pydantic base
# -----------------------------------------------------------------------------

PYDANTIC_AVAILABLE = False

try:
    from pydantic import BaseModel, ConfigDict, Field
    from pydantic import field_validator

    PYDANTIC_AVAILABLE = True

    class Model(BaseModel):
        """Sentinel-43 strict API model base."""

        model_config = ConfigDict(
            extra="forbid",
            populate_by_name=True,
            str_strip_whitespace=True,
            validate_assignment=True,
            use_enum_values=False,
        )

except Exception:  # pragma: no cover

    logger.warning(
        "Pydantic unavailable. Sentinel-43 models running in degraded fallback mode."
    )

    class Model:  # type: ignore
        """
        Fallback datalike object.

        WARNING:
        - No validation
        - No type enforcement
        - No constraints
        - No schema protection

        Sentinel-43 API deployments SHOULD NOT run without Pydantic.
        """

        def __init__(self, **data: Any):
            for k, v in data.items():
                setattr(self, k, v)

        def model_dump(self) -> Dict[str, Any]:
            return dict(vars(self))

        def model_copy(self, update: Optional[Dict[str, Any]] = None):
            data = dict(vars(self))
            if update:
                data.update(update)
            return self.__class__(**data)

    def Field(default: Any = None, **kwargs: Any) -> Any:  # type: ignore
        return default

    def field_validator(*args: Any, **kwargs: Any):  # type: ignore
        def deco(fn):
            return fn
        return deco


# -----------------------------------------------------------------------------
# Shared response structures
# -----------------------------------------------------------------------------

class ErrorDetail(Model):
    """Structured Sentinel-43 API error."""

    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional debug/context payload",
    )


class ApiResponse(Model):
    """Base Sentinel-43 API response."""

    status: ApiStatus = Field(default=ApiStatus.ok)
    request_id: Optional[str] = Field(
        default=None,
        description="Correlation identifier",
    )
    ts: str = Field(default_factory=utc_now_iso)
    error: Optional[ErrorDetail] = Field(default=None)


# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------

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
    uptime_s: Optional[int] = Field(default=None)


# -----------------------------------------------------------------------------
# Threat assessment
# -----------------------------------------------------------------------------

class ThreatSignal(Model):
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

    ts: Optional[str] = Field(
        default=None,
        description="Signal timestamp ISO string",
    )

    fields: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured signal payload",
    )


class ThreatAssessmentIn(Model):
    """Inbound Sentinel-43 assessment request."""

    mode: AssessmentMode = Field(default=AssessmentMode.shadow)

    actor_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Operator or account identifier",
    )

    tenant_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Tenant/customer identifier",
    )

    signals: List[ThreatSignal] = Field(default_factory=list)

    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional contextual payload",
    )

    @field_validator("signals")
    @classmethod
    def _signals_nonempty(
        cls,
        v: List[ThreatSignal],
    ) -> List[ThreatSignal]:
        """
        Validation hook.

        Empty lists are currently allowed intentionally for:
        - health tests
        - dry runs
        - diagnostics
        """

        if v is None:
            return []

        return v


class ThreatAssessmentOut(ApiResponse):
    """Normalized Sentinel-43 assessment response."""

    assessment_id: str = Field(
        ...,
        min_length=1,
        description="Unique assessment identifier",
    )

    severity: int = Field(
        ...,
        ge=0,
        le=100,
        description="Threat severity score",
    )

    confidence: int = Field(
        ...,
        ge=0,
        le=100,
        description="Threat confidence score",
    )

    summary: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Human-readable summary",
    )

    tags: List[str] = Field(default_factory=list)

    raw: Optional[Any] = Field(
        default=None,
        description="Optional raw engine payload",
    )


# -----------------------------------------------------------------------------
# Action workflows
# -----------------------------------------------------------------------------

class ActionRequest(Model):
    """Approve/veto request payload."""

    action_id: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=256,
        description="Optional cross-check action identifier",
    )

    operator_id: str = Field(
        ...,
        min_length=2,
        max_length=256,
        description="Human operator identifier",
    )

    reason: Optional[str] = Field(
        default="",
        max_length=4096,
        description="Human-readable action rationale",
    )


class ActionStatus(Model):
    """Action decision state."""

    action_id: str = Field(...)

    decision: ActionDecision = Field(
        default=ActionDecision.unknown,
    )

    decided_by: Optional[str] = Field(default=None)

    decided_ts: Optional[str] = Field(default=None)

    reason: Optional[str] = Field(default=None)


class ActionResponse(ApiResponse):
    """Single action operation response."""

    result: bool = Field(
        ...,
        description="Operation success state",
    )

    action: Optional[ActionStatus] = Field(default=None)


# -----------------------------------------------------------------------------
# Listings / pagination
# -----------------------------------------------------------------------------

class ActionListResponse(ApiResponse):
    """Paginated Sentinel-43 action list response."""

    items: List[ActionStatus] = Field(default_factory=list)

    next_cursor: Optional[str] = Field(
        default=None,
        description="Pagination cursor",
    )


# -----------------------------------------------------------------------------
# Notes
# -----------------------------------------------------------------------------

"""
Next recommended files:

- api/routes.py
    Sentinel-43 Watchgate route layer

- api/deps.py
    Engine/store dependency resolution

- api/config.py
    Environment + runtime configuration

- api/auth.py
    Authorization + request identity layer

- api/audit.py
    Audit correlation and logging helpers
"""
