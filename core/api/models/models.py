# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
#
# See LICENSE.md and COMMERCIAL_LICENSE.md at the repository root.
# =============================================================================

"""Sentinel-43 API layer: shared models (request/response schemas).

Why this exists:
- Your core stays clean and testable.
- Your API can evolve (versioning, OpenAPI docs) without dragging core types.
- We keep strict type handling and predictable validation.

Design rules:
- API models should be *stable* and backwards compatible where possible.
- No business logic here. No DB access. No side effects.
- Convert between API models <-> core models in the router/service layer.

File: api/models.py
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def utc_now_iso() -> str:
    """UTC timestamp as RFC3339-ish ISO string with 'Z'."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


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
# Base shapes
# -----------------------------------------------------------------------------

# NOTE: Pydantic is optional. If you wire FastAPI, it'll be present.
try:
    from pydantic import BaseModel, Field, ConfigDict
    from pydantic import field_validator

    class Model(BaseModel):
        """Common Pydantic base with sane defaults."""

        model_config = ConfigDict(
            extra="forbid",  # strict inputs
            populate_by_name=True,
            str_strip_whitespace=True,
        )

except Exception:  # pragma: no cover
    # Fallback datalike objects so core can import this without pydantic installed.
    # If you run the API, install pydantic/fastapi.
    class Model:  # type: ignore
        def __init__(self, **data: Any):
            for k, v in data.items():
                setattr(self, k, v)

    def Field(default: Any = None, **kwargs: Any) -> Any:  # type: ignore
        return default

    def field_validator(*args: Any, **kwargs: Any):  # type: ignore
        def deco(fn):
            return fn
        return deco


# -----------------------------------------------------------------------------
# Common responses
# -----------------------------------------------------------------------------

class ErrorDetail(Model):
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Optional debug details")


class ApiResponse(Model):
    status: ApiStatus = Field(default=ApiStatus.ok)
    request_id: Optional[str] = Field(default=None, description="Trace correlation id")
    ts: str = Field(default_factory=utc_now_iso)
    error: Optional[ErrorDetail] = Field(default=None)


# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------

class HealthResponse(ApiResponse):
    service: str = Field(default="sentinel-43-api")
    version: str = Field(default="0.1.0")
    uptime_s: Optional[int] = Field(default=None)


# -----------------------------------------------------------------------------
# Assessment ingest
# -----------------------------------------------------------------------------

class ThreatSignal(Model):
    """A single observable event/signal coming in from a source."""

    source: str = Field(..., description="Sensor/source name")
    kind: str = Field(..., description="Signal type, e.g. auth_fail, exfil, anomaly")
    ts: Optional[str] = Field(default=None, description="Event timestamp ISO string")
    fields: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary signal fields")


class ThreatAssessmentIn(Model):
    """External request to assess a set of signals."""

    mode: AssessmentMode = Field(default=AssessmentMode.shadow)
    actor_id: Optional[str] = Field(default=None, description="Operator/account initiating assessment")
    tenant_id: Optional[str] = Field(default=None, description="Tenant/customer id")
    signals: List[ThreatSignal] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict, description="Extra assessment context")


class ThreatAssessmentOut(ApiResponse):
    assessment_id: str = Field(..., description="Unique assessment id")
    severity: int = Field(..., ge=0, le=100, description="0-100 severity")
    confidence: int = Field(..., ge=0, le=100, description="0-100 confidence")
    summary: str = Field(..., description="Short human summary")
    tags: List[str] = Field(default_factory=list)
    raw: Optional[Dict[str, Any]] = Field(default=None, description="Optional raw engine payload")


@field_validator("signals")
def _signals_nonempty(cls, v: List[ThreatSignal]):  # type: ignore
    # Allow empty signals for now (useful for tests/health), but keep hook.
    return v


# -----------------------------------------------------------------------------
# Actions (approve/veto)
# -----------------------------------------------------------------------------

class ActionRequest(Model):
    action_id: str = Field(..., min_length=3)
    operator_id: str = Field(..., min_length=2)
    reason: Optional[str] = Field(default="")


class ActionStatus(Model):
    action_id: str
    decision: ActionDecision = Field(default=ActionDecision.unknown)
    decided_by: Optional[str] = Field(default=None)
    decided_ts: Optional[str] = Field(default=None)
    reason: Optional[str] = Field(default=None)


class ActionResponse(ApiResponse):
    result: bool = Field(..., description="True if operation succeeded")
    action: Optional[ActionStatus] = Field(default=None)


# -----------------------------------------------------------------------------
# Listing
# -----------------------------------------------------------------------------

class ActionListResponse(ApiResponse):
    items: List[ActionStatus] = Field(default_factory=list)
    next_cursor: Optional[str] = Field(default=None)


# -----------------------------------------------------------------------------
# Notes
# -----------------------------------------------------------------------------
# Next file after this:
# - api/routes.py (FastAPI routers)
#   * /health
#   * /v1/assess
#   * /v1/actions/{id}/approve
#   * /v1/actions/{id}/veto
#   * /v1/actions?status=
# - api/deps.py (wiring engine/store into request handlers)
# - api/config.py (env, settings)
