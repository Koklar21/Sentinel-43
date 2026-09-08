# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 Watchgate API models.

Stable Pydantic schemas for the API layer.

This module contains:
    - request/response schema definitions
    - field normalization/validation
    - enum definitions

It intentionally contains no business logic, database access, network I/O,
authorization decisions, or enforcement behavior.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


S43_API_NAME: Final[str] = "Sentinel-43 Watchgate API"
S43_API_VERSION: Final[str] = "1.0.0"

_IDENTIFIER_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_.:@/-]{1,256}$"
)

_TAG_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_.:-]{1,64}$"
)

MAX_SIGNALS: Final[int] = 256
MAX_SIGNAL_FIELDS: Final[int] = 128
MAX_CONTEXT_KEYS: Final[int] = 128
MAX_TAGS: Final[int] = 64


def utc_now_iso() -> str:
    """Return an RFC3339 UTC timestamp with second precision."""
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
    OK = "ok"
    ERROR = "error"


class AssessmentMode(str, Enum):
    """Assessment execution posture.

    SHADOW:
        Observe/assess only.

    HUMAN_GATED:
        Assessment may stage recommendations for human review, but does not
        authorize autonomous enforcement.
    """

    SHADOW = "shadow"
    HUMAN_GATED = "human_gated"


class ActionDecision(str, Enum):
    APPROVED = "approved"
    VETOED = "vetoed"
    PENDING = "pending"
    UNKNOWN = "unknown"


class ErrorDetail(SentinelModel):
    """Structured Sentinel-43 API error."""

    code: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Machine-readable error code",
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Human-readable error message",
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Optional bounded diagnostic/context payload",
    )

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", cleaned):
            raise ValueError("error code contains unsupported characters")
        return cleaned

    @field_validator("details")
    @classmethod
    def validate_details(
        cls,
        value: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if len(value) > MAX_CONTEXT_KEYS:
            raise ValueError(
                f"error details may contain at most {MAX_CONTEXT_KEYS} keys"
            )
        return value


class ApiResponse(SentinelModel):
    """Base Sentinel-43 API response."""

    status: ApiStatus = Field(default=ApiStatus.OK)
    request_id: str | None = Field(
        default=None,
        max_length=256,
        description="Correlation identifier",
    )
    ts: str = Field(default_factory=utc_now_iso)
    error: ErrorDetail | None = Field(default=None)

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not _IDENTIFIER_RE.fullmatch(cleaned):
            raise ValueError("request_id contains unsupported characters")
        return cleaned

    @model_validator(mode="after")
    def validate_status_error_consistency(self) -> "ApiResponse":
        if self.status is ApiStatus.ERROR and self.error is None:
            raise ValueError(
                "error responses must include error details"
            )

        if self.status is ApiStatus.OK and self.error is not None:
            raise ValueError(
                "successful responses must not include error details"
            )

        return self


class HealthResponse(ApiResponse):
    """Sentinel-43 Watchgate health response."""

    service: str = Field(
        default=S43_API_NAME,
        min_length=1,
        max_length=128,
    )
    version: str = Field(
        default=S43_API_VERSION,
        min_length=1,
        max_length=64,
    )
    principle: str = Field(
        default=(
            "Advisory-first. Human-gated. "
            "Audit-backed. No autonomous enforcement in core."
        ),
        max_length=512,
    )
    uptime_s: int | None = Field(
        default=None,
        ge=0,
    )


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
        max_length=64,
        description="Signal timestamp in RFC3339/ISO-8601 form",
    )
    fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured signal payload",
    )

    @field_validator("source", "kind")
    @classmethod
    def validate_identifier_like(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", cleaned):
            raise ValueError("value contains unsupported characters")
        return cleaned

    @field_validator("fields")
    @classmethod
    def validate_fields(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        if len(value) > MAX_SIGNAL_FIELDS:
            raise ValueError(
                f"signal fields may contain at most {MAX_SIGNAL_FIELDS} keys"
            )
        return value


class ThreatAssessmentIn(SentinelModel):
    """Inbound Sentinel-43 assessment request."""

    mode: AssessmentMode = Field(
        default=AssessmentMode.SHADOW
    )
    actor_id: str | None = Field(
        default=None,
        max_length=128,
    )
    tenant_id: str | None = Field(
        default=None,
        max_length=128,
    )
    signals: list[ThreatSignal] = Field(
        default_factory=list,
        max_length=MAX_SIGNALS,
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
    )

    @field_validator("actor_id", "tenant_id")
    @classmethod
    def validate_optional_identifier(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip()
        if not cleaned:
            return None

        if not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", cleaned):
            raise ValueError("identifier contains unsupported characters")

        return cleaned

    @field_validator("context")
    @classmethod
    def validate_context(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        if len(value) > MAX_CONTEXT_KEYS:
            raise ValueError(
                f"context may contain at most {MAX_CONTEXT_KEYS} keys"
            )
        return value


class ThreatAssessmentOut(ApiResponse):
    """Normalized Sentinel-43 assessment response."""

    assessment_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
    )
    severity: int = Field(
        ...,
        ge=0,
        le=100,
    )
    confidence: int = Field(
        ...,
        ge=0,
        le=100,
    )
    summary: str = Field(
        ...,
        min_length=1,
        max_length=4096,
    )
    tags: list[str] = Field(
        default_factory=list,
        max_length=MAX_TAGS,
    )

    # Optional bounded diagnostic payload. Avoid returning arbitrary internal
    # engine objects or unserializable Python state.
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional bounded assessment metadata",
    )

    @field_validator("assessment_id")
    @classmethod
    def validate_assessment_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not _IDENTIFIER_RE.fullmatch(cleaned):
            raise ValueError(
                "assessment_id contains unsupported characters"
            )
        return cleaned

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str]) -> list[str]:
        cleaned_tags: list[str] = []

        for tag in value:
            cleaned = tag.strip()
            if not _TAG_RE.fullmatch(cleaned):
                raise ValueError(
                    f"invalid assessment tag {tag!r}"
                )
            if cleaned not in cleaned_tags:
                cleaned_tags.append(cleaned)

        return cleaned_tags

    @field_validator("metadata")
    @classmethod
    def validate_metadata(
        cls,
        value: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if len(value) > MAX_CONTEXT_KEYS:
            raise ValueError(
                f"metadata may contain at most {MAX_CONTEXT_KEYS} keys"
            )
        return value


class ActionRequest(SentinelModel):
    """Approve/veto request payload."""

    action_id: str | None = Field(
        default=None,
        min_length=3,
        max_length=256,
    )
    operator_id: str = Field(
        ...,
        min_length=2,
        max_length=256,
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
    )

    @field_validator("action_id", "operator_id")
    @classmethod
    def validate_action_identifiers(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip()

        if not _IDENTIFIER_RE.fullmatch(cleaned):
            raise ValueError(
                "identifier contains unsupported characters"
            )

        return cleaned


class ActionStatus(SentinelModel):
    """Action decision state."""

    action_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
    )
    decision: ActionDecision = Field(
        default=ActionDecision.UNKNOWN
    )
    decided_by: str | None = Field(
        default=None,
        max_length=256,
    )
    decided_ts: str | None = Field(
        default=None,
        max_length=64,
    )
    reason: str | None = Field(
        default=None,
        max_length=500,
    )

    @field_validator("action_id", "decided_by")
    @classmethod
    def validate_status_identifiers(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip()
        if not _IDENTIFIER_RE.fullmatch(cleaned):
            raise ValueError(
                "identifier contains unsupported characters"
            )
        return cleaned

    @model_validator(mode="after")
    def validate_decision_fields(self) -> "ActionStatus":
        if self.decision in {
            ActionDecision.APPROVED,
            ActionDecision.VETOED,
        }:
            if not self.decided_by:
                raise ValueError(
                    "final decisions must include decided_by"
                )
            if not self.decided_ts:
                raise ValueError(
                    "final decisions must include decided_ts"
                )
            if not self.reason:
                raise ValueError(
                    "final decisions must include reason"
                )

        return self


class ActionResponse(ApiResponse):
    """Single action operation response."""

    result: bool = Field(
        ...,
        description="Operation success state",
    )
    action: ActionStatus | None = Field(
        default=None,
    )

    @model_validator(mode="after")
    def validate_result_action_consistency(self) -> "ActionResponse":
        if self.result and self.action is None:
            raise ValueError(
                "successful action responses must include action state"
            )
        return self


class ActionListResponse(ApiResponse):
    """Paginated Sentinel-43 action list response."""

    items: list[ActionStatus] = Field(
        default_factory=list,
        max_length=500,
    )
    next_cursor: str | None = Field(
        default=None,
        max_length=512,
    )


__all__ = [
    "ActionDecision",
    "ActionListResponse",
    "ActionRequest",
    "ActionResponse",
    "ActionStatus",
    "ApiResponse",
    "ApiStatus",
    "AssessmentMode",
    "ErrorDetail",
    "HealthResponse",
    "S43_API_NAME",
    "S43_API_VERSION",
    "SentinelModel",
    "ThreatAssessmentIn",
    "ThreatAssessmentOut",
    "ThreatSignal",
    "utc_now_iso",
]
