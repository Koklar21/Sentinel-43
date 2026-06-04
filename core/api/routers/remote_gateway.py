# =============================================================================
# Sentinel-43 Remote Gateway
#
# Scope:
#   Authorized remote operations gateway.
#
# This module does NOT:
#   - Provide arbitrary URL forwarding
#   - Provide covert backdoor access
#   - Handle payment enforcement
#   - Bypass tenant/client authorization
#
# This module DOES:
#   - Validate approved operators
#   - Validate approved targets
#   - Validate approved remote event types
#   - Require reason + correlation ID
#   - Support dry-run validation
#   - Produce bounded audit records
#   - Use constant-time token comparison
#   - Enforce payload key/depth/byte limits
# =============================================================================

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/remote", tags=["remote-gateway"])


# =============================================================================
# Config
# =============================================================================

def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        logger.warning("Invalid integer for %s=%r; using default %s", name, value, default)
        return default


@dataclass(frozen=True)
class RemoteGatewayConfig:
    enabled: bool
    gateway_name: str
    owner_token: str | None
    max_payload_keys: int
    max_payload_depth: int
    max_payload_bytes: int
    max_reason_length: int
    max_audit_records: int


def load_remote_gateway_config() -> RemoteGatewayConfig:
    return RemoteGatewayConfig(
        enabled=_env_bool("SENTINEL_REMOTE_GATEWAY_ENABLED", True),
        gateway_name=_env("SENTINEL_REMOTE_GATEWAY_NAME", "sentinel-43-remote-gateway")
        or "sentinel-43-remote-gateway",
        owner_token=_env("SENTINEL_REMOTE_OWNER_TOKEN"),
        max_payload_keys=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_KEYS", 50),
        max_payload_depth=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_DEPTH", 6),
        max_payload_bytes=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_BYTES", 65_536),
        max_reason_length=_env_int("SENTINEL_REMOTE_MAX_REASON_LENGTH", 500),
        max_audit_records=_env_int("SENTINEL_REMOTE_MAX_AUDIT_RECORDS", 10_000),
    )


CONFIG = load_remote_gateway_config()


# =============================================================================
# Enums / Policy
# =============================================================================

class RemoteGatewayState(str, Enum):
    ONLINE = "online"
    DISABLED = "disabled"


class OperatorRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    AUDITOR = "auditor"


class RemoteEventType(str, Enum):
    FORCE_HEALTH_CHECK = "force_health_check"
    FORCE_SYNC = "force_sync"
    ROTATE_REMOTE_TOKEN = "rotate_remote_token"
    REQUEST_DIAGNOSTIC_SNAPSHOT = "request_diagnostic_snapshot"


ROLE_EVENT_POLICY: dict[OperatorRole, set[RemoteEventType]] = {
    OperatorRole.OWNER: {
        RemoteEventType.FORCE_HEALTH_CHECK,
        RemoteEventType.FORCE_SYNC,
        RemoteEventType.ROTATE_REMOTE_TOKEN,
        RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
    },
    OperatorRole.ADMIN: {
        RemoteEventType.FORCE_HEALTH_CHECK,
        RemoteEventType.FORCE_SYNC,
        RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
    },
    OperatorRole.AUDITOR: {
        RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
    },
}


REGISTERED_TARGETS: dict[str, dict[str, Any]] = {
    "local-sentinel": {
        "name": "Local Sentinel-43 Instance",
        "enabled": True,
        "environment": "development",
        "allowed_events": {
            RemoteEventType.FORCE_HEALTH_CHECK,
            RemoteEventType.FORCE_SYNC,
            RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
        },
    }
}


AUDIT_LOG: deque[dict[str, Any]] = deque(maxlen=CONFIG.max_audit_records)


# =============================================================================
# Models
# =============================================================================

class RemoteHealthResponse(BaseModel):
    gateway: str
    state: RemoteGatewayState
    enabled: bool
    registered_targets: int
    available_events: list[str]
    audit_buffer_max: int


class RemoteTargetResponse(BaseModel):
    target_id: str
    name: str
    enabled: bool
    environment: str
    allowed_events: list[str]


class RemoteEventActivationRequest(BaseModel):
    operator_id: str = Field(..., min_length=2, max_length=80)
    operator_role: OperatorRole
    target_id: str = Field(..., min_length=2, max_length=120)
    event_type: RemoteEventType
    reason: str = Field(..., min_length=10, max_length=500)
    correlation_id: str = Field(..., min_length=8, max_length=160)
    dry_run: bool = True
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("operator_id", "target_id", "correlation_id")
    @classmethod
    def no_blank_or_control_chars(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("value cannot be blank")

        if any(ord(char) < 32 for char in cleaned):
            raise ValueError("control characters are not allowed")

        return cleaned

    @field_validator("reason")
    @classmethod
    def reason_must_be_clean(cls, value: str) -> str:
        cleaned = value.strip()

        if len(cleaned) < 10:
            raise ValueError("reason must be at least 10 characters")

        if any(ord(char) < 32 for char in cleaned):
            raise ValueError("control characters are not allowed")

        return cleaned


class RemoteEventActivationResponse(BaseModel):
    ok: bool
    dry_run: bool
    gateway: str
    target_id: str
    event_type: str
    correlation_id: str
    audit_id: str
    message: str
    elapsed_ms: float


class RemoteAuditRecord(BaseModel):
    audit_id: str
    timestamp_unix: float
    operator_id: str
    operator_role: str
    target_id: str
    event_type: str
    reason: str
    correlation_id: str
    dry_run: bool
    accepted: bool
    message: str


# =============================================================================
# Routes
# =============================================================================

@router.get("/health", response_model=RemoteHealthResponse)
async def remote_gateway_health() -> RemoteHealthResponse:
    return RemoteHealthResponse(
        gateway=CONFIG.gateway_name,
        state=RemoteGatewayState.ONLINE if CONFIG.enabled else RemoteGatewayState.DISABLED,
        enabled=CONFIG.enabled,
        registered_targets=len(REGISTERED_TARGETS),
        available_events=[event.value for event in RemoteEventType],
        audit_buffer_max=CONFIG.max_audit_records,
    )


@router.get("/targets", response_model=list[RemoteTargetResponse])
async def list_remote_targets(
    authorization: str | None = Header(default=None),
) -> list[RemoteTargetResponse]:
    _require_gateway_enabled()
    _require_owner_token_if_configured(authorization)

    return [
        RemoteTargetResponse(
            target_id=target_id,
            name=str(target["name"]),
            enabled=bool(target["enabled"]),
            environment=str(target["environment"]),
            allowed_events=sorted(event.value for event in target["allowed_events"]),
        )
        for target_id, target in REGISTERED_TARGETS.items()
    ]


@router.post("/events/activate", response_model=RemoteEventActivationResponse)
async def activate_remote_event(
    body: RemoteEventActivationRequest,
    authorization: str | None = Header(default=None),
) -> RemoteEventActivationResponse:
    started = time.perf_counter()

    _require_gateway_enabled()
    _require_owner_token_if_configured(authorization)
    _validate_payload(body.payload)

    target = _validate_target(body.target_id)

    _validate_role_event_permission(body.operator_role, body.event_type)
    _validate_target_event_permission(target, body.event_type)

    if body.dry_run:
        message = "Dry-run accepted. No remote event was activated."
    else:
        await _dispatch_remote_event(body)
        message = "Remote event accepted and activated."

    audit_id = _write_audit_record(
        body=body,
        accepted=True,
        message=message,
    )

    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

    return RemoteEventActivationResponse(
        ok=True,
        dry_run=body.dry_run,
        gateway=CONFIG.gateway_name,
        target_id=body.target_id,
        event_type=body.event_type.value,
        correlation_id=body.correlation_id,
        audit_id=audit_id,
        message=message,
        elapsed_ms=elapsed_ms,
    )


@router.get("/audit/{correlation_id}", response_model=list[RemoteAuditRecord])
async def get_remote_audit_records(
    correlation_id: str,
    authorization: str | None = Header(default=None),
) -> list[RemoteAuditRecord]:
    _require_gateway_enabled()
    _require_owner_token_if_configured(authorization)

    cleaned = correlation_id.strip()

    return [
        RemoteAuditRecord(**record)
        for record in AUDIT_LOG
        if record["correlation_id"] == cleaned
    ]


# =============================================================================
# Validation / Security
# =============================================================================

def _require_gateway_enabled() -> None:
    if not CONFIG.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Remote gateway is disabled.",
        )


def _require_owner_token_if_configured(authorization: str | None) -> None:
    """
    Development-safe token check.

    In production:
      SENTINEL_REMOTE_OWNER_TOKEN must be set.
    """
    if CONFIG.owner_token is None:
        logger.warning(
            "SENTINEL_REMOTE_OWNER_TOKEN is not configured. "
            "Remote gateway is running without bearer-token enforcement."
        )
        return

    expected = f"Bearer {CONFIG.owner_token}"

    if authorization is None or not secrets.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing remote gateway authorization token.",
        )


def _validate_payload(payload: dict[str, Any]) -> None:
    if len(payload.keys()) > CONFIG.max_payload_keys:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload contains too many top-level keys.",
        )

    try:
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be JSON serializable.",
        ) from None

    if len(raw) > CONFIG.max_payload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds configured byte limit.",
        )

    depth = _payload_depth(payload)

    if depth > CONFIG.max_payload_depth:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds configured nesting depth.",
        )


def _payload_depth(value: Any, current_depth: int = 0) -> int:
    if isinstance(value, dict):
        if not value:
            return current_depth + 1
        return max(_payload_depth(item, current_depth + 1) for item in value.values())

    if isinstance(value, list):
        if not value:
            return current_depth + 1
        return max(_payload_depth(item, current_depth + 1) for item in value)

    return current_depth + 1


def _validate_target(target_id: str) -> dict[str, Any]:
    target = REGISTERED_TARGETS.get(target_id)

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown remote target.",
        )

    if not bool(target.get("enabled", False)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Remote target is disabled.",
        )

    return target


def _validate_role_event_permission(
    role: OperatorRole,
    event_type: RemoteEventType,
) -> None:
    allowed_events = ROLE_EVENT_POLICY.get(role, set())

    if event_type not in allowed_events:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {role.value!r} is not allowed to activate {event_type.value!r}.",
        )


def _validate_target_event_permission(
    target: dict[str, Any],
    event_type: RemoteEventType,
) -> None:
    allowed_events: set[RemoteEventType] = target.get("allowed_events", set())

    if event_type not in allowed_events:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target does not allow event {event_type.value!r}.",
        )


# =============================================================================
# Event Dispatch / Audit
# =============================================================================

async def _dispatch_remote_event(body: RemoteEventActivationRequest) -> None:
    """
    Placeholder for live Sentinel-43 backend integration.

    Future recommended wiring:
      - Redis Streams for early beta
      - Kafka/NATS/RabbitMQ for enterprise deployments
      - Internal Watchtower/MonitoringManager event intake

    Keep this async so future event-broker clients do not block the FastAPI loop.
    """
    logger.info(
        "Remote event activated: operator=%s role=%s target=%s event=%s correlation_id=%s",
        body.operator_id,
        body.operator_role.value,
        body.target_id,
        body.event_type.value,
        body.correlation_id,
    )


def _write_audit_record(
    *,
    body: RemoteEventActivationRequest,
    accepted: bool,
    message: str,
) -> str:
    audit_id = str(uuid4())

    record = {
        "audit_id": audit_id,
        "timestamp_unix": time.time(),
        "operator_id": body.operator_id,
        "operator_role": body.operator_role.value,
        "target_id": body.target_id,
        "event_type": body.event_type.value,
        "reason": body.reason,
        "correlation_id": body.correlation_id,
        "dry_run": body.dry_run,
        "accepted": accepted,
        "message": message,
    }

    AUDIT_LOG.append(record)

    logger.info(
        "Remote gateway audit record created: audit_id=%s correlation_id=%s dry_run=%s accepted=%s",
        audit_id,
        body.correlation_id,
        body.dry_run,
        accepted,
    )

    return audit_id


# =============================================================================
# Compatibility Export
# =============================================================================

def get_remote_gateway_router() -> APIRouter:
    return router