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
#   - Validate approved operators via per-role bearer tokens
#   - Validate approved targets
#   - Validate approved remote event types
#   - Require reason + correlation ID
#   - Support dry-run validation
#   - Produce bounded audit records
#   - Use constant-time token comparison
#   - Enforce payload key/depth/byte limits
#   - Rate-limit repeated authentication failures
#   - Fail CLOSED if no operator tokens are configured
#
# Changes from previous revision:
#   - SENTINEL_REMOTE_OWNER_TOKEN (and friends) no longer optional-with-warning.
#     If no operator tokens are configured at all, the gateway returns 503
#     for every authenticated route instead of running open.
#   - operator_role is now resolved server-side from the bearer token, not
#     trusted from the request body. A mismatched body.operator_role is a
#     403, not silently accepted.
#   - Non-dry-run event activation now requires SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED;
#     otherwise it returns 501 instead of falsely reporting success.
#   - Added a simple per-client rate limit on authentication failures.
#   - ROTATE_REMOTE_TOKEN is now reachable (added to local-sentinel's
#     allowed_events) since OWNER is the only role permitted to use it.
#   - Config is loaded lazily via get_config()/reload_config() instead of
#     a module-level singleton computed at import time.
# =============================================================================

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/remote-gateway", tags=["remote-gateway"])


# =============================================================================
# Env helpers
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
            # OWNER-only event; previously unreachable because no target
            # permitted it. Added here so the OWNER role policy entry
            # is not dead.
            RemoteEventType.ROTATE_REMOTE_TOKEN,
        },
    }
}


# =============================================================================
# Config
# =============================================================================

@dataclass(frozen=True)
class RemoteGatewayConfig:
    enabled: bool
    gateway_name: str
    # token string -> role granted by that token
    operator_tokens: dict[str, OperatorRole] = field(default_factory=dict)
    live_dispatch_enabled: bool = False
    max_payload_keys: int = 50
    max_payload_depth: int = 6
    max_payload_bytes: int = 65_536
    max_reason_length: int = 500
    max_audit_records: int = 10_000
    auth_failure_limit: int = 5
    auth_failure_window_seconds: float = 60.0


def _build_config() -> RemoteGatewayConfig:
    operator_tokens: dict[str, OperatorRole] = {}

    # SENTINEL_REMOTE_OWNER_TOKEN kept for backward compatibility with
    # existing deployments; SENTINEL_REMOTE_TOKEN_OWNER is the preferred name.
    owner_token = _env("SENTINEL_REMOTE_TOKEN_OWNER") or _env("SENTINEL_REMOTE_OWNER_TOKEN")
    admin_token = _env("SENTINEL_REMOTE_TOKEN_ADMIN")
    auditor_token = _env("SENTINEL_REMOTE_TOKEN_AUDITOR")

    if owner_token:
        operator_tokens[owner_token] = OperatorRole.OWNER
    if admin_token:
        operator_tokens[admin_token] = OperatorRole.ADMIN
    if auditor_token:
        operator_tokens[auditor_token] = OperatorRole.AUDITOR

    return RemoteGatewayConfig(
        enabled=_env_bool("SENTINEL_REMOTE_GATEWAY_ENABLED", True),
        gateway_name=_env("SENTINEL_REMOTE_GATEWAY_NAME", "sentinel-43-remote-gateway")
        or "sentinel-43-remote-gateway",
        operator_tokens=operator_tokens,
        live_dispatch_enabled=_env_bool("SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED", False),
        max_payload_keys=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_KEYS", 50),
        max_payload_depth=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_DEPTH", 6),
        max_payload_bytes=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_BYTES", 65_536),
        max_reason_length=_env_int("SENTINEL_REMOTE_MAX_REASON_LENGTH", 500),
        max_audit_records=_env_int("SENTINEL_REMOTE_MAX_AUDIT_RECORDS", 10_000),
        auth_failure_limit=_env_int("SENTINEL_REMOTE_AUTH_FAILURE_LIMIT", 5),
        auth_failure_window_seconds=float(
            _env_int("SENTINEL_REMOTE_AUTH_FAILURE_WINDOW_SECONDS", 60)
        ),
    )


@lru_cache(maxsize=1)
def get_config() -> RemoteGatewayConfig:
    """
    Lazily load (and cache) the remote gateway config.

    Using a function instead of a module-level constant means env vars
    are read on first use rather than at import time, which matters for
    test setups and for Docker contexts where env injection can happen
    after the module graph is imported.
    """
    return _build_config()


def reload_config() -> RemoteGatewayConfig:
    """Clear the cached config and reload from the environment. Mainly for tests."""
    get_config.cache_clear()
    return get_config()


# =============================================================================
# Audit log
# =============================================================================

# Bounded by max_audit_records at the time of first access. If you need to
# change the bound at runtime, call reload_config() and reset_audit_log().
AUDIT_LOG: deque[dict[str, Any]] = deque(maxlen=get_config().max_audit_records)


def reset_audit_log() -> None:
    """Recreate AUDIT_LOG using the current config's max_audit_records. For tests."""
    global AUDIT_LOG
    AUDIT_LOG = deque(maxlen=get_config().max_audit_records)


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
# Authentication / rate limiting
# =============================================================================

# client_id -> timestamps (monotonic) of recent auth failures
_AUTH_FAILURES: dict[str, deque[float]] = {}


def _client_id(request: Request) -> str:
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def _check_rate_limit(client_id: str) -> None:
    config = get_config()
    now = time.monotonic()
    window = _AUTH_FAILURES.setdefault(client_id, deque())

    while window and now - window[0] > config.auth_failure_window_seconds:
        window.popleft()

    if len(window) >= config.auth_failure_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed authentication attempts. Try again later.",
        )


def _record_auth_failure(client_id: str) -> None:
    _AUTH_FAILURES.setdefault(client_id, deque()).append(time.monotonic())


def _resolve_operator_role(authorization: str | None) -> OperatorRole:
    """
    Resolve the operator role from a bearer token.

    Fails CLOSED: if no operator tokens are configured at all, every
    authenticated route is unavailable rather than open.
    """
    config = get_config()

    if not config.operator_tokens:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Remote gateway has no operator tokens configured. "
                "Set SENTINEL_REMOTE_TOKEN_OWNER (and optionally "
                "SENTINEL_REMOTE_TOKEN_ADMIN / SENTINEL_REMOTE_TOKEN_AUDITOR)."
            ),
        )

    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
        )

    token = authorization.removeprefix("Bearer ")

    for candidate, role in config.operator_tokens.items():
        if secrets.compare_digest(token, candidate):
            return role

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid remote gateway token.",
    )


def _authenticate(request: Request, authorization: str | None) -> OperatorRole:
    client_id = _client_id(request)
    _check_rate_limit(client_id)

    try:
        return _resolve_operator_role(authorization)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _record_auth_failure(client_id)
        raise


# =============================================================================
# Routes
# =============================================================================

@router.get("/health", response_model=RemoteHealthResponse)
async def remote_gateway_health() -> RemoteHealthResponse:
    config = get_config()

    return RemoteHealthResponse(
        gateway=config.gateway_name,
        state=RemoteGatewayState.ONLINE if config.enabled else RemoteGatewayState.DISABLED,
        enabled=config.enabled,
        registered_targets=len(REGISTERED_TARGETS),
        available_events=[event.value for event in RemoteEventType],
        audit_buffer_max=config.max_audit_records,
    )


@router.get("/targets", response_model=list[RemoteTargetResponse])
async def list_remote_targets(
    request: Request,
    authorization: str | None = Header(default=None),
) -> list[RemoteTargetResponse]:
    _require_gateway_enabled()
    _authenticate(request, authorization)

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
    request: Request,
    body: RemoteEventActivationRequest,
    authorization: str | None = Header(default=None),
) -> RemoteEventActivationResponse:
    started = time.perf_counter()
    config = get_config()

    _require_gateway_enabled()
    effective_role = _authenticate(request, authorization)

    if body.operator_role != effective_role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "operator_role does not match the role associated with the "
                "provided token."
            ),
        )

    _validate_payload(body.payload)

    target = _validate_target(body.target_id)

    _validate_role_event_permission(effective_role, body.event_type)
    _validate_target_event_permission(target, body.event_type)

    if body.dry_run:
        message = "Dry-run accepted. No remote event was activated."
    elif not config.live_dispatch_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Live dispatch is not enabled on this gateway. Set "
                "SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED=true once an event "
                "broker is wired up, or use dry_run=true."
            ),
        )
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
        gateway=config.gateway_name,
        target_id=body.target_id,
        event_type=body.event_type.value,
        correlation_id=body.correlation_id,
        audit_id=audit_id,
        message=message,
        elapsed_ms=elapsed_ms,
    )


@router.get("/audit/{correlation_id}", response_model=list[RemoteAuditRecord])
async def get_remote_audit_records(
    request: Request,
    correlation_id: str,
    authorization: str | None = Header(default=None),
) -> list[RemoteAuditRecord]:
    _require_gateway_enabled()
    _authenticate(request, authorization)

    cleaned = correlation_id.strip()

    return [
        RemoteAuditRecord(**record)
        for record in AUDIT_LOG
        if record["correlation_id"] == cleaned
    ]


# =============================================================================
# Validation
# =============================================================================

def _require_gateway_enabled() -> None:
    if not get_config().enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Remote gateway is disabled.",
        )


def _validate_payload(payload: dict[str, Any]) -> None:
    config = get_config()

    if len(payload.keys()) > config.max_payload_keys:
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

    if len(raw) > config.max_payload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds configured byte limit.",
        )

    depth = _payload_depth(payload)

    if depth > config.max_payload_depth:
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
    Live event dispatch.

    Only reached when SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED=true and
    dry_run=False. Currently still a placeholder for the real event-broker
    integration (Redis Streams / Kafka / NATS / RabbitMQ / internal
    Watchtower intake) — operators who enable live dispatch should be aware
    this currently only logs.

    Keep this async so future event-broker clients do not block the
    FastAPI loop.
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
