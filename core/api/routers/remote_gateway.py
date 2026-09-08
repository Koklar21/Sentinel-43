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

"""Sentinel-43 authorized remote operations gateway.

The gateway is intentionally narrow. It does not provide arbitrary forwarding,
shell access, tenant bypass, or autonomous enforcement.

Security properties:
    - bearer token resolves the effective server-side role
    - no configured tokens => authenticated routes fail closed
    - live dispatch is disabled by default
    - live dispatch requires an explicitly registered in-process handler
    - human-gated approve/veto payloads require both action_id and decision_id
    - payload size/key/depth limits are enforced before dispatch
    - correlation IDs are replay-protected within a bounded retention window
    - authentication-failure state is bounded
    - monitoring/Watchtower reporting is best-effort and off the critical path
    - the in-memory event buffer is operational telemetry, not a durable audit
      ledger and must not be treated as authoritative security evidence
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, Awaitable, Callable, Final
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ...monitoring.watchtower_client import watchtower_request

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/remote-gateway",
    tags=["remote-gateway"],
)

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)
_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)
_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)
_SAFE_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9_.:@/-]{2,160}$"
)
_MAX_DISPATCH_MESSAGE: Final[int] = 1024


# =============================================================================
# Configuration helpers
# =============================================================================

def _env(name: str, default: str | None = None) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip()
    return value if value else default


def _environment() -> str:
    value = (
        _env("SENTINEL_ENV")
        or _env("S43_ENV")
        or "production"
    ).lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "prod": "production",
        "stage": "staging",
    }
    return aliases.get(value, value)


def _is_local() -> bool:
    return _environment() in _LOCAL_ENVIRONMENTS


def _env_bool(
    name: str,
    default: bool,
    *,
    strict: bool,
) -> bool:
    raw = _env(name)
    if raw is None:
        return default

    normalized = raw.lower()

    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False

    if strict:
        raise RuntimeError(
            f"{name} must be boolean; got {raw!r}"
        )

    logger.warning(
        "RemoteGateway: invalid boolean for %s=%r; using default %s",
        name,
        raw,
        default,
    )
    return default


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
    strict: bool,
) -> int:
    raw = _env(name)

    if raw is None:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError as exc:
            if strict:
                raise RuntimeError(
                    f"{name} must be integer; got {raw!r}"
                ) from exc

            logger.warning(
                "RemoteGateway: invalid integer for %s=%r; using default %s",
                name,
                raw,
                default,
            )
            return default

    if not minimum <= value <= maximum:
        if strict:
            raise RuntimeError(
                f"{name} must be between {minimum} and {maximum}; got {value}"
            )

        logger.warning(
            "RemoteGateway: %s=%s outside %s..%s; using default %s",
            name,
            value,
            minimum,
            maximum,
            default,
        )
        return default

    return value


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
    strict: bool,
) -> float:
    raw = _env(name)

    if raw is None:
        value = default
    else:
        try:
            value = float(raw)
        except ValueError as exc:
            if strict:
                raise RuntimeError(
                    f"{name} must be numeric; got {raw!r}"
                ) from exc

            logger.warning(
                "RemoteGateway: invalid number for %s=%r; using default %s",
                name,
                raw,
                default,
            )
            return default

    if not minimum <= value <= maximum:
        if strict:
            raise RuntimeError(
                f"{name} must be between {minimum} and {maximum}; got {value}"
            )

        logger.warning(
            "RemoteGateway: %s=%s outside %s..%s; using default %s",
            name,
            value,
            minimum,
            maximum,
            default,
        )
        return default

    return value


# =============================================================================
# Policy
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
    APPROVE_DECISION = "approve_decision"
    VETO_DECISION = "veto_decision"


ROLE_EVENT_POLICY: Final[dict[OperatorRole, frozenset[RemoteEventType]]] = {
    OperatorRole.OWNER: frozenset(
        {
            RemoteEventType.FORCE_HEALTH_CHECK,
            RemoteEventType.FORCE_SYNC,
            RemoteEventType.ROTATE_REMOTE_TOKEN,
            RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
            RemoteEventType.APPROVE_DECISION,
            RemoteEventType.VETO_DECISION,
        }
    ),
    OperatorRole.ADMIN: frozenset(
        {
            RemoteEventType.FORCE_HEALTH_CHECK,
            RemoteEventType.FORCE_SYNC,
            RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
            RemoteEventType.APPROVE_DECISION,
            RemoteEventType.VETO_DECISION,
        }
    ),
    OperatorRole.AUDITOR: frozenset(
        {
            RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
        }
    ),
}

_AUDIT_VISIBLE_ROLES: Final[dict[OperatorRole, frozenset[str]]] = {
    OperatorRole.OWNER: frozenset({"owner", "admin", "auditor"}),
    OperatorRole.ADMIN: frozenset({"admin", "auditor"}),
    OperatorRole.AUDITOR: frozenset({"auditor"}),
}


@dataclass(frozen=True, slots=True)
class TargetPolicy:
    target_id: str
    name: str
    enabled: bool
    allowed_events: frozenset[RemoteEventType]


REGISTERED_TARGETS: Final[dict[str, TargetPolicy]] = {
    "local-sentinel": TargetPolicy(
        target_id="local-sentinel",
        name="Local Sentinel-43 Instance",
        enabled=True,
        allowed_events=frozenset(RemoteEventType),
    )
}


# =============================================================================
# Config
# =============================================================================

@dataclass(frozen=True, slots=True)
class RemoteGatewayConfig:
    enabled: bool
    gateway_name: str
    operator_tokens: dict[bytes, OperatorRole] = field(default_factory=dict)

    live_dispatch_enabled: bool = False

    max_payload_keys: int = 50
    max_payload_depth: int = 6
    max_payload_bytes: int = 65_536
    max_reason_length: int = 500

    max_event_records: int = 10_000

    auth_failure_limit: int = 5
    auth_failure_window_seconds: float = 60.0
    auth_failure_max_clients: int = 10_000

    replay_window_seconds: float = 86_400.0
    replay_max_entries: int = 50_000

    monitoring_timeout_seconds: float = 1.5


def _token_digest(value: str) -> bytes:
    return hashlib.sha256(
        value.encode("utf-8")
    ).digest()


def _build_config() -> RemoteGatewayConfig:
    strict = not _is_local()

    tokens: dict[bytes, OperatorRole] = {}

    token_values = (
        (
            _env("SENTINEL_REMOTE_TOKEN_OWNER")
            or _env("SENTINEL_REMOTE_OWNER_TOKEN"),
            OperatorRole.OWNER,
        ),
        (
            _env("SENTINEL_REMOTE_TOKEN_ADMIN"),
            OperatorRole.ADMIN,
        ),
        (
            _env("SENTINEL_REMOTE_TOKEN_AUDITOR"),
            OperatorRole.AUDITOR,
        ),
    )

    seen_raw: set[str] = set()

    for token, role in token_values:
        if not token:
            continue

        if token in seen_raw:
            raise RuntimeError(
                "Remote gateway tokens must be unique across roles"
            )

        if len(token) < 32:
            raise RuntimeError(
                f"Remote gateway {role.value} token must be at least 32 characters"
            )

        seen_raw.add(token)
        tokens[_token_digest(token)] = role

    return RemoteGatewayConfig(
        enabled=_env_bool(
            "SENTINEL_REMOTE_GATEWAY_ENABLED",
            False,
            strict=strict,
        ),
        gateway_name=(
            _env(
                "SENTINEL_REMOTE_GATEWAY_NAME",
                "sentinel-43-remote-gateway",
            )
            or "sentinel-43-remote-gateway"
        ),
        operator_tokens=tokens,
        live_dispatch_enabled=_env_bool(
            "SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED",
            False,
            strict=strict,
        ),
        max_payload_keys=_env_int(
            "SENTINEL_REMOTE_MAX_PAYLOAD_KEYS",
            50,
            minimum=1,
            maximum=500,
            strict=strict,
        ),
        max_payload_depth=_env_int(
            "SENTINEL_REMOTE_MAX_PAYLOAD_DEPTH",
            6,
            minimum=1,
            maximum=32,
            strict=strict,
        ),
        max_payload_bytes=_env_int(
            "SENTINEL_REMOTE_MAX_PAYLOAD_BYTES",
            65_536,
            minimum=256,
            maximum=1_048_576,
            strict=strict,
        ),
        max_reason_length=_env_int(
            "SENTINEL_REMOTE_MAX_REASON_LENGTH",
            500,
            minimum=10,
            maximum=4096,
            strict=strict,
        ),
        max_event_records=_env_int(
            "SENTINEL_REMOTE_MAX_AUDIT_RECORDS",
            10_000,
            minimum=100,
            maximum=100_000,
            strict=strict,
        ),
        auth_failure_limit=_env_int(
            "SENTINEL_REMOTE_AUTH_FAILURE_LIMIT",
            5,
            minimum=1,
            maximum=100,
            strict=strict,
        ),
        auth_failure_window_seconds=_env_float(
            "SENTINEL_REMOTE_AUTH_FAILURE_WINDOW_SECONDS",
            60.0,
            minimum=1.0,
            maximum=3600.0,
            strict=strict,
        ),
        auth_failure_max_clients=_env_int(
            "SENTINEL_REMOTE_AUTH_FAILURE_MAX_CLIENTS",
            10_000,
            minimum=100,
            maximum=1_000_000,
            strict=strict,
        ),
        replay_window_seconds=_env_float(
            "SENTINEL_REMOTE_REPLAY_WINDOW_SECONDS",
            86_400.0,
            minimum=60.0,
            maximum=604_800.0,
            strict=strict,
        ),
        replay_max_entries=_env_int(
            "SENTINEL_REMOTE_REPLAY_MAX_ENTRIES",
            50_000,
            minimum=100,
            maximum=1_000_000,
            strict=strict,
        ),
        monitoring_timeout_seconds=_env_float(
            "SENTINEL_REMOTE_MONITORING_TIMEOUT_SECONDS",
            1.5,
            minimum=0.1,
            maximum=30.0,
            strict=strict,
        ),
    )


@lru_cache(maxsize=1)
def get_config() -> RemoteGatewayConfig:
    return _build_config()


def reload_config() -> RemoteGatewayConfig:
    get_config.cache_clear()
    cfg = get_config()

    EVENT_BUFFER.reset()
    _reset_auth_failures()
    _reset_replay_guard()

    return cfg


# =============================================================================
# Models
# =============================================================================

class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class RemoteHealthResponse(StrictModel):
    gateway: str
    state: RemoteGatewayState
    enabled: bool
    registered_targets: int
    available_events: list[str]
    event_buffer_max: int
    event_buffer_durable: bool = False


class RemoteTargetResponse(StrictModel):
    target_id: str
    name: str
    enabled: bool
    allowed_events: list[str]


class RemoteEventActivationRequest(StrictModel):
    operator_id: str = Field(
        ...,
        min_length=2,
        max_length=80,
    )

    # Compatibility-only claim. Authorization always uses the bearer token's
    # server-side role. If present and mismatched, the request is rejected.
    operator_role: OperatorRole | None = Field(
        default=None
    )

    target_id: str = Field(
        ...,
        min_length=2,
        max_length=120,
    )
    event_type: RemoteEventType

    reason: str = Field(
        ...,
        min_length=10,
    )
    correlation_id: str = Field(
        ...,
        min_length=8,
        max_length=160,
    )
    dry_run: bool = True
    payload: dict[str, Any] = Field(
        default_factory=dict,
    )

    @field_validator(
        "operator_id",
        "target_id",
        "correlation_id",
    )
    @classmethod
    def validate_identifier(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if not _SAFE_ID_RE.fullmatch(cleaned):
            raise ValueError(
                "value contains unsupported characters"
            )

        return cleaned

    @field_validator("reason")
    @classmethod
    def validate_reason(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if len(cleaned) < 10:
            raise ValueError(
                "reason must be at least 10 characters"
            )

        max_length = get_config().max_reason_length
        if len(cleaned) > max_length:
            raise ValueError(
                f"reason must be at most {max_length} characters"
            )

        if any(ord(char) < 32 for char in cleaned):
            raise ValueError(
                "control characters are not allowed"
            )

        return cleaned

    @model_validator(mode="after")
    def validate_governance_payload(
        self,
    ) -> "RemoteEventActivationRequest":
        if self.event_type not in {
            RemoteEventType.APPROVE_DECISION,
            RemoteEventType.VETO_DECISION,
        }:
            return self

        action_id = str(
            self.payload.get("action_id") or ""
        ).strip()
        decision_id = str(
            self.payload.get("decision_id") or ""
        ).strip()

        if not action_id:
            raise ValueError(
                f"{self.event_type.value} requires payload.action_id"
            )

        if not decision_id:
            raise ValueError(
                f"{self.event_type.value} requires payload.decision_id"
            )

        if not _SAFE_ID_RE.fullmatch(action_id):
            raise ValueError(
                "payload.action_id contains unsupported characters"
            )

        if not _SAFE_ID_RE.fullmatch(decision_id):
            raise ValueError(
                "payload.decision_id contains unsupported characters"
            )

        return self


class RemoteEventActivationResponse(StrictModel):
    ok: bool
    dry_run: bool
    gateway: str
    target_id: str
    event_type: str
    correlation_id: str
    event_record_id: str
    message: str
    elapsed_ms: float


class RemoteEventRecord(StrictModel):
    event_record_id: str
    timestamp_unix: float
    principal_id: str
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
# Operational event buffer
# =============================================================================

class _EventBuffer:
    """Bounded process-local operational record buffer.

    This is not a durable audit ledger.
    """

    def __init__(self) -> None:
        self._records: deque[dict[str, Any]] | None = None
        self._lock = threading.RLock()

    def _ensure(
        self,
    ) -> deque[dict[str, Any]]:
        with self._lock:
            if self._records is None:
                self._records = deque(
                    maxlen=get_config().max_event_records
                )
            return self._records

    def append(
        self,
        record: dict[str, Any],
    ) -> None:
        with self._lock:
            self._ensure().append(
                dict(record)
            )

    def snapshot(
        self,
    ) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(record)
                for record in self._ensure()
            ]

    def reset(self) -> None:
        with self._lock:
            self._records = deque(
                maxlen=get_config().max_event_records
            )

    def __len__(self) -> int:
        with self._lock:
            return len(self._ensure())


EVENT_BUFFER = _EventBuffer()

# Backward-compatible name. It is intentionally documented as non-durable.
AUDIT_LOG = EVENT_BUFFER


def reset_audit_log() -> None:
    EVENT_BUFFER.reset()


# =============================================================================
# Monitoring integration
# =============================================================================

_monitoring_manager: Any | None = None


def set_monitoring_manager(
    manager: Any | None,
) -> None:
    global _monitoring_manager
    _monitoring_manager = manager


async def _notify_monitoring_pipeline(
    event: dict[str, Any],
    *,
    source_ip: str | None,
) -> None:
    manager = _monitoring_manager
    if manager is None:
        return

    result = manager.analyze_event(
        event,
        source_ip=source_ip,
    )

    if inspect.isawaitable(result):
        await result


async def _report_security_event(
    event: dict[str, Any],
    *,
    source_ip: str | None = None,
) -> None:
    config = get_config()

    async def report() -> None:
        if _monitoring_manager is not None:
            try:
                await _notify_monitoring_pipeline(
                    event,
                    source_ip=source_ip,
                )
            except Exception:
                logger.debug(
                    "RemoteGateway monitoring notification failed",
                    exc_info=True,
                )

        try:
            await asyncio.to_thread(
                watchtower_request,
                "POST",
                "/watchtower/analyze",
                {"event": event},
            )
        except Exception:
            logger.debug(
                "RemoteGateway Watchtower notification failed",
                exc_info=True,
            )

    try:
        await asyncio.wait_for(
            report(),
            timeout=config.monitoring_timeout_seconds,
        )
    except asyncio.TimeoutError:
        logger.debug(
            "RemoteGateway security-event reporting timed out"
        )


def _schedule_security_event(
    event: dict[str, Any],
    *,
    source_ip: str | None = None,
) -> None:
    try:
        asyncio.create_task(
            _report_security_event(
                event,
                source_ip=source_ip,
            ),
            name="s43-remote-gateway-telemetry",
        )
    except RuntimeError:
        logger.debug(
            "RemoteGateway telemetry task could not be scheduled",
            exc_info=True,
        )


# =============================================================================
# Authentication / rate limiting
# =============================================================================

@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    role: OperatorRole
    principal_id: str


_AUTH_FAILURES: dict[str, deque[float]] = {}
_AUTH_FAILURES_LOCK = threading.Lock()


def _reset_auth_failures() -> None:
    with _AUTH_FAILURES_LOCK:
        _AUTH_FAILURES.clear()


def _client_id(
    request: Request,
) -> str:
    # Prefer the firewall's trusted-proxy-resolved client identity.
    state = getattr(request, "state", None)
    resolved = getattr(
        state,
        "s43_client_ip",
        None,
    )

    if resolved:
        return str(resolved)

    if (
        request.client is not None
        and request.client.host
    ):
        return request.client.host

    return "unknown"


def _check_auth_rate_limit(
    client_id: str,
) -> None:
    config = get_config()
    now = time.monotonic()
    cutoff = (
        now
        - config.auth_failure_window_seconds
    )

    with _AUTH_FAILURES_LOCK:
        window = _AUTH_FAILURES.get(
            client_id
        )

        if window is None:
            return

        while window and window[0] <= cutoff:
            window.popleft()

        if not window:
            _AUTH_FAILURES.pop(
                client_id,
                None,
            )
            return

        if len(window) >= config.auth_failure_limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "Too many failed authentication attempts. "
                    "Try again later."
                ),
            )


def _record_auth_failure(
    client_id: str,
) -> None:
    config = get_config()
    now = time.monotonic()
    cutoff = (
        now
        - config.auth_failure_window_seconds
    )

    with _AUTH_FAILURES_LOCK:
        window = _AUTH_FAILURES.setdefault(
            client_id,
            deque(),
        )

        while window and window[0] <= cutoff:
            window.popleft()

        window.append(now)

        if len(_AUTH_FAILURES) <= config.auth_failure_max_clients:
            return

        stale = [
            key
            for key, values in _AUTH_FAILURES.items()
            if not values
            or values[-1] <= cutoff
        ]

        for key in stale:
            _AUTH_FAILURES.pop(
                key,
                None,
            )

        while len(_AUTH_FAILURES) > config.auth_failure_max_clients:
            oldest = min(
                _AUTH_FAILURES,
                key=lambda key: (
                    _AUTH_FAILURES[key][-1]
                    if _AUTH_FAILURES[key]
                    else float("-inf")
                ),
            )
            _AUTH_FAILURES.pop(
                oldest,
                None,
            )


def _resolve_principal(
    authorization: str | None,
) -> AuthPrincipal:
    config = get_config()

    if not config.operator_tokens:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Remote gateway has no operator tokens configured."
            ),
        )

    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    parts = authorization.strip().split()

    if (
        len(parts) != 2
        or parts[0].lower() != "bearer"
        or not parts[1].strip()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    raw_token = parts[1].strip()
    digest = _token_digest(raw_token)

    matched_role: OperatorRole | None = None

    for candidate_digest, role in config.operator_tokens.items():
        if secrets.compare_digest(
            digest,
            candidate_digest,
        ):
            matched_role = role

    if matched_role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid remote gateway token.",
        )

    principal_id = (
        "remote:"
        + hashlib.sha256(
            raw_token.encode("utf-8")
        ).hexdigest()[:16]
    )

    return AuthPrincipal(
        role=matched_role,
        principal_id=principal_id,
    )


async def _authenticate(
    request: Request,
    authorization: str | None,
) -> AuthPrincipal:
    client_id = _client_id(request)

    try:
        _check_auth_rate_limit(
            client_id
        )
    except HTTPException:
        _schedule_security_event(
            {
                "kind": "security",
                "event_category": "remote_gateway_rate_limited",
                "gateway": get_config().gateway_name,
                "client_id": client_id,
                "path": request.url.path,
                "rate_limited": True,
            },
            source_ip=client_id,
        )
        raise

    try:
        return _resolve_principal(
            authorization
        )

    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _record_auth_failure(
                client_id
            )

            _schedule_security_event(
                {
                    "kind": "security",
                    "event_category": "remote_gateway_auth_failure",
                    "gateway": get_config().gateway_name,
                    "client_id": client_id,
                    "path": request.url.path,
                    "auth_failure": True,
                },
                source_ip=client_id,
            )

        raise


# =============================================================================
# Replay protection
# =============================================================================

_REPLAY_GUARD: dict[str, float] = {}
_REPLAY_LOCK = threading.Lock()


def _reset_replay_guard() -> None:
    with _REPLAY_LOCK:
        _REPLAY_GUARD.clear()


def _reserve_correlation_id(
    correlation_id: str,
) -> None:
    config = get_config()
    now = time.monotonic()
    cutoff = now - config.replay_window_seconds

    with _REPLAY_LOCK:
        stale = [
            key
            for key, seen_at in _REPLAY_GUARD.items()
            if seen_at <= cutoff
        ]

        for key in stale:
            _REPLAY_GUARD.pop(
                key,
                None,
            )

        if correlation_id in _REPLAY_GUARD:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "correlation_id has already been used within "
                    "the replay-protection window."
                ),
            )

        if len(_REPLAY_GUARD) >= config.replay_max_entries:
            oldest = min(
                _REPLAY_GUARD,
                key=_REPLAY_GUARD.__getitem__,
            )
            _REPLAY_GUARD.pop(
                oldest,
                None,
            )

        _REPLAY_GUARD[correlation_id] = now


def _release_correlation_id(
    correlation_id: str,
) -> None:
    with _REPLAY_LOCK:
        _REPLAY_GUARD.pop(
            correlation_id,
            None,
        )


# =============================================================================
# Dispatch registry
# =============================================================================

DispatchHandler = Callable[
    [RemoteEventActivationRequest],
    Awaitable[str],
]

_dispatch_registry: dict[
    RemoteEventType,
    DispatchHandler,
] = {}
_dispatch_registry_lock = threading.Lock()


def register_dispatch_handler(
    event_type: RemoteEventType,
    handler: DispatchHandler,
) -> None:
    if not callable(handler):
        raise TypeError(
            "dispatch handler must be callable"
        )

    with _dispatch_registry_lock:
        if event_type in _dispatch_registry:
            raise RuntimeError(
                f"Dispatch handler already registered for {event_type.value}"
            )

        _dispatch_registry[
            event_type
        ] = handler


def clear_dispatch_handlers() -> None:
    with _dispatch_registry_lock:
        _dispatch_registry.clear()


async def _dispatch_remote_event(
    body: RemoteEventActivationRequest,
) -> str:
    with _dispatch_registry_lock:
        handler = _dispatch_registry.get(
            body.event_type
        )

    if handler is None:
        raise NotImplementedError(
            f"No dispatch handler registered for "
            f"event_type={body.event_type.value!r}"
        )

    message = await handler(body)

    if not isinstance(message, str):
        raise RuntimeError(
            "Remote dispatch handler must return a string message"
        )

    cleaned = message.strip()

    if not cleaned:
        raise RuntimeError(
            "Remote dispatch handler returned an empty message"
        )

    if len(cleaned) > _MAX_DISPATCH_MESSAGE:
        cleaned = (
            cleaned[:_MAX_DISPATCH_MESSAGE]
            + "…"
        )

    return cleaned


# =============================================================================
# Validation
# =============================================================================

def _require_gateway_enabled() -> None:
    if not get_config().enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Remote gateway is disabled.",
        )


def _payload_depth(
    value: Any,
    *,
    max_allowed: int,
) -> int:
    stack: list[tuple[Any, int]] = [
        (value, 1)
    ]
    maximum = 0

    while stack:
        node, depth = stack.pop()

        if depth > max_allowed:
            return depth

        maximum = max(
            maximum,
            depth,
        )

        if isinstance(node, dict):
            stack.extend(
                (child, depth + 1)
                for child in node.values()
            )

        elif isinstance(node, list):
            stack.extend(
                (child, depth + 1)
                for child in node
            )

    return maximum


def _validate_payload(
    payload: dict[str, Any],
) -> None:
    config = get_config()

    if len(payload) > config.max_payload_keys:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload contains too many top-level keys.",
        )

    try:
        raw = json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be JSON serializable.",
        ) from exc

    if len(raw) > config.max_payload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds configured byte limit.",
        )

    if _payload_depth(
        payload,
        max_allowed=config.max_payload_depth,
    ) > config.max_payload_depth:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds configured nesting depth.",
        )


def _validate_target(
    target_id: str,
) -> TargetPolicy:
    target = REGISTERED_TARGETS.get(
        target_id
    )

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown remote target.",
        )

    if not target.enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Remote target is disabled.",
        )

    return target


def _validate_role_event_permission(
    role: OperatorRole,
    event_type: RemoteEventType,
) -> None:
    if event_type not in ROLE_EVENT_POLICY.get(
        role,
        frozenset(),
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role is not permitted to activate this event.",
        )


def _validate_target_event_permission(
    target: TargetPolicy,
    event_type: RemoteEventType,
) -> None:
    if event_type not in target.allowed_events:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target does not permit this event.",
        )


# =============================================================================
# Event record
# =============================================================================

def _write_event_record(
    *,
    principal: AuthPrincipal,
    body: RemoteEventActivationRequest,
    accepted: bool,
    message: str,
) -> str:
    event_record_id = str(
        uuid4()
    )

    record = {
        "event_record_id": event_record_id,
        "timestamp_unix": time.time(),
        "principal_id": principal.principal_id,
        "operator_id": body.operator_id,
        "operator_role": principal.role.value,
        "target_id": body.target_id,
        "event_type": body.event_type.value,
        "reason": body.reason,
        "correlation_id": body.correlation_id,
        "dry_run": body.dry_run,
        "accepted": accepted,
        "message": message,
    }

    EVENT_BUFFER.append(
        record
    )

    return event_record_id


# =============================================================================
# Routes
# =============================================================================

@router.get(
    "/health",
    response_model=RemoteHealthResponse,
)
async def remote_gateway_health(
    request: Request,
    authorization: str | None = Header(
        default=None,
    ),
) -> RemoteHealthResponse:
    _require_gateway_enabled()
    await _authenticate(
        request,
        authorization,
    )

    config = get_config()

    return RemoteHealthResponse(
        gateway=config.gateway_name,
        state=RemoteGatewayState.ONLINE,
        enabled=True,
        registered_targets=len(
            REGISTERED_TARGETS
        ),
        available_events=[
            event.value
            for event in RemoteEventType
        ],
        event_buffer_max=config.max_event_records,
        event_buffer_durable=False,
    )


@router.get(
    "/targets",
    response_model=list[RemoteTargetResponse],
)
async def list_remote_targets(
    request: Request,
    authorization: str | None = Header(
        default=None,
    ),
) -> list[RemoteTargetResponse]:
    _require_gateway_enabled()
    await _authenticate(
        request,
        authorization,
    )

    return [
        RemoteTargetResponse(
            target_id=target.target_id,
            name=target.name,
            enabled=target.enabled,
            allowed_events=sorted(
                event.value
                for event in target.allowed_events
            ),
        )
        for target in REGISTERED_TARGETS.values()
    ]


@router.post(
    "/events/activate",
    response_model=RemoteEventActivationResponse,
)
async def activate_remote_event(
    request: Request,
    body: RemoteEventActivationRequest,
    authorization: str | None = Header(
        default=None,
    ),
) -> RemoteEventActivationResponse:
    started = time.perf_counter()
    config = get_config()
    client_id = _client_id(
        request
    )

    _require_gateway_enabled()

    principal = await _authenticate(
        request,
        authorization,
    )

    if (
        body.operator_role is not None
        and body.operator_role is not principal.role
    ):
        _schedule_security_event(
            {
                "kind": "security",
                "event_category": "remote_gateway_role_mismatch",
                "gateway": config.gateway_name,
                "client_id": client_id,
                "operator_id": body.operator_id,
                "claimed_role": body.operator_role.value,
                "token_role": principal.role.value,
                "correlation_id": body.correlation_id,
                "privilege_escalation": True,
            },
            source_ip=client_id,
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="operator_role does not match authenticated role.",
        )

    _validate_payload(
        body.payload
    )

    target = _validate_target(
        body.target_id
    )

    _validate_role_event_permission(
        principal.role,
        body.event_type,
    )

    _validate_target_event_permission(
        target,
        body.event_type,
    )

    _reserve_correlation_id(
        body.correlation_id
    )

    try:
        if body.dry_run:
            message = (
                "Dry-run accepted. No remote event was activated."
            )

        else:
            if not config.live_dispatch_enabled:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Live remote dispatch is disabled.",
                )

            try:
                message = await _dispatch_remote_event(
                    body
                )

            except NotImplementedError as exc:
                raise HTTPException(
                    status_code=status.HTTP_501_NOT_IMPLEMENTED,
                    detail=(
                        "No live dispatch handler is registered "
                        "for this event type."
                    ),
                ) from exc

        event_record_id = _write_event_record(
            principal=principal,
            body=body,
            accepted=True,
            message=message,
        )

    except Exception:
        # Validation/availability failures should not permanently consume the
        # replay key. Once a handler starts and returns successfully, the key
        # remains reserved for the configured replay window.
        _release_correlation_id(
            body.correlation_id
        )
        raise

    _schedule_security_event(
        {
            "kind": "log",
            "event_category": "remote_gateway_event_activation",
            "gateway": config.gateway_name,
            "event_record_id": event_record_id,
            "principal_id": principal.principal_id,
            "operator_id": body.operator_id,
            "operator_role": principal.role.value,
            "target_id": body.target_id,
            "event_type": body.event_type.value,
            "correlation_id": body.correlation_id,
            "dry_run": body.dry_run,
        },
        source_ip=client_id,
    )

    elapsed_ms = round(
        (
            time.perf_counter()
            - started
        )
        * 1000,
        3,
    )

    return RemoteEventActivationResponse(
        ok=True,
        dry_run=body.dry_run,
        gateway=config.gateway_name,
        target_id=body.target_id,
        event_type=body.event_type.value,
        correlation_id=body.correlation_id,
        event_record_id=event_record_id,
        message=message,
        elapsed_ms=elapsed_ms,
    )


@router.get(
    "/audit/{correlation_id}",
    response_model=list[RemoteEventRecord],
)
async def get_remote_event_records(
    request: Request,
    correlation_id: str,
    authorization: str | None = Header(
        default=None,
    ),
) -> list[RemoteEventRecord]:
    _require_gateway_enabled()

    principal = await _authenticate(
        request,
        authorization,
    )

    cleaned = correlation_id.strip()

    if not _SAFE_ID_RE.fullmatch(
        cleaned
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid correlation_id.",
        )

    visible_roles = _AUDIT_VISIBLE_ROLES.get(
        principal.role,
        frozenset(),
    )

    return [
        RemoteEventRecord(
            **record
        )
        for record in EVENT_BUFFER.snapshot()
        if record.get("correlation_id") == cleaned
        and record.get("operator_role") in visible_roles
    ]


__all__ = [
    "AUDIT_LOG",
    "EVENT_BUFFER",
    "OperatorRole",
    "REGISTERED_TARGETS",
    "RemoteEventActivationRequest",
    "RemoteEventActivationResponse",
    "RemoteEventRecord",
    "RemoteEventType",
    "RemoteGatewayConfig",
    "RemoteGatewayState",
    "clear_dispatch_handlers",
    "get_config",
    "register_dispatch_handler",
    "reload_config",
    "reset_audit_log",
    "router",
    "set_monitoring_manager",
]
