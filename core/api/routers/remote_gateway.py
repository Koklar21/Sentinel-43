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
    - the in-memory event buffer is operational telemetry, not the
      authoritative audit trail, and is not itself durable
    - a live (non-dry-run) activation requires a durably-accepted pre-action
      audit record before dispatch in any non-local environment; if no
      AuditStore is configured, or the write fails, the activation is
      refused (503) rather than proceeding unaudited -- see
      _require_durable_pre_action_audit()
    - durably-persisted records are retrievable via GET /audit/{id} after a
      restart, through AuditStore.get_records(), merged with the buffer
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
from ...security_context import IdentityType, client_ip_of, set_identity

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


# Protocol-compatible decision event names remain parseable so old clients get
# an explicit authorization refusal instead of a schema mystery. They are NOT
# remote capabilities: the gateway authenticates service/role tokens, not a
# server-verified human DecisionPrincipal.
REMOTE_NON_DECISION_EVENTS: Final[frozenset[RemoteEventType]] = frozenset(
    {
        RemoteEventType.FORCE_HEALTH_CHECK,
        RemoteEventType.FORCE_SYNC,
        RemoteEventType.ROTATE_REMOTE_TOKEN,
        RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
    }
)


ROLE_EVENT_POLICY: Final[dict[OperatorRole, frozenset[RemoteEventType]]] = {
    OperatorRole.OWNER: REMOTE_NON_DECISION_EVENTS,
    OperatorRole.ADMIN: frozenset(
        {
            RemoteEventType.FORCE_HEALTH_CHECK,
            RemoteEventType.FORCE_SYNC,
            RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
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
        allowed_events=REMOTE_NON_DECISION_EVENTS,
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
    # The in-memory buffer itself is never durable, full stop -- it is lost
    # on every restart regardless of whether an authoritative AuditStore is
    # also configured. Do not compute this from audit-store availability.
    event_buffer_durable: bool = False
    # Whether the registered AuditStore's LAST KNOWN append()/
    # verify_integrity() outcome was healthy -- not merely whether an
    # AuditStore object is registered, and not a live guarantee that the
    # *next* write will succeed. False here means a live (non-dry-run)
    # activation would currently be refused outside a local/dev environment
    # -- see _require_durable_pre_action_audit(). Derived from
    # AuditStore.last_known_health, never by performing a write during this
    # health check.
    audit_write_available: bool = False
    # Whether durably-persisted Remote Gateway records can currently be read
    # back (AuditStore.get_records()), derived from the same last-known
    # health as audit_write_available -- both depend on the same integrity
    # chain, so they share one signal here rather than two independently
    # meaningful ones. Distinct from event_buffer_durable, which describes
    # the separate, always-non-durable, process-local buffer.
    audit_read_available: bool = False


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


class RemoteEventRecordsResponse(StrictModel):
    """Records visible to the caller's role, plus their provenance.

    ``authoritative`` is True only when the durable AuditStore was
    consulted and its read succeeded (records may still be merged with the
    process-local buffer in that case -- see get_remote_event_records()).
    False means the durable store was NOT consulted at all: only the
    non-durable, in-process EVENT_BUFFER backs this response, which is
    permitted only in a local/dev environment with no AuditStore
    configured. Callers must not treat authoritative=False as a complete
    history -- a record written before this process started, or by another
    process, would be missing. A durable store that IS configured but whose
    read fails never reaches this model: that fails the request closed
    (503) instead of returning a response that could be mistaken for a
    complete (if empty) authoritative history.
    """

    records: list[RemoteEventRecord]
    authoritative: bool


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
    """Override the MonitoringManager this router reports through.

    Optional. When unset, ``_resolve_monitoring_manager()`` falls back to the
    canonical registry in ``core.monitoring``, which the API composition root
    populates at startup.
    """
    global _monitoring_manager
    _monitoring_manager = manager


def _resolve_monitoring_manager() -> Any | None:
    """The active MonitoringManager, local override first.

    Nothing ever called this module's ``set_monitoring_manager()``, so the
    local global stayed None and every remote-gateway monitoring
    notification silently no-opped. The composition root registers the
    manager with ``core.monitoring.set_monitoring_manager()``; read that
    registry rather than keeping a second, unwired one. Imported lazily so
    core.api.routers does not import core.monitoring at module scope.
    """
    if _monitoring_manager is not None:
        return _monitoring_manager

    try:
        from core.monitoring import get_monitoring_manager

        return get_monitoring_manager()
    except Exception:  # pragma: no cover - registry must never break dispatch
        logger.debug(
            "MonitoringManager registry lookup failed",
            exc_info=True,
        )
        return None


# =============================================================================
# Durable audit persistence
# =============================================================================

_audit_store: Any | None = None


def set_audit_store(
    store: Any | None,
) -> None:
    """Override the AuditStore this router persists event records through.

    Optional. When unset, ``_resolve_audit_store()`` falls back to the
    canonical registry in ``core.audit``, which the API composition root
    populates at startup.
    """
    global _audit_store
    _audit_store = store


def _resolve_audit_store() -> Any | None:
    """The active authoritative AuditStore, local override first.

    Mirrors ``_resolve_monitoring_manager()``: reads the registry the
    composition root populates via ``core.audit.set_audit_store()`` rather
    than keeping a second, unwired handoff. May legitimately be None (no
    S43_AUDIT_HMAC_KEY configured, e.g. local/dev) -- callers must treat a
    missing store as "durable persistence unavailable", not an error.
    Imported lazily so core.api.routers does not import core.audit at
    module scope.
    """
    if _audit_store is not None:
        return _audit_store

    try:
        from core.audit import get_audit_store

        return get_audit_store()
    except Exception:  # pragma: no cover - registry must never break dispatch
        logger.debug(
            "AuditStore registry lookup failed",
            exc_info=True,
        )
        return None


async def _require_durable_pre_action_audit(
    *,
    principal: AuthPrincipal,
    body: "RemoteEventActivationRequest",
) -> None:
    """Durably record intent to activate a live event BEFORE dispatch.

    This is the mandatory gate: in any non-local environment, a live
    (non-dry-run) activation must not reach _dispatch_remote_event() at all
    unless this pre-action record is durably accepted first. If no
    AuditStore is registered, or the write itself raises, the action is
    refused (503) and nothing is dispatched, mutated, or committed against
    the replay ledger -- the caller's own except-and-release-correlation-id
    handling around this call site returns the reservation exactly as it
    would for any other pre-dispatch validation failure.

    In a local/dev environment this is attempted best-effort and never
    blocks: mirrors this module's existing strict-outside-local pattern
    (RemoteGatewayConfig's own `strict = not _is_local()`), so a developer
    without S43_AUDIT_HMAC_KEY configured can still exercise the gateway.

    The synchronous AuditStore.append() (SQLite BEGIN IMMEDIATE + fsync) is
    run via asyncio.to_thread -- it must never block the event loop that
    every other concurrent request depends on.
    """
    store = _resolve_audit_store()
    record = {
        "component": "remote_gateway",
        "phase": "pre_dispatch",
        "event_record_id": str(uuid4()),
        "timestamp_unix": time.time(),
        "principal_id": principal.principal_id,
        "operator_id": body.operator_id,
        "operator_role": principal.role.value,
        "target_id": body.target_id,
        "event_type": body.event_type.value,
        "reason": body.reason,
        "correlation_id": body.correlation_id,
    }

    if store is None:
        if _is_local():
            logger.warning(
                "Remote Gateway live activation proceeding without a "
                "durable pre-action audit record (local/dev only, no "
                "AuditStore configured): correlation_id=%s",
                body.correlation_id,
            )
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Remote Gateway activation requires the authoritative "
                "audit store; none is configured."
            ),
        )

    try:
        await asyncio.to_thread(store.append, record)
    except Exception as exc:
        if _is_local():
            logger.warning(
                "Remote Gateway pre-action durable audit write failed "
                "(local/dev, non-blocking): %s",
                type(exc).__name__,
            )
            return
        logger.error(
            "Remote Gateway pre-action durable audit write failed; "
            "refusing activation: %s",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Remote Gateway activation could not be durably audited.",
        ) from None


async def _persist_event_record(
    record: dict[str, Any],
) -> None:
    """Best-effort durable persistence of the post-action event record.

    By the time this runs, the mandatory pre-action gate (in non-local
    environments) has already durably recorded intent -- this second,
    post-action write adds the outcome (accepted/message) to the same
    ledger. The in-memory EVENT_BUFFER remains the source for the
    /audit/{id} read path when the durable store is unavailable, and is
    unaffected by this. A durable-write failure here does not fail the
    request: the irreversible effect (if any) already happened, and the
    pre-action record already proves the activation was authorized before
    it did. Run via asyncio.to_thread for the same reason as the pre-action
    write -- synchronous SQLite I/O must never run on the event loop.
    """
    store = _resolve_audit_store()

    if store is None:
        return

    try:
        await asyncio.to_thread(
            store.append,
            {
                "component": "remote_gateway",
                "phase": "post_dispatch",
                **record,
            },
        )
    except Exception:
        logger.warning(
            "Remote Gateway post-action durable audit write failed",
            exc_info=True,
        )


async def _notify_monitoring_pipeline(
    event: dict[str, Any],
    *,
    source_ip: str | None,
) -> None:
    manager = _resolve_monitoring_manager()
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
    """Client identity for rate limiting and security events.

    Delegates to the canonical resolver so the trusted-proxy decision has a
    single implementation; this used to be one of three near-identical
    copies that disagreed on the unknown-peer fallback.
    """
    return client_ip_of(request)


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
        principal = _resolve_principal(
            authorization
        )
        # Distinct service identity; a gateway token is never an operator
        # session and never another service's credential. The token itself
        # is not recorded -- principal_id is already a truncated digest.
        set_identity(
            request,
            IdentityType.SERVICE_REMOTE_GATEWAY,
            principal.principal_id,
        )
        return principal

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
    """Register (or replace) the dispatch handler for ``event_type``.

    Idempotent: re-registering an event type replaces the prior handler
    rather than raising. The API lifespan registers handlers on every
    startup, so a second lifespan pass (test clients, a module reload)
    must not fail on an already-populated registry. Last writer wins.
    """
    if not callable(handler):
        raise TypeError(
            "dispatch handler must be callable"
        )

    with _dispatch_registry_lock:
        existing = _dispatch_registry.get(event_type)
        if existing is not None and existing is not handler:
            logger.debug(
                "Replacing dispatch handler for %s", event_type.value
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

async def _write_event_record(
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
    await _persist_event_record(
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
    store = _resolve_audit_store()
    # Derived from the store's own last-known health (its real append()/
    # verify_integrity() outcomes), never from object existence alone, and
    # never by performing a write here -- a health check must not mutate
    # the audit ledger. This is honestly a *last known* state: it does not
    # guarantee the next write will succeed, only that the last real
    # operation did.
    audit_write_available = (
        store is not None
        and store.last_known_health.value == "healthy"
    )
    audit_read_available = audit_write_available

    return RemoteHealthResponse(
        gateway=config.gateway_name,
        state=RemoteGatewayState.ONLINE,
        enabled=True,
        registered_targets=len(
            REGISTERED_TARGETS
        ),
        available_events=[
            event.value
            for event in sorted(
                REMOTE_NON_DECISION_EVENTS,
                key=lambda item: item.value,
            )
        ],
        event_buffer_max=config.max_event_records,
        event_buffer_durable=False,
        audit_write_available=audit_write_available,
        audit_read_available=audit_read_available,
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

            # Mandatory pre-action gate: in any non-local environment, a
            # live activation must not reach dispatch at all unless this
            # durably succeeds. Raises 503 and performs no dispatch, state
            # change, or replay-ledger commitment on failure -- the
            # except-block below releases the correlation-id reservation
            # exactly as it would for any other pre-dispatch failure.
            await _require_durable_pre_action_audit(
                principal=principal,
                body=body,
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

        event_record_id = await _write_event_record(
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


_DURABLE_AUDIT_REQUIRED_DETAIL = (
    "Remote Gateway audit history requires the authoritative audit store; "
    "durable retrieval is currently unavailable."
)


@router.get(
    "/audit/{correlation_id}",
    response_model=RemoteEventRecordsResponse,
)
async def get_remote_event_records(
    request: Request,
    correlation_id: str,
    authorization: str | None = Header(
        default=None,
    ),
) -> RemoteEventRecordsResponse:
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

    # Merge the process-local buffer (fast, but lost on restart) with the
    # durable store (survives restart, when configured) so a record written
    # before the current process started is still retrievable. Keyed by
    # event_record_id so a record present in both is not duplicated.
    by_id: dict[str, dict[str, Any]] = {}
    authoritative = False

    store = _resolve_audit_store()
    if store is not None:
        try:
            durable_records = await asyncio.to_thread(
                store.get_records,
                component="remote_gateway",
                correlation_id=cleaned,
            )
        except Exception:
            # A configured durable store whose read failed must never fall
            # back to the process-local buffer: that would return a normal
            # (possibly empty) 200 that looks like a complete authoritative
            # history when it is actually missing whatever the durable
            # store held. Fail the request closed instead. Never include
            # the raw exception (SQLite path, HMAC/signing details) in the
            # response -- it is logged server-side only.
            logger.warning(
                "Remote Gateway durable audit read failed for %s",
                cleaned,
                exc_info=True,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=_DURABLE_AUDIT_REQUIRED_DETAIL,
            ) from None

        authoritative = True
        for record in durable_records:
            # Only "post_dispatch" records carry the full RemoteEventRecord
            # shape (dry_run/accepted/message); "pre_dispatch" intent
            # records exist to satisfy the mandatory pre-action gate and
            # are not surfaced through this read shape.
            if record.get("phase") != "post_dispatch":
                continue
            event_record_id = record.get("event_record_id")
            if not isinstance(event_record_id, str):
                continue
            cleaned_record = {
                key: value
                for key, value in record.items()
                if key not in ("component", "phase")
            }
            by_id[event_record_id] = cleaned_record
    elif not _is_local():
        # No durable store configured at all, outside local/dev: the same
        # "authoritative audit storage is required outside local"
        # requirement _require_durable_pre_action_audit() already enforces
        # at write time applies to reads too -- a buffer-only answer here
        # could not be a complete history either.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_DURABLE_AUDIT_REQUIRED_DETAIL,
        )

    for record in EVENT_BUFFER.snapshot():
        if record.get("correlation_id") != cleaned:
            continue
        event_record_id = record.get("event_record_id")
        if isinstance(event_record_id, str):
            by_id[event_record_id] = record

    return RemoteEventRecordsResponse(
        records=[
            RemoteEventRecord(
                **record
            )
            for record in sorted(
                by_id.values(),
                key=lambda r: r.get("timestamp_unix", 0.0),
            )
            if record.get("operator_role") in visible_roles
        ],
        authoritative=authoritative,
    )


__all__ = [
    "AUDIT_LOG",
    "EVENT_BUFFER",
    "OperatorRole",
    "REGISTERED_TARGETS",
    "RemoteEventActivationRequest",
    "RemoteEventActivationResponse",
    "RemoteEventRecord",
    "RemoteEventRecordsResponse",
    "RemoteEventType",
    "RemoteGatewayConfig",
    "RemoteGatewayState",
    "clear_dispatch_handlers",
    "get_config",
    "register_dispatch_handler",
    "reload_config",
    "reset_audit_log",
    "router",
    "set_audit_store",
    "set_monitoring_manager",
]
