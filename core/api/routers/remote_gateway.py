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
#   - Best-effort report security-relevant events to Watchtower
#   - Route security events through MonitoringManager for threat scoring
#
# Changelog
# ---------
# v2 (security hardening):
#   - SENTINEL_REMOTE_OWNER_TOKEN (and friends) no longer optional-with-warning.
#     If no operator tokens are configured at all, the gateway returns 503
#     for every authenticated route instead of running open.
#   - operator_role is resolved server-side from the bearer token, not
#     trusted from the request body. A mismatched body.operator_role is a
#     403 (and is reported to Watchtower as a possible privilege-escalation
#     signal - see v3 below).
#   - Non-dry-run event activation now requires SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED;
#     otherwise it returns 501 instead of falsely reporting success.
#   - Added a simple per-client rate limit on authentication failures.
#   - ROTATE_REMOTE_TOKEN is now reachable (added to local-sentinel's
#     allowed_events) since OWNER is the only role permitted to use it.
#   - Config is loaded lazily via get_config()/reload_config() instead of
#     a module-level singleton computed at import time.
#
# v3 (Watchtower integration):
#   - Authentication failures, rate-limit (429) hits, operator-role
#     mismatches, and event-activation audit records are now reported,
#     best-effort, to Watchtower's /analyze endpoint
#     (SENTINEL_WATCHTOWER_URL). Reporting failures never block or fail
#     the gateway request.
#   - Role mismatches are reported with privilege_escalation=True, which
#     Watchtower's SECURITY_BASELINE tower treats as a CRITICAL alert.
#
# v4 (correctness hardening):
#   - Fix #1: AUDIT_LOG no longer calls get_config() at import time.
#     _AuditLog proxy lazy-initializes on first use, keeping maxlen in
#     sync with reload_config().
#   - Fix #2: _payload_depth rewritten as iterative stack traversal --
#     deeply nested payloads no longer cause RecursionError DoS.
#   - Fix #3: _dispatch_remote_event raises NotImplementedError so the
#     caller cannot claim success before a real broker is wired up.
#   - Fix #4+5: _AUTH_FAILURES protected by a lock; check+record are
#     atomic; periodic GC prevents unbounded dict growth under IP churn.
#   - Fix #6: audit endpoint scoped by role -- AUDITOR sees only auditor
#     records, ADMIN sees admin+auditor, OWNER sees all.
#   - Fix #7: reason max_length enforced via validator that reads live
#     config, not a hardcoded Field() constant that diverges silently.
#   - Fix #8: /audit/{correlation_id} path param validated for length
#     and control characters.
#   - Fix #9: set_monitoring_manager() wires in MonitoringManager so
#     gateway security events populate the SentinelWindowStore and get
#     threat-scored alongside events from other entry points.
#   - Fix #10: APPROVE_DECISION / VETO_DECISION event types added for
#     mobile companion app HUMAN_GATED approve/veto workflow.
#   - Fix #11: removed dead double-default for gateway_name.
#   - Fix #12: auth_failure_window_seconds uses _env_float() directly.
#   - Fix #13: redundant get_remote_gateway_router() removed.
# =============================================================================

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any
from uuid import uuid4

import httpx
from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator


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


def _env_float(name: str, default: float) -> float:
    value = _env(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        logger.warning("Invalid float for %s=%r; using default %s", name, value, default)
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
    # Fix #10: human-gated governance decisions for the mobile companion
    # app HUMAN_GATED approve/veto workflow. Restricted to OWNER and ADMIN
    # -- AUDITOR is read-only and cannot approve or veto decisions.
    # Payload must include "decision_id" (the pending governance decision
    # to act on). See RemoteEventActivationRequest.validate_governance_payload.
    APPROVE_DECISION = "approve_decision"
    VETO_DECISION = "veto_decision"


ROLE_EVENT_POLICY: dict[OperatorRole, set[RemoteEventType]] = {
    OperatorRole.OWNER: {
        RemoteEventType.FORCE_HEALTH_CHECK,
        RemoteEventType.FORCE_SYNC,
        RemoteEventType.ROTATE_REMOTE_TOKEN,
        RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
        RemoteEventType.APPROVE_DECISION,
        RemoteEventType.VETO_DECISION,
    },
    OperatorRole.ADMIN: {
        RemoteEventType.FORCE_HEALTH_CHECK,
        RemoteEventType.FORCE_SYNC,
        RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
        RemoteEventType.APPROVE_DECISION,
        RemoteEventType.VETO_DECISION,
    },
    OperatorRole.AUDITOR: {
        RemoteEventType.REQUEST_DIAGNOSTIC_SNAPSHOT,
    },
}

# Audit scoping: which operator_role values each role can see in the audit log.
# OWNER sees all; ADMIN sees admin+auditor records; AUDITOR sees only their own.
_AUDIT_VISIBLE_ROLES: dict[OperatorRole, set[str]] = {
    OperatorRole.OWNER: {"owner", "admin", "auditor"},
    OperatorRole.ADMIN: {"admin", "auditor"},
    OperatorRole.AUDITOR: {"auditor"},
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
            RemoteEventType.ROTATE_REMOTE_TOKEN,
            RemoteEventType.APPROVE_DECISION,
            RemoteEventType.VETO_DECISION,
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
    operator_tokens: dict[str, OperatorRole] = field(default_factory=dict)
    live_dispatch_enabled: bool = False
    max_payload_keys: int = 50
    max_payload_depth: int = 6
    max_payload_bytes: int = 65_536
    max_reason_length: int = 500
    max_audit_records: int = 10_000
    auth_failure_limit: int = 5
    auth_failure_window_seconds: float = 60.0
    watchtower_url: str | None = None
    watchtower_timeout_seconds: float = 1.5


def _build_config() -> RemoteGatewayConfig:
    operator_tokens: dict[str, OperatorRole] = {}

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
        # Fix #11: removed dead double-default; _env() already returns the
        # default when the var is missing or blank.
        gateway_name=_env("SENTINEL_REMOTE_GATEWAY_NAME", "sentinel-43-remote-gateway"),
        operator_tokens=operator_tokens,
        live_dispatch_enabled=_env_bool("SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED", False),
        max_payload_keys=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_KEYS", 50),
        max_payload_depth=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_DEPTH", 6),
        max_payload_bytes=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_BYTES", 65_536),
        max_reason_length=_env_int("SENTINEL_REMOTE_MAX_REASON_LENGTH", 500),
        max_audit_records=_env_int("SENTINEL_REMOTE_MAX_AUDIT_RECORDS", 10_000),
        auth_failure_limit=_env_int("SENTINEL_REMOTE_AUTH_FAILURE_LIMIT", 5),
        # Fix #12: was float(_env_int(...)), silently truncating fractional
        # seconds before casting to float. Use _env_float() directly.
        auth_failure_window_seconds=_env_float("SENTINEL_REMOTE_AUTH_FAILURE_WINDOW_SECONDS", 60.0),
        watchtower_url=_env("SENTINEL_WATCHTOWER_URL"),
        watchtower_timeout_seconds=_env_float("SENTINEL_WATCHTOWER_TIMEOUT_SECONDS", 1.5),
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
    cfg = get_config()
    # Keep the audit log's maxlen in sync with the reloaded config.
    AUDIT_LOG.reset()
    return cfg


# =============================================================================
# Audit log
# =============================================================================

class _AuditLog:
    """
    Fix #1: the original code had:

        AUDIT_LOG: deque[...] = deque(maxlen=get_config().max_audit_records)

    This called get_config() at module import time, defeating the lazy-load
    design the changelog describes (env vars may not be injected yet in
    Docker / test contexts). It also meant reload_config() didn't update
    the deque's maxlen -- the live config and AUDIT_LOG could silently
    diverge unless reset_audit_log() was also called, but nothing enforced
    that pairing.

    This proxy lazily initializes the inner deque on first access and
    re-reads config.max_audit_records in reset(), keeping them in sync
    automatically when reload_config() calls AUDIT_LOG.reset().
    """

    def __init__(self) -> None:
        self._deque: deque[dict[str, Any]] | None = None
        self._lock = threading.Lock()

    def _ensure(self) -> deque[dict[str, Any]]:
        if self._deque is None:
            with self._lock:
                if self._deque is None:
                    self._deque = deque(maxlen=get_config().max_audit_records)
        return self._deque

    def append(self, record: dict[str, Any]) -> None:
        self._ensure().append(record)

    def reset(self) -> None:
        with self._lock:
            self._deque = deque(maxlen=get_config().max_audit_records)

    def __iter__(self):
        return iter(self._ensure())

    def __len__(self) -> int:
        return len(self._ensure())


AUDIT_LOG = _AuditLog()


def reset_audit_log() -> None:
    """Reset the audit log using the current config's max_audit_records. For tests."""
    AUDIT_LOG.reset()


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
    # Fix #7: previously Field(..., max_length=500) hardcoded 500 independently
    # from config.max_reason_length. If SENTINEL_REMOTE_MAX_REASON_LENGTH was
    # changed, the Pydantic Field would still enforce 500 while the config said
    # something else. Max is now enforced in the validator below which reads
    # the live config value.
    reason: str = Field(..., min_length=10)
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
        # Fix #7: read max from live config, not from a hardcoded constant.
        max_len = get_config().max_reason_length
        if len(cleaned) > max_len:
            raise ValueError(f"reason must be at most {max_len} characters")
        if any(ord(char) < 32 for char in cleaned):
            raise ValueError("control characters are not allowed")
        return cleaned

    @model_validator(mode="after")
    def validate_governance_payload(self) -> "RemoteEventActivationRequest":
        """
        Fix #10: APPROVE_DECISION and VETO_DECISION require a non-empty
        'decision_id' in the payload identifying the pending governance
        decision to act on. Validated here rather than in a field_validator
        so we have access to both event_type and payload simultaneously.
        """
        governance_events = {RemoteEventType.APPROVE_DECISION, RemoteEventType.VETO_DECISION}
        if self.event_type in governance_events:
            decision_id = self.payload.get("decision_id", "")
            if not decision_id or not str(decision_id).strip():
                raise ValueError(
                    f"{self.event_type.value} requires a non-empty 'decision_id' "
                    "in the payload identifying the pending governance decision."
                )
        return self


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
# Monitoring pipeline integration (Fix #9)
# =============================================================================

# Optional MonitoringManager injected at app startup via set_monitoring_manager().
# When set, gateway security events are routed through the monitoring pipeline
# (including SentinelWindowStore / threat scoring) rather than being siloed in
# a separate raw httpx POST to Watchtower.
_monitoring_manager: Any | None = None


def set_monitoring_manager(manager: Any) -> None:
    """
    Wire a MonitoringManager instance into the gateway.

    When set, security events (auth failures, rate-limit hits, role mismatches,
    event activations) are also routed through MonitoringManager.analyze_event()
    so they populate the SentinelWindowStore rolling buffer and contribute to
    threat scoring alongside events from other entry points.

    Call this from the application's lifespan startup handler, after the
    MonitoringManager itself has been started:

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            mm = MonitoringManager(config, window_store=ws, threat_detector=td)
            mm.start()
            remote_gateway.set_monitoring_manager(mm)
            yield
            mm.stop()
    """
    global _monitoring_manager
    _monitoring_manager = manager
    logger.info(
        "RemoteGateway: MonitoringManager wired in -- security events will "
        "now route through the monitoring pipeline."
    )


async def _notify_monitoring_pipeline(
    event_dict: dict[str, Any],
    *,
    source_ip: str | None,
) -> None:
    """
    Route a security event through the monitoring pipeline.

    Runs MonitoringManager.analyze_event() in a thread-pool executor to
    avoid blocking the event loop with its synchronous urllib calls.
    Best-effort: any exception is logged and swallowed.
    """
    if _monitoring_manager is None:
        return

    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: _monitoring_manager.analyze_event(event_dict, source_ip=source_ip),
        )
    except Exception as exc:
        logger.debug(
            "MonitoringManager notification failed for gateway security event: %s", exc
        )


# =============================================================================
# Watchtower reporting (best-effort, never blocks the request)
# =============================================================================

async def _report_to_watchtower(
    event: dict[str, Any],
    *,
    source_ip: str | None = None,
) -> None:
    """
    Best-effort POST of a security event to Watchtower and optionally
    through the monitoring pipeline for window store / threat scoring.

    Failures are logged and swallowed -- monitoring must never become a
    hard dependency for the gateway's own availability.
    """
    config = get_config()

    # Route through the monitoring pipeline first so the event reaches
    # the window store (and accumulates toward threat scores) regardless
    # of whether the raw Watchtower POST succeeds.
    await _notify_monitoring_pipeline(event, source_ip=source_ip)

    if not config.watchtower_url:
        return

    url = config.watchtower_url.rstrip("/") + "/analyze"

    try:
        async with httpx.AsyncClient(timeout=config.watchtower_timeout_seconds) as client:
            response = await client.post(url, json={"event": event})
            if response.status_code >= 400:
                logger.warning(
                    "Watchtower /analyze returned %s for event kind=%s",
                    response.status_code,
                    event.get("kind"),
                )
    except httpx.HTTPError as exc:
        logger.warning("Failed to report event to Watchtower (%s): %s", url, exc)


# =============================================================================
# Authentication / rate limiting
# =============================================================================

# Fix #4+5: protect _AUTH_FAILURES with a lock so check and record are
# atomic. Add periodic GC to prevent unbounded growth under IP churn.
_AUTH_FAILURES: dict[str, deque[float]] = {}
_AUTH_FAILURES_LOCK = threading.Lock()
_auth_gc_counter: int = 0
_AUTH_GC_EVERY: int = 50  # run GC pass every N total calls


def _client_id(request: Request) -> str:
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def _check_auth_rate_limit(client_id: str) -> None:
    """
    Thread-safe rate limit check. Raises HTTP 429 if the client has
    exceeded the configured auth failure limit within the window.
    """
    config = get_config()
    now = time.monotonic()
    cutoff = now - config.auth_failure_window_seconds
    global _auth_gc_counter

    with _AUTH_FAILURES_LOCK:
        window = _AUTH_FAILURES.get(client_id, deque())

        # Prune expired entries from this client's window
        while window and window[0] < cutoff:
            window.popleft()

        over_limit = len(window) >= config.auth_failure_limit

        # GC: remove stale client entries periodically to prevent
        # unbounded dict growth when many distinct IPs fail auth once
        # and never return.
        _auth_gc_counter += 1
        if _auth_gc_counter >= _AUTH_GC_EVERY:
            _auth_gc_counter = 0
            stale = [
                cid for cid, w in _AUTH_FAILURES.items()
                if not w or (w and w[-1] < cutoff)
            ]
            for cid in stale:
                _AUTH_FAILURES.pop(cid, None)

    if over_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed authentication attempts. Try again later.",
        )


def _record_auth_failure(client_id: str) -> None:
    """Thread-safe auth failure recording."""
    with _AUTH_FAILURES_LOCK:
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


async def _authenticate(request: Request, authorization: str | None) -> OperatorRole:
    client_id = _client_id(request)

    try:
        _check_auth_rate_limit(client_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            await _report_to_watchtower(
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
        return _resolve_operator_role(authorization)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _record_auth_failure(client_id)
            await _report_to_watchtower(
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
    await _authenticate(request, authorization)

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
    client_id = _client_id(request)

    _require_gateway_enabled()
    effective_role = await _authenticate(request, authorization)

    if body.operator_role != effective_role:
        await _report_to_watchtower(
            {
                "kind": "security",
                "event_category": "remote_gateway_role_mismatch",
                "gateway": config.gateway_name,
                "client_id": client_id,
                "operator_id": body.operator_id,
                "claimed_role": body.operator_role.value,
                "token_role": effective_role.value,
                "correlation_id": body.correlation_id,
                # Watchtower's SECURITY_BASELINE tower treats this as CRITICAL.
                "privilege_escalation": True,
            },
            source_ip=client_id,
        )
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
        # Fix #3: _dispatch_remote_event raises NotImplementedError until a
        # real broker is wired in. Catch it here so we return 501 rather
        # than letting a placeholder log line produce a false ok=True audit
        # record and a success response to the operator.
        try:
            await _dispatch_remote_event(body)
        except NotImplementedError as exc:
            logger.error(
                "Live dispatch enabled but _dispatch_remote_event is not "
                "implemented: %s -- returning 501 to prevent false success report.",
                exc,
            )
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail=(
                    "Live dispatch is enabled but the event broker integration "
                    "is not yet implemented on this gateway instance. "
                    "Contact the system administrator."
                ),
            ) from exc
        message = "Remote event accepted and activated."

    audit_id = _write_audit_record(
        body=body,
        accepted=True,
        message=message,
    )

    await _report_to_watchtower(
        {
            "kind": "log",
            "event_category": "remote_gateway_event_activation",
            "gateway": config.gateway_name,
            "audit_id": audit_id,
            "operator_id": body.operator_id,
            "operator_role": body.operator_role.value,
            "target_id": body.target_id,
            "event_type": body.event_type.value,
            "correlation_id": body.correlation_id,
            "dry_run": body.dry_run,
        },
        source_ip=client_id,
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
    # Fix #6: resolve the authenticated role for audit scoping below.
    effective_role = await _authenticate(request, authorization)

    # Fix #8: path param was only .strip()'d, with no length or character
    # validation -- unlike correlation_id in the request body which has
    # min/max length and control-character checks. Enforce the same rules.
    cleaned = correlation_id.strip()
    if not cleaned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="correlation_id cannot be blank.")
    if len(cleaned) > 160:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="correlation_id exceeds maximum length.")
    if any(ord(c) < 32 for c in cleaned):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="correlation_id contains control characters.")

    # Fix #6: scope results to what this role is permitted to see.
    # OWNER sees all records; ADMIN sees admin+auditor; AUDITOR sees only
    # their own tier. This prevents lower-privilege roles from reading
    # audit records for operations above their level.
    visible_roles = _AUDIT_VISIBLE_ROLES.get(effective_role, set())

    return [
        RemoteAuditRecord(**record)
        for record in AUDIT_LOG
        if record["correlation_id"] == cleaned
        and record.get("operator_role") in visible_roles
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

    depth = _payload_depth(payload, max_allowed=config.max_payload_depth)

    if depth > config.max_payload_depth:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds configured nesting depth.",
        )


def _payload_depth(value: Any, *, max_allowed: int) -> int:
    """
    Fix #2: the original implementation was recursive. A malicious payload
    nested ~1000 levels deep would hit Python's call stack limit and raise
    RecursionError *before* the depth check ran, producing an unhandled 500
    from a security validation boundary.

    Rewritten as an iterative stack traversal that short-circuits as soon
    as max_allowed+1 is exceeded, so deeply nested payloads are rejected
    cheaply without ever triggering RecursionError.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    max_seen = 0

    while stack:
        node, depth = stack.pop()
        if depth > max_allowed:
            # Already over limit -- return immediately without scanning deeper.
            return depth
        if depth > max_seen:
            max_seen = depth
        if isinstance(node, dict):
            for child in node.values():
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            for child in node:
                stack.append((child, depth + 1))

    return max_seen


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
    Fix #3: the original implementation only logged and returned, but the
    caller then wrote accepted=True to the audit log and returned ok=True
    to the operator -- falsely claiming the event was dispatched when
    nothing actually happened.

    This now raises NotImplementedError so the caller must handle it and
    return 501 rather than a false success. Wire in a real event broker
    (Redis Streams, Kafka, NATS, RabbitMQ, or internal Watchtower intake)
    and replace this stub before enabling SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED.
    """
    raise NotImplementedError(
        "Live event dispatch is not yet implemented on this gateway instance. "
        "Integrate an event broker and replace _dispatch_remote_event() before "
        "setting SENTINEL_REMOTE_LIVE_DISPATCH_ENABLED=true."
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
