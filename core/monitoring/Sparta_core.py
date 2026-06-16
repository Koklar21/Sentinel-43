# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
Sentinel-43 SpartaCore
v1.1.0 — File Integrity Watchdog + Hardened Node API Router

Security improvements in this recode:

  - Thread-safe event recording via SpartaCore._record().
  - Startup no longer forces LOCKDOWN/COMPROMISED back to OPERATIONAL.
  - Route-level authentication failure tracking.
  - Temporary client blocking after repeated auth failures.
  - Request-aware auth guards for /status, /events, /auth, /register, /heartbeat.
  - JSON payload size guards for node registration and heartbeat metadata.
  - Safer MonitoringManager dispatch using wrapped daemon-thread calls.
  - Public /health endpoint no longer leaks node_signature or exact internal state
    unless explicitly enabled.
  - Maintains fail-closed node API token behavior.
  - Maintains bounded in-memory event log via deque(maxlen=...).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger("SentinelSpartaCore")


# =============================================================================
# Utilities
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False

    logger.warning("Invalid bool for %s=%r, using default %s", name, raw, default)
    return default


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = int(raw.strip())
        if not lo <= value <= hi:
            raise ValueError(f"out of [{lo},{hi}]")
        return value
    except ValueError:
        logger.warning("Invalid int for %s=%r, using default %s", name, raw, default)
        return default


def _env_float(name: str, default: float, lo: float | None = None, hi: float | None = None) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = float(raw.strip())
        if lo is not None and value < lo:
            raise ValueError(f"below minimum {lo}")
        if hi is not None and value > hi:
            raise ValueError(f"above maximum {hi}")
        return value
    except ValueError:
        logger.warning("Invalid float for %s=%r, using default %s", name, raw, default)
        return default


def _json_size_bytes(obj: Any) -> int:
    return len(json.dumps(obj, default=str, sort_keys=True).encode("utf-8"))


def _json_size_guard(obj: Any, max_bytes: int) -> None:
    try:
        size = _json_size_bytes(obj)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload.",
        ) from exc

    if size > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Node payload too large.",
        )


# =============================================================================
# State machine
# =============================================================================

class SpartaState(Enum):
    INITIALIZING = "INITIALIZING"
    OPERATIONAL = "OPERATIONAL"
    LOCKDOWN = "LOCKDOWN"
    COMPROMISED = "COMPROMISED"
    SHUTDOWN = "SHUTDOWN"


# =============================================================================
# Configuration
# =============================================================================

@dataclass(frozen=True)
class IntegrityConfig:
    """
    Immutable configuration for SpartaCore.

    Required in production:
      - S43_SPARTA_TOKEN_SECRET
      - S43_SPARTA_NODE_TOKEN

    S43_ENV=dev allows an insecure dev signing secret, but the node API still
    fails closed if S43_SPARTA_NODE_TOKEN is missing.
    """

    watched_files: MappingProxyType
    node_signature: str

    check_interval_seconds: float = 30.0
    max_event_log_entries: int = 1_000

    node_api_token: str = ""
    token_secret: str = ""
    token_ttl_seconds: float = 3_600.0

    max_auth_failures_per_window: int = 8
    auth_failure_window_seconds: float = 300.0
    auth_block_seconds: float = 900.0

    max_node_payload_bytes: int = 8_192
    public_health_detail: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.watched_files, MappingProxyType):
            object.__setattr__(
                self,
                "watched_files",
                MappingProxyType(dict(self.watched_files)),
            )

        if not self.node_signature.strip():
            raise ValueError("IntegrityConfig.node_signature must not be empty")

        if self.check_interval_seconds <= 0:
            raise ValueError("check_interval_seconds must be > 0")

        if self.max_event_log_entries < 1:
            raise ValueError("max_event_log_entries must be >= 1")

        if self.max_auth_failures_per_window < 1:
            raise ValueError("max_auth_failures_per_window must be >= 1")

        if self.auth_failure_window_seconds <= 0:
            raise ValueError("auth_failure_window_seconds must be > 0")

        if self.auth_block_seconds <= 0:
            raise ValueError("auth_block_seconds must be > 0")

        if self.max_node_payload_bytes < 1:
            raise ValueError("max_node_payload_bytes must be >= 1")

    @classmethod
    def from_env(cls, watched_files: dict[str, str]) -> "IntegrityConfig":
        token_secret = _env("S43_SPARTA_TOKEN_SECRET")
        if not token_secret:
            env = _env("S43_ENV", "production")
            if env != "dev":
                raise RuntimeError(
                    "S43_SPARTA_TOKEN_SECRET is required for tamper-resistant "
                    "session tokens outside of S43_ENV=dev."
                )

            token_secret = "dev-only-change-me"
            logger.warning(
                "S43_SPARTA_TOKEN_SECRET not set; using insecure dev default. "
                "Never use outside S43_ENV=dev."
            )

        return cls(
            watched_files=MappingProxyType(watched_files),
            node_signature=_env("S43_SPARTA_NODE_SIGNATURE", "SPARTA-CORE-SIG-v1.1"),
            check_interval_seconds=_env_float(
                "S43_SPARTA_CHECK_INTERVAL",
                30.0,
                lo=0.1,
                hi=86_400.0,
            ),
            max_event_log_entries=_env_int(
                "S43_SPARTA_MAX_EVENT_LOG",
                1_000,
                100,
                100_000,
            ),
            node_api_token=_env("S43_SPARTA_NODE_TOKEN"),
            token_secret=token_secret,
            token_ttl_seconds=_env_float(
                "S43_SPARTA_TOKEN_TTL",
                3_600.0,
                lo=30.0,
                hi=86_400.0,
            ),
            max_auth_failures_per_window=_env_int(
                "S43_SPARTA_MAX_AUTH_FAILURES",
                8,
                1,
                10_000,
            ),
            auth_failure_window_seconds=_env_float(
                "S43_SPARTA_AUTH_FAILURE_WINDOW",
                300.0,
                lo=1.0,
                hi=86_400.0,
            ),
            auth_block_seconds=_env_float(
                "S43_SPARTA_AUTH_BLOCK_SECONDS",
                900.0,
                lo=1.0,
                hi=86_400.0,
            ),
            max_node_payload_bytes=_env_int(
                "S43_SPARTA_MAX_NODE_PAYLOAD_BYTES",
                8_192,
                512,
                1_048_576,
            ),
            public_health_detail=_env_bool(
                "S43_SPARTA_PUBLIC_HEALTH_DETAIL",
                False,
            ),
        )


# =============================================================================
# Integrity events
# =============================================================================

@dataclass(frozen=True)
class IntegrityEvent:
    event_type: str
    source: str
    file_path: str
    details: dict[str, Any]
    timestamp: str = field(default_factory=utc_now)
    state_at_event: str = SpartaState.OPERATIONAL.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "source": self.source,
            "file_path": self.file_path,
            "details": self.details,
            "timestamp": self.timestamp,
            "state_at_event": self.state_at_event,
        }


# =============================================================================
# SpartaCore
# =============================================================================

class SpartaCore:
    """
    Hardened file integrity watchdog and local node API security anchor.

    Responsibilities:
      - Watch configured files by SHA-256 digest.
      - Transition to LOCKDOWN on missing/unreadable/tampered files.
      - Recover LOCKDOWN -> OPERATIONAL only after clean integrity checks.
      - Record bounded integrity/auth events.
      - Notify MonitoringManager on important security events.
      - Track bad node API clients and temporarily block repeated failures.
    """

    def __init__(
        self,
        config: IntegrityConfig,
        *,
        monitoring_manager: Optional[Any] = None,
    ) -> None:
        self._config = config
        self._monitoring_manager = monitoring_manager

        self._state = SpartaState.INITIALIZING
        self._lock = threading.RLock()
        self._event_log: deque[dict[str, Any]] = deque(maxlen=config.max_event_log_entries)

        self._tamper_count = 0
        self._total_checks = 0
        self._stop_requested = threading.Event()

        self._auth_guard_lock = threading.Lock()
        self._auth_failures: dict[str, deque[float]] = defaultdict(deque)
        self._blocked_clients: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Client/auth guard helpers
    # ------------------------------------------------------------------

    def _client_id(self, request: Request | None) -> str:
        """
        Prefer the firewall-resolved client IP if SentinelFirewall injected it.
        Fall back to Starlette's immediate peer address.
        """
        if request is None:
            return "unknown"

        state_ip = getattr(request.state, "s43_client_ip", None)
        if isinstance(state_ip, str) and state_ip.strip():
            return state_ip.strip()

        if request.client is None:
            return "unknown"

        return request.client.host or "unknown"

    def _is_client_blocked(self, client_id: str) -> bool:
        now = time.monotonic()

        with self._auth_guard_lock:
            until = self._blocked_clients.get(client_id)
            if until is None:
                return False

            if now >= until:
                self._blocked_clients.pop(client_id, None)
                return False

            return True

    def _record_auth_failure(self, client_id: str, reason: str) -> None:
        now = time.monotonic()
        cutoff = now - self._config.auth_failure_window_seconds
        blocked_until: float | None = None

        with self._auth_guard_lock:
            failures = self._auth_failures[client_id]

            while failures and failures[0] < cutoff:
                failures.popleft()

            failures.append(now)

            if len(failures) >= self._config.max_auth_failures_per_window:
                blocked_until = now + self._config.auth_block_seconds
                self._blocked_clients[client_id] = blocked_until

            self._gc_auth_guard_locked(now)

        details: dict[str, Any] = {
            "client_id": client_id,
            "reason": reason,
        }
        if blocked_until is not None:
            details["blocked_until_monotonic"] = blocked_until
            details["block_seconds"] = self._config.auth_block_seconds

        event = IntegrityEvent(
            event_type="AuthFailure",
            source="NodeAPI",
            file_path="",
            details=details,
            state_at_event=self.get_status()["state"],
        )
        self._record(event)
        self._emit_to_monitoring("AuthFailure", client_id)

    def _gc_auth_guard_locked(self, now: float) -> None:
        """
        Called under _auth_guard_lock. Prevents unbounded growth if many unique
        troll IPs each hit once and disappear into the internet swamp.
        """
        cutoff = now - self._config.auth_failure_window_seconds

        stale_failure_clients = [
            client_id
            for client_id, failures in self._auth_failures.items()
            if not failures or failures[-1] < cutoff
        ]
        for client_id in stale_failure_clients:
            self._auth_failures.pop(client_id, None)

        expired_blocks = [
            client_id
            for client_id, until in self._blocked_clients.items()
            if now >= until
        ]
        for client_id in expired_blocks:
            self._blocked_clients.pop(client_id, None)

    def require_node_auth(
        self,
        request: Request,
        authorization: str | None,
    ) -> None:
        """
        Route-level guard for node API endpoints.

        This wraps _require_node_token() with:
          - client identification
          - temporary client blocking
          - auth failure event logging
          - monitoring notification
        """
        client_id = self._client_id(request)

        if self._is_client_blocked(client_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed authentication attempts.",
            )

        try:
            _require_node_token(authorization, self._config)
        except HTTPException as exc:
            reason = "missing_or_invalid_bearer"
            if exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
                reason = "node_api_token_not_configured"
            self._record_auth_failure(client_id, reason)
            raise

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _calculate_sha256(self, file_path: str) -> str | None:
        """
        Hash a file without a separate exists() check, avoiding a TOCTOU window.
        Returns None on any read failure.
        """
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65_536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except OSError as exc:
            logger.warning(
                "Integrity check: cannot read file path=%s error=%s",
                file_path,
                exc,
            )
            return None

    def _record(self, event: IntegrityEvent) -> None:
        """
        Thread-safe bounded event record.
        """
        event_dict = event.to_dict()

        with self._lock:
            self._event_log.append(event_dict)

        logger.warning(
            "INTEGRITY EVENT type=%s file=%s state=%s",
            event.event_type,
            event.file_path,
            event.state_at_event,
        )

    def _safe_monitoring_dispatch(self, payload: dict[str, Any]) -> None:
        """
        Notify MonitoringManager without blocking the caller.

        The try/except must live inside the worker thread, not merely around
        Thread.start(), because exceptions raised inside the thread are not
        caught by the outer call site. Yes, Python made that a little foot-gun.
        """
        if self._monitoring_manager is None:
            return

        def _worker() -> None:
            try:
                self._monitoring_manager.analyze_event(payload)
            except Exception as exc:
                logger.debug("MonitoringManager notification failed: %s", exc)

        try:
            threading.Thread(target=_worker, daemon=True).start()
        except Exception as exc:
            logger.debug("MonitoringManager thread start failed: %s", exc)

    def _emit_to_monitoring(self, event_type: str, subject: str) -> None:
        """
        Route security-relevant events to MonitoringManager.

        event_type:
          - TamperDetected
          - FileMissing
          - AuthFailure
          - LockdownTriggered
        """
        if self._monitoring_manager is None:
            return

        if event_type == "TamperDetected":
            payload: dict[str, Any] = {
                "kind": "log",
                "integrity_status": "tampered",
                "audit_write_failed": False,
                "file_path": subject,
                "source": "SpartaCore",
                "event_category": "tamper_detected",
                "timestamp": utc_now(),
            }
        elif event_type == "AuthFailure":
            payload = {
                "kind": "security",
                "auth_failure": True,
                "source_ip": subject,
                "source": "SpartaCore",
                "event_category": "node_api_auth_failure",
                "timestamp": utc_now(),
            }
        elif event_type == "LockdownTriggered":
            payload = {
                "kind": "security",
                "secrets_exposed": True,
                "source": "SpartaCore",
                "event_category": "lockdown_triggered",
                "timestamp": utc_now(),
            }
        else:
            payload = {
                "kind": "security",
                "unsigned_artifact": True,
                "file_path": subject,
                "source": "SpartaCore",
                "event_category": "file_missing",
                "timestamp": utc_now(),
            }

        self._safe_monitoring_dispatch(payload)

    # ------------------------------------------------------------------
    # Integrity check
    # ------------------------------------------------------------------

    def check_integrity(self) -> bool:
        """
        Hash every watched file. Returns True if all pass.

        Records events and updates state for any failures. File hashing happens
        outside the lock so slow disk reads do not freeze status calls.
        """
        with self._lock:
            current_state = self._state
            self._total_checks += 1

        all_ok = True

        for file_path, expected_hash in self._config.watched_files.items():
            actual_hash = self._calculate_sha256(file_path)

            if actual_hash is None:
                event = IntegrityEvent(
                    event_type="FileMissing",
                    source="IntegrityCheck",
                    file_path=file_path,
                    details={"expected_hash": expected_hash},
                    state_at_event=current_state.value,
                )
                self._record(event)
                self._emit_to_monitoring("FileMissing", file_path)
                all_ok = False
                continue

            expected_normalized = expected_hash.strip().lower()

            if not secrets.compare_digest(actual_hash, expected_normalized):
                event = IntegrityEvent(
                    event_type="TamperDetected",
                    source="IntegrityCheck",
                    file_path=file_path,
                    details={
                        "expected_hash": expected_hash,
                        "actual_hash": actual_hash,
                    },
                    state_at_event=current_state.value,
                )
                self._record(event)
                self._emit_to_monitoring("TamperDetected", file_path)
                all_ok = False

        return all_ok

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def _transition(self, new_state: SpartaState) -> None:
        with self._lock:
            old = self._state
            if old != new_state:
                logger.info(
                    "SpartaCore state transition: %s -> %s",
                    old.value,
                    new_state.value,
                )
                self._state = new_state

    def _mark_operational_if_initializing(self) -> None:
        """
        Startup-safe transition.

        Does not turn LOCKDOWN/COMPROMISED back into OPERATIONAL just because
        run() started. Security state should not be erased by a coroutine entry.
        That would be stupid, and yet disturbingly common.
        """
        with self._lock:
            if self._state == SpartaState.INITIALIZING:
                logger.info(
                    "SpartaCore state transition: %s -> %s",
                    self._state.value,
                    SpartaState.OPERATIONAL.value,
                )
                self._state = SpartaState.OPERATIONAL

    def _initiate_lockdown(self) -> None:
        logger.critical(
            "SPARTA LOCKDOWN: integrity violation detected. "
            "Monitoring pipeline notified. Awaiting recovery or operator action."
        )

        event = IntegrityEvent(
            event_type="LockdownTriggered",
            source="SpartaCore",
            file_path="",
            details={"reason": "integrity_violation"},
            state_at_event=self.get_status()["state"],
        )
        self._record(event)
        self._emit_to_monitoring("LockdownTriggered", "SpartaCore")

    # ------------------------------------------------------------------
    # Main watchdog loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Main watchdog loop.

        Behavior:
          - INITIALIZING -> OPERATIONAL only on first entry.
          - LOCKDOWN -> OPERATIONAL only after a clean check.
          - SHUTDOWN exits cleanly.
        """
        self._mark_operational_if_initializing()
        interval = self._config.check_interval_seconds

        while not self._stop_requested.is_set():
            ok = self.check_integrity()

            with self._lock:
                current = self._state

            if not ok and current == SpartaState.OPERATIONAL:
                with self._lock:
                    self._tamper_count += 1
                self._transition(SpartaState.LOCKDOWN)
                self._initiate_lockdown()

            elif ok and current == SpartaState.LOCKDOWN:
                logger.info(
                    "All integrity checks passed -- transitioning LOCKDOWN -> OPERATIONAL"
                )
                self._transition(SpartaState.OPERATIONAL)

            deadline = time.monotonic() + interval
            while not self._stop_requested.is_set() and time.monotonic() < deadline:
                await asyncio.sleep(min(1.0, deadline - time.monotonic()))

        self._transition(SpartaState.SHUTDOWN)
        logger.info("SpartaCore watchdog stopped cleanly.")

    def stop(self) -> None:
        """Request watchdog shutdown. Safe to call from any thread."""
        self._stop_requested.set()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            state = self._state.value
            watched_file_count = len(self._config.watched_files)
            total_checks = self._total_checks
            tamper_count = self._tamper_count
            event_log_entries = len(self._event_log)

        with self._auth_guard_lock:
            blocked_clients = len(self._blocked_clients)
            tracked_auth_clients = len(self._auth_failures)

        return {
            "state": state,
            "node_signature": self._config.node_signature,
            "watched_file_count": watched_file_count,
            "total_checks": total_checks,
            "tamper_count": tamper_count,
            "event_log_entries": event_log_entries,
            "blocked_clients": blocked_clients,
            "tracked_auth_clients": tracked_auth_clients,
            "timestamp": utc_now(),
        }

    def get_public_health(self) -> dict[str, Any]:
        status_obj = self.get_status()
        state_value = status_obj["state"]

        ok = state_value == SpartaState.OPERATIONAL.value

        if self._config.public_health_detail:
            return {
                "status": "ok" if ok else state_value.lower(),
                "state": state_value,
                "node_signature": self._config.node_signature,
                "timestamp": utc_now(),
            }

        return {
            "status": "ok" if ok else "degraded",
            "timestamp": utc_now(),
        }

    def get_event_log(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        with self._lock:
            return list(self._event_log)[-limit:]


# =============================================================================
# Session token helpers
# =============================================================================

def _sign_token(node_id: str, secret: str, ttl: float) -> str:
    """
    Generate a time-limited HMAC-SHA256 session token.

    Format:
      <node_id>:<expiry_unix>:<hex_signature>
    """
    expiry = int(time.time() + ttl)
    payload = f"{node_id}:{expiry}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_token(token: str, secret: str) -> str | None:
    """
    Verify a session token. Returns node_id on success, None on failure.
    """
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return None

        node_id, expiry_str, provided_sig = parts
        expiry = int(expiry_str)

        if time.time() > expiry:
            return None

        payload = f"{node_id}:{expiry_str}"
        expected_sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()

        if not secrets.compare_digest(provided_sig, expected_sig):
            return None

        return node_id
    except Exception:
        return None


def _require_node_token(authorization: str | None, config: IntegrityConfig) -> None:
    """
    Validate bearer token against S43_SPARTA_NODE_TOKEN.

    Fails closed:
      - no configured token = 503
      - missing/malformed header = 401
      - wrong token = 401
    """
    if not config.node_api_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Node API token not configured. "
                "Set S43_SPARTA_NODE_TOKEN to enable authenticated node endpoints."
            ),
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
        )

    token = authorization.removeprefix("Bearer ").strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token.",
        )

    if not secrets.compare_digest(token, config.node_api_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid node API token.",
        )


# =============================================================================
# Pydantic request models
# =============================================================================

class NodeAuthRequest(BaseModel):
    node_id: str = Field(..., min_length=2, max_length=120)
    credential: str = Field(..., min_length=8, max_length=512)


class NodeRegisterRequest(BaseModel):
    node_id: str = Field(..., min_length=2, max_length=120)
    node_type: str = Field(default="generic", min_length=1, max_length=80)
    version: str = Field(default="unknown", min_length=1, max_length=80)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NodeHeartbeatRequest(BaseModel):
    node_id: str = Field(..., min_length=2, max_length=120)
    status_value: str = Field(default="online", alias="status", min_length=1, max_length=80)
    metrics: dict[str, Any] = Field(default_factory=dict)

    class Config:
        populate_by_name = True


# =============================================================================
# FastAPI node API router
# =============================================================================

def create_node_router(
    sparta: SpartaCore,
    *,
    prefix: str = "/node",
) -> APIRouter:
    """
    Create and return an APIRouter for node management and authentication.

    Mount on the main S43 FastAPI app:
        app.include_router(create_node_router(sparta_instance))
    """
    router = APIRouter(prefix=prefix, tags=["node"])
    cfg = sparta._config

    def _require_route_auth(request: Request, authorization: str | None) -> None:
        sparta.require_node_auth(request, authorization)

    @router.get("/health")
    def node_health() -> dict[str, Any]:
        """
        Public health check.

        By default, intentionally does not expose node_signature or exact state.
        Set S43_SPARTA_PUBLIC_HEALTH_DETAIL=true only for trusted/private
        deployments.
        """
        return sparta.get_public_health()

    @router.get("/status")
    def node_status(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Full node status. Requires bearer token."""
        _require_route_auth(request, authorization)
        return sparta.get_status()

    @router.get("/events")
    def node_events(
        request: Request,
        authorization: str | None = Header(default=None),
        limit: int = 50,
    ) -> dict[str, Any]:
        """Recent integrity/security events. Requires bearer token."""
        _require_route_auth(request, authorization)
        limit = max(1, min(limit, 500))
        events = sparta.get_event_log(limit)
        return {
            "count": len(events),
            "limit": limit,
            "events": events,
        }

    @router.post("/auth", status_code=status.HTTP_200_OK)
    def authenticate(
        request: Request,
        body: NodeAuthRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """
        Authenticate a node and issue a time-limited HMAC session token.

        Requires:
          - valid Authorization: Bearer <S43_SPARTA_NODE_TOKEN>
          - body.credential matching S43_SPARTA_NODE_TOKEN

        Repeated failures are locally tracked and temporarily blocked.
        """
        _require_route_auth(request, authorization)

        client_id = sparta._client_id(request)

        if not secrets.compare_digest(body.credential, cfg.node_api_token):
            sparta._record_auth_failure(client_id, "invalid_body_credential")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid node credential.",
            )

        if not cfg.token_secret:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Token signing not configured on this node.",
            )

        session_token = _sign_token(
            body.node_id,
            cfg.token_secret,
            cfg.token_ttl_seconds,
        )

        return {
            "message": "Authentication successful.",
            "node_id": body.node_id,
            "token": session_token,
            "expires_in_seconds": int(cfg.token_ttl_seconds),
            "issued_at": utc_now(),
        }

    @router.post("/register", status_code=status.HTTP_201_CREATED)
    def register_node(
        request: Request,
        body: NodeRegisterRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """
        Register a node. Requires bearer token.

        In a full S43 deployment this can delegate into WatchtowerNode or
        governance. Here SpartaCore records the registration as an integrity
        event and applies payload-size guards.
        """
        _require_route_auth(request, authorization)

        _json_size_guard(body.capabilities, cfg.max_node_payload_bytes)
        _json_size_guard(body.metadata, cfg.max_node_payload_bytes)

        event = IntegrityEvent(
            event_type="NodeRegistered",
            source="NodeAPI",
            file_path="",
            details={
                "node_id": body.node_id,
                "node_type": body.node_type,
                "version": body.version,
                "capabilities": body.capabilities,
                "metadata_size_bytes": _json_size_bytes(body.metadata),
            },
            state_at_event=sparta.get_status()["state"],
        )
        sparta._record(event)

        return {
            "status": "registered",
            "node_id": body.node_id,
            "node_type": body.node_type,
            "version": body.version,
            "registered_at": utc_now(),
        }

    @router.post("/heartbeat")
    def node_heartbeat(
        request: Request,
        body: NodeHeartbeatRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """
        Node heartbeat / status update. Requires bearer token.

        Metrics are accepted only within configured JSON size limits.
        """
        _require_route_auth(request, authorization)
        _json_size_guard(body.metrics, cfg.max_node_payload_bytes)

        event = IntegrityEvent(
            event_type="NodeHeartbeat",
            source="NodeAPI",
            file_path="",
            details={
                "node_id": body.node_id,
                "status": body.status_value,
                "metrics_size_bytes": _json_size_bytes(body.metrics),
            },
            state_at_event=sparta.get_status()["state"],
        )
        sparta._record(event)

        return {
            "status": "acknowledged",
            "node_id": body.node_id,
            "received_status": body.status_value,
            "timestamp": utc_now(),
        }

    return router


# =============================================================================
# Signal handling
# =============================================================================

def setup_signal_handlers(sparta: SpartaCore, loop: asyncio.AbstractEventLoop) -> None:
    """
    Register graceful shutdown handlers.

    Uses loop.add_signal_handler where supported, with a Windows-compatible
    fallback.
    """
    def _handle() -> None:
        logger.warning("Shutdown signal received -- stopping SpartaCore watchdog.")
        sparta.stop()
        loop.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda _s, _f: _handle())


# =============================================================================
# Factory / Entry point
# =============================================================================

def build_sparta_core(
    watched_files: dict[str, str],
    *,
    monitoring_manager: Optional[Any] = None,
) -> SpartaCore:
    """
    Build SpartaCore from S43_SPARTA_* environment configuration.
    """
    config = IntegrityConfig.from_env(watched_files)
    return SpartaCore(config, monitoring_manager=monitoring_manager)


if __name__ == "__main__":
    WATCHED_FILES = {
        "sparta_core.py": os.getenv("S43_SPARTA_HASH_SPARTA_CORE", "PLACEHOLDER_HASH"),
        "security_layer.py": os.getenv("S43_SPARTA_HASH_SECURITY_LAYER", "PLACEHOLDER_HASH"),
    }

    sparta = build_sparta_core(WATCHED_FILES)

    async def _main() -> None:
        loop = asyncio.get_running_loop()
        setup_signal_handlers(sparta, loop)
        await sparta.run()

    asyncio.run(_main())
```
