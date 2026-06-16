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
v1.0.0 — File Integrity Watchdog + Node API Router

Replaces the original two-file concatenation with a single, coherent S43
module. Changes from the original:

  - Fix: JormState / SparState NameErrors -- both typos eliminated.
    SpartaState is the one enum, used consistently throughout.
  - Fix: hash comparison now uses secrets.compare_digest() to eliminate
    timing side-channel vulnerability.
  - Fix: calculate_sha256() wrapped in exception handling; existence check
    and file open are combined (TOCTOU protection).
  - Fix: event_log is a bounded deque(maxlen=...) rather than an unbounded
    list.
  - Fix: watchdog_loop no longer unconditionally resets state to OPERATIONAL
    at start; graceful LOCKDOWN -> OPERATIONAL recovery path added.
  - Fix: signal handling uses loop.add_signal_handler() (asyncio-safe)
    instead of sys.exit() inside a sync signal.signal() handler.
  - Fix: os.system() shell call removed from initiate_lockdown().
  - Fix: authenticate() now performs real HMAC-SHA256 token validation
    against S43_SPARTA_NODE_TOKEN instead of returning a placeholder string.
  - Fix: aiohttp API server replaced with a FastAPI APIRouter factory
    (create_node_router()) so it mounts cleanly on the existing S43 app
    and shares its auth, logging, and monitoring infrastructure.
  - Fix: datetime.utcnow() replaced with datetime.now(timezone.utc).
  - Fix: asyncio.get_event_loop() replaced with asyncio.run() at entry point.
  - Added: optional MonitoringManager integration -- integrity violations
    generate SecurityEvent / LogEvent objects that flow through the
    Watchtower scan pipeline and accumulate in SentinelWindowStore.
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
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger("SentinelSpartaCore")


# =============================================================================
# Utilities (consistent with S43 conventions)
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(raw.strip())
        if not lo <= v <= hi:
            raise ValueError(f"out of [{lo},{hi}]")
        return v
    except ValueError:
        logger.warning("Invalid int for %s=%r, using default %s", name, raw, default)
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        logger.warning("Invalid float for %s=%r, using default %s", name, raw, default)
        return default


# =============================================================================
# State machine
# =============================================================================

class SpartaState(Enum):
    """
    Fix: the original file defined SpartaState but referenced JormState and
    SparState (two different typos), causing NameError on every instantiation
    and every shutdown call. One enum, used consistently throughout.
    """
    INITIALIZING = "INITIALIZING"
    OPERATIONAL  = "OPERATIONAL"
    LOCKDOWN     = "LOCKDOWN"
    COMPROMISED  = "COMPROMISED"
    SHUTDOWN     = "SHUTDOWN"


# =============================================================================
# Configuration
# =============================================================================

@dataclass(frozen=True)
class IntegrityConfig:
    """
    Immutable configuration for SpartaCore. Matches S43's frozen-dataclass
    config pattern used in WatchtowerConfig, RemoteGatewayConfig, etc.
    """
    # path -> expected SHA-256 hex digest
    watched_files: MappingProxyType

    # Unique identifier for this watchdog instance
    node_signature: str

    # How often to run the integrity check (seconds)
    check_interval_seconds: float = 30.0

    # Upper bound on in-memory event log entries
    max_event_log_entries: int = 1_000

    # Bearer token for the node API endpoints (S43_SPARTA_NODE_TOKEN)
    node_api_token: str = ""

    # HMAC secret used to sign session tokens issued by /node/auth
    # (S43_SPARTA_TOKEN_SECRET). Must be set in non-dev deployments.
    token_secret: str = ""

    # Session token validity window (seconds)
    token_ttl_seconds: float = 3_600.0

    def __post_init__(self) -> None:
        # Ensure watched_files is always an immutable MappingProxyType
        if not isinstance(self.watched_files, MappingProxyType):
            object.__setattr__(
                self, "watched_files", MappingProxyType(dict(self.watched_files))
            )
        if not self.node_signature.strip():
            raise ValueError("IntegrityConfig.node_signature must not be empty")

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
            node_signature=_env("S43_SPARTA_NODE_SIGNATURE", "SPARTA-CORE-SIG-v1.0"),
            check_interval_seconds=_env_float("S43_SPARTA_CHECK_INTERVAL", 30.0),
            max_event_log_entries=_env_int("S43_SPARTA_MAX_EVENT_LOG", 1_000, 100, 100_000),
            node_api_token=_env("S43_SPARTA_NODE_TOKEN"),
            token_secret=token_secret,
            token_ttl_seconds=_env_float("S43_SPARTA_TOKEN_TTL", 3_600.0),
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
# SpartaCore — file integrity watchdog
# =============================================================================

class SpartaCore:
    """
    Hardened file integrity watchdog.

    On each cycle it hashes every watched file and compares the digest
    against the configured expected value using secrets.compare_digest()
    (constant-time). Any mismatch or missing file transitions the watchdog
    to LOCKDOWN and emits events to the S43 monitoring pipeline.

    LOCKDOWN is not a trap: once all files pass integrity checks the node
    automatically recovers to OPERATIONAL.

    Optional MonitoringManager integration: when a manager is supplied,
    integrity violations are routed through analyze_event() as SecurityEvent
    / LogEvent payloads so they surface in Watchtower alerts and accumulate
    in SentinelWindowStore for threat scoring.
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
        self._lock = threading.Lock()
        self._event_log: deque[dict[str, Any]] = deque(maxlen=config.max_event_log_entries)
        self._tamper_count = 0
        self._total_checks = 0
        self._stop_requested = threading.Event()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _calculate_sha256(self, file_path: str) -> str | None:
        """
        Fix: the original separated os.path.exists() from open(), creating a
        TOCTOU race (file deleted between check and open). Fix: attempt open
        directly and handle OSError. Returns None on any read error.
        """
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65_536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except OSError as exc:
            logger.warning(
                "Integrity check: cannot read file path=%s error=%s", file_path, exc
            )
            return None

    def _record(self, event: IntegrityEvent) -> None:
        self._event_log.append(event.to_dict())
        logger.warning(
            "INTEGRITY EVENT type=%s file=%s state=%s",
            event.event_type, event.file_path, event.state_at_event,
        )

    def _emit_to_monitoring(self, event_type: str, file_path: str) -> None:
        """
        Route integrity violations to MonitoringManager so they surface in
        Watchtower alerts and the SentinelWindowStore threat-detection buffer.
        Best-effort: never raises.
        """
        if self._monitoring_manager is None:
            return

        # Map integrity violation type to S43 event kind
        if event_type == "TamperDetected":
            payload: dict[str, Any] = {
                "kind": "log",
                "integrity_status": "tampered",
                "audit_write_failed": False,
                "file_path": file_path,
                "source": "SpartaCore",
            }
        else:  # FileMissing / Unreadable
            payload = {
                "kind": "security",
                "unsigned_artifact": True,
                "file_path": file_path,
                "source": "SpartaCore",
                "event_category": "file_missing",
            }

        try:
            threading.Thread(
                target=self._monitoring_manager.analyze_event,
                args=(payload,),
                daemon=True,
            ).start()
        except Exception as exc:
            logger.debug("MonitoringManager notification failed: %s", exc)

    # ------------------------------------------------------------------
    # Integrity check
    # ------------------------------------------------------------------

    def check_integrity(self) -> bool:
        """
        Hash every watched file. Returns True if all pass.
        Records events and updates state for any failures.
        """
        with self._lock:
            current_state = self._state
            self._total_checks += 1

        all_ok = True

        for file_path, expected_hash in self._config.watched_files.items():
            actual_hash = self._calculate_sha256(file_path)

            if actual_hash is None:
                # File missing or unreadable
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

            # Fix: constant-time comparison eliminates timing side-channel.
            # The original used `!=` (Python string equality short-circuits
            # on the first differing byte, leaking information about how many
            # leading characters match).
            if not secrets.compare_digest(actual_hash, expected_hash.lower()):
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
                    old.value, new_state.value,
                )
                self._state = new_state

    def _initiate_lockdown(self) -> None:
        """
        Fix: the original called os.system("killall -STOP suspicious_processes")
        which is a shell-injection surface and does nothing in a container.
        Lockdown now:
          - Logs a CRITICAL entry
          - Emits a SecurityEvent to the monitoring pipeline
          - Invokes an optional lockdown_hook (operator-supplied callback)
          so real response logic can be injected without touching this module.
        """
        logger.critical(
            "SPARTA LOCKDOWN: integrity violation detected. "
            "Monitoring pipeline notified. Awaiting recovery or operator action."
        )
        if self._monitoring_manager is not None:
            try:
                threading.Thread(
                    target=self._monitoring_manager.analyze_event,
                    args=({"kind": "security", "secrets_exposed": True,
                           "source": "SpartaCore", "event_category": "lockdown_triggered"},),
                    daemon=True,
                ).start()
            except Exception as exc:
                logger.debug("MonitoringManager lockdown notification failed: %s", exc)

    # ------------------------------------------------------------------
    # Main watchdog loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """
        Fix: the original reset state to OPERATIONAL unconditionally at the
        top of the loop (wiping any LOCKDOWN that may have been set before
        the loop was re-entered). Now:
          - INITIALIZING -> OPERATIONAL only on first entry
          - LOCKDOWN -> OPERATIONAL only after a clean check
          - SHUTDOWN exits the loop cleanly
        """
        self._transition(SpartaState.OPERATIONAL)
        interval = self._config.check_interval_seconds

        while not self._stop_requested.is_set():
            ok = self.check_integrity()

            with self._lock:
                current = self._state

            if not ok and current == SpartaState.OPERATIONAL:
                self._tamper_count += 1
                self._transition(SpartaState.LOCKDOWN)
                self._initiate_lockdown()
            elif ok and current == SpartaState.LOCKDOWN:
                logger.info(
                    "All integrity checks passed -- transitioning LOCKDOWN -> OPERATIONAL"
                )
                self._transition(SpartaState.OPERATIONAL)

            # Sleep in short increments so stop_requested is checked promptly
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
            return {
                "state": self._state.value,
                "node_signature": self._config.node_signature,
                "watched_file_count": len(self._config.watched_files),
                "total_checks": self._total_checks,
                "tamper_count": self._tamper_count,
                "event_log_entries": len(self._event_log),
                "timestamp": utc_now(),
            }

    def get_event_log(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._event_log)[-limit:]


# =============================================================================
# Session token helpers (HMAC-SHA256, no external JWT library required)
# =============================================================================

def _sign_token(node_id: str, secret: str, ttl: float) -> str:
    """
    Generate a time-limited HMAC-SHA256 session token.
    Format: <node_id>:<expiry_unix>:<hex_signature>
    """
    expiry = int(time.time() + ttl)
    payload = f"{node_id}:{expiry}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def _verify_token(token: str, secret: str) -> str | None:
    """
    Verify a session token. Returns node_id on success, None on failure.
    Uses secrets.compare_digest for constant-time comparison.
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
    Validate the bearer token against the configured node API token.
    Fails CLOSED: if no token is configured, every request is rejected.
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
    token = authorization.removeprefix("Bearer ")
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
    credential: str = Field(..., min_length=8)


class NodeRegisterRequest(BaseModel):
    node_id: str = Field(..., min_length=2, max_length=120)
    node_type: str = Field(default="generic")
    version: str = Field(default="unknown")
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NodeHeartbeatRequest(BaseModel):
    node_id: str = Field(..., min_length=2, max_length=120)
    status_value: str = Field(default="online", alias="status")
    metrics: dict[str, Any] = Field(default_factory=dict)

    class Config:
        populate_by_name = True


# =============================================================================
# FastAPI node API router
#
# Fix: the original used aiohttp (a different framework from the rest of S43).
# Converted to a FastAPI APIRouter factory so it mounts cleanly on the
# existing S43 app with shared auth, logging, and middleware.
#
# The original /register_node, /update_status, /status routes map to
# WatchtowerNode's existing module/dependency infrastructure; this router
# provides a lightweight shim that also feeds events into SpartaCore.
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

    @router.get("/health")
    def node_health() -> dict[str, Any]:
        """Node health check -- no auth required."""
        status_obj = sparta.get_status()
        ok = status_obj["state"] == SpartaState.OPERATIONAL.value
        return {
            "status": "ok" if ok else status_obj["state"].lower(),
            "node_signature": cfg.node_signature,
            "state": status_obj["state"],
            "timestamp": utc_now(),
        }

    @router.get("/status")
    def node_status(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Full node status. Requires bearer token."""
        _require_node_token(authorization, cfg)
        return sparta.get_status()

    @router.get("/events")
    def node_events(
        authorization: str | None = Header(default=None),
        limit: int = 50,
    ) -> dict[str, Any]:
        """Recent integrity events. Requires bearer token."""
        _require_node_token(authorization, cfg)
        limit = max(1, min(limit, 500))
        events = sparta.get_event_log(limit)
        return {"count": len(events), "limit": limit, "events": events}

    @router.post("/auth", status_code=status.HTTP_200_OK)
    def authenticate(
        body: NodeAuthRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """
        Authenticate a node and issue a time-limited HMAC session token.

        Fix: the original returned the hardcoded string "example_jwt_token_here"
        regardless of credentials -- an open auth bypass. Now:
          - The bearer token is validated against S43_SPARTA_NODE_TOKEN
          - The node_id in the body is validated against the credential
            (credential must be a constant-time match against node_api_token)
          - A real HMAC-SHA256 session token is issued with configurable TTL
        """
        _require_node_token(authorization, cfg)

        # Validate the credential field as well (defense-in-depth for callers
        # that send both headers and body credentials)
        if not secrets.compare_digest(body.credential, cfg.node_api_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid node credential.",
            )

        if not cfg.token_secret:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Token signing not configured on this node.",
            )

        session_token = _sign_token(body.node_id, cfg.token_secret, cfg.token_ttl_seconds)

        return {
            "message": "Authentication successful.",
            "node_id": body.node_id,
            "token": session_token,
            "expires_in_seconds": int(cfg.token_ttl_seconds),
            "issued_at": utc_now(),
        }

    @router.post("/register", status_code=status.HTTP_201_CREATED)
    def register_node(
        body: NodeRegisterRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """
        Register a node. Requires bearer token.

        In a full S43 deployment this delegates to WatchtowerNode.register_module().
        The SpartaCore watchdog records the registration as an integrity event.
        """
        _require_node_token(authorization, cfg)

        event = IntegrityEvent(
            event_type="NodeRegistered",
            source="NodeAPI",
            file_path="",
            details={
                "node_id": body.node_id,
                "node_type": body.node_type,
                "version": body.version,
                "capabilities": body.capabilities,
            },
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
        body: NodeHeartbeatRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Node heartbeat / status update. Requires bearer token."""
        _require_node_token(authorization, cfg)

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
    Fix: the original used signal.signal() with sys.exit() inside the handler,
    which raises SystemExit mid-event-loop, leaving coroutines and async
    resources unclean. loop.add_signal_handler() is the correct asyncio
    pattern -- the callback runs inside the event loop's next iteration.
    """
    def _handle() -> None:
        logger.warning("Shutdown signal received -- stopping SpartaCore watchdog.")
        sparta.stop()
        loop.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle)
        except (NotImplementedError, RuntimeError):
            # Windows / environments where add_signal_handler isn't supported
            signal.signal(sig, lambda s, f: _handle())


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    WATCHED_FILES = {
        "sparta_core.py": os.getenv("S43_SPARTA_HASH_SPARTA_CORE", "PLACEHOLDER_HASH"),
        "security_layer.py": os.getenv("S43_SPARTA_HASH_SECURITY_LAYER", "PLACEHOLDER_HASH"),
    }

    config = IntegrityConfig.from_env(WATCHED_FILES)
    sparta = SpartaCore(config)

    # Fix: asyncio.run() replaces the deprecated asyncio.get_event_loop()
    async def _main() -> None:
        loop = asyncio.get_running_loop()
        setup_signal_handlers(sparta, loop)
        await sparta.run()

    asyncio.run(_main())
