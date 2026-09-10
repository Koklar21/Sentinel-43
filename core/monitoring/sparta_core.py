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

"""SpartaCore file-integrity watchdog + optional node API.

SpartaCore itself is an observational integrity component:
    - hash configured files
    - compare against expected SHA-256 digests
    - track bounded integrity events
    - expose current integrity state
    - run an explicit async watchdog loop
    - optionally emit coarse events through an injected sink

On top of that observational core this module also provides an OPTIONAL
authenticated ``/node`` FastAPI router (``create_node_router``) for the
Sentinel-43 node mesh. That router:
    - authenticates with ``Authorization: Bearer <S43_SPARTA_NODE_TOKEN>``
      ONLY -- a distinct machine identity, verified by constant-time compare,
      never by the human JWT / session machinery
    - fails closed: an unset / blank node token is 503, not an anonymous 200
    - temporarily blocks a client after repeated auth failures
    - keeps ``/node/health`` coarse unless S43_SPARTA_PUBLIC_HEALTH_DETAIL

The watchdog is usable with no node config at all; the node token / signing
secret are only consulted when the router is mounted. SpartaCore performs no
autonomous enforcement outside its own reported state.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import signal
import threading
import time
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

import logging

logger = logging.getLogger("SentinelSpartaCore")


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


# =============================================================================
# Environment helpers (used only by IntegrityConfig.from_env / build_sparta_core)
# =============================================================================

def _env(name: str, default: str = "") -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "on", "enabled"}


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, value))


def _env_float(name: str, default: float, *, lo: float, hi: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return max(lo, min(hi, value))


def _json_size_bytes(obj: Any) -> int:
    try:
        return len(json.dumps(obj, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def _json_size_guard(obj: Any, max_bytes: int) -> None:
    if _json_size_bytes(obj) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Request payload exceeds the {max_bytes}-byte node limit.",
        )


class SpartaState(StrEnum):
    INITIALIZING = "INITIALIZING"
    OPERATIONAL = "OPERATIONAL"
    DEGRADED = "DEGRADED"
    COMPROMISED = "COMPROMISED"
    SHUTDOWN = "SHUTDOWN"


@runtime_checkable
class IntegrityEventSink(Protocol):
    def emit(
        self,
        event: dict[str, Any],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class IntegrityConfig:
    """Immutable SpartaCore configuration.

    ``watched_files`` may be empty -- a node that only serves the ``/node``
    API has nothing to hash. The node-API fields (``node_api_token``,
    ``token_secret``) are only consulted when ``create_node_router`` is
    mounted; ``_require_node_token`` fails closed (503) if the token is unset.
    """

    watched_files: Mapping[str, str]
    check_interval_seconds: float = 30.0
    max_event_log_entries: int = 1000

    # --- Node API (optional) -------------------------------------------------
    node_signature: str = ""
    node_api_token: str = ""
    token_secret: str = ""
    token_ttl_seconds: float = 3_600.0
    public_health_detail: bool = False
    max_node_payload_bytes: int = 8_192

    # Node-API auth guard (temporary client blocking after repeated failures)
    max_auth_failures_per_window: int = 8
    auth_failure_window_seconds: float = 300.0
    auth_block_seconds: float = 900.0

    def __post_init__(self) -> None:
        normalized: dict[str, str] = {}

        for path, digest in dict(
            self.watched_files
        ).items():
            clean_path = str(
                path
            ).strip()

            clean_digest = str(
                digest
            ).strip().lower()

            if not clean_path:
                raise ValueError(
                    "watched file path must not be empty"
                )

            if len(
                clean_digest
            ) != 64:
                raise ValueError(
                    f"expected SHA-256 digest for {clean_path!r} must be 64 hex characters"
                )

            try:
                int(
                    clean_digest,
                    16,
                )
            except ValueError as exc:
                raise ValueError(
                    f"expected digest for {clean_path!r} is not valid hexadecimal"
                ) from exc

            normalized[
                clean_path
            ] = clean_digest

        if not 0.1 <= self.check_interval_seconds <= 86_400.0:
            raise ValueError(
                "check_interval_seconds must be between 0.1 and 86400"
            )

        if not 1 <= self.max_event_log_entries <= 100_000:
            raise ValueError(
                "max_event_log_entries must be between 1 and 100000"
            )

        if self.max_auth_failures_per_window < 1:
            raise ValueError("max_auth_failures_per_window must be >= 1")
        if self.auth_failure_window_seconds <= 0:
            raise ValueError("auth_failure_window_seconds must be > 0")
        if self.auth_block_seconds <= 0:
            raise ValueError("auth_block_seconds must be > 0")
        if self.max_node_payload_bytes < 1:
            raise ValueError("max_node_payload_bytes must be >= 1")

        object.__setattr__(
            self,
            "watched_files",
            MappingProxyType(
                normalized
            ),
        )

    @classmethod
    def from_env(cls, watched_files: Mapping[str, str]) -> "IntegrityConfig":
        """Build from the S43_SPARTA_* environment.

        ``S43_SPARTA_TOKEN_SECRET`` is required outside a local/dev/test
        environment when the node API is in use -- session tokens issued by
        ``/node/auth`` are only tamper-resistant with a real secret.
        """
        token_secret = _env("S43_SPARTA_TOKEN_SECRET")
        if not token_secret:
            env = _env("SENTINEL_ENV") or _env("S43_ENV", "production")
            if env.lower() not in {"development", "dev", "local", "test"}:
                raise RuntimeError(
                    "S43_SPARTA_TOKEN_SECRET is required for tamper-resistant "
                    "node session tokens outside development/local/test."
                )
            token_secret = "dev-only-change-me"
            logger.warning(
                "S43_SPARTA_TOKEN_SECRET not set; using an insecure dev "
                "default. Never use this outside development/local/test."
            )

        return cls(
            watched_files=dict(watched_files),
            check_interval_seconds=_env_float(
                "S43_SPARTA_CHECK_INTERVAL", 30.0, lo=0.1, hi=86_400.0
            ),
            max_event_log_entries=_env_int(
                "S43_SPARTA_MAX_EVENT_LOG", 1_000, 1, 100_000
            ),
            node_signature=_env("S43_SPARTA_NODE_SIGNATURE", "sparta-core"),
            node_api_token=_env("S43_SPARTA_NODE_TOKEN"),
            token_secret=token_secret,
            token_ttl_seconds=_env_float(
                "S43_SPARTA_TOKEN_TTL", 3_600.0, lo=30.0, hi=86_400.0
            ),
            public_health_detail=_env_bool(
                "S43_SPARTA_PUBLIC_HEALTH_DETAIL", False
            ),
            max_node_payload_bytes=_env_int(
                "S43_SPARTA_MAX_NODE_PAYLOAD_BYTES", 8_192, 512, 1_048_576
            ),
            max_auth_failures_per_window=_env_int(
                "S43_SPARTA_MAX_AUTH_FAILURES", 8, 1, 10_000
            ),
            auth_failure_window_seconds=_env_float(
                "S43_SPARTA_AUTH_FAILURE_WINDOW", 300.0, lo=1.0, hi=86_400.0
            ),
            auth_block_seconds=_env_float(
                "S43_SPARTA_AUTH_BLOCK_SECONDS", 900.0, lo=1.0, hi=86_400.0
            ),
        )


@dataclass(frozen=True, slots=True)
class IntegrityEvent:
    event_type: str
    file_path: str
    state_at_event: SpartaState
    source: str = ""
    details: Mapping[str, Any] = field(
        default_factory=dict
    )
    timestamp: str = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:
        event_type = str(
            self.event_type
        ).strip()

        if not event_type:
            raise ValueError(
                "event_type must not be empty"
            )

        object.__setattr__(
            self,
            "event_type",
            event_type,
        )

        object.__setattr__(
            self,
            "file_path",
            str(
                self.file_path
            ).strip(),
        )

        object.__setattr__(
            self,
            "details",
            MappingProxyType(
                dict(
                    self.details
                )
            ),
        )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "file_path": self.file_path,
            "state_at_event": self.state_at_event.value,
            "source": self.source,
            "details": dict(
                self.details
            ),
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class IntegrityCheckResult:
    ok: bool
    checked_files: int
    failed_files: tuple[str, ...]
    state: SpartaState


class SpartaCore:
    """Thread-safe file-integrity watchdog + node-API security anchor."""

    def __init__(
        self,
        config: IntegrityConfig,
        *,
        event_sink: IntegrityEventSink | None = None,
        monitoring_manager: Any | None = None,
    ) -> None:
        self._config = config
        self._event_sink = event_sink
        self._monitoring_manager = monitoring_manager

        self._state = SpartaState.INITIALIZING
        self._lock = threading.RLock()

        self._event_log: deque[
            IntegrityEvent
        ] = deque(
            maxlen=config.max_event_log_entries
        )

        self._tamper_count = 0
        self._total_checks = 0
        self._stop_requested = threading.Event()

        # Node-API auth guard
        self._auth_guard_lock = threading.Lock()
        self._auth_failures: dict[str, deque[float]] = defaultdict(deque)
        self._blocked_clients: dict[str, float] = {}

    def _emit(
        self,
        event: IntegrityEvent,
    ) -> None:
        with self._lock:
            self._event_log.append(
                event
            )

        payload = event.to_dict()

        sink = self._event_sink
        if sink is not None:
            try:
                sink.emit(payload)
            except Exception:
                pass

        self._notify_monitoring(event, payload)

    def _notify_monitoring(
        self,
        event: IntegrityEvent,
        payload: dict[str, Any],
    ) -> None:
        """Forward one integrity event to MonitoringManager, if wired.

        MonitoringManager normalizes through ``core.monitoring.event_types``,
        which keeps only the fields declared on the typed event for the given
        ``kind`` and drops the rest. A raw ``IntegrityEvent.to_dict()`` has no
        ``kind``, so it normalized to a bare ``BaseEvent`` and every piece of
        Sparta provenance was silently discarded. Integrity findings are
        therefore emitted as a typed ``log`` event carrying
        ``integrity_status``, with the full detail preserved under
        ``details`` for sinks that accept unknown fields.

        Observational only: a monitoring failure never changes the integrity
        outcome, and Sparta takes no action on the result.
        """
        manager = self._monitoring_manager
        if manager is None:
            return

        analyze = getattr(manager, "analyze_event", None)
        if not callable(analyze):
            return

        compromised = event.state_at_event is SpartaState.COMPROMISED
        monitoring_event = {
            "kind": "log",
            "integrity_status": "compromised" if compromised else "ok",
            "missing_required_fields": False,
            "source": event.source or "SpartaCore",
            "node": self._config.node_signature or "sparta-core",
            "event_type": event.event_type,
            "details": payload,
        }

        try:
            analyze(monitoring_event)
        except Exception:
            logger.debug(
                "MonitoringManager notification failed", exc_info=True
            )

    @staticmethod
    def _calculate_sha256(
        file_path: str,
    ) -> str | None:
        try:
            digest = hashlib.sha256()

            with open(
                file_path,
                "rb",
            ) as handle:
                for chunk in iter(
                    lambda: handle.read(
                        65_536
                    ),
                    b"",
                ):
                    digest.update(
                        chunk
                    )

            return digest.hexdigest()

        except OSError:
            return None

    def _set_state(
        self,
        state: SpartaState,
    ) -> None:
        with self._lock:
            self._state = state

    def check_integrity(
        self,
    ) -> IntegrityCheckResult:
        with self._lock:
            self._total_checks += 1
            state_before = self._state

        failed_files: list[str] = []

        for (
            file_path,
            expected_hash,
        ) in self._config.watched_files.items():
            actual_hash = self._calculate_sha256(
                file_path
            )

            if actual_hash is None:
                failed_files.append(
                    file_path
                )

                self._emit(
                    IntegrityEvent(
                        event_type="FileUnavailable",
                        file_path=file_path,
                        state_at_event=state_before,
                        details={
                            "expected_hash": expected_hash
                        },
                    )
                )
                continue

            if not secrets.compare_digest(
                actual_hash,
                expected_hash,
            ):
                failed_files.append(
                    file_path
                )

                self._emit(
                    IntegrityEvent(
                        event_type="TamperDetected",
                        file_path=file_path,
                        state_at_event=state_before,
                        details={
                            "expected_hash": expected_hash,
                            "actual_hash": actual_hash,
                        },
                    )
                )

        if failed_files:
            with self._lock:
                self._tamper_count += len(
                    failed_files
                )
                self._state = SpartaState.COMPROMISED

            self._emit(
                IntegrityEvent(
                    event_type="IntegrityCompromised",
                    file_path="",
                    state_at_event=SpartaState.COMPROMISED,
                    details={
                        "failed_files": tuple(
                            failed_files
                        )
                    },
                )
            )

            state = SpartaState.COMPROMISED

        else:
            with self._lock:
                if self._state in {
                    SpartaState.INITIALIZING,
                    SpartaState.DEGRADED,
                }:
                    self._state = SpartaState.OPERATIONAL

                state = self._state

        return IntegrityCheckResult(
            ok=not failed_files,
            checked_files=len(
                self._config.watched_files
            ),
            failed_files=tuple(
                failed_files
            ),
            state=state,
        )

    def acknowledge_recovery(
        self,
        *,
        operator: str,
        reason: str,
    ) -> bool:
        """Allow a human/operator path to clear COMPROMISED after a clean check.

        This method changes only SpartaCore's reported state. It does not alter
        firewall, auth, routing, or any other subsystem.
        """
        normalized_operator = str(
            operator
        ).strip()

        normalized_reason = str(
            reason
        ).strip()

        if not normalized_operator:
            raise ValueError(
                "operator must not be empty"
            )

        if not normalized_reason:
            raise ValueError(
                "reason must not be empty"
            )

        result = self.check_integrity()

        if not result.ok:
            return False

        with self._lock:
            if self._state is not SpartaState.COMPROMISED:
                return False

            self._state = SpartaState.OPERATIONAL

        self._emit(
            IntegrityEvent(
                event_type="RecoveryAcknowledged",
                file_path="",
                state_at_event=SpartaState.OPERATIONAL,
                source="NodeAPI",
                details={
                    "operator": normalized_operator,
                    "reason": normalized_reason,
                },
            )
        )

        return True

    # Node /unlock maps to the same operator-gated recovery path.
    def unlock_lockdown(self, *, operator: str, reason: str) -> bool:
        return self.acknowledge_recovery(operator=operator, reason=reason)

    async def run(
        self,
    ) -> None:
        with self._lock:
            if self._state is SpartaState.INITIALIZING:
                self._state = SpartaState.DEGRADED

        interval = self._config.check_interval_seconds

        while not self._stop_requested.is_set():
            await asyncio.to_thread(
                self.check_integrity
            )

            deadline = (
                time.monotonic()
                + interval
            )

            while (
                not self._stop_requested.is_set()
                and time.monotonic()
                < deadline
            ):
                await asyncio.sleep(
                    min(
                        1.0,
                        max(
                            0.0,
                            deadline
                            - time.monotonic(),
                        ),
                    )
                )

        self._set_state(
            SpartaState.SHUTDOWN
        )

    def stop(
        self,
    ) -> None:
        self._stop_requested.set()

    def close(self) -> None:
        """Release resources / stop the watchdog. Idempotent."""
        self._stop_requested.set()

    def get_status(
        self,
    ) -> dict[str, Any]:
        """Authenticated status snapshot.

        The field set is the contract consumed by
        ``core.monitoring.rules.sparta_core_rule``: ``state``,
        ``tamper_count``, ``blocked_clients``, ``tracked_auth_clients``,
        ``watched_file_count`` and ``total_checks``.
        """
        now = time.monotonic()

        with self._auth_guard_lock:
            self._gc_auth_guard_locked(now)
            blocked_clients = len(self._blocked_clients)
            tracked_auth_clients = len(self._auth_failures)

        with self._lock:
            return {
                "state": self._state.value,
                "node_signature": self._config.node_signature,
                "watched_file_count": len(
                    self._config.watched_files
                ),
                "total_checks": self._total_checks,
                "tamper_count": self._tamper_count,
                "event_log_entries": len(
                    self._event_log
                ),
                "blocked_clients": blocked_clients,
                "tracked_auth_clients": tracked_auth_clients,
                "timestamp": utc_now(),
            }

    def get_public_health(
        self,
    ) -> dict[str, str]:
        with self._lock:
            state = self._state
            operational = state is SpartaState.OPERATIONAL

        if self._config.public_health_detail:
            return {
                "status": "ok" if operational else state.value.lower(),
                "state": state.value,
                "node_signature": self._config.node_signature,
                "timestamp": utc_now(),
            }

        return {
            "status": "ok" if operational else "degraded",
            "timestamp": utc_now(),
        }

    def get_event_log(
        self,
        *,
        limit: int = 50,
    ) -> tuple[
        dict[str, Any],
        ...
    ]:
        bounded_limit = max(
            1,
            min(
                int(
                    limit
                ),
                500,
            ),
        )

        with self._lock:
            return tuple(
                event.to_dict()
                for event in list(
                    self._event_log
                )[
                    -bounded_limit:
                ]
            )

    # ------------------------------------------------------------------
    # Node-API auth guard
    # ------------------------------------------------------------------

    def get_client_id(self, request: Request | None) -> str:
        """The SentinelFirewall-resolved client IP if present, else the peer."""
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

    def _gc_auth_guard_locked(self, now: float) -> None:
        cutoff = now - self._config.auth_failure_window_seconds
        stale = [
            cid
            for cid, failures in self._auth_failures.items()
            if not failures or failures[-1] < cutoff
        ]
        for cid in stale:
            self._auth_failures.pop(cid, None)
        expired = [
            cid for cid, until in self._blocked_clients.items() if now >= until
        ]
        for cid in expired:
            self._blocked_clients.pop(cid, None)

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

        details: dict[str, Any] = {"client_id": client_id, "reason": reason}
        if blocked_until is not None:
            details["block_seconds"] = self._config.auth_block_seconds

        with self._lock:
            state_now = self._state

        self._emit(
            IntegrityEvent(
                event_type="AuthFailure",
                file_path="",
                state_at_event=state_now,
                source="NodeAPI",
                details=details,
            )
        )

    def require_node_auth(
        self,
        request: Request,
        authorization: str | None,
    ) -> None:
        """Route-level guard for the /node API.

        Wraps ``_require_node_token`` with per-client temporary blocking and
        auth-failure event logging.
        """
        client_id = self.get_client_id(request)

        if self._is_client_blocked(client_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed authentication attempts.",
            )

        try:
            _require_node_token(authorization, self._config)
        except HTTPException as exc:
            if exc.status_code != status.HTTP_503_SERVICE_UNAVAILABLE:
                self._record_auth_failure(client_id, "missing_or_invalid_bearer")
            raise


# =============================================================================
# Node session-token helpers
# =============================================================================

def _sign_token(node_id: str, secret: str, ttl: float) -> str:
    """Time-limited HMAC-SHA256 session token: ``<node_id>:<expiry>:<sig>``."""
    expiry = int(time.time() + ttl)
    payload = f"{node_id}:{expiry}"
    sig = hmac.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return f"{payload}:{sig}"


def _verify_token(token: str, secret: str) -> str | None:
    """Return node_id on success, None on failure.

    ``rsplit(":", 2)`` so a node_id containing colons (``rack:node-1``) still
    parses -- the format is always ``{node_id}:{expiry}:{sig}``.
    """
    try:
        parts = token.rsplit(":", 2)
        if len(parts) != 3:
            return None

        node_id, expiry_str, provided_sig = parts
        expiry = int(expiry_str)

        if time.time() > expiry:
            return None

        payload = f"{node_id}:{expiry_str}"
        expected_sig = hmac.new(
            secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

        if not secrets.compare_digest(provided_sig, expected_sig):
            return None

        return node_id
    except Exception:
        return None


def _require_node_token(
    authorization: str | None, config: IntegrityConfig
) -> None:
    """Validate a bearer token against ``S43_SPARTA_NODE_TOKEN``.

    Fails closed:
      - no configured token (unset / blank / whitespace-only) -> 503
      - missing / malformed Authorization header -> 401
      - empty or wrong token -> 401

    Authenticates by constant-time secret compare only. This is a distinct
    machine identity: it never consults the human session/JWT machinery.
    """
    if not config.node_api_token or not config.node_api_token.strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Node API token not configured. Set S43_SPARTA_NODE_TOKEN to "
                "enable authenticated node endpoints."
            ),
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
        )

    token = authorization[len("Bearer "):].strip()

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
# Node API request models
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
    model_config = ConfigDict(populate_by_name=True)

    node_id: str = Field(..., min_length=2, max_length=120)
    status_value: str = Field(
        default="online", alias="status", min_length=1, max_length=80
    )
    metrics: dict[str, Any] = Field(default_factory=dict)


class NodeUnlockRequest(BaseModel):
    operator: str = Field(default="unknown", min_length=1, max_length=120)
    reason: str = Field(default="manual", min_length=1, max_length=512)


# =============================================================================
# Node API router
# =============================================================================

def create_node_router(
    sparta: Any,
    *,
    prefix: str = "/node",
) -> APIRouter:
    """FastAPI router for the authenticated Sentinel-43 node mesh.

    ``sparta`` is resolved lazily on every request: the router is mounted at
    import time, but the backing SpartaCore is built during lifespan startup,
    so the caller may pass a late-bound proxy. Such a proxy signals "not
    backed yet" by raising ``RuntimeError`` on attribute access; every route
    turns that into a 503, never a 500 -- the node must report itself
    unavailable rather than leak an unhandled error from ``/node/health``,
    which is public.

    Mount it on the API app:
    ``app.include_router(create_node_router(sparta))``.
    """
    router = APIRouter(prefix=prefix, tags=["node"])

    def _resolve() -> Any:
        """Return the live SpartaCore, or fail closed with 503."""
        try:
            # Force a late-bound proxy to resolve before any route logic runs.
            sparta.get_public_health
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="SpartaCore is not running on this node.",
            ) from exc
        return sparta

    def _guard(request: Request, authorization: str | None) -> Any:
        core = _resolve()
        core.require_node_auth(request, authorization)
        return core

    @router.get("/health")
    def node_health() -> dict[str, Any]:
        return _resolve().get_public_health()

    @router.get("/status")
    def node_status(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        return _guard(request, authorization).get_status()

    @router.get("/events")
    def node_events(
        request: Request,
        authorization: str | None = Header(default=None),
        limit: int = 50,
    ) -> dict[str, Any]:
        core = _guard(request, authorization)
        limit = max(1, min(int(limit), 500))
        events = list(core.get_event_log(limit=limit))
        return {"count": len(events), "limit": limit, "events": events}

    @router.post("/auth", status_code=status.HTTP_200_OK)
    def node_authenticate(
        request: Request,
        body: NodeAuthRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        core = _guard(request, authorization)
        cfg = core._config

        if not secrets.compare_digest(body.credential, cfg.node_api_token):
            core._record_auth_failure(
                core.get_client_id(request), "invalid_body_credential"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid node credential.",
            )

        if not cfg.token_secret:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Token signing is not configured on this node.",
            )

        session_token = _sign_token(
            body.node_id, cfg.token_secret, cfg.token_ttl_seconds
        )
        return {
            "message": "Authentication successful.",
            "node_id": body.node_id,
            "token": session_token,
            "expires_in_seconds": int(cfg.token_ttl_seconds),
            "issued_at": utc_now(),
        }

    @router.post("/register", status_code=status.HTTP_201_CREATED)
    def node_register(
        request: Request,
        body: NodeRegisterRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        core = _guard(request, authorization)
        cfg = core._config
        _json_size_guard(body.capabilities, cfg.max_node_payload_bytes)
        _json_size_guard(body.metadata, cfg.max_node_payload_bytes)

        core._emit(
            IntegrityEvent(
                event_type="NodeRegistered",
                file_path="",
                state_at_event=SpartaState(core.get_status()["state"]),
                source="NodeAPI",
                details={
                    "node_id": body.node_id,
                    "node_type": body.node_type,
                    "version": body.version,
                    "capabilities": list(body.capabilities),
                    "metadata_size_bytes": _json_size_bytes(body.metadata),
                },
            )
        )
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
        core = _guard(request, authorization)
        cfg = core._config
        _json_size_guard(body.metrics, cfg.max_node_payload_bytes)

        core._emit(
            IntegrityEvent(
                event_type="NodeHeartbeat",
                file_path="",
                state_at_event=SpartaState(core.get_status()["state"]),
                source="NodeAPI",
                details={
                    "node_id": body.node_id,
                    "status": body.status_value,
                    "metrics_size_bytes": _json_size_bytes(body.metrics),
                },
            )
        )
        return {
            "status": "acknowledged",
            "node_id": body.node_id,
            "received_status": body.status_value,
            "timestamp": utc_now(),
        }

    @router.post("/unlock")
    def node_unlock(
        request: Request,
        body: NodeUnlockRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        core = _guard(request, authorization)
        changed = core.unlock_lockdown(
            operator=body.operator, reason=body.reason
        )
        return {
            "status": "unlocked" if changed else "no_change",
            "state": core.get_status()["state"],
            "operator": body.operator,
            "timestamp": utc_now(),
        }

    return router


# =============================================================================
# Signal handling / factory
# =============================================================================

def setup_signal_handlers(
    sparta: SpartaCore, loop: asyncio.AbstractEventLoop
) -> None:
    """Register graceful-shutdown handlers (Windows-compatible fallback)."""

    def _handle() -> None:
        logger.warning("Shutdown signal received -- stopping SpartaCore.")
        sparta.stop()
        sparta.close()
        loop.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda _s, _f: _handle())


def build_sparta_core(
    watched_files: Mapping[str, str],
    *,
    monitoring_manager: Any | None = None,
) -> SpartaCore:
    """Build SpartaCore from the S43_SPARTA_* environment."""
    config = IntegrityConfig.from_env(watched_files)
    return SpartaCore(config, monitoring_manager=monitoring_manager)


__all__ = [
    "IntegrityCheckResult",
    "IntegrityConfig",
    "IntegrityEvent",
    "IntegrityEventSink",
    "NodeAuthRequest",
    "NodeHeartbeatRequest",
    "NodeRegisterRequest",
    "NodeUnlockRequest",
    "SpartaCore",
    "SpartaState",
    "build_sparta_core",
    "create_node_router",
    "setup_signal_handlers",
]
