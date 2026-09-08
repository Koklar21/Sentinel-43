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

"""Sentinel-43 Fenrir local monitoring node.

Fenrir is an observation/reporting component. It may collect local monitoring
signals, track state, report health/metrics, and register with the Sentinel
mesh. It does not execute external enforcement.

The default runtime is HUMAN_GATED + LOCAL_ONLY. Demonstration/synthetic event
generation is disabled unless explicitly enabled in a local/test environment.
"""

from __future__ import annotations

import asyncio
import enum
import json
import logging
import os
import random
import signal
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Final
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientError, ClientSession, web
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

try:
    from core.security.fenrir_auth import (
        FenrirAuthConfig,
        FenrirAuthError,
        extract_bearer_token,
        verify_fenrir_token,
    )
except ImportError:
    from fenrir_auth import (  # type: ignore
        FenrirAuthConfig,
        FenrirAuthError,
        extract_bearer_token,
        verify_fenrir_token,
    )

logger = logging.getLogger("sentinel43.fenrir")

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "y", "on"}
)
_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "n", "off"}
)
_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)
_BLOCKED_MESH_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }
)
_SAFE_EVENT_KEYS: Final[frozenset[str]] = frozenset(
    {"human_gated", "old", "new"}
)


# =============================================================================
# Utilities
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None and value.strip():
            return value.strip()
    return default


def _environment() -> str:
    raw = _env_first(
        "SENTINEL_ENV",
        "S43_ENV",
        default="production",
    ).lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "prod": "production",
        "stage": "staging",
    }
    return aliases.get(raw, raw)


def _is_local_environment() -> bool:
    return _environment() in _LOCAL_ENVIRONMENTS


def _env_bool(
    primary: str,
    fallback: str,
    default: bool,
    *,
    strict: bool,
) -> bool:
    for name in (primary, fallback):
        raw = os.getenv(name)
        if raw is None or not raw.strip():
            continue

        normalized = raw.strip().lower()
        if normalized in _TRUE_VALUES:
            return True
        if normalized in _FALSE_VALUES:
            return False

        if strict:
            raise ValueError(
                f"{name} must be boolean; got {raw!r}"
            )

        logger.warning(
            "Fenrir: invalid boolean for %s=%r; using default %s",
            name,
            raw,
            default,
        )
        return default

    return default


def _env_int(
    primary: str,
    fallback: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
    strict: bool,
) -> int:
    for name in (primary, fallback):
        raw = os.getenv(name)
        if raw is None or not raw.strip():
            continue

        try:
            value = int(raw.strip())
        except ValueError as exc:
            if strict:
                raise ValueError(
                    f"{name} must be an integer; got {raw!r}"
                ) from exc

            logger.warning(
                "Fenrir: invalid integer for %s=%r; using default %s",
                name,
                raw,
                default,
            )
            return default

        if not minimum <= value <= maximum:
            if strict:
                raise ValueError(
                    f"{name} must be between {minimum} and {maximum}; got {value}"
                )

            logger.warning(
                "Fenrir: %s=%s outside %s..%s; using default %s",
                name,
                value,
                minimum,
                maximum,
                default,
            )
            return default

        return value

    return default


def _env_float(
    primary: str,
    fallback: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
    strict: bool,
) -> float:
    for name in (primary, fallback):
        raw = os.getenv(name)
        if raw is None or not raw.strip():
            continue

        try:
            value = float(raw.strip())
        except ValueError as exc:
            if strict:
                raise ValueError(
                    f"{name} must be numeric; got {raw!r}"
                ) from exc

            logger.warning(
                "Fenrir: invalid number for %s=%r; using default %s",
                name,
                raw,
                default,
            )
            return default

        if not minimum <= value <= maximum:
            if strict:
                raise ValueError(
                    f"{name} must be between {minimum} and {maximum}; got {value}"
                )

            logger.warning(
                "Fenrir: %s=%s outside %s..%s; using default %s",
                name,
                value,
                minimum,
                maximum,
                default,
            )
            return default

        return value

    return default


def _validate_mesh_url_for_ssrf(url: str) -> None:
    """Reject obviously dangerous mesh destinations.

    Private RFC1918/RFC4193 addresses remain allowed because Sentinel mesh
    services commonly live on private deployment networks. Loopback, link-local,
    and well-known metadata hostnames are rejected.
    """
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "mesh_registry_url must use http:// or https://"
        )

    if not parsed.hostname:
        raise ValueError(
            "mesh_registry_url must include a hostname"
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "mesh_registry_url must not contain embedded credentials"
        )

    host = parsed.hostname.lower()

    if host in _BLOCKED_MESH_HOSTS:
        raise ValueError(
            f"mesh_registry_url host {host!r} is blocked"
        )

    try:
        address = ip_address(host)
    except ValueError:
        return

    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise ValueError(
            f"mesh_registry_url IP {host!r} is not an allowed destination"
        )


# =============================================================================
# State / mode
# =============================================================================

class FenrirState(str, enum.Enum):
    INITIALIZING = "INITIALIZING"
    HUNTING = "HUNTING"
    TRACKING = "TRACKING"
    ENGAGED = "ENGAGED"
    DORMANT = "DORMANT"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


class FenrirMode(str, enum.Enum):
    SHADOW = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"
    LOCAL_ONLY = "LOCAL_ONLY"


# =============================================================================
# Configuration
# =============================================================================

class FenrirConfig(BaseModel):
    node_id: str = Field(default="FENRIR-01", min_length=1, max_length=128)
    mesh_registry_url: str = Field(
        default="https://watchtower:8000/mesh",
        min_length=1,
        max_length=2048,
    )
    secret_token: str = Field(default="", max_length=8192)

    log_level: str = Field(
        default="INFO",
        pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
    )

    health_bind_host: str = Field(default="127.0.0.1", min_length=1, max_length=255)
    metrics_bind_host: str = Field(default="127.0.0.1", min_length=1, max_length=255)
    health_port: int = Field(default=8200, ge=1024, le=65535)
    metrics_port: int = Field(default=9200, ge=1024, le=65535)

    main_loop_interval: float = Field(default=2.0, ge=0.25, le=60.0)
    mesh_timeout: float = Field(default=30.0, ge=1.0, le=120.0)
    max_retries: int = Field(default=5, ge=1, le=10)
    retry_delay: float = Field(default=1.0, gt=0.0, le=10.0)

    mode: FenrirMode = Field(default=FenrirMode.HUMAN_GATED)
    deployment_scope: str = Field(default="LOCAL_ONLY")

    require_auth: bool = Field(default=True)
    verify_tls: bool = Field(default=True)

    # Synthetic/demo events must never be the default behavior.
    demo_simulation_enabled: bool = Field(default=False)

    @field_validator("mesh_registry_url")
    @classmethod
    def validate_mesh_url(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")
        _validate_mesh_url_for_ssrf(cleaned)
        return cleaned

    @field_validator("deployment_scope")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if cleaned != "LOCAL_ONLY":
            raise ValueError(
                "Fenrir is locked to LOCAL_ONLY deployment scope"
            )
        return cleaned

    @model_validator(mode="after")
    def validate_security_posture(self) -> "FenrirConfig":
        local = _is_local_environment()

        if not local and not self.require_auth:
            raise ValueError(
                "Fenrir authentication cannot be disabled outside local/test"
            )

        if not local and not self.verify_tls:
            raise ValueError(
                "Fenrir TLS verification cannot be disabled outside local/test"
            )

        if (
            self.secret_token
            and self.mesh_registry_url.startswith("http://")
        ):
            raise ValueError(
                "Fenrir refuses to send a bearer token over plaintext HTTP"
            )

        if self.demo_simulation_enabled and not local:
            raise ValueError(
                "Fenrir demo simulation is allowed only in local/test"
            )

        if self.health_port == self.metrics_port and (
            self.health_bind_host == self.metrics_bind_host
        ):
            raise ValueError(
                "Fenrir health and metrics endpoints must not bind the same host/port"
            )

        return self

    @classmethod
    def from_environment(cls) -> "FenrirConfig":
        strict = not _is_local_environment()

        mode_raw = _env_first(
            "SENTINEL_FENRIR_MODE",
            "FENRIR_MODE",
            default="HUMAN_GATED",
        ).upper()

        try:
            mode = FenrirMode(mode_raw)
        except ValueError as exc:
            raise ValueError(
                f"Invalid Fenrir mode {mode_raw!r}"
            ) from exc

        return cls(
            node_id=_env_first(
                "SENTINEL_FENRIR_NODE_ID",
                "FENRIR_NODE_ID",
                default="FENRIR-01",
            ),
            mesh_registry_url=_env_first(
                "SENTINEL_FENRIR_MESH_REGISTRY_URL",
                "FENRIR_MESH_REGISTRY_URL",
                default="https://watchtower:8000/mesh",
            ),
            secret_token=_env_first(
                "SENTINEL_FENRIR_SECRET_TOKEN",
                "FENRIR_SECRET_TOKEN",
            ),
            log_level=_env_first(
                "SENTINEL_FENRIR_LOG_LEVEL",
                "FENRIR_LOG_LEVEL",
                default="INFO",
            ).upper(),
            health_bind_host=_env_first(
                "SENTINEL_FENRIR_HEALTH_BIND",
                "FENRIR_HEALTH_BIND",
                default="127.0.0.1",
            ),
            metrics_bind_host=_env_first(
                "SENTINEL_FENRIR_METRICS_BIND",
                "FENRIR_METRICS_BIND",
                default="127.0.0.1",
            ),
            health_port=_env_int(
                "SENTINEL_FENRIR_HEALTH_PORT",
                "FENRIR_HEALTH_PORT",
                8200,
                minimum=1024,
                maximum=65535,
                strict=strict,
            ),
            metrics_port=_env_int(
                "SENTINEL_FENRIR_METRICS_PORT",
                "FENRIR_METRICS_PORT",
                9200,
                minimum=1024,
                maximum=65535,
                strict=strict,
            ),
            main_loop_interval=_env_float(
                "SENTINEL_FENRIR_MAIN_LOOP_INTERVAL",
                "FENRIR_MAIN_LOOP_INTERVAL",
                2.0,
                minimum=0.25,
                maximum=60.0,
                strict=strict,
            ),
            mesh_timeout=_env_float(
                "SENTINEL_FENRIR_MESH_TIMEOUT",
                "FENRIR_MESH_TIMEOUT",
                30.0,
                minimum=1.0,
                maximum=120.0,
                strict=strict,
            ),
            max_retries=_env_int(
                "SENTINEL_FENRIR_MAX_RETRIES",
                "FENRIR_MAX_RETRIES",
                5,
                minimum=1,
                maximum=10,
                strict=strict,
            ),
            retry_delay=_env_float(
                "SENTINEL_FENRIR_RETRY_DELAY",
                "FENRIR_RETRY_DELAY",
                1.0,
                minimum=0.01,
                maximum=10.0,
                strict=strict,
            ),
            mode=mode,
            deployment_scope=_env_first(
                "SENTINEL_DEPLOYMENT_SCOPE",
                "FENRIR_DEPLOYMENT_SCOPE",
                default="LOCAL_ONLY",
            ),
            require_auth=_env_bool(
                "SENTINEL_FENRIR_REQUIRE_AUTH",
                "FENRIR_REQUIRE_AUTH",
                True,
                strict=strict,
            ),
            verify_tls=_env_bool(
                "SENTINEL_FENRIR_VERIFY_TLS",
                "FENRIR_VERIFY_TLS",
                True,
                strict=strict,
            ),
            demo_simulation_enabled=_env_bool(
                "SENTINEL_FENRIR_DEMO_SIMULATION",
                "FENRIR_DEMO_SIMULATION",
                False,
                strict=strict,
            ),
        )

    def safe_dict(self) -> dict[str, Any]:
        data = self.model_dump()
        if data.get("secret_token"):
            data["secret_token"] = "<redacted>"
        return data


# =============================================================================
# Metrics
# =============================================================================

@dataclass(slots=True)
class FenrirMetrics:
    targets_tracked: int = 0
    engagements: int = 0
    errors: int = 0
    state_transitions: int = 0
    request_count: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    last_event: dict[str, Any] | None = None

    _started_monotonic: float = field(
        default_factory=time.monotonic,
        init=False,
        repr=False,
    )
    started_at: str = field(
        default_factory=utc_now,
    )

    def record_event(
        self,
        event_type: str,
        **extra: Any,
    ) -> None:
        safe_extra = {
            key: value
            for key, value in extra.items()
            if key in _SAFE_EVENT_KEYS
        }

        self.last_event = {
            "type": event_type,
            "timestamp": utc_now(),
            **safe_extra,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "targets_tracked": self.targets_tracked,
            "engagements": self.engagements,
            "errors": self.errors,
            "state_transitions": self.state_transitions,
            "request_count": self.request_count,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "last_event": self.last_event,
            "started_at": self.started_at,
            "uptime_seconds": max(
                0,
                int(time.monotonic() - self._started_monotonic),
            ),
        }


# =============================================================================
# Fenrir node
# =============================================================================

class FenrirNode:
    """Local-only, non-enforcing Sentinel-43 monitoring node."""

    def __init__(
        self,
        config: FenrirConfig,
        auth_config: FenrirAuthConfig | None = None,
    ) -> None:
        self.config = config
        self.auth_config = (
            auth_config
            if auth_config is not None
            else FenrirAuthConfig.from_env()
        )

        self.state = FenrirState.INITIALIZING
        self.metrics = FenrirMetrics()

        self.health_runner: web.AppRunner | None = None
        self.metrics_runner: web.AppRunner | None = None
        self.mesh_session: ClientSession | None = None
        self.main_task: asyncio.Task[None] | None = None

        self.shutdown_event = asyncio.Event()
        self._shutdown_lock = asyncio.Lock()
        self._started = False

        self.ssl_context = self._create_ssl_context()

        logger.setLevel(self.config.log_level)
        logger.info(
            "Fenrir initialized: %s",
            json.dumps(
                self.config.safe_dict(),
                sort_keys=True,
                default=str,
            ),
        )

    def _create_ssl_context(self) -> ssl.SSLContext | bool:
        if self.config.verify_tls:
            return ssl.create_default_context()

        if not _is_local_environment():
            raise RuntimeError(
                "Fenrir TLS verification cannot be disabled outside local/test"
            )

        logger.warning(
            "Fenrir mesh TLS verification is disabled for local/test use"
        )

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def _require_scope(
        self,
        request: web.Request,
        scope: str,
    ) -> dict[str, Any]:
        if not self.config.require_auth:
            if not _is_local_environment():
                raise FenrirAuthError(
                    "Authentication disabled outside local/test"
                )
            return {
                "sub": "auth-disabled-local",
                "scope": "*",
            }

        token = extract_bearer_token(
            request.headers.get("Authorization")
        )

        if token is None:
            raise FenrirAuthError(
                "Authorization header missing or malformed"
            )

        return verify_fenrir_token(
            token,
            self.auth_config,
            required_scope=scope,
        )

    # ------------------------------------------------------------------
    # Health / metrics
    # ------------------------------------------------------------------

    async def health_check(
        self,
        request: web.Request,
    ) -> web.Response:
        self.metrics.request_count += 1

        try:
            await self._require_scope(
                request,
                "fenrir:read",
            )
        except FenrirAuthError:
            self.metrics.failed_requests += 1
            return web.json_response(
                {"error": "unauthorized"},
                status=401,
                headers={"Cache-Control": "no-store"},
            )

        self.metrics.successful_requests += 1

        return web.json_response(
            {
                "status": self.state.value,
                "node_id": self.config.node_id,
                "mode": self.config.mode.value,
                "deployment_scope": self.config.deployment_scope,
            },
            headers={"Cache-Control": "no-store"},
        )

    async def metrics_check(
        self,
        request: web.Request,
    ) -> web.Response:
        self.metrics.request_count += 1

        try:
            await self._require_scope(
                request,
                "fenrir:read",
            )
        except FenrirAuthError:
            self.metrics.failed_requests += 1
            return web.json_response(
                {"error": "unauthorized"},
                status=401,
                headers={"Cache-Control": "no-store"},
            )

        self.metrics.successful_requests += 1

        return web.json_response(
            self.metrics.as_dict(),
            headers={"Cache-Control": "no-store"},
        )

    async def _start_http_servers(self) -> None:
        health_app = web.Application(
            client_max_size=16 * 1024,
        )
        health_app.router.add_get(
            "/health",
            self.health_check,
        )

        metrics_app = web.Application(
            client_max_size=16 * 1024,
        )
        metrics_app.router.add_get(
            "/metrics",
            self.metrics_check,
        )

        self.health_runner = web.AppRunner(
            health_app,
            handle_signals=False,
            access_log=None,
        )
        self.metrics_runner = web.AppRunner(
            metrics_app,
            handle_signals=False,
            access_log=None,
        )

        await self.health_runner.setup()
        await self.metrics_runner.setup()

        try:
            health_site = web.TCPSite(
                self.health_runner,
                self.config.health_bind_host,
                self.config.health_port,
            )
            metrics_site = web.TCPSite(
                self.metrics_runner,
                self.config.metrics_bind_host,
                self.config.metrics_port,
            )

            await health_site.start()
            await metrics_site.start()
        except Exception:
            await self._cleanup_http_servers()
            raise

        logger.info(
            "Fenrir health endpoint listening on %s:%s",
            self.config.health_bind_host,
            self.config.health_port,
        )
        logger.info(
            "Fenrir metrics endpoint listening on %s:%s",
            self.config.metrics_bind_host,
            self.config.metrics_port,
        )

    async def _cleanup_http_servers(self) -> None:
        if self.health_runner is not None:
            await self.health_runner.cleanup()
            self.health_runner = None

        if self.metrics_runner is not None:
            await self.metrics_runner.cleanup()
            self.metrics_runner = None

    # ------------------------------------------------------------------
    # Mesh
    # ------------------------------------------------------------------

    async def register_node(self) -> None:
        if self.config.deployment_scope != "LOCAL_ONLY":
            raise RuntimeError(
                "Fenrir refuses non-local deployment scope"
            )

        if self.mesh_session is None:
            raise RuntimeError(
                "Mesh session has not been initialized"
            )

        payload = {
            "node_id": self.config.node_id,
            "type": "fenrir",
            "mode": self.config.mode.value,
            "deployment_scope": self.config.deployment_scope,
            "timestamp": utc_now(),
            "capabilities": [
                "local_monitoring",
                "tracking",
                "human_gated_reporting",
            ],
        }

        headers = {
            "Content-Type": "application/json",
        }

        if self.config.secret_token:
            headers["Authorization"] = (
                f"Bearer {self.config.secret_token}"
            )

        timeout = aiohttp.ClientTimeout(
            total=self.config.mesh_timeout
        )

        for attempt in range(
            1,
            self.config.max_retries + 1,
        ):
            try:
                async with self.mesh_session.post(
                    f"{self.config.mesh_registry_url}/register",
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                ) as response:
                    if response.status in {
                        200,
                        201,
                        202,
                    }:
                        self.metrics.successful_requests += 1
                        logger.info(
                            "Fenrir registered with mesh registry"
                        )
                        return

                    # Do not reflect arbitrary upstream body content into logs.
                    raise RuntimeError(
                        "Mesh registration failed with "
                        f"HTTP {response.status}"
                    )

            except (
                ClientError,
                asyncio.TimeoutError,
                RuntimeError,
            ) as exc:
                self.metrics.failed_requests += 1

                if attempt >= self.config.max_retries:
                    raise

                base_delay = min(
                    30.0,
                    self.config.retry_delay
                    * (2 ** (attempt - 1)),
                )
                delay = random.uniform(
                    0.0,
                    base_delay,
                )

                logger.warning(
                    "Fenrir mesh registration attempt %s/%s failed "
                    "(%s); retrying in %.2fs",
                    attempt,
                    self.config.max_retries,
                    type(exc).__name__,
                    delay,
                )

                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(),
                        timeout=delay,
                    )
                    raise asyncio.CancelledError
                except asyncio.TimeoutError:
                    pass

    # ------------------------------------------------------------------
    # Observation loop
    # ------------------------------------------------------------------

    async def record_local_observation(
        self,
        *,
        tracked: bool = True,
    ) -> None:
        """Record a local monitoring observation without external enforcement."""
        if self.shutdown_event.is_set():
            return

        self.transition_state(
            FenrirState.TRACKING
        )

        if tracked:
            self.metrics.targets_tracked += 1

        # ENGAGED here means "monitoring event produced", not enforcement.
        self.transition_state(
            FenrirState.ENGAGED
        )
        self.metrics.engagements += 1
        self.metrics.record_event(
            "local_monitoring_event",
            human_gated=True,
        )

        self.transition_state(
            FenrirState.HUNTING
        )

    async def _demo_tick(self) -> None:
        """Optional local-only synthetic event generator."""
        if not self.config.demo_simulation_enabled:
            return

        if not _is_local_environment():
            raise RuntimeError(
                "Fenrir demo simulation is local/test only"
            )

        if os.urandom(1)[0] < 32:
            await self.record_local_observation()

    async def hunting_loop(self) -> None:
        self.transition_state(
            FenrirState.HUNTING
        )
        logger.info(
            "Fenrir local monitoring loop online"
        )

        consecutive_errors = 0

        while not self.shutdown_event.is_set():
            try:
                await self._demo_tick()
                consecutive_errors = 0

                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(),
                        timeout=self.config.main_loop_interval,
                    )
                except asyncio.TimeoutError:
                    pass

            except asyncio.CancelledError:
                raise

            except Exception:
                consecutive_errors += 1
                self.metrics.errors += 1

                self.transition_state(
                    FenrirState.DEGRADED
                    if consecutive_errors >= 3
                    else FenrirState.ERROR
                )

                logger.exception(
                    "Fenrir monitoring-loop failure "
                    "(consecutive=%s)",
                    consecutive_errors,
                )

                base = min(
                    30.0,
                    self.config.retry_delay
                    * (2 ** min(consecutive_errors, 5)),
                )
                delay = random.uniform(
                    base * 0.5,
                    base,
                )

                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(),
                        timeout=delay,
                    )
                except asyncio.TimeoutError:
                    pass

                if not self.shutdown_event.is_set():
                    self.transition_state(
                        FenrirState.HUNTING
                    )

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def transition_state(
        self,
        new_state: FenrirState,
    ) -> None:
        if self.state == new_state:
            return

        old_state = self.state
        self.state = new_state
        self.metrics.state_transitions += 1

        self.metrics.record_event(
            "state_transition",
            old=old_state.value,
            new=new_state.value,
        )

        logger.info(
            "Fenrir state: %s -> %s",
            old_state.value,
            new_state.value,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._started:
            return

        if self.shutdown_event.is_set():
            raise RuntimeError(
                "FenrirNode cannot be restarted after shutdown"
            )

        connector = aiohttp.TCPConnector(
            ssl=self.ssl_context,
        )
        self.mesh_session = ClientSession(
            connector=connector,
            raise_for_status=False,
        )

        try:
            await self.register_node()
            await self._start_http_servers()

            self.main_task = asyncio.create_task(
                self.hunting_loop(),
                name=f"fenrir-{self.config.node_id}",
            )

            self._started = True

            logger.info(
                "Fenrir operational in %s / %s",
                self.config.deployment_scope,
                self.config.mode.value,
            )

        except Exception:
            await self.shutdown()
            raise

    async def shutdown(
        self,
        signal_name: str | None = None,
    ) -> None:
        async with self._shutdown_lock:
            if self.shutdown_event.is_set():
                return

            if signal_name:
                logger.warning(
                    "Fenrir received %s; shutting down",
                    signal_name,
                )
            else:
                logger.info(
                    "Fenrir shutdown requested"
                )

            self.shutdown_event.set()
            self.transition_state(
                FenrirState.DORMANT
            )

            task = self.main_task
            self.main_task = None

            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            await self._cleanup_http_servers()

            if self.mesh_session is not None:
                await self.mesh_session.close()
                self.mesh_session = None

            self._started = False

    async def main(self) -> None:
        loop = asyncio.get_running_loop()
        installed_signals: list[signal.Signals] = []

        for sig in (
            signal.SIGTERM,
            signal.SIGINT,
        ):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda s=sig.name: asyncio.create_task(
                        self.shutdown(s)
                    ),
                )
                installed_signals.append(sig)
            except (
                NotImplementedError,
                RuntimeError,
            ):
                logger.debug(
                    "Signal handlers unavailable on this platform"
                )

        try:
            await self.start()

            task = self.main_task
            if task is None:
                raise RuntimeError(
                    "Fenrir monitoring task did not start"
                )

            await task

        finally:
            await self.shutdown()

            for sig in installed_signals:
                try:
                    loop.remove_signal_handler(sig)
                except Exception:
                    pass


# =============================================================================
# Standalone entry point
# =============================================================================

def configure_logging(
    level: str = "INFO",
) -> None:
    logging.basicConfig(
        level=level.upper(),
        format=(
            "%(asctime)s | %(levelname)-8s | "
            "%(name)s | %(message)s"
        ),
    )


def run() -> None:
    try:
        config = FenrirConfig.from_environment()
        configure_logging(config.log_level)

        node = FenrirNode(config)
        asyncio.run(node.main())

    except ValidationError as exc:
        configure_logging("ERROR")
        logger.critical(
            "Fenrir configuration validation failed: %s",
            exc,
        )
        raise SystemExit(1) from exc

    except KeyboardInterrupt:
        logger.warning(
            "Fenrir stopped by keyboard interrupt"
        )

    except Exception as exc:
        logger.critical(
            "Fenrir stopped after fatal error: %s",
            exc,
            exc_info=True,
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    run()


__all__ = [
    "FenrirConfig",
    "FenrirMetrics",
    "FenrirMode",
    "FenrirNode",
    "FenrirState",
    "configure_logging",
    "run",
]
