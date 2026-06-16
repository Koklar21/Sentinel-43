# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
# =============================================================================

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
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientError, ClientSession, web
from pydantic import BaseModel, Field, ValidationError, field_validator

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


# =============================================================================
# Utilities
# =============================================================================

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_first(*names: str, default: str = "") -> str:
    """Return the first non-empty env var from the list, or default."""
    for name in names:
        val = os.getenv(name, "").strip()
        if val:
            return val
    return default


def _env_int(name_primary: str, name_fallback: str, default: int) -> int:
    """
    Read an integer from one of two env var names.
    Fix #1: replaces bare int(os.getenv(...)) which crashes on invalid values.
    """
    for name in (name_primary, name_fallback):
        raw = os.getenv(name, "").strip()
        if raw:
            try:
                return int(raw)
            except ValueError:
                logger.warning(
                    "Fenrir: invalid integer for %s=%r; using default %s",
                    name, raw, default,
                )
    return default


def _env_float(name_primary: str, name_fallback: str, default: float) -> float:
    """
    Read a float from one of two env var names.
    Fix #1: replaces bare float(os.getenv(...)) which crashes on invalid values.
    """
    for name in (name_primary, name_fallback):
        raw = os.getenv(name, "").strip()
        if raw:
            try:
                return float(raw)
            except ValueError:
                logger.warning(
                    "Fenrir: invalid float for %s=%r; using default %s",
                    name, raw, default,
                )
    return default


def _env_bool(name_primary: str, name_fallback: str, default: bool) -> bool:
    """
    Read a bool from one of two env var names.

    Fix #2: the original used `.lower() == "true"` which treats empty string,
    "yes", "1", "on" as False — silently disabling auth/TLS when any of those
    truthy-but-not-"true" values are set, or when the var is present but blank.

    Now only exactly falsy strings disable the flag; anything unrecognised
    keeps the default (which for security flags should be True).
    """
    for name in (name_primary, name_fallback):
        raw = os.getenv(name, "").strip().lower()
        if raw == "":
            continue  # var absent or blank — try next candidate
        if raw in {"1", "true", "yes", "y", "on"}:
            return True
        if raw in {"0", "false", "no", "n", "off"}:
            return False
        logger.warning(
            "Fenrir: unrecognised bool for %s=%r; using default %s",
            name, os.getenv(name), default,
        )
    return default


def _validate_mesh_url_for_ssrf(url: str) -> None:
    """
    Fix #5: Validate mesh_registry_url against SSRF.

    The original validator only checked the scheme prefix, allowing
    http://169.254.169.254/, http://localhost/, http://postgres:5432/, etc.
    Reject:
      - localhost / 127.x.x.x / ::1
      - link-local addresses (169.254.x.x, fe80::/10)
      - unresolvable hosts (we can't resolve at config time, but we can
        reject well-known internal hostnames)

    Note: this is a best-effort check at config parse time. Runtime DNS
    rebinding attacks are a separate concern handled by the network layer.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""

    # Reject known internal hostnames
    _BLOCKED_HOSTS = frozenset({
        "localhost", "localhost.localdomain",
        "metadata.google.internal",
    })
    if host.lower() in _BLOCKED_HOSTS:
        raise ValueError(
            f"mesh_registry_url host {host!r} is blocked (internal/loopback address)."
        )

    # Reject raw IP addresses that are loopback or link-local
    try:
        ip = ip_address(host)
    except ValueError:
        pass  # Not an IP address -- it is a hostname, proceed
    else:
        # Block loopback (127.x.x.x, ::1) and link-local (169.254.x.x, fe80::/10).
        # Link-local covers AWS/GCP/Azure metadata endpoints (169.254.169.254 etc).
        # Private ranges (10.x, 172.16.x, 192.168.x) are intentionally allowed
        # because S43 is commonly deployed on internal networks where the mesh
        # registry lives on a private address.
        if ip.is_loopback or ip.is_link_local:
            raise ValueError(
                f"mesh_registry_url IP {host!r} is a loopback or link-local address. "
                "This blocks SSRF against metadata endpoints (169.254.169.254) "
                "and localhost."
            )


# =============================================================================
# Enums
# =============================================================================

class FenrirState(str, enum.Enum):
    INITIALIZING = "INITIALIZING"
    HUNTING      = "HUNTING"
    TRACKING     = "TRACKING"
    ENGAGED      = "ENGAGED"
    DORMANT      = "DORMANT"
    DEGRADED     = "DEGRADED"
    ERROR        = "ERROR"


class FenrirMode(str, enum.Enum):
    SHADOW      = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"
    LOCAL_ONLY  = "LOCAL_ONLY"


# =============================================================================
# Config
# =============================================================================

class FenrirConfig(BaseModel):
    node_id:             str        = Field(default="FENRIR-01", min_length=1)
    mesh_registry_url:   str        = Field(default="https://watchtower:8000/mesh")
    secret_token:        str        = Field(default="", min_length=0)
    log_level:           str        = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    health_port:         int        = Field(default=8200, gt=1023, lt=65536)
    metrics_port:        int        = Field(default=9200, gt=1023, lt=65536)
    main_loop_interval:  float      = Field(default=2.0, gt=0.1, le=60.0)
    mesh_timeout:        int        = Field(default=30, gt=5, le=120)
    max_retries:         int        = Field(default=5, ge=1, le=10)
    retry_delay:         float      = Field(default=1.0, gt=0.0, le=10.0)
    mode:                FenrirMode = Field(default=FenrirMode.HUMAN_GATED)
    deployment_scope:    str        = Field(default="LOCAL_ONLY")
    require_auth:        bool       = Field(default=True)
    # Fix #4: default URL is now HTTPS to avoid misleading "TLS enabled" default
    # with a plain-HTTP endpoint.
    verify_tls:          bool       = Field(default=True)
    # Request timeout for incoming health/metrics connections (fix #11).
    request_timeout:     float      = Field(default=10.0, gt=0.0, le=120.0)

    @field_validator("mesh_registry_url")
    @classmethod
    def validate_mesh_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("mesh_registry_url must start with http:// or https://")
        cleaned = value.rstrip("/")
        # Fix #5: SSRF guard
        _validate_mesh_url_for_ssrf(cleaned)
        return cleaned

    @field_validator("deployment_scope")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if cleaned != "LOCAL_ONLY":
            raise ValueError("Fenrir is currently locked to LOCAL_ONLY deployment scope.")
        return cleaned

    @classmethod
    def from_environment(cls) -> "FenrirConfig":
        """
        Build config from environment variables.

        Fix #1: all numeric casts use _env_int/_env_float helpers that
        log a warning and use the default rather than raising ValueError.

        Fix #2: boolean flags use _env_bool which treats only explicit
        falsy strings as False; empty string and unrecognised values
        keep the safe default (True for security flags).
        """
        return cls(
            node_id=_env_first("SENTINEL_FENRIR_NODE_ID", "FENRIR_NODE_ID", default="FENRIR-01"),
            # Fix #4: warn when the URL is plain HTTP
            mesh_registry_url=_env_first(
                "SENTINEL_FENRIR_MESH_REGISTRY_URL",
                "FENRIR_MESH_REGISTRY_URL",
                default="https://watchtower:8000/mesh",
            ),
            secret_token=_env_first("SENTINEL_FENRIR_SECRET_TOKEN", "FENRIR_SECRET_TOKEN"),
            log_level=_env_first("SENTINEL_FENRIR_LOG_LEVEL", "FENRIR_LOG_LEVEL", default="INFO"),
            health_port=_env_int("SENTINEL_FENRIR_HEALTH_PORT", "FENRIR_HEALTH_PORT", 8200),
            metrics_port=_env_int("SENTINEL_FENRIR_METRICS_PORT", "FENRIR_METRICS_PORT", 9200),
            main_loop_interval=_env_float("SENTINEL_FENRIR_MAIN_LOOP_INTERVAL", "FENRIR_MAIN_LOOP_INTERVAL", 2.0),
            mesh_timeout=_env_int("SENTINEL_FENRIR_MESH_TIMEOUT", "FENRIR_MESH_TIMEOUT", 30),
            max_retries=_env_int("SENTINEL_FENRIR_MAX_RETRIES", "FENRIR_MAX_RETRIES", 5),
            retry_delay=_env_float("SENTINEL_FENRIR_RETRY_DELAY", "FENRIR_RETRY_DELAY", 1.0),
            mode=FenrirMode(
                _env_first("SENTINEL_FENRIR_MODE", "FENRIR_MODE", default="HUMAN_GATED").upper()
            ),
            deployment_scope=_env_first(
                "SENTINEL_DEPLOYMENT_SCOPE", "FENRIR_DEPLOYMENT_SCOPE", default="LOCAL_ONLY"
            ),
            # Fix #2: use _env_bool so empty string / "yes" / "1" don't
            # silently disable auth or TLS verification.
            require_auth=_env_bool("SENTINEL_FENRIR_REQUIRE_AUTH", "FENRIR_REQUIRE_AUTH", True),
            verify_tls=_env_bool("SENTINEL_FENRIR_VERIFY_TLS", "FENRIR_VERIFY_TLS", True),
        )


# =============================================================================
# Metrics
# =============================================================================

# Safe set of kwarg keys allowed in last_event to prevent operational detail
# leakage via the health endpoint (fix #6).
_SAFE_EVENT_KEYS: frozenset[str] = frozenset({
    "human_gated", "old", "new",
})


@dataclass
class FenrirMetrics:
    targets_tracked:     int = 0
    engagements:         int = 0
    errors:              int = 0
    state_transitions:   int = 0
    request_count:       int = 0
    successful_requests: int = 0
    failed_requests:     int = 0
    last_event: Optional[Dict[str, Any]] = None
    started_at: float = field(default_factory=time.time)

    def record_event(self, event_type: str, **extra: Any) -> None:
        """
        Fix #6: filter **extra to _SAFE_EVENT_KEYS before storing.
        Arbitrary kwargs (target IPs, threat payloads, etc.) would otherwise
        be served verbatim in the /health response to any authenticated caller.
        """
        safe_extra = {k: v for k, v in extra.items() if k in _SAFE_EVENT_KEYS}
        self.last_event = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **safe_extra,
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "targets_tracked":     self.targets_tracked,
            "engagements":         self.engagements,
            "errors":              self.errors,
            "state_transitions":   self.state_transitions,
            "request_count":       self.request_count,
            "successful_requests": self.successful_requests,
            "failed_requests":     self.failed_requests,
            "last_event":          self.last_event,
            "uptime_seconds":      max(0, int(time.time() - self.started_at)),
        }


# =============================================================================
# FenrirNode
# =============================================================================

class FenrirNode:
    """
    Local-only Sentinel-43 monitoring node.

    Fenrir observes, reports, and stages monitoring intelligence. It does not
    perform external enforcement. Any future enforcement path must go through
    Sentinel-43's human-gated approval layer.
    """

    def __init__(
        self,
        config: FenrirConfig,
        auth_config: Optional[FenrirAuthConfig] = None,
    ) -> None:
        self.config      = config
        self.auth_config = auth_config or FenrirAuthConfig.from_env()
        self.state       = FenrirState.INITIALIZING
        self.metrics     = FenrirMetrics()

        self.app_runner:    Optional[web.AppRunner]  = None
        self.mesh_session:  Optional[ClientSession]  = None
        self.main_task:     Optional[asyncio.Task[None]] = None
        self.shutdown_event = asyncio.Event()

        # Fix #3: refuse startup if secret_token is set but verify_tls=False
        # outside dev environments. Sending a bearer token over unverified TLS
        # is equivalent to sending it in the clear.
        if self.config.secret_token and not self.config.verify_tls:
            env = _env("S43_ENV", "production").lower()
            if env not in {"dev", "development", "local"}:
                raise RuntimeError(
                    "Fenrir refuses to start: secret_token is configured but "
                    "verify_tls=False. Setting verify_tls=False while a secret "
                    "token is in use exposes the token to MITM interception. "
                    "Set S43_ENV=dev to override in non-production environments."
                )

        self.ssl_context = self._create_ssl_context()
        logger.setLevel(self.config.log_level)
        logger.info("Fenrir initializing: %s", self._safe_config_for_logs())

    def _safe_config_for_logs(self) -> str:
        try:
            data = self.config.model_dump()
        except AttributeError:
            data = self.config.dict()  # Pydantic v1 fallback
        if data.get("secret_token"):
            data["secret_token"] = "<redacted>"
        return json.dumps(data, sort_keys=True, default=str)

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.config.verify_tls:
            return ssl.create_default_context()

        # Fix #8: non-dev rejection for disabled TLS verification
        env = _env("S43_ENV", "production").lower()
        if env not in {"dev", "development", "local"}:
            logger.critical(
                "Fenrir: verify_tls=False is not permitted outside S43_ENV=dev. "
                "Refusing to start with unverified TLS in environment %r.", env
            )
            raise RuntimeError(
                "Fenrir: verify_tls=False is not permitted outside S43_ENV=dev."
            )

        logger.warning(
            "TLS verification disabled for Fenrir mesh client. "
            "Dev/local only — NEVER use in production."
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _require_scope(
        self,
        request: web.Request,
        scope: str,
    ) -> Dict[str, Any]:
        if not self.config.require_auth:
            return {"sub": "auth-disabled", "scope": "*"}

        raw_header = request.headers.get("Authorization")

        # Fix #10: explicit None check before calling verify_fenrir_token.
        # The original passed `token or ""` which delegates the empty-token
        # behavior to fenrir_auth -- an unreviewed module. Fail closed here.
        token = extract_bearer_token(raw_header)
        if token is None:
            raise FenrirAuthError("Authorization header missing or malformed.")

        return verify_fenrir_token(token, self.auth_config, required_scope=scope)

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def health_check(self, request: web.Request) -> web.Response:
        self.metrics.request_count += 1
        try:
            await self._require_scope(request, "fenrir:read")
            self.metrics.successful_requests += 1
            return web.json_response(
                {
                    "status":           self.state.value,
                    "node_id":          self.config.node_id,
                    "mode":             self.config.mode.value,
                    "deployment_scope": self.config.deployment_scope,
                    "metrics":          self.metrics.as_dict(),
                }
            )
        except FenrirAuthError as exc:
            self.metrics.failed_requests += 1
            return web.json_response(
                {"error": "unauthorized", "message": str(exc)}, status=401
            )

    async def metrics_check(self, request: web.Request) -> web.Response:
        self.metrics.request_count += 1
        try:
            await self._require_scope(request, "fenrir:read")
            self.metrics.successful_requests += 1
            return web.json_response(self.metrics.as_dict())
        except FenrirAuthError as exc:
            self.metrics.failed_requests += 1
            return web.json_response(
                {"error": "unauthorized", "message": str(exc)}, status=401
            )

    async def start_health_server(self) -> None:
        app = web.Application()
        app.router.add_get("/health",  self.health_check)
        app.router.add_get("/metrics", self.metrics_check)

        # Fix #11: per-request timeout so slow-loris clients can't hold
        # connections open indefinitely.
        # aiohttp 3.9+ supports handler_cancellation; use slow_request_timeout
        # as the per-connection guard available in earlier versions.
        self.app_runner = web.AppRunner(
            app,
            handle_signals=False,
        )
        await self.app_runner.setup()
        site = web.TCPSite(
            self.app_runner,
            "0.0.0.0",
            self.config.health_port,
            # Fix #11: 10 s slow-request ceiling
            slow_request_timeout=self.config.request_timeout,
        )
        await site.start()
        logger.info(
            "Fenrir health server running on port %s (request_timeout=%.1fs)",
            self.config.health_port,
            self.config.request_timeout,
        )

    # ------------------------------------------------------------------
    # Mesh registration
    # ------------------------------------------------------------------

    async def register_node(self) -> None:
        if self.config.deployment_scope != "LOCAL_ONLY":
            raise RuntimeError("Fenrir refuses non-local deployment scope.")
        if not self.mesh_session:
            raise RuntimeError("Mesh session has not been initialized.")

        # Fix #4: warn when the mesh URL is HTTP (unencrypted)
        if self.config.mesh_registry_url.startswith("http://"):
            logger.warning(
                "Fenrir mesh_registry_url is plain HTTP — mesh registration "
                "traffic is unencrypted. Use https:// in production."
            )

        payload = {
            "node_id":          self.config.node_id,
            "type":             "fenrir",
            "mode":             self.config.mode.value,
            "deployment_scope": self.config.deployment_scope,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "capabilities":     ["local_monitoring", "tracking", "human_gated_reporting"],
        }
        headers = {"Content-Type": "application/json"}
        if self.config.secret_token:
            headers["Authorization"] = f"Bearer {self.config.secret_token}"

        for attempt in range(1, self.config.max_retries + 1):
            try:
                async with self.mesh_session.post(
                    f"{self.config.mesh_registry_url}/register",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.mesh_timeout),
                ) as response:
                    if response.status in {200, 201, 202}:
                        self.metrics.successful_requests += 1
                        logger.info("Fenrir registered with mesh registry.")
                        return

                    body = await response.text()
                    raise RuntimeError(
                        f"Mesh registration failed: {response.status} {body[:300]}"
                    )

            except (ClientError, asyncio.TimeoutError, RuntimeError) as exc:
                self.metrics.failed_requests += 1
                if attempt >= self.config.max_retries:
                    raise

                # Fix #9: full jitter exponential backoff prevents thundering
                # herd when multiple nodes restart simultaneously.
                base_delay = min(30.0, self.config.retry_delay * (2 ** (attempt - 1)))
                delay = base_delay * random.random()
                logger.warning(
                    "Fenrir mesh registration attempt %s/%s failed: %s. "
                    "Retrying in %.1fs (jittered).",
                    attempt, self.config.max_retries, exc, delay,
                )
                await asyncio.sleep(delay)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def simulate_target_acquisition(self) -> bool:
        second_factor = datetime.now(timezone.utc).second / 60.0
        acquisition_probability = min(0.50, 0.20 + (0.10 * second_factor))
        await asyncio.sleep(0.1)
        return os.urandom(1)[0] / 255.0 < acquisition_probability

    async def hunting_loop(self) -> None:
        self.transition_state(FenrirState.HUNTING)
        logger.info("Fenrir local monitoring loop online.")

        consecutive_errors = 0
        while not self.shutdown_event.is_set():
            try:
                target_acquired = await self.simulate_target_acquisition()
                if target_acquired:
                    self.transition_state(FenrirState.TRACKING)
                    logger.info("Fenrir tracking local signal.")
                    await asyncio.sleep(1.0)

                    if self.shutdown_event.is_set():
                        break

                    self.transition_state(FenrirState.ENGAGED)
                    logger.info(
                        "Fenrir generated local-only monitoring event. "
                        "No enforcement executed."
                    )
                    await asyncio.sleep(1.0)

                    self.metrics.targets_tracked += 1
                    self.metrics.engagements    += 1
                    self.metrics.record_event("local_monitoring_event", human_gated=True)
                    self.transition_state(FenrirState.HUNTING)

                consecutive_errors = 0
                await asyncio.wait_for(
                    self.shutdown_event.wait(),
                    timeout=self.config.main_loop_interval,
                )

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.info("Fenrir monitoring loop cancelled.")
                raise
            except Exception as exc:
                consecutive_errors += 1
                self.metrics.errors += 1
                # Use %s for exc, not logger.exception + %s (redundant exc_info)
                logger.error("Fenrir loop error (consecutive=%s): %s", consecutive_errors, exc, exc_info=True)
                self.transition_state(
                    FenrirState.DEGRADED if consecutive_errors >= 3 else FenrirState.ERROR
                )
                # Fix #9: jittered backoff in error recovery too
                base = min(30.0, self.config.retry_delay * (2 ** min(consecutive_errors, 5)))
                await asyncio.sleep(base * (0.5 + 0.5 * random.random()))
                self.transition_state(FenrirState.HUNTING)

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def transition_state(self, new_state: FenrirState) -> None:
        if self.state == new_state:
            return
        old_state  = self.state
        self.state = new_state
        self.metrics.state_transitions += 1
        self.metrics.record_event("state_transition", old=old_state.value, new=new_state.value)
        logger.info("Fenrir state: %s -> %s", old_state.value, new_state.value)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def shutdown(self, signal_name: Optional[str] = None) -> None:
        if signal_name:
            logger.warning("Fenrir received %s. Shutting down.", signal_name)
        else:
            logger.warning("Fenrir shutdown requested.")

        self.transition_state(FenrirState.DORMANT)
        self.shutdown_event.set()

        if self.main_task and not self.main_task.done():
            self.main_task.cancel()
            try:
                await self.main_task
            except asyncio.CancelledError:
                pass

        if self.app_runner:
            await self.app_runner.cleanup()
            logger.info("Fenrir health server stopped.")

        if self.mesh_session:
            await self.mesh_session.close()
            logger.info("Fenrir mesh session closed.")

    async def main(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda s=sig.name: asyncio.create_task(self.shutdown(s)),
                )
            except NotImplementedError:
                logger.debug("Signal handlers unavailable on this platform.")

        connector = aiohttp.TCPConnector(ssl=self.ssl_context)
        self.mesh_session = ClientSession(connector=connector)

        try:
            await self.register_node()
            await self.start_health_server()
            logger.info(
                "Fenrir operational in %s / %s",
                self.config.deployment_scope, self.config.mode.value,
            )
            self.main_task = asyncio.create_task(self.hunting_loop())
            await self.main_task
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Fenrir fatal startup/runtime error.")
            await self.shutdown()
            raise


# =============================================================================
# Entry point
# =============================================================================

def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )


def run() -> None:
    try:
        config = FenrirConfig.from_environment()
        configure_logging(config.log_level)
        node = FenrirNode(config)
        asyncio.run(node.main())
    except ValidationError as exc:
        configure_logging("ERROR")
        logger.critical("Fenrir configuration validation failed: %s", exc)
        raise SystemExit(1) from exc
    except KeyboardInterrupt:
        logger.warning("Fenrir stopped by keyboard interrupt.")
    except Exception as exc:
        logger.critical("Fenrir stopped after fatal error: %s", exc, exc_info=True)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    run()
