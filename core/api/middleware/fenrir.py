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
import signal
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

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
except ImportError:  # Allows local standalone testing outside package root.
    from fenrir_auth import (  # type: ignore
        FenrirAuthConfig,
        FenrirAuthError,
        extract_bearer_token,
        verify_fenrir_token,
    )

logger = logging.getLogger("sentinel43.fenrir")


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


class FenrirConfig(BaseModel):
    node_id: str = Field(default="FENRIR-01", min_length=1)
    mesh_registry_url: str = Field(default="http://watchtower:8000/mesh")
    secret_token: str = Field(default="", min_length=0)
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    health_port: int = Field(default=8200, gt=1023, lt=65536)
    metrics_port: int = Field(default=9200, gt=1023, lt=65536)
    main_loop_interval: float = Field(default=2.0, gt=0.1, le=60.0)
    mesh_timeout: int = Field(default=30, gt=5, le=120)
    max_retries: int = Field(default=5, ge=1, le=10)
    retry_delay: float = Field(default=1.0, gt=0.0, le=10.0)
    mode: FenrirMode = Field(default=FenrirMode.HUMAN_GATED)
    deployment_scope: str = Field(default="LOCAL_ONLY")
    require_auth: bool = Field(default=True)
    verify_tls: bool = Field(default=True)

    @field_validator("mesh_registry_url")
    @classmethod
    def validate_mesh_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("mesh_registry_url must start with http:// or https://")
        return value.rstrip("/")

    @field_validator("deployment_scope")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if cleaned != "LOCAL_ONLY":
            raise ValueError("Fenrir is currently locked to LOCAL_ONLY deployment scope.")
        return cleaned

    @classmethod
    def from_environment(cls) -> "FenrirConfig":
        return cls(
            node_id=os.getenv("SENTINEL_FENRIR_NODE_ID", os.getenv("FENRIR_NODE_ID", "FENRIR-01")),
            mesh_registry_url=os.getenv("SENTINEL_FENRIR_MESH_REGISTRY_URL", os.getenv("FENRIR_MESH_REGISTRY_URL", "http://watchtower:8000/mesh")),
            secret_token=os.getenv("SENTINEL_FENRIR_SECRET_TOKEN", os.getenv("FENRIR_SECRET_TOKEN", "")),
            log_level=os.getenv("SENTINEL_FENRIR_LOG_LEVEL", os.getenv("FENRIR_LOG_LEVEL", "INFO")),
            health_port=int(os.getenv("SENTINEL_FENRIR_HEALTH_PORT", os.getenv("FENRIR_HEALTH_PORT", "8200"))),
            metrics_port=int(os.getenv("SENTINEL_FENRIR_METRICS_PORT", os.getenv("FENRIR_METRICS_PORT", "9200"))),
            main_loop_interval=float(os.getenv("SENTINEL_FENRIR_MAIN_LOOP_INTERVAL", os.getenv("FENRIR_MAIN_LOOP_INTERVAL", "2.0"))),
            mesh_timeout=int(os.getenv("SENTINEL_FENRIR_MESH_TIMEOUT", os.getenv("FENRIR_MESH_TIMEOUT", "30"))),
            max_retries=int(os.getenv("SENTINEL_FENRIR_MAX_RETRIES", os.getenv("FENRIR_MAX_RETRIES", "5"))),
            retry_delay=float(os.getenv("SENTINEL_FENRIR_RETRY_DELAY", os.getenv("FENRIR_RETRY_DELAY", "1"))),
            mode=FenrirMode(os.getenv("SENTINEL_FENRIR_MODE", os.getenv("FENRIR_MODE", "HUMAN_GATED")).upper()),
            deployment_scope=os.getenv("SENTINEL_DEPLOYMENT_SCOPE", os.getenv("FENRIR_DEPLOYMENT_SCOPE", "LOCAL_ONLY")),
            require_auth=os.getenv("SENTINEL_FENRIR_REQUIRE_AUTH", os.getenv("FENRIR_REQUIRE_AUTH", "true")).lower() == "true",
            verify_tls=os.getenv("SENTINEL_FENRIR_VERIFY_TLS", os.getenv("FENRIR_VERIFY_TLS", "true")).lower() == "true",
        )


@dataclass
class FenrirMetrics:
    targets_tracked: int = 0
    engagements: int = 0
    errors: int = 0
    state_transitions: int = 0
    request_count: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    last_event: Optional[Dict[str, Any]] = None
    started_at: float = field(default_factory=time.time)

    def record_event(self, event_type: str, **extra: Any) -> None:
        self.last_event = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **extra,
        }

    def as_dict(self) -> Dict[str, Any]:
        uptime_seconds = max(0, int(time.time() - self.started_at))
        return {
            "targets_tracked": self.targets_tracked,
            "engagements": self.engagements,
            "errors": self.errors,
            "state_transitions": self.state_transitions,
            "request_count": self.request_count,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "last_event": self.last_event,
            "uptime_seconds": uptime_seconds,
        }


class FenrirNode:
    """
    Local-only Sentinel-43 monitoring node.

    Fenrir observes, reports, and stages monitoring intelligence. It does not perform
    external enforcement. Any future enforcement path must go through Sentinel-43's
    human-gated approval layer.
    """

    def __init__(self, config: FenrirConfig, auth_config: Optional[FenrirAuthConfig] = None) -> None:
        self.config = config
        self.auth_config = auth_config or FenrirAuthConfig.from_env()
        self.state = FenrirState.INITIALIZING
        self.metrics = FenrirMetrics()
        self.app_runner: Optional[web.AppRunner] = None
        self.mesh_session: Optional[ClientSession] = None
        self.main_task: Optional[asyncio.Task[None]] = None
        self.shutdown_event = asyncio.Event()
        self.ssl_context = self._create_ssl_context()

        logger.setLevel(self.config.log_level)
        logger.info("Fenrir initializing: %s", self._safe_config_for_logs())

    def _safe_config_for_logs(self) -> str:
        data = self.config.model_dump()
        if data.get("secret_token"):
            data["secret_token"] = "<redacted>"
        return json.dumps(data, sort_keys=True, default=str)

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.config.verify_tls:
            return ssl.create_default_context()
        logger.warning("TLS verification disabled for Fenrir mesh client. Dev/local only.")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def transition_state(self, new_state: FenrirState) -> None:
        if self.state == new_state:
            return
        old_state = self.state
        self.state = new_state
        self.metrics.state_transitions += 1
        self.metrics.record_event("state_transition", old=old_state.value, new=new_state.value)
        logger.info("Fenrir state transition: %s -> %s", old_state.value, new_state.value)

    async def _require_scope(self, request: web.Request, scope: str) -> Dict[str, Any]:
        if not self.config.require_auth:
            return {"sub": "auth-disabled", "scope": "*"}
        token = extract_bearer_token(request.headers.get("Authorization"))
        return verify_fenrir_token(token or "", self.auth_config, required_scope=scope)

    async def health_check(self, request: web.Request) -> web.Response:
        self.metrics.request_count += 1
        try:
            await self._require_scope(request, "fenrir:read")
            self.metrics.successful_requests += 1
            return web.json_response(
                {
                    "status": self.state.value,
                    "node_id": self.config.node_id,
                    "mode": self.config.mode.value,
                    "deployment_scope": self.config.deployment_scope,
                    "metrics": self.metrics.as_dict(),
                }
            )
        except FenrirAuthError as exc:
            self.metrics.failed_requests += 1
            return web.json_response({"error": "unauthorized", "message": str(exc)}, status=401)

    async def metrics_check(self, request: web.Request) -> web.Response:
        self.metrics.request_count += 1
        try:
            await self._require_scope(request, "fenrir:read")
            self.metrics.successful_requests += 1
            return web.json_response(self.metrics.as_dict())
        except FenrirAuthError as exc:
            self.metrics.failed_requests += 1
            return web.json_response({"error": "unauthorized", "message": str(exc)}, status=401)

    async def start_health_server(self) -> None:
        app = web.Application()
        app.router.add_get("/health", self.health_check)
        app.router.add_get("/metrics", self.metrics_check)

        self.app_runner = web.AppRunner(app)
        await self.app_runner.setup()
        site = web.TCPSite(self.app_runner, "0.0.0.0", self.config.health_port)
        await site.start()
        logger.info("Fenrir health server running on port %s", self.config.health_port)

    async def register_node(self) -> None:
        if self.config.deployment_scope != "LOCAL_ONLY":
            raise RuntimeError("Fenrir refuses non-local deployment scope.")

        if not self.mesh_session:
            raise RuntimeError("Mesh session has not been initialized.")

        payload = {
            "node_id": self.config.node_id,
            "type": "fenrir",
            "mode": self.config.mode.value,
            "deployment_scope": self.config.deployment_scope,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "capabilities": ["local_monitoring", "tracking", "human_gated_reporting"],
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
                    raise RuntimeError(f"Mesh registration failed: {response.status} {body[:300]}")
            except (ClientError, asyncio.TimeoutError, RuntimeError) as exc:
                self.metrics.failed_requests += 1
                if attempt >= self.config.max_retries:
                    raise
                delay = min(30.0, self.config.retry_delay * (2 ** (attempt - 1)))
                logger.warning("Fenrir mesh registration attempt %s failed: %s. Retrying in %.1fs", attempt, exc, delay)
                await asyncio.sleep(delay)

    async def simulate_target_acquisition(self) -> bool:
        # Local-only simulation placeholder until real local signal adapters are wired in.
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
                    logger.info("Fenrir generated local-only monitoring event. No enforcement executed.")
                    await asyncio.sleep(1.0)

                    self.metrics.targets_tracked += 1
                    self.metrics.engagements += 1
                    self.metrics.record_event("local_monitoring_event", human_gated=True)
                    self.transition_state(FenrirState.HUNTING)

                consecutive_errors = 0
                await asyncio.wait_for(self.shutdown_event.wait(), timeout=self.config.main_loop_interval)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                logger.info("Fenrir monitoring loop cancelled.")
                raise
            except Exception as exc:
                consecutive_errors += 1
                self.metrics.errors += 1
                logger.exception("Fenrir loop error: %s", exc)
                self.transition_state(FenrirState.DEGRADED if consecutive_errors >= 3 else FenrirState.ERROR)
                await asyncio.sleep(min(30.0, self.config.retry_delay * (2 ** min(consecutive_errors, 5))))
                self.transition_state(FenrirState.HUNTING)

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
                loop.add_signal_handler(sig, lambda s=sig.name: asyncio.create_task(self.shutdown(s)))
            except NotImplementedError:
                # Windows event loops may not support add_signal_handler.
                logger.debug("Signal handlers unavailable on this platform.")

        connector = aiohttp.TCPConnector(ssl=self.ssl_context)
        self.mesh_session = ClientSession(connector=connector)

        try:
            await self.register_node()
            await self.start_health_server()
            logger.info("Fenrir operational in %s / %s", self.config.deployment_scope, self.config.mode.value)
            self.main_task = asyncio.create_task(self.hunting_loop())
            await self.main_task
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Fenrir fatal startup/runtime error.")
            await self.shutdown()
            raise


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
