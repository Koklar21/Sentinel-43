"""
Sentinel-43 Watchtower Node
v1.2.1 Hardened Interconnect

Docker command:
python -m core.monitoring.watchtower

Production command:
uvicorn core.monitoring.watchtower:app --host 0.0.0.0 --port 9100
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import logging
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


logger = logging.getLogger("SentinelWatchtower")


def configure_logging() -> None:
    if logging.getLogger().handlers:
        return

    logging.basicConfig(
        level=os.getenv("S43_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


configure_logging()


# ============================================================
# Thresholds
# ============================================================

@dataclass(frozen=True)
class ThresholdProfile:
    error_rate_percent: int
    expectation_fail_count: int
    stale_config_seconds: int
    cpu_percent: int
    memory_percent: int
    disk_percent: int


def thresholds_for(sensitivity: int) -> ThresholdProfile:
    s = max(1, min(int(sensitivity), 10))

    return ThresholdProfile(
        error_rate_percent=max(5, 55 - (s * 5)),
        expectation_fail_count=max(1, 12 - s),
        stale_config_seconds=max(60, 900 - (s * 60)),
        cpu_percent=max(60, 98 - (s * 3)),
        memory_percent=max(60, 98 - (s * 3)),
        disk_percent=max(70, 99 - (s * 2)),
    )


# ============================================================
# Utilities
# ============================================================

def _now() -> float:
    return time.time()


def _clamp_int(name: str, value: Any, lo: int, hi: int) -> int:
    try:
        iv = int(value)
    except Exception as exc:
        raise ValueError(f"{name} must be an int in [{lo}, {hi}], got {value!r}") from exc

    if not lo <= iv <= hi:
        raise ValueError(f"{name} must be in [{lo}, {hi}], got {iv}")

    return iv


def _safe_metric_int(raw: Any, default: int = 0) -> tuple[int, int]:
    if isinstance(raw, bool):
        return default, 1

    try:
        return int(float(raw)), 0
    except (TypeError, ValueError):
        return default, 1


def _assign_event_id(event: dict[str, Any]) -> str:
    event_id = event.get("id")

    if isinstance(event_id, str) and event_id.strip():
        return event_id

    new_id = str(uuid.uuid4())
    event["id"] = new_id
    return new_id


# ============================================================
# Enums
# ============================================================

class WatchtowerState(enum.Enum):
    INITIALIZING = "INITIALIZING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class TowerSlot(enum.Enum):
    N = "N"
    NE = "NE"
    E = "E"
    SE = "SE"
    S = "S"
    SW = "SW"
    W = "W"
    NW = "NW"


class TowerType(enum.Enum):
    API_HEALTH = "API_HEALTH"
    EXPECTATION_GUARD = "EXPECTATION_GUARD"
    CONFIG_DRIFT = "CONFIG_DRIFT"
    LOGGING_AUDIT = "LOGGING_AUDIT"
    ERROR_RATE = "ERROR_RATE"
    DEPENDENCY_HEALTH = "DEPENDENCY_HEALTH"
    RESOURCE_PRESSURE = "RESOURCE_PRESSURE"
    SECURITY_BASELINE = "SECURITY_BASELINE"


# ============================================================
# Config
# ============================================================

@dataclass(frozen=True)
class TowerConfig:
    name: str
    slot: TowerSlot
    tower_type: TowerType
    enabled: bool = True
    sensitivity: int = 5

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("tower name must be non-empty")

        if not isinstance(self.slot, TowerSlot):
            raise TypeError("slot must be TowerSlot")

        if not isinstance(self.tower_type, TowerType):
            raise TypeError("tower_type must be TowerType")

        object.__setattr__(
            self,
            "sensitivity",
            _clamp_int("sensitivity", self.sensitivity, 1, 10),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "slot": self.slot.value,
            "tower_type": self.tower_type.value,
            "enabled": self.enabled,
            "sensitivity": self.sensitivity,
        }


@dataclass(frozen=True)
class WatchtowerConfig:
    node_id: str
    environment: str = "production"
    host: str = "0.0.0.0"
    port: int = 9100
    towers: tuple[TowerConfig, ...] = field(default_factory=tuple)
    scan_failure_degrade_threshold: int = 2
    module_stale_seconds: int = 60
    max_recent_events: int = 250

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id.strip():
            raise ValueError("node_id must be non-empty")

        object.__setattr__(self, "port", _clamp_int("port", self.port, 1024, 65535))
        object.__setattr__(
            self,
            "scan_failure_degrade_threshold",
            _clamp_int(
                "scan_failure_degrade_threshold",
                self.scan_failure_degrade_threshold,
                1,
                100,
            ),
        )
        object.__setattr__(
            self,
            "module_stale_seconds",
            _clamp_int("module_stale_seconds", self.module_stale_seconds, 5, 3600),
        )
        object.__setattr__(
            self,
            "max_recent_events",
            _clamp_int("max_recent_events", self.max_recent_events, 10, 5000),
        )
        object.__setattr__(self, "towers", tuple(self.towers))

    @property
    def api_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @classmethod
    def default_sentinel_octagon(cls, node_id: str) -> "WatchtowerConfig":
        return cls(
            node_id=node_id,
            environment=os.getenv("S43_ENV", "production"),
            host=os.getenv("S43_WATCHTOWER_HOST", "0.0.0.0"),
            port=_clamp_int(
                "S43_WATCHTOWER_PORT",
                os.getenv("S43_WATCHTOWER_PORT", "9100"),
                1024,
                65535,
            ),
            module_stale_seconds=_clamp_int(
                "S43_MODULE_STALE_SECONDS",
                os.getenv("S43_MODULE_STALE_SECONDS", "60"),
                5,
                3600,
            ),
            max_recent_events=_clamp_int(
                "S43_WATCHTOWER_MAX_EVENTS",
                os.getenv("S43_WATCHTOWER_MAX_EVENTS", "250"),
                10,
                5000,
            ),
            towers=(
                TowerConfig("API Health Sentinel", TowerSlot.N, TowerType.API_HEALTH, sensitivity=5),
                TowerConfig("Expectation Guard", TowerSlot.NE, TowerType.EXPECTATION_GUARD, sensitivity=7),
                TowerConfig("Config Drift Sentinel", TowerSlot.E, TowerType.CONFIG_DRIFT, sensitivity=6),
                TowerConfig("Logging Audit Sentinel", TowerSlot.SE, TowerType.LOGGING_AUDIT, sensitivity=5),
                TowerConfig("Error Rate Sentinel", TowerSlot.S, TowerType.ERROR_RATE, sensitivity=7),
                TowerConfig("Dependency Health Sentinel", TowerSlot.SW, TowerType.DEPENDENCY_HEALTH, sensitivity=5),
                TowerConfig("Resource Pressure Sentinel", TowerSlot.W, TowerType.RESOURCE_PRESSURE, sensitivity=6),
                TowerConfig("Security Baseline Sentinel", TowerSlot.NW, TowerType.SECURITY_BASELINE, sensitivity=6),
            ),
        )

    def to_dict(self, expose_bind_host: bool = False) -> dict[str, Any]:
        payload = {
            "node_id": self.node_id,
            "environment": self.environment,
            "port": self.port,
            "api_url": self.api_url,
            "scan_failure_degrade_threshold": self.scan_failure_degrade_threshold,
            "module_stale_seconds": self.module_stale_seconds,
            "max_recent_events": self.max_recent_events,
            "towers": [tower.to_dict() for tower in self.towers],
        }

        if expose_bind_host:
            payload["host"] = self.host

        return payload


# ============================================================
# API Models
# ============================================================

class AnalyzeRequest(BaseModel):
    event: dict[str, Any] = Field(default_factory=dict)


class ModuleRegisterRequest(BaseModel):
    module_id: str = Field(min_length=1)
    module_type: str = Field(default="generic")
    version: str = Field(default="unknown")
    endpoint: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModuleHeartbeatRequest(BaseModel):
    module_id: str = Field(min_length=1)
    status: str = Field(default="online")
    metrics: dict[str, Any] = Field(default_factory=dict)
    message: str | None = None


class DependencyReportRequest(BaseModel):
    name: str = Field(min_length=1)
    status: str = Field(default="online")
    latency_ms: int | None = None
    version: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


# ============================================================
# Runtime Segment
# ============================================================

class WatchtowerSegment:
    def __init__(self, cfg: TowerConfig) -> None:
        self.cfg = cfg
        self._thresholds = thresholds_for(cfg.sensitivity)
        self._last_scan_ts: float | None = None
        self._alert_count = 0
        self._malformed_input_count = 0
        self._lock = threading.Lock()

    @property
    def id(self) -> str:
        return f"{self.cfg.slot.value}:{self.cfg.tower_type.value}"

    def _safe_int(self, event: dict[str, Any], field_name: str, default: int = 0) -> tuple[int, int]:
        raw = event.get(field_name, default)
        value, malformed = _safe_metric_int(raw, default)

        if malformed:
            logger.warning(
                "Malformed numeric field field=%s raw=%r event_id=%s tower=%s",
                field_name,
                raw,
                event.get("id"),
                self.id,
            )
            return default, 1

        return value, 0

    def scan(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if not self.cfg.enabled:
            return None

        if not isinstance(event, dict):
            raise TypeError(f"event must be dict, got {type(event).__name__}")

        scan_ts = _now()
        suspicious = False
        reason: str | None = None
        malformed_delta = 0
        tower_type = self.cfg.tower_type

        if tower_type == TowerType.API_HEALTH and event.get("kind") == "request":
            status_code, bad = self._safe_int(event, "status_code", 200)
            malformed_delta += bad
            latency_ms, bad = self._safe_int(event, "latency_ms", 0)
            malformed_delta += bad

            if status_code >= 500:
                suspicious = True
                reason = f"API returned server error ({status_code})"
            elif status_code == 404:
                suspicious = True
                reason = "API route not found (404)"
            elif latency_ms > 2000:
                suspicious = True
                reason = f"High API latency ({latency_ms}ms)"

        elif tower_type == TowerType.EXPECTATION_GUARD and event.get("kind") == "expectation":
            fail_count, bad = self._safe_int(event, "failed_checks", 0)
            malformed_delta += bad

            if fail_count >= self._thresholds.expectation_fail_count:
                suspicious = True
                reason = f"Expectation failures exceeded threshold ({fail_count})"
            elif event.get("expectation_status") == "failed":
                suspicious = True
                reason = "Expectation contract failed"

        elif tower_type == TowerType.CONFIG_DRIFT and event.get("kind") == "config":
            age_seconds, bad = self._safe_int(event, "config_age_seconds", 0)
            malformed_delta += bad

            if event.get("drift_detected", False):
                suspicious = True
                reason = "Configuration drift detected"
            elif age_seconds >= self._thresholds.stale_config_seconds:
                suspicious = True
                reason = f"Configuration stale ({age_seconds}s)"

        elif tower_type == TowerType.LOGGING_AUDIT and event.get("kind") == "log":
            if event.get("missing_required_fields", False):
                suspicious = True
                reason = "Required audit/log fields missing"
            elif event.get("integrity_status") == "tampered":
                suspicious = True
                reason = "Log integrity issue detected"

        elif tower_type == TowerType.ERROR_RATE and event.get("kind") == "runtime":
            error_rate, bad = self._safe_int(event, "error_rate_percent", 0)
            malformed_delta += bad

            if error_rate >= self._thresholds.error_rate_percent:
                suspicious = True
                reason = f"Error rate exceeded threshold ({error_rate}%)"
            elif event.get("crash_loop", False):
                suspicious = True
                reason = "Crash loop detected"

        elif tower_type == TowerType.DEPENDENCY_HEALTH and event.get("kind") == "dependency":
            dep_status = event.get("dependency_status")

            if dep_status in {"down", "degraded", "timeout", "offline", "failed"}:
                suspicious = True
                reason = f"Dependency unhealthy ({dep_status})"
            elif event.get("version_mismatch", False):
                suspicious = True
                reason = "Dependency version mismatch detected"

        elif tower_type == TowerType.RESOURCE_PRESSURE and event.get("kind") == "resource":
            cpu, bad = self._safe_int(event, "cpu_percent", 0)
            malformed_delta += bad
            mem, bad = self._safe_int(event, "memory_percent", 0)
            malformed_delta += bad
            disk, bad = self._safe_int(event, "disk_percent", 0)
            malformed_delta += bad

            if (
                cpu >= self._thresholds.cpu_percent
                or mem >= self._thresholds.memory_percent
                or disk >= self._thresholds.disk_percent
            ):
                suspicious = True
                reason = f"Resource pressure detected cpu={cpu} mem={mem} disk={disk}"

        elif tower_type == TowerType.SECURITY_BASELINE and event.get("kind") == "security":
            if event.get("unsigned_artifact", False):
                suspicious = True
                reason = "Unsigned artifact detected"
            elif event.get("secrets_exposed", False):
                suspicious = True
                reason = "Possible secrets exposure detected"
            elif event.get("debug_mode_enabled", False):
                suspicious = True
                reason = "Debug mode enabled in protected environment"

        with self._lock:
            current_last = self._last_scan_ts or 0.0
            self._last_scan_ts = max(current_last, scan_ts)
            self._malformed_input_count += malformed_delta
            if suspicious:
                self._alert_count += 1

        if not suspicious:
            return None

        event_id = _assign_event_id(event)

        return {
            "tower_id": self.id,
            "tower_name": self.cfg.name,
            "tower_type": self.cfg.tower_type.value,
            "slot": self.cfg.slot.value,
            "reason": reason,
            "sensitivity": self.cfg.sensitivity,
            "event_ref": event_id,
            "created_ts": scan_ts,
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "name": self.cfg.name,
                "slot": self.cfg.slot.value,
                "tower_type": self.cfg.tower_type.value,
                "enabled": self.cfg.enabled,
                "sensitivity": self.cfg.sensitivity,
                "thresholds": dataclasses.asdict(self._thresholds),
                "last_scan_ts": self._last_scan_ts,
                "alert_count": self._alert_count,
                "malformed_input_count": self._malformed_input_count,
            }


# ============================================================
# Runtime Node
# ============================================================

class WatchtowerNode:
    _ALLOWED_TRANSITIONS: dict[WatchtowerState, set[WatchtowerState]] = {
        WatchtowerState.INITIALIZING: {
            WatchtowerState.ACTIVE,
            WatchtowerState.DEGRADED,
            WatchtowerState.FAILED,
        },
        WatchtowerState.ACTIVE: {
            WatchtowerState.DEGRADED,
            WatchtowerState.FAILED,
        },
        WatchtowerState.DEGRADED: {
            WatchtowerState.ACTIVE,
            WatchtowerState.FAILED,
        },
        WatchtowerState.FAILED: set(),
    }

    def __init__(self, config: WatchtowerConfig) -> None:
        if not isinstance(config, WatchtowerConfig):
            raise TypeError(f"config must be WatchtowerConfig, got {type(config).__name__}")

        self.config = config
        self._lock = threading.RLock()
        self._state = WatchtowerState.INITIALIZING
        self.towers: dict[str, WatchtowerSegment] = {}
        self.modules: dict[str, dict[str, Any]] = {}
        self.dependencies: dict[str, dict[str, Any]] = {}
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=config.max_recent_events)
        self.created_ts = _now()

        self._total_scan_failures = 0
        self._consecutive_scan_failures = 0
        self._last_scan_failure_ts: float | None = None

        for tower_cfg in config.towers:
            segment = WatchtowerSegment(tower_cfg)
            if segment.id in self.towers:
                raise ValueError(f"Duplicate tower id detected: {segment.id}")
            self.towers[segment.id] = segment

        logger.info(
            "[%s] Watchtower initialized with %d segments",
            self.config.node_id,
            len(self.towers),
        )

    @property
    def state(self) -> WatchtowerState:
        with self._lock:
            return self._state

    def set_state(self, new_state: WatchtowerState) -> None:
        if not isinstance(new_state, WatchtowerState):
            raise TypeError(f"new_state must be WatchtowerState, got {type(new_state).__name__}")

        with self._lock:
            current = self._state
            allowed = self._ALLOWED_TRANSITIONS.get(current, set())

            if new_state != current and new_state not in allowed:
                logger.warning("Invalid state transition ignored: %s -> %s", current.value, new_state.value)
                return

            if new_state != current:
                logger.info("Watchtower state changed: %s -> %s", current.value, new_state.value)

            self._state = new_state

    def start(self) -> bool:
        if self.state == WatchtowerState.FAILED:
            logger.error("Cannot start FAILED Watchtower node")
            return False

        self.set_state(WatchtowerState.ACTIVE)
        return True

    def scan_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")

        local_event = copy.deepcopy(event)
        event_id = _assign_event_id(local_event)
        local_event.setdefault("received_ts", _now())

        with self._lock:
            self.recent_events.append(local_event)

            if self._state != WatchtowerState.ACTIVE:
                return []

            tower_snapshot = list(self.towers.values())

        alerts: list[dict[str, Any]] = []
        failures = 0

        for segment in tower_snapshot:
            with self._lock:
                if self._state != WatchtowerState.ACTIVE:
                    break

            try:
                alert = segment.scan(local_event)
                if alert:
                    alerts.append(alert)
            except Exception as exc:
                failures += 1
                logger.exception("Segment scan failure tower=%s error=%s", segment.id, exc)

        if alerts:
            alert_event = {
                "id": str(uuid.uuid4()),
                "kind": "watchtower_alerts",
                "source_event_id": event_id,
                "alerts": alerts,
                "created_ts": _now(),
            }
            with self._lock:
                self.recent_events.append(alert_event)

        should_degrade = False

        with self._lock:
            if failures:
                self._total_scan_failures += failures
                self._consecutive_scan_failures += failures
                self._last_scan_failure_ts = _now()
            else:
                self._consecutive_scan_failures = 0

            should_degrade = (
                failures >= self.config.scan_failure_degrade_threshold
                or self._consecutive_scan_failures >= self.config.scan_failure_degrade_threshold
            )

        if should_degrade:
            self.set_state(WatchtowerState.DEGRADED)

        return alerts

    def register_module(self, payload: ModuleRegisterRequest) -> dict[str, Any]:
        now = _now()
        record = {
            "module_id": payload.module_id,
            "module_type": payload.module_type,
            "version": payload.version,
            "endpoint": payload.endpoint,
            "capabilities": payload.capabilities,
            "metadata": payload.metadata,
            "registered_ts": now,
            "last_heartbeat_ts": now,
            "status": "registered",
        }

        with self._lock:
            self.modules[payload.module_id] = record
            snapshot = copy.deepcopy(record)

        self.scan_event({
            "kind": "dependency",
            "dependency_name": payload.module_id,
            "dependency_status": "online",
            "version": payload.version,
        })

        return snapshot

    def heartbeat_module(self, payload: ModuleHeartbeatRequest) -> dict[str, Any]:
        now = _now()

        with self._lock:
            record = self.modules.get(payload.module_id)

            if record is None:
                record = {
                    "module_id": payload.module_id,
                    "module_type": "unknown",
                    "version": "unknown",
                    "endpoint": None,
                    "capabilities": [],
                    "metadata": {},
                    "registered_ts": now,
                }

            record.update({
                "last_heartbeat_ts": now,
                "status": payload.status,
                "metrics": payload.metrics,
                "message": payload.message,
            })

            self.modules[payload.module_id] = record
            snapshot = copy.deepcopy(record)

        self.scan_event({
            "kind": "dependency",
            "dependency_name": payload.module_id,
            "dependency_status": payload.status,
        })

        return snapshot

    def report_dependency(self, payload: DependencyReportRequest) -> dict[str, Any]:
        now = _now()
        record = {
            "name": payload.name,
            "status": payload.status,
            "latency_ms": payload.latency_ms,
            "version": payload.version,
            "details": payload.details,
            "last_report_ts": now,
        }

        with self._lock:
            self.dependencies[payload.name] = record
            snapshot = copy.deepcopy(record)

        self.scan_event({
            "kind": "dependency",
            "dependency_name": payload.name,
            "dependency_status": payload.status,
            "latency_ms": payload.latency_ms,
            "version": payload.version,
        })

        return snapshot

    def module_snapshot(self) -> dict[str, Any]:
        now = _now()

        with self._lock:
            modules = copy.deepcopy(self.modules)

        for module in modules.values():
            last = module.get("last_heartbeat_ts")
            stale = last is None or (now - float(last)) > self.config.module_stale_seconds
            module["stale"] = stale

            if stale and module.get("status") not in {"offline", "down", "failed"}:
                module["computed_status"] = "stale"
            else:
                module["computed_status"] = module.get("status", "unknown")

        return {
            "module_count": len(modules),
            "stale_after_seconds": self.config.module_stale_seconds,
            "modules": list(modules.values()),
        }

    def dependency_snapshot(self) -> dict[str, Any]:
        with self._lock:
            dependencies = copy.deepcopy(self.dependencies)

        return {
            "dependency_count": len(dependencies),
            "dependencies": list(dependencies.values()),
        }

    def readiness_from_snapshots(
        self,
        modules: dict[str, Any],
        dependencies: dict[str, Any],
    ) -> dict[str, Any]:
        module_records = modules.get("modules", [])
        dependency_records = dependencies.get("dependencies", [])

        stale_modules = [
            item["module_id"]
            for item in module_records
            if item.get("computed_status") == "stale"
        ]

        bad_modules = [
            item["module_id"]
            for item in module_records
            if item.get("status") in {"down", "offline", "failed", "degraded"}
        ]

        bad_dependencies = [
            item["name"]
            for item in dependency_records
            if item.get("status") in {"down", "offline", "failed", "timeout"}
        ]

        with self._lock:
            state = self._state
            total_failures = self._total_scan_failures
            consecutive_failures = self._consecutive_scan_failures

        ready = (
            state == WatchtowerState.ACTIVE
            and not stale_modules
            and not bad_modules
            and not bad_dependencies
        )

        return {
            "ready": ready,
            "node_id": self.config.node_id,
            "state": state.value,
            "module_count": modules.get("module_count", 0),
            "dependency_count": dependencies.get("dependency_count", 0),
            "stale_modules": stale_modules,
            "bad_modules": bad_modules,
            "bad_dependencies": bad_dependencies,
            "scan_failures": {
                "total": total_failures,
                "consecutive": consecutive_failures,
            },
        }

    def readiness(self) -> dict[str, Any]:
        modules = self.module_snapshot()
        dependencies = self.dependency_snapshot()
        return self.readiness_from_snapshots(modules, dependencies)

    def get_status(self) -> dict[str, Any]:
        modules = self.module_snapshot()
        dependencies = self.dependency_snapshot()
        readiness = self.readiness_from_snapshots(modules, dependencies)

        with self._lock:
            state = self._state
            tower_snapshot = list(self.towers.values())
            total_failures = self._total_scan_failures
            consecutive_failures = self._consecutive_scan_failures
            last_failure_ts = self._last_scan_failure_ts

        return {
            "node_id": self.config.node_id,
            "state": state.value,
            "environment": self.config.environment,
            "uptime_seconds": int(_now() - self.created_ts),
            "ready": readiness["ready"],
            "version": "1.2.1",
            "config": self.config.to_dict(expose_bind_host=False),
            "scan_failures": {
                "total": total_failures,
                "consecutive": consecutive_failures,
                "last_failure_ts": last_failure_ts,
            },
            "modules": modules,
            "dependencies": dependencies,
            "readiness": readiness,
            "towers": [tower.status() for tower in tower_snapshot],
        }

    def recent_event_snapshot(self, limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(limit, self.config.max_recent_events))

        with self._lock:
            events = list(self.recent_events)[-limit:]

        return {
            "count": len(events),
            "limit": limit,
            "events": events,
        }


# ============================================================
# Build
# ============================================================

def build_node() -> WatchtowerNode:
    node_id = os.getenv("S43_WATCHTOWER_NODE_ID", "sentinel43-watchtower")
    config = WatchtowerConfig.default_sentinel_octagon(node_id)
    node = WatchtowerNode(config)
    node.start()
    return node


NODE = build_node()


# ============================================================
# FastAPI Runtime
# ============================================================

def create_api_app(node: WatchtowerNode) -> FastAPI:
    if not isinstance(node, WatchtowerNode):
        raise TypeError(f"node must be WatchtowerNode, got {type(node).__name__}")

    api = FastAPI(
        title="Sentinel-43 Watchtower",
        version="1.2.1",
        description="Sentinel-43 hardened monitoring, module registry, heartbeat, dependency, and alert analysis node.",
    )

    @api.get("/")
    def root() -> dict[str, Any]:
        return {
            "service": "sentinel-43-watchtower",
            "version": "1.2.1",
            "status": "online",
            "node_id": node.config.node_id,
            "routes": [
                "/health",
                "/ready",
                "/status",
                "/modules",
                "/modules/register",
                "/modules/heartbeat",
                "/dependencies",
                "/dependencies/report",
                "/events/recent",
                "/analyze",
                "/watchtower/health",
                "/watchtower/ready",
                "/watchtower/status",
                "/watchtower/modules",
                "/watchtower/modules/register",
                "/watchtower/modules/heartbeat",
                "/watchtower/dependencies",
                "/watchtower/dependencies/report",
                "/watchtower/events/recent",
                "/watchtower/analyze",
            ],
        }

    @api.get("/health")
    def health_check() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": "1.2.1",
            "node_state": node.state.value,
            "node_id": node.config.node_id,
        }

    @api.get("/ready")
    def ready_check() -> dict[str, Any]:
        result = node.readiness()
        return {
            **result,
            "status": "ready" if result["ready"] else "not_ready",
        }

    @api.get("/status")
    def node_status() -> dict[str, Any]:
        return node.get_status()

    @api.get("/modules")
    def modules_status() -> dict[str, Any]:
        return node.module_snapshot()

    @api.post("/modules/register")
    def register_module(payload: ModuleRegisterRequest) -> dict[str, Any]:
        return {
            "status": "registered",
            "module": node.register_module(payload),
        }

    @api.post("/modules/heartbeat")
    def module_heartbeat(payload: ModuleHeartbeatRequest) -> dict[str, Any]:
        return {
            "status": "heartbeat_accepted",
            "module": node.heartbeat_module(payload),
        }

    @api.get("/dependencies")
    def dependencies_status() -> dict[str, Any]:
        return node.dependency_snapshot()

    @api.post("/dependencies/report")
    def report_dependency(payload: DependencyReportRequest) -> dict[str, Any]:
        return {
            "status": "dependency_report_accepted",
            "dependency": node.report_dependency(payload),
        }

    @api.get("/events/recent")
    def recent_events(limit: int = 50) -> dict[str, Any]:
        return node.recent_event_snapshot(limit)

    @api.post("/analyze")
    def analyze_event(payload: AnalyzeRequest) -> dict[str, Any]:
        try:
            alerts = node.scan_event(payload.event)
            return {
                "alerts": alerts,
                "alert_count": len(alerts),
            }
        except Exception as exc:
            logger.exception("Analyze failed: %s", exc)
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.post("/state/{state_name}")
    def change_state(state_name: str) -> dict[str, Any]:
        try:
            state = WatchtowerState[state_name.upper()]
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid state: {state_name}") from exc

        node.set_state(state)
        return {
            "node_id": node.config.node_id,
            "state": node.state.value,
        }

    # ========================================================
    # /watchtower aliases
    # ========================================================

    @api.get("/watchtower/health")
    def wt_health_check() -> dict[str, Any]:
        return health_check()

    @api.get("/watchtower/ready")
    def wt_ready_check() -> dict[str, Any]:
        return ready_check()

    @api.get("/watchtower/status")
    def wt_node_status() -> dict[str, Any]:
        return node_status()

    @api.get("/watchtower/modules")
    def wt_modules_status() -> dict[str, Any]:
        return modules_status()

    @api.post("/watchtower/modules/register")
    def wt_register_module(payload: ModuleRegisterRequest) -> dict[str, Any]:
        return register_module(payload)

    @api.post("/watchtower/modules/heartbeat")
    def wt_module_heartbeat(payload: ModuleHeartbeatRequest) -> dict[str, Any]:
        return module_heartbeat(payload)

    @api.get("/watchtower/dependencies")
    def wt_dependencies_status() -> dict[str, Any]:
        return dependencies_status()

    @api.post("/watchtower/dependencies/report")
    def wt_report_dependency(payload: DependencyReportRequest) -> dict[str, Any]:
        return report_dependency(payload)

    @api.get("/watchtower/events/recent")
    def wt_recent_events(limit: int = 50) -> dict[str, Any]:
        return recent_events(limit)

    @api.post("/watchtower/analyze")
    def wt_analyze_event(payload: AnalyzeRequest) -> dict[str, Any]:
        return analyze_event(payload)

    return api


app = create_api_app(NODE)


def main() -> None:
    uvicorn.run(
        "core.monitoring.watchtower:app",
        host=NODE.config.host,
        port=NODE.config.port,
        reload=False,
        log_level=os.getenv("S43_LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()


__all__ = [
    "ThresholdProfile",
    "thresholds_for",
    "WatchtowerState",
    "TowerSlot",
    "TowerType",
    "TowerConfig",
    "WatchtowerConfig",
    "WatchtowerSegment",
    "WatchtowerNode",
    "AnalyzeRequest",
    "ModuleRegisterRequest",
    "ModuleHeartbeatRequest",
    "DependencyReportRequest",
    "build_node",
    "NODE",
    "app",
    "create_api_app",
]