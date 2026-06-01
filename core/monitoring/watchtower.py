"""
Sentinel-43 Watchtower Node
Single-file monitoring subsystem with FastAPI runtime.
"""

from __future__ import annotations

import enum
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import uvicorn


logging.basicConfig(
    level=os.getenv("S43_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("SentinelWatchtower")


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

def _clamp_int(name: str, value: Any, lo: int, hi: int) -> int:
    try:
        iv = int(value)
    except Exception as exc:
        raise ValueError(f"{name} must be an int in [{lo}, {hi}], got {value!r}") from exc

    if not (lo <= iv <= hi):
        raise ValueError(f"{name} must be in [{lo}, {hi}], got {iv}")

    return iv


def _ensure_event_id(event: dict[str, Any]) -> str:
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
        object.__setattr__(
            self,
            "sensitivity",
            _clamp_int("sensitivity", self.sensitivity, 1, 10),
        )

        if not self.name.strip():
            raise ValueError("tower name must be non-empty")

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

    def __post_init__(self) -> None:
        if not self.node_id.strip():
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

    @property
    def api_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @classmethod
    def default_sentinel_octagon(cls, node_id: str) -> "WatchtowerConfig":
        return cls(
            node_id=node_id,
            environment=os.getenv("S43_ENV", "production"),
            host=os.getenv("S43_WATCHTOWER_HOST", "0.0.0.0"),
            port=int(os.getenv("S43_WATCHTOWER_PORT", "9100")),
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


# ============================================================
# Runtime
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

        try:
            return int(raw), 0
        except (TypeError, ValueError):
            logger.warning(
                "Malformed numeric field field=%s raw=%r event_id=%s tower=%s",
                field_name,
                raw,
                event.get("id"),
                self.id,
            )
            return default, 1

    def scan(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if not self.cfg.enabled:
            return None

        scan_ts = time.time()
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

            if dep_status in {"down", "degraded", "timeout"}:
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
            self._last_scan_ts = scan_ts
            self._malformed_input_count += malformed_delta

            if suspicious:
                self._alert_count += 1

        if not suspicious:
            return None

        event_id = _ensure_event_id(event)

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
                "thresholds": self._thresholds.__dict__,
                "last_scan_ts": self._last_scan_ts,
                "alert_count": self._alert_count,
                "malformed_input_count": self._malformed_input_count,
            }


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
        self.config = config
        self._lock = threading.RLock()
        self._state = WatchtowerState.INITIALIZING
        self.towers: dict[str, WatchtowerSegment] = {}

        for tower_cfg in config.towers:
            segment = WatchtowerSegment(tower_cfg)

            if segment.id in self.towers:
                raise ValueError(f"Duplicate tower id detected: {segment.id}")

            self.towers[segment.id] = segment

    @property
    def state(self) -> WatchtowerState:
        with self._lock:
            return self._state

    def set_state(self, new_state: WatchtowerState) -> None:
        with self._lock:
            current = self._state
            allowed = self._ALLOWED_TRANSITIONS.get(current, set())

            if new_state != current and new_state not in allowed:
                logger.warning("Invalid state transition ignored: %s -> %s", current.value, new_state.value)
                return

            self._state = new_state

    def start(self) -> bool:
        if self.state == WatchtowerState.FAILED:
            return False

        self.set_state(WatchtowerState.ACTIVE)
        return True

    def scan_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")

        local_event = dict(event)
        _ensure_event_id(local_event)

        with self._lock:
            if self._state != WatchtowerState.ACTIVE:
                return []

            tower_snapshot = list(self.towers.values())

        alerts: list[dict[str, Any]] = []
        failures = 0

        for segment in tower_snapshot:
            try:
                alert = segment.scan(local_event)

                if alert:
                    alerts.append(alert)

            except Exception as exc:
                failures += 1
                logger.exception("Segment scan failure tower=%s error=%s", segment.id, exc)

        if failures >= self.config.scan_failure_degrade_threshold:
            self.set_state(WatchtowerState.DEGRADED)

        return alerts

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "node_id": self.config.node_id,
                "state": self._state.value,
                "environment": self.config.environment,
                "api_url": self.config.api_url,
                "scan_failure_degrade_threshold": self.config.scan_failure_degrade_threshold,
                "towers": [tower.status() for tower in self.towers.values()],
            }


# ============================================================
# FastAPI App
# ============================================================

class AnalyzeRequest(BaseModel):
    event: dict[str, Any] = Field(default_factory=dict)


NODE_ID = os.getenv("S43_WATCHTOWER_NODE_ID", "sentinel43-watchtower")
CONFIG = WatchtowerConfig.default_sentinel_octagon(NODE_ID)
NODE = WatchtowerNode(CONFIG)
NODE.start()

app = FastAPI(
    title="Sentinel-43 Watchtower",
    version="0.1.0",
    description="Sentinel-43 monitoring and alert analysis node.",
)


@app.get("/health")
def health_check() -> dict[str, Any]:
    return {
        "status": "ok",
        "node_state": NODE.state.value,
        "node_id": NODE.config.node_id,
    }


@app.get("/status")
def node_status() -> dict[str, Any]:
    return NODE.get_status()


@app.post("/analyze")
def analyze_event(payload: AnalyzeRequest) -> dict[str, Any]:
    try:
        alerts = NODE.scan_event(payload.event)
        return {
            "alerts": alerts,
            "alert_count": len(alerts),
        }
    except Exception as exc:
        logger.exception("Analyze failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/state/{state_name}")
def change_state(state_name: str) -> dict[str, Any]:
    try:
        state = WatchtowerState[state_name.upper()]
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid state: {state_name}") from exc

    NODE.set_state(state)
    return {
        "node_id": NODE.config.node_id,
        "state": NODE.state.value,
    }


def main() -> None:
    uvicorn.run(
        "core.watchtower:app",
        host=CONFIG.host,
        port=CONFIG.port,
        reload=False,
        log_level=os.getenv("S43_LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()