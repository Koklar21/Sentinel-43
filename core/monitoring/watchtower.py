"""
Sentinel-43 Monitoring Subsystem
Watchtower Node Implementation
"""

from __future__ import annotations

import enum
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from .rules import ThresholdProfile, thresholds_for


logger = logging.getLogger("SentinelWatchtower")


# ============================================================
# Utilities
# ============================================================

def _clamp_int(name: str, value: Any, lo: int, hi: int) -> int:
    try:
        iv = int(value)
    except Exception as exc:
        raise ValueError(
            f"{name} must be an int in [{lo}, {hi}], got {value!r}"
        ) from exc

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


def _threshold_attr(
    thresholds: ThresholdProfile,
    attr: str,
    fallback: int,
) -> int:
    return int(getattr(thresholds, attr, fallback))


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

        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("tower name must be a non-empty string")

        if not isinstance(self.slot, TowerSlot):
            raise TypeError("slot must be TowerSlot")

        if not isinstance(self.tower_type, TowerType):
            raise TypeError("tower_type must be TowerType")

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
    port: int = 9200
    towers: tuple[TowerConfig, ...] = field(default_factory=tuple)

    scan_failure_degrade_threshold: int = 2

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id.strip():
            raise ValueError("node_id must be a non-empty string")

        object.__setattr__(
            self,
            "port",
            _clamp_int("port", self.port, 1024, 65535),
        )

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

        object.__setattr__(self, "towers", tuple(self.towers))

    @property
    def api_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @classmethod
    def default_sentinel_octagon(cls, node_id: str) -> "WatchtowerConfig":
        return cls(
            node_id=node_id,
            towers=(
                TowerConfig(
                    "API Health Sentinel",
                    TowerSlot.N,
                    TowerType.API_HEALTH,
                    sensitivity=5,
                ),
                TowerConfig(
                    "Expectation Guard",
                    TowerSlot.NE,
                    TowerType.EXPECTATION_GUARD,
                    sensitivity=7,
                ),
                TowerConfig(
                    "Config Drift Sentinel",
                    TowerSlot.E,
                    TowerType.CONFIG_DRIFT,
                    sensitivity=6,
                ),
                TowerConfig(
                    "Logging Audit Sentinel",
                    TowerSlot.SE,
                    TowerType.LOGGING_AUDIT,
                    sensitivity=5,
                ),
                TowerConfig(
                    "Error Rate Sentinel",
                    TowerSlot.S,
                    TowerType.ERROR_RATE,
                    sensitivity=7,
                ),
                TowerConfig(
                    "Dependency Health Sentinel",
                    TowerSlot.SW,
                    TowerType.DEPENDENCY_HEALTH,
                    sensitivity=5,
                ),
                TowerConfig(
                    "Resource Pressure Sentinel",
                    TowerSlot.W,
                    TowerType.RESOURCE_PRESSURE,
                    sensitivity=6,
                ),
                TowerConfig(
                    "Security Baseline Sentinel",
                    TowerSlot.NW,
                    TowerType.SECURITY_BASELINE,
                    sensitivity=6,
                ),
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "environment": self.environment,
            "host": self.host,
            "port": self.port,
            "api_url": self.api_url,
            "scan_failure_degrade_threshold": self.scan_failure_degrade_threshold,
            "towers": [tower.to_dict() for tower in self.towers],
        }


# ============================================================
# Tower Runtime
# ============================================================

class WatchtowerSegment:
    def __init__(self, cfg: TowerConfig) -> None:
        self.cfg = cfg
        self._last_scan_ts: float | None = None
        self._alert_count = 0
        self._malformed_input_count = 0
        self._thresholds: ThresholdProfile = thresholds_for(cfg.sensitivity)
        self._lock = threading.Lock()

    @property
    def id(self) -> str:
        return f"{self.cfg.slot.value}:{self.cfg.tower_type.value}"

    def scan(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if not self.cfg.enabled:
            return None

        if not isinstance(event, dict):
            raise TypeError(f"event must be dict, got {type(event).__name__}")

        scan_ts = time.time()
        tower_type = self.cfg.tower_type

        suspicious = False
        reason: str | None = None
        malformed_delta = 0

        def safe_int(field_name: str, default: int = 0) -> int:
            raw = event.get(field_name, default)

            try:
                return int(raw)
            except (TypeError, ValueError):
                nonlocal malformed_delta
                malformed_delta += 1

                logger.warning(
                    "[%s] malformed numeric field '%s' tower=%s raw=%r "
                    "defaulting=%d event_id=%s",
                    self.cfg.name,
                    field_name,
                    self.id,
                    raw,
                    default,
                    event.get("id"),
                )

                return default

        if tower_type == TowerType.API_HEALTH:
            if event.get("kind") == "request":
                status_code = safe_int("status_code", 200)
                latency_ms = safe_int("latency_ms", 0)

                if status_code >= 500:
                    suspicious = True
                    reason = f"API returned server error ({status_code})"
                elif latency_ms > 2000:
                    suspicious = True
                    reason = f"High API latency ({latency_ms}ms)"

        elif tower_type == TowerType.EXPECTATION_GUARD:
            if event.get("kind") == "expectation":
                fail_count = safe_int("failed_checks", 0)

                if fail_count >= self._thresholds.expectation_fail_count:
                    suspicious = True
                    reason = (
                        "Expectation failures exceeded threshold "
                        f"(>= {self._thresholds.expectation_fail_count})"
                    )
                elif event.get("expectation_status") == "failed":
                    suspicious = True
                    reason = "Expectation contract failed"

        elif tower_type == TowerType.CONFIG_DRIFT:
            if event.get("kind") == "config":
                if event.get("drift_detected", False):
                    suspicious = True
                    reason = "Configuration drift detected"
                else:
                    age_seconds = safe_int("config_age_seconds", 0)

                    if age_seconds >= self._thresholds.stale_config_seconds:
                        suspicious = True
                        reason = (
                            "Configuration is stale "
                            f"(>= {self._thresholds.stale_config_seconds}s)"
                        )

        elif tower_type == TowerType.LOGGING_AUDIT:
            if event.get("kind") == "log":
                if event.get("missing_required_fields", False):
                    suspicious = True
                    reason = "Required audit/log fields missing"
                elif event.get("integrity_status") == "tampered":
                    suspicious = True
                    reason = "Log integrity issue detected"

        elif tower_type == TowerType.ERROR_RATE:
            if event.get("kind") == "runtime":
                error_rate = safe_int("error_rate_percent", 0)

                if error_rate >= self._thresholds.error_rate_percent:
                    suspicious = True
                    reason = (
                        "Error rate exceeded threshold "
                        f"(>= {self._thresholds.error_rate_percent}%)"
                    )
                elif event.get("crash_loop", False):
                    suspicious = True
                    reason = "Crash loop detected"

        elif tower_type == TowerType.DEPENDENCY_HEALTH:
            if event.get("kind") == "dependency":
                dependency_status = event.get("dependency_status")

                if dependency_status in {"down", "degraded", "timeout"}:
                    suspicious = True
                    reason = f"Dependency unhealthy ({dependency_status})"
                elif event.get("version_mismatch", False):
                    suspicious = True
                    reason = "Dependency version mismatch detected"

        elif tower_type == TowerType.RESOURCE_PRESSURE:
            if event.get("kind") == "resource":
                cpu = safe_int("cpu_percent", 0)
                mem = safe_int("memory_percent", 0)
                disk = safe_int("disk_percent", 0)

                cpu_thresh = _threshold_attr(self._thresholds, "cpu_percent", 90)
                mem_thresh = _threshold_attr(self._thresholds, "memory_percent", 90)
                disk_thresh = _threshold_attr(self._thresholds, "disk_percent", 95)

                if cpu >= cpu_thresh or mem >= mem_thresh or disk >= disk_thresh:
                    suspicious = True
                    reason = (
                        "Resource pressure detected "
                        f"(cpu={cpu}>={cpu_thresh} | "
                        f"mem={mem}>={mem_thresh} | "
                        f"disk={disk}>={disk_thresh})"
                    )

        elif tower_type == TowerType.SECURITY_BASELINE:
            if event.get("kind") == "security":
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
            alert_count = self._alert_count
            malformed_input_count = self._malformed_input_count
            last_scan_ts = self._last_scan_ts

        thresholds: dict[str, Any] = {
            "error_rate_percent": self._thresholds.error_rate_percent,
            "expectation_fail_count": self._thresholds.expectation_fail_count,
            "stale_config_seconds": self._thresholds.stale_config_seconds,
            "cpu_percent": _threshold_attr(self._thresholds, "cpu_percent", 90),
            "memory_percent": _threshold_attr(self._thresholds, "memory_percent", 90),
            "disk_percent": _threshold_attr(self._thresholds, "disk_percent", 95),
        }

        return {
            "id": self.id,
            "name": self.cfg.name,
            "slot": self.cfg.slot.value,
            "tower_type": self.cfg.tower_type.value,
            "enabled": self.cfg.enabled,
            "sensitivity": self.cfg.sensitivity,
            "thresholds": thresholds,
            "last_scan_ts": last_scan_ts,
            "alert_count": alert_count,
            "malformed_input_count": malformed_input_count,
        }


# ============================================================
# Node
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
            raise TypeError(
                f"config must be WatchtowerConfig, got {type(config).__name__}"
            )

        self.config = config
        self._lock = threading.RLock()
        self._state = WatchtowerState.INITIALIZING
        self.towers: dict[str, WatchtowerSegment] = {}

        for tower_cfg in self.config.towers:
            segment = WatchtowerSegment(tower_cfg)

            if segment.id in self.towers:
                raise ValueError(f"Duplicate tower id detected: {segment.id}")

            self.towers[segment.id] = segment

        logger.info(
            "[%s] Sentinel Watchtower initialized with %d segments on %s",
            self.config.node_id,
            len(self.towers),
            self.config.api_url,
        )

    @property
    def state(self) -> WatchtowerState:
        with self._lock:
            return self._state

    def set_state(self, new_state: WatchtowerState) -> None:
        if not isinstance(new_state, WatchtowerState):
            raise TypeError(
                f"new_state must be WatchtowerState, got {type(new_state).__name__}"
            )

        with self._lock:
            current = self._state
            allowed = self._ALLOWED_TRANSITIONS.get(current, set())

            if new_state != current and new_state not in allowed:
                logger.warning(
                    "[%s] Invalid state transition %s -> %s ignored",
                    self.config.node_id,
                    current.value,
                    new_state.value,
                )
                return

            if new_state != current:
                logger.info(
                    "[%s] Watchtower state changed: %s -> %s",
                    self.config.node_id,
                    current.value,
                    new_state.value,
                )
                self._state = new_state

    def start(self) -> bool:
        with self._lock:
            if self._state == WatchtowerState.FAILED:
                logger.error("[%s] Cannot start a FAILED node.", self.config.node_id)
                return False

        try:
            self.set_state(WatchtowerState.ACTIVE)
            return True
        except Exception as exc:
            logger.exception(
                "[%s] Failed to start watchtower: %s",
                self.config.node_id,
                exc,
            )
            self.set_state(WatchtowerState.FAILED)
            return False

    def scan_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(event, dict):
            raise TypeError(f"event must be dict, got {type(event).__name__}")

        local_event = dict(event)
        _ensure_event_id(local_event)

        with self._lock:
            if self._state != WatchtowerState.ACTIVE:
                logger.debug(
                    "[%s] Ignoring event; state=%s",
                    self.config.node_id,
                    self._state.value,
                )
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
                logger.exception(
                    "[%s] Segment scan failure tower=%s error=%s event_id=%s",
                    self.config.node_id,
                    segment.id,
                    type(exc).__name__,
                    local_event.get("id"),
                )

        if failures >= self.config.scan_failure_degrade_threshold:
            self.set_state(WatchtowerState.DEGRADED)

        return alerts

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            state = self._state
            tower_snapshot = list(self.towers.values())

        return {
            "node_id": self.config.node_id,
            "state": state.value,
            "environment": self.config.environment,
            "api_url": self.config.api_url,
            "scan_failure_degrade_threshold": self.config.scan_failure_degrade_threshold,
            "towers": [tower.status() for tower in tower_snapshot],
        }


# ============================================================
# API Factory
# ============================================================

def create_api_app(node: WatchtowerNode) -> dict[str, Any]:
    if not isinstance(node, WatchtowerNode):
        raise TypeError(f"node must be WatchtowerNode, got {type(node).__name__}")

    logger.info("Creating Sentinel Watchtower API for node %s", node.config.node_id)

    def health_check() -> dict[str, Any]:
        return {
            "status": "ok",
            "node_state": node.state.value,
        }

    def node_status() -> dict[str, Any]:
        return node.get_status()

    def analyze(event: dict[str, Any]) -> dict[str, Any]:
        alerts = node.scan_event(event)
        return {
            "alerts": alerts,
            "alert_count": len(alerts),
        }

    return {
        "node_id": node.config.node_id,
        "endpoint_handlers": {
            "/health": health_check,
            "/status": node_status,
            "/analyze": analyze,
        },
        "is_ready": lambda: node.state == WatchtowerState.ACTIVE,
    }


__all__ = [
    "WatchtowerState",
    "TowerSlot",
    "TowerType",
    "TowerConfig",
    "WatchtowerConfig",
    "WatchtowerSegment",
    "WatchtowerNode",
    "create_api_app",
]
