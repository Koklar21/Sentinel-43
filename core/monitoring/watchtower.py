"""
Sentinel-43 Monitoring Subsystem
Watchtower Node Implementation

Copyright (c) 2026 Justin [Last Name]

This file is part of the Sentinel-43 project.

LICENSE STRUCTURE
-----------------
Sentinel-43 is distributed under a dual-purpose license:

1. Non-Commercial Research License
   This software may be used, studied, modified, and shared for
   personal, academic, and non-commercial research purposes.

2. Commercial License
   Any commercial, enterprise, governmental, or production use
   requires a separate commercial license issued by the author.

Restrictions
------------
You may NOT:

- Sell this software or derivatives
- Use this software in a commercial product
- Deploy this software in a paid service
- Repackage or redistribute this software for profit

without explicit written permission.

DISCLAIMER
----------
This software is provided "AS IS", without warranty of any kind.
The author shall not be liable for damages arising from its use.

Commercial licensing inquiries:
contact: licensing@sentinel43.ai
"""

from __future__ import annotations

import enum
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .rules import ThresholdProfile, thresholds_for


# ============================================================
# Logging
# ============================================================
logger = logging.getLogger("SentinelWatchtower")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - SentinelWatchtower - %(levelname)s - %(message)s",
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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ensure_event_id(event: Dict[str, Any]) -> str:
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
@dataclass
class TowerConfig:
    name: str
    slot: TowerSlot
    tower_type: TowerType
    enabled: bool = True
    sensitivity: int = 5

    def __post_init__(self) -> None:
        self.sensitivity = _clamp_int("sensitivity", self.sensitivity, 1, 10)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "slot": self.slot.value,
            "tower_type": self.tower_type.value,
            "enabled": self.enabled,
            "sensitivity": self.sensitivity,
        }


@dataclass
class WatchtowerConfig:
    node_id: str
    environment: str = "production"
    host: str = "0.0.0.0"
    port: int = 9200
    towers: List[TowerConfig] = field(default_factory=list)

    # Per-scan failure doctrine:
    # if N or more tower scan failures happen during one scan_event() call,
    # the node moves to DEGRADED.
    scan_failure_degrade_threshold: int = 2

    def __post_init__(self) -> None:
        self.port = _clamp_int("port", self.port, 1024, 65535)
        self.scan_failure_degrade_threshold = _clamp_int(
            "scan_failure_degrade_threshold",
            self.scan_failure_degrade_threshold,
            1,
            100,
        )

    @property
    def api_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @classmethod
    def default_sentinel_octagon(cls, node_id: str) -> "WatchtowerConfig":
        return cls(
            node_id=node_id,
            towers=[
                TowerConfig("API Health Sentinel", TowerSlot.N, TowerType.API_HEALTH, sensitivity=5),
                TowerConfig("Expectation Guard", TowerSlot.NE, TowerType.EXPECTATION_GUARD, sensitivity=7),
                TowerConfig("Config Drift Sentinel", TowerSlot.E, TowerType.CONFIG_DRIFT, sensitivity=6),
                TowerConfig("Logging Audit Sentinel", TowerSlot.SE, TowerType.LOGGING_AUDIT, sensitivity=5),
                TowerConfig("Error Rate Sentinel", TowerSlot.S, TowerType.ERROR_RATE, sensitivity=7),
                TowerConfig("Dependency Health Sentinel", TowerSlot.SW, TowerType.DEPENDENCY_HEALTH, sensitivity=5),
                TowerConfig("Resource Pressure Sentinel", TowerSlot.W, TowerType.RESOURCE_PRESSURE, sensitivity=6),
                TowerConfig("Security Baseline Sentinel", TowerSlot.NW, TowerType.SECURITY_BASELINE, sensitivity=6),
            ],
        )

    def to_dict(self) -> Dict[str, Any]:
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
    def __init__(self, cfg: TowerConfig):
        self.cfg = cfg
        self.last_scan_ts: Optional[float] = None
        self.alert_count: int = 0
        self.malformed_input_count: int = 0
        self._thresholds: ThresholdProfile = thresholds_for(cfg.sensitivity)
        self._lock = threading.Lock()

    @property
    def id(self) -> str:
        return f"{self.cfg.slot.value}:{self.cfg.tower_type.value}"

    def _event_int(
        self,
        event: Dict[str, Any],
        field_name: str,
        default: int = 0,
    ) -> int:
        raw = event.get(field_name, default)
        try:
            return int(raw)
        except (TypeError, ValueError):
            with self._lock:
                self.malformed_input_count += 1

            logger.warning(
                "[%s] malformed numeric field '%s' on tower=%s raw=%r defaulting=%d event_id=%s",
                self.cfg.name,
                field_name,
                self.id,
                raw,
                default,
                event.get("id"),
            )
            return default

    def scan(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.cfg.enabled:
            return None

        self.last_scan_ts = time.time()
        tower_type = self.cfg.tower_type
        suspicious = False
        reason: Optional[str] = None

        # ------------------------------------------------------------
        # Sentinel-specific monitoring logic
        # ------------------------------------------------------------
        if tower_type == TowerType.API_HEALTH:
            if event.get("kind") == "request":
                status_code = self._event_int(event, "status_code", 200)
                latency_ms = self._event_int(event, "latency_ms", 0)

                if status_code >= 500:
                    suspicious = True
                    reason = f"API returned server error ({status_code})"
                elif latency_ms > 2000:
                    suspicious = True
                    reason = f"High API latency ({latency_ms}ms)"

        elif tower_type == TowerType.EXPECTATION_GUARD:
            if event.get("kind") == "expectation":
                fail_count = self._event_int(event, "failed_checks", 0)

                if fail_count >= self._thresholds.expectation_fail_count:
                    suspicious = True
                    reason = (
                        f"Expectation failures exceeded threshold "
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
                    age_seconds = self._event_int(event, "config_age_seconds", 0)
                    if age_seconds >= self._thresholds.stale_config_seconds:
                        suspicious = True
                        reason = (
                            f"Configuration is stale "
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
                error_rate = self._event_int(event, "error_rate_percent", 0)

                if error_rate >= self._thresholds.error_rate_percent:
                    suspicious = True
                    reason = (
                        f"Error rate exceeded threshold "
                        f"(>= {self._thresholds.error_rate_percent}%)"
                    )
                elif event.get("crash_loop", False):
                    suspicious = True
                    reason = "Crash loop detected"

        elif tower_type == TowerType.DEPENDENCY_HEALTH:
            if event.get("kind") == "dependency":
                if event.get("dependency_status") in {"down", "degraded", "timeout"}:
                    suspicious = True
                    reason = f"Dependency unhealthy ({event.get('dependency_status')})"
                elif event.get("version_mismatch", False):
                    suspicious = True
                    reason = "Dependency version mismatch detected"

        elif tower_type == TowerType.RESOURCE_PRESSURE:
            if event.get("kind") == "resource":
                cpu = self._event_int(event, "cpu_percent", 0)
                mem = self._event_int(event, "memory_percent", 0)
                disk = self._event_int(event, "disk_percent", 0)

                if cpu >= 90 or mem >= 90 or disk >= 95:
                    suspicious = True
                    reason = f"Resource pressure detected (cpu={cpu} mem={mem} disk={disk})"

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

        if not suspicious:
            return None

        with self._lock:
            self.alert_count += 1

        event_id = _ensure_event_id(event)

        return {
            "tower_id": self.id,
            "tower_name": self.cfg.name,
            "tower_type": self.cfg.tower_type.value,
            "slot": self.cfg.slot.value,
            "reason": reason,
            "sensitivity": self.cfg.sensitivity,
            "event_ref": event_id,
            "created_ts": self.last_scan_ts,
        }

    def status(self) -> Dict[str, Any]:
        with self._lock:
            alert_count = self.alert_count
            malformed_input_count = self.malformed_input_count

        return {
            "id": self.id,
            "name": self.cfg.name,
            "slot": self.cfg.slot.value,
            "tower_type": self.cfg.tower_type.value,
            "enabled": self.cfg.enabled,
            "sensitivity": self.cfg.sensitivity,
            "thresholds": {
                "error_rate_percent": self._thresholds.error_rate_percent,
                "expectation_fail_count": self._thresholds.expectation_fail_count,
                "stale_config_seconds": self._thresholds.stale_config_seconds,
            },
            "last_scan_ts": self.last_scan_ts,
            "alert_count": alert_count,
            "malformed_input_count": malformed_input_count,
        }


# ============================================================
# Node
# ============================================================
class WatchtowerNode:
    _ALLOWED_TRANSITIONS = {
        WatchtowerState.INITIALIZING: {
            WatchtowerState.ACTIVE,
            WatchtowerState.DEGRADED,
            WatchtowerState.FAILED,
        },
        WatchtowerState.ACTIVE: {WatchtowerState.DEGRADED, WatchtowerState.FAILED},
        WatchtowerState.DEGRADED: {WatchtowerState.ACTIVE, WatchtowerState.FAILED},
        WatchtowerState.FAILED: set(),
    }

    def __init__(self, config: WatchtowerConfig):
        self.config = config
        self._lock = threading.RLock()
        self._state: WatchtowerState = WatchtowerState.INITIALIZING
        self.towers: Dict[str, WatchtowerSegment] = {}

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

    def start(self) -> None:
        try:
            self.set_state(WatchtowerState.ACTIVE)
        except Exception as exc:
            logger.exception("[%s] Failed to start watchtower: %s", self.config.node_id, exc)
            with self._lock:
                self._state = WatchtowerState.FAILED

    def scan_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        with self._lock:
            if self._state != WatchtowerState.ACTIVE:
                logger.debug("[%s] Ignoring event; state=%s", self.config.node_id, self._state.value)
                return []
            tower_snapshot = list(self.towers.values())

        _ensure_event_id(event)

        alerts: List[Dict[str, Any]] = []
        failures = 0

        for segment in tower_snapshot:
            try:
                alert = segment.scan(event)
                if alert:
                    alerts.append(alert)
            except Exception as exc:
                failures += 1
                logger.exception(
                    "[%s] Segment scan failure tower=%s error=%s event_id=%s",
                    self.config.node_id,
                    segment.id,
                    type(exc).__name__,
                    event.get("id"),
                )

        # Intentional doctrine:
        # degrade only when enough segment failures occur in a single scan pass.
        if failures >= self.config.scan_failure_degrade_threshold:
            self.set_state(WatchtowerState.DEGRADED)

        return alerts

    def get_status(self) -> Dict[str, Any]:
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
def create_api_app(node: WatchtowerNode) -> Dict[str, Any]:
    logger.info("Creating Sentinel Watchtower API for node %s", node.config.node_id)

    def health_check() -> Dict[str, Any]:
        return {"status": "ok", "node_state": node.state.value}

    def node_status() -> Dict[str, Any]:
        return node.get_status()

    def analyze(event: Dict[str, Any]) -> Dict[str, Any]:
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
        "is_ready": node.state == WatchtowerState.ACTIVE,
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