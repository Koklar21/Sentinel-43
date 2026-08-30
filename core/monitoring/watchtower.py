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
Sentinel-43 Watchtower Node
v1.3.7 RLock Deadlock Fix

Docker:
    S43_WATCHTOWER_SERVE=true python -m core.monitoring.watchtower

Production:
    uvicorn core.monitoring.watchtower:app --host 0.0.0.0 --port 9100

Changes from v1.3.6:
  - Fix #10: _SINGLETON_LOCK changed from threading.Lock() to threading.RLock().
    Root cause of container startup hang: _get_or_create_app() acquired
    _SINGLETON_LOCK, then called _get_or_create_node() which attempted to
    acquire the same non-reentrant Lock. Python's threading.Lock does not
    allow the same thread to acquire it twice — the second acquisition
    blocked forever. Uvicorn resolved `module:app` via __getattr__, which
    called _get_or_create_app(), which deadlocked immediately. The process
    remained alive as PID 1 but never bound to port 9100 and emitted zero
    logs. threading.RLock (reentrant lock) allows the same thread to acquire
    it multiple times, resolving the deadlock with no other logic changes.

Changes from v1.3.5 (carried forward from v1.3.6):
  - Fix #1: NODE and app are now lazy singletons accessed via module-level
    __getattr__. Importing types (WatchtowerConfig, WatchtowerNode, etc.)
    no longer triggers node construction or FastAPI app creation at import
    time. uvicorn compatibility preserved: `uvicorn module:app` triggers
    __getattr__("app") which initialises on first access.
  - Fix #2: WatchtowerNode.stop() added. Transitions node to FAILED,
    dropping all subsequent events. MonitoringManager.stop() no longer
    raises AttributeError.
  - Fix #3: ThresholdProfile renamed to TowerThresholdProfile and
    thresholds_for renamed to tower_thresholds_for to eliminate the name
    collision with the rules_engine ThresholdProfile enum.
  - Fix #4: build_node() now raises RuntimeError if node.start() returns
    False instead of silently returning an INITIALIZING node.
  - Fix #5: create_api_app() no longer double-registers routes. All routes
    live under the /watchtower prefix. A root shim at / redirects callers
    that previously used bare paths.
  - Fix #6: bad_dependencies no longer double-counts stale items; stale
    and explicitly-unhealthy dependencies are tracked in separate lists.
  - Fix #7: NODE removed from __all__; use get_node() to access the
    singleton.
  - Fix #9: start() now raises RuntimeError on disallowed transition
    instead of silently returning False.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import logging
import os
import secrets
import threading
import time
import uuid
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


VERSION = "1.3.7"
logger = logging.getLogger("SentinelWatchtower")


def configure_logging() -> None:
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=os.getenv("S43_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


configure_logging()


# =============================================================================
# Utilities
# =============================================================================

def _now() -> float:
    return time.time()


def _new_id() -> str:
    return str(uuid.uuid4())


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _clamp_int(name: str, value: Any, lo: int, hi: int) -> int:
    try:
        iv = int(value)
    except Exception as exc:
        raise ValueError(f"{name} must be an int in [{lo}, {hi}], got {value!r}") from exc

    if not lo <= iv <= hi:
        raise ValueError(f"{name} must be in [{lo}, {hi}], got {iv}")

    return iv


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        return _clamp_int(name, raw, lo, hi)
    except ValueError:
        logger.warning("Invalid env integer %s=%r; using default=%s", name, raw, default)
        return default


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

    event_id = _new_id()
    event["id"] = event_id
    return event_id


# =============================================================================
# Threshold profiles
#
# Fix #3: renamed from ThresholdProfile / thresholds_for to
# TowerThresholdProfile / tower_thresholds_for to eliminate the name
# collision with the rules_engine.ThresholdProfile enum (DEV/TEST/PROD)
# and rules_engine.thresholds_for(profile) function.
# =============================================================================

@dataclass(frozen=True)
class TowerThresholdProfile:
    error_rate_percent: int
    expectation_fail_count: int
    stale_config_seconds: int
    cpu_percent: int
    memory_percent: int
    disk_percent: int
    latency_ms: int


def tower_thresholds_for(sensitivity: int) -> TowerThresholdProfile:
    s = max(1, min(int(sensitivity), 10))
    return TowerThresholdProfile(
        error_rate_percent=max(5, 55 - (s * 5)),
        expectation_fail_count=max(1, 12 - s),
        stale_config_seconds=max(60, 900 - (s * 60)),
        cpu_percent=max(60, 98 - (s * 3)),
        memory_percent=max(60, 98 - (s * 3)),
        disk_percent=max(70, 99 - (s * 2)),
        latency_ms=max(500, 3500 - (s * 250)),
    )


# =============================================================================
# Enums
# =============================================================================

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


class AlertSeverity(enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CoordinatorDecision(enum.Enum):
    OBSERVE = "OBSERVE"
    ALLOW = "ALLOW"
    DEGRADED_SERVICE = "DEGRADED_SERVICE"
    REQUIRE_HUMAN = "REQUIRE_HUMAN"
    DENY = "DENY"


# =============================================================================
# Data models
# =============================================================================

@dataclass(frozen=True)
class ScanResult:
    alerts: list[dict[str, Any]]
    decision: dict[str, Any] | None
    accepted: bool
    dropped_reason: str | None = None


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
        object.__setattr__(self, "sensitivity", _clamp_int("sensitivity", self.sensitivity, 1, 10))

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
    dependency_stale_seconds: int = 60
    max_recent_events: int = 250
    recent_query_limit: int = 500
    correlation_window_seconds: int = 30
    critical_alert_degrade_threshold: int = 1
    high_alert_degrade_threshold: int = 3
    recovery_clean_scan_threshold: int = 3
    expose_bind_host: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id.strip():
            raise ValueError("node_id must be non-empty")

        object.__setattr__(self, "port", _clamp_int("port", self.port, 1024, 65535))
        object.__setattr__(self, "scan_failure_degrade_threshold",
            _clamp_int("scan_failure_degrade_threshold", self.scan_failure_degrade_threshold, 1, 100))
        object.__setattr__(self, "module_stale_seconds",
            _clamp_int("module_stale_seconds", self.module_stale_seconds, 5, 3600))
        object.__setattr__(self, "dependency_stale_seconds",
            _clamp_int("dependency_stale_seconds", self.dependency_stale_seconds, 5, 3600))
        object.__setattr__(self, "max_recent_events",
            _clamp_int("max_recent_events", self.max_recent_events, 10, 5000))
        object.__setattr__(self, "recent_query_limit",
            _clamp_int("recent_query_limit", self.recent_query_limit, 10, 5000))
        if self.recent_query_limit > self.max_recent_events:
            object.__setattr__(self, "recent_query_limit", self.max_recent_events)
        object.__setattr__(self, "correlation_window_seconds",
            _clamp_int("correlation_window_seconds", self.correlation_window_seconds, 5, 300))
        object.__setattr__(self, "critical_alert_degrade_threshold",
            _clamp_int("critical_alert_degrade_threshold", self.critical_alert_degrade_threshold, 1, 20))
        object.__setattr__(self, "high_alert_degrade_threshold",
            _clamp_int("high_alert_degrade_threshold", self.high_alert_degrade_threshold, 1, 50))
        object.__setattr__(self, "recovery_clean_scan_threshold",
            _clamp_int("recovery_clean_scan_threshold", self.recovery_clean_scan_threshold, 1, 20))
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
            port=_env_int("S43_WATCHTOWER_PORT", 9100, 1024, 65535),
            module_stale_seconds=_env_int("S43_MODULE_STALE_SECONDS", 60, 5, 3600),
            dependency_stale_seconds=_env_int("S43_DEPENDENCY_STALE_SECONDS", 60, 5, 3600),
            max_recent_events=_env_int("S43_WATCHTOWER_MAX_EVENTS", 250, 10, 5000),
            recent_query_limit=_env_int("S43_RECENT_QUERY_LIMIT", 500, 10, 5000),
            correlation_window_seconds=_env_int("S43_CORRELATION_WINDOW_SECONDS", 30, 5, 300),
            recovery_clean_scan_threshold=_env_int("S43_RECOVERY_CLEAN_SCAN_THRESHOLD", 3, 1, 20),
            expose_bind_host=_env_bool("S43_EXPOSE_BIND_HOST", False),
            towers=(
                TowerConfig("API Watchtower",            TowerSlot.N,  TowerType.API_HEALTH,         sensitivity=7),
                TowerConfig("Core Logic Watchtower",     TowerSlot.NE, TowerType.EXPECTATION_GUARD,   sensitivity=8),
                TowerConfig("Configuration Watchtower",  TowerSlot.E,  TowerType.CONFIG_DRIFT,        sensitivity=7),
                TowerConfig("Audit Chain Watchtower",    TowerSlot.SE, TowerType.LOGGING_AUDIT,       sensitivity=8),
                TowerConfig("Runtime Stability Watchtower", TowerSlot.S, TowerType.ERROR_RATE,        sensitivity=8),
                TowerConfig("Dependency Watchtower",     TowerSlot.SW, TowerType.DEPENDENCY_HEALTH,   sensitivity=7),
                TowerConfig("Resource Watchtower",       TowerSlot.W,  TowerType.RESOURCE_PRESSURE,   sensitivity=7),
                TowerConfig("Security Watchtower",       TowerSlot.NW, TowerType.SECURITY_BASELINE,   sensitivity=9),
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "node_id": self.node_id,
            "environment": self.environment,
            "port": self.port,
            "api_url": self.api_url,
            "scan_failure_degrade_threshold": self.scan_failure_degrade_threshold,
            "module_stale_seconds": self.module_stale_seconds,
            "dependency_stale_seconds": self.dependency_stale_seconds,
            "max_recent_events": self.max_recent_events,
            "recent_query_limit": self.recent_query_limit,
            "correlation_window_seconds": self.correlation_window_seconds,
            "critical_alert_degrade_threshold": self.critical_alert_degrade_threshold,
            "high_alert_degrade_threshold": self.high_alert_degrade_threshold,
            "recovery_clean_scan_threshold": self.recovery_clean_scan_threshold,
            "towers": [tower.to_dict() for tower in self.towers],
        }
        if self.expose_bind_host:
            payload["host"] = self.host
        return payload


# =============================================================================
# Pydantic request models
# =============================================================================

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


# =============================================================================
# WatchtowerSegment
# =============================================================================

class WatchtowerSegment:
    def __init__(self, cfg: TowerConfig) -> None:
        self.cfg = cfg
        self._thresholds = tower_thresholds_for(cfg.sensitivity)
        self._last_scan_ts: float | None = None
        self._alert_count = 0
        self._malformed_input_count = 0
        self._lock = threading.Lock()

    @property
    def id(self) -> str:
        return f"{self.cfg.slot.value}:{self.cfg.tower_type.value}"

    def _safe_int(self, event: dict[str, Any], field_name: str, default: int = 0) -> tuple[int, int]:
        value, malformed = _safe_metric_int(event.get(field_name, default), default)
        if malformed:
            logger.warning(
                "Malformed numeric field=%s raw=%r event_id=%s tower=%s",
                field_name, event.get(field_name), event.get("id"), self.id,
            )
        return value, malformed

    def _alert(
        self,
        event: dict[str, Any],
        reason: str,
        severity: AlertSeverity,
        created_ts: float,
    ) -> dict[str, Any]:
        event_id = _assign_event_id(event)
        return {
            "alert_id": _new_id(),
            "tower_id": self.id,
            "tower_name": self.cfg.name,
            "tower_type": self.cfg.tower_type.value,
            "slot": self.cfg.slot.value,
            "reason": reason,
            "severity": severity.value,
            "sensitivity": self.cfg.sensitivity,
            "event_ref": event_id,
            "created_ts": created_ts,
        }

    def scan(self, event: dict[str, Any], scan_ts: float | None = None) -> dict[str, Any] | None:
        if not self.cfg.enabled:
            return None
        if not isinstance(event, dict):
            raise TypeError(f"event must be dict, got {type(event).__name__}")

        scan_ts = scan_ts or _now()
        malformed_delta = 0
        tower_type = self.cfg.tower_type
        kind = event.get("kind")

        reason: str | None = None
        severity = AlertSeverity.LOW

        if tower_type == TowerType.API_HEALTH and kind == "request":
            status_code, bad = self._safe_int(event, "status_code", 200)
            malformed_delta += bad
            latency_ms, bad = self._safe_int(event, "latency_ms", 0)
            malformed_delta += bad

            if status_code >= 500:
                reason = f"API server error ({status_code})"
                severity = AlertSeverity.HIGH
            elif status_code == 404:
                reason = "API route not found (404)"
                severity = AlertSeverity.MEDIUM
            elif latency_ms > self._thresholds.latency_ms:
                reason = f"High API latency ({latency_ms}ms)"
                severity = AlertSeverity.MEDIUM

        elif tower_type == TowerType.EXPECTATION_GUARD and kind == "expectation":
            fail_count, bad = self._safe_int(event, "failed_checks", 0)
            malformed_delta += bad

            if fail_count >= self._thresholds.expectation_fail_count:
                reason = f"Expectation failures exceeded threshold ({fail_count})"
                severity = AlertSeverity.HIGH
            elif event.get("expectation_status") == "failed":
                reason = "Expectation contract failed"
                severity = AlertSeverity.MEDIUM

        elif tower_type == TowerType.CONFIG_DRIFT and kind == "config":
            age_seconds, bad = self._safe_int(event, "config_age_seconds", 0)
            malformed_delta += bad

            if event.get("unsafe_config", False):
                reason = "Unsafe configuration detected"
                severity = AlertSeverity.CRITICAL
            elif event.get("drift_detected", False):
                reason = "Configuration drift detected"
                severity = AlertSeverity.HIGH
            elif age_seconds >= self._thresholds.stale_config_seconds:
                reason = f"Configuration stale ({age_seconds}s)"
                severity = AlertSeverity.MEDIUM

        elif tower_type == TowerType.LOGGING_AUDIT and kind == "log":
            if event.get("integrity_status") == "tampered":
                reason = "Log integrity issue detected"
                severity = AlertSeverity.CRITICAL
            elif event.get("audit_write_failed", False):
                reason = "Audit write failure detected"
                severity = AlertSeverity.CRITICAL
            elif event.get("missing_required_fields", False):
                reason = "Required audit/log fields missing"
                severity = AlertSeverity.HIGH

        elif tower_type == TowerType.ERROR_RATE and kind == "runtime":
            error_rate, bad = self._safe_int(event, "error_rate_percent", 0)
            malformed_delta += bad

            if event.get("crash_loop", False):
                reason = "Crash loop detected"
                severity = AlertSeverity.CRITICAL
            elif error_rate >= self._thresholds.error_rate_percent:
                reason = f"Error rate exceeded threshold ({error_rate}%)"
                severity = AlertSeverity.HIGH

        elif tower_type == TowerType.DEPENDENCY_HEALTH and kind == "dependency":
            dep_status = str(event.get("dependency_status", "")).lower()

            if dep_status in {"down", "offline", "failed"}:
                reason = f"Dependency unhealthy ({dep_status})"
                severity = AlertSeverity.HIGH
            elif dep_status in {"degraded", "timeout"}:
                reason = f"Dependency degraded ({dep_status})"
                severity = AlertSeverity.MEDIUM
            elif event.get("version_mismatch", False):
                reason = "Dependency version mismatch detected"
                severity = AlertSeverity.MEDIUM

        elif tower_type == TowerType.RESOURCE_PRESSURE and kind == "resource":
            cpu, bad = self._safe_int(event, "cpu_percent", 0)
            malformed_delta += bad
            mem, bad = self._safe_int(event, "memory_percent", 0)
            malformed_delta += bad
            disk, bad = self._safe_int(event, "disk_percent", 0)
            malformed_delta += bad

            if disk >= self._thresholds.disk_percent:
                reason = f"Disk pressure detected disk={disk}%"
                severity = AlertSeverity.HIGH
            elif cpu >= self._thresholds.cpu_percent or mem >= self._thresholds.memory_percent:
                reason = f"Resource pressure detected cpu={cpu}% mem={mem}% disk={disk}%"
                severity = AlertSeverity.MEDIUM

        elif tower_type == TowerType.SECURITY_BASELINE and kind in {"security", "mobile"}:
            if event.get("secrets_exposed", False):
                reason = "Possible secrets exposure detected"
                severity = AlertSeverity.CRITICAL
            elif event.get("privilege_escalation", False):
                reason = "Privilege escalation signal detected"
                severity = AlertSeverity.CRITICAL
            elif event.get("unsigned_artifact", False):
                reason = "Unsigned artifact detected"
                severity = AlertSeverity.HIGH
            elif event.get("debug_mode_enabled", False):
                reason = "Debug mode enabled in protected environment"
                severity = AlertSeverity.HIGH
            elif event.get("rate_limited", False):
                reason = "Repeated authentication failures triggered rate limiting"
                severity = AlertSeverity.HIGH
            elif event.get("auth_failure", False):
                reason = "Remote authentication failure detected"
                severity = AlertSeverity.MEDIUM

        with self._lock:
            self._last_scan_ts = max(self._last_scan_ts or 0.0, scan_ts)
            self._malformed_input_count += malformed_delta
            if reason:
                self._alert_count += 1

        if not reason:
            return None
        return self._alert(event, reason, severity, scan_ts)

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


# =============================================================================
# WatchtowerNode
# =============================================================================

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

    _DROP_EVENT_STATES: set[WatchtowerState] = {
        WatchtowerState.INITIALIZING,
        WatchtowerState.FAILED,
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
        self._failure_scan_streak = 0
        self._clean_scan_streak = 0
        self._dropped_event_count = 0
        self._last_scan_failure_ts: float | None = None
        self._last_decision: dict[str, Any] | None = None

        for tower_cfg in config.towers:
            segment = WatchtowerSegment(tower_cfg)
            if segment.id in self.towers:
                raise ValueError(f"Duplicate tower id detected: {segment.id}")
            self.towers[segment.id] = segment

        logger.info("[%s] Watchtower initialized with %d segments", self.config.node_id, len(self.towers))

    @property
    def state(self) -> WatchtowerState:
        with self._lock:
            return self._state

    def _set_state_locked(self, new_state: WatchtowerState) -> bool:
        current = self._state
        if new_state == current:
            return True
        allowed = self._ALLOWED_TRANSITIONS.get(current, set())
        if new_state not in allowed:
            logger.warning("Invalid state transition rejected: %s -> %s", current.value, new_state.value)
            return False
        logger.info("Watchtower state changed: %s -> %s", current.value, new_state.value)
        self._state = new_state
        return True

    def set_state(self, new_state: WatchtowerState) -> bool:
        if not isinstance(new_state, WatchtowerState):
            raise TypeError(f"new_state must be WatchtowerState, got {type(new_state).__name__}")
        with self._lock:
            return self._set_state_locked(new_state)

    def start(self) -> None:
        with self._lock:
            if self._state == WatchtowerState.FAILED:
                raise RuntimeError(
                    f"[{self.config.node_id}] Cannot start a FAILED WatchtowerNode."
                )
            applied = self._set_state_locked(WatchtowerState.ACTIVE)
            if not applied:
                raise RuntimeError(
                    f"[{self.config.node_id}] start() state transition "
                    f"{self._state.value} -> ACTIVE was rejected."
                )

    def stop(self) -> None:
        with self._lock:
            if self._state == WatchtowerState.FAILED:
                return
            self._set_state_locked(WatchtowerState.FAILED)

        logger.info(
            "[%s] WatchtowerNode stopped (transitioned to FAILED -- all subsequent events will be dropped).",
            self.config.node_id,
        )

    def last_decision_snapshot(self) -> dict[str, Any] | None:
        with self._lock:
            return copy.deepcopy(self._last_decision)

    def _correlate_findings(
        self,
        event: dict[str, Any],
        findings: list[dict[str, Any]],
        decision_ts: float,
    ) -> dict[str, Any]:
        severity_counts = Counter(item.get("severity", "LOW") for item in findings)
        tower_types = sorted({str(item.get("tower_type", "UNKNOWN")) for item in findings})

        critical_count = severity_counts.get(AlertSeverity.CRITICAL.value, 0)
        high_count = severity_counts.get(AlertSeverity.HIGH.value, 0)

        decision = CoordinatorDecision.OBSERVE
        classification = "NO_ALERT"
        summary = "No tower findings."

        if critical_count:
            decision = CoordinatorDecision.DENY
            classification = "CRITICAL_SYSTEM_RISK"
            summary = "Critical tower finding detected."
        elif (
            TowerType.DEPENDENCY_HEALTH.value in tower_types
            and (
                TowerType.API_HEALTH.value in tower_types
                or TowerType.ERROR_RATE.value in tower_types
                or TowerType.RESOURCE_PRESSURE.value in tower_types
            )
        ):
            decision = CoordinatorDecision.DEGRADED_SERVICE
            classification = "DEPENDENCY_CORRELATED_DEGRADATION"
            summary = "Dependency degradation correlates with API/runtime/resource findings."
        elif high_count >= self.config.high_alert_degrade_threshold:
            decision = CoordinatorDecision.REQUIRE_HUMAN
            classification = "MULTI_TOWER_HIGH_RISK"
            summary = "Multiple high-severity tower findings detected."
        elif high_count:
            decision = CoordinatorDecision.REQUIRE_HUMAN
            classification = "HIGH_RISK_SINGLE_TOWER"
            summary = "High-severity tower finding detected."
        elif findings:
            decision = CoordinatorDecision.OBSERVE
            classification = "LOW_MEDIUM_RISK"
            summary = "Non-critical tower finding detected."

        return {
            "decision_id": _new_id(),
            "source_event_id": event.get("id"),
            "decision": decision.value,
            "classification": classification,
            "summary": summary,
            "severity_counts": dict(severity_counts),
            "tower_types": tower_types,
            "alert_count": len(findings),
            "created_ts": decision_ts,
        }

    def scan_event(self, event: dict[str, Any]) -> ScanResult:
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")

        scan_ts = _now()
        local_event = copy.deepcopy(event)
        event_id = _assign_event_id(local_event)
        local_event.setdefault("received_ts", scan_ts)

        with self._lock:
            state_snapshot = self._state
            tower_snapshot = list(self.towers.values())

        if state_snapshot in self._DROP_EVENT_STATES:
            dropped_reason = f"node_state_{state_snapshot.value.lower()}"
            dropped_event = {
                "id": _new_id(),
                "kind": "watchtower_dropped_event",
                "source_event_id": event_id,
                "accepted": False,
                "dropped_reason": dropped_reason,
                "node_state": state_snapshot.value,
                "created_ts": scan_ts,
            }
            with self._lock:
                self._dropped_event_count += 1
                self.recent_events.append(dropped_event)

            return ScanResult(alerts=[], decision=None, accepted=False, dropped_reason=dropped_reason)

        with self._lock:
            self.recent_events.append(local_event)

        findings: list[dict[str, Any]] = []
        failures = 0

        for segment in tower_snapshot:
            try:
                alert = segment.scan(local_event, scan_ts=scan_ts)
                if alert:
                    findings.append(alert)
            except Exception as exc:
                failures += 1
                logger.exception("Segment scan failure tower=%s error=%s", segment.id, exc)

        decision = self._correlate_findings(local_event, findings, decision_ts=scan_ts)

        alert_event: dict[str, Any] | None = None
        if findings:
            alert_event = {
                "id": _new_id(),
                "kind": "watchtower_alerts",
                "source_event_id": event_id,
                "alerts": copy.deepcopy(findings),
                "coordinator_decision": copy.deepcopy(decision),
                "created_ts": scan_ts,
            }

        decision_value = decision["decision"]
        direct_degrade = (
            failures >= self.config.scan_failure_degrade_threshold
            or decision_value == CoordinatorDecision.DEGRADED_SERVICE.value
            or decision_value == CoordinatorDecision.DENY.value
        )

        with self._lock:
            self._last_decision = copy.deepcopy(decision)

            if alert_event is not None:
                self.recent_events.append(alert_event)

            if failures or direct_degrade:
                self._total_scan_failures += failures
                self._failure_scan_streak += 1
                self._clean_scan_streak = 0
                if failures:
                    self._last_scan_failure_ts = scan_ts
            elif decision_value == CoordinatorDecision.REQUIRE_HUMAN.value:
                self._clean_scan_streak = 0
            else:
                self._clean_scan_streak += 1
                if self._clean_scan_streak >= self.config.recovery_clean_scan_threshold:
                    self._failure_scan_streak = 0

            should_degrade = (
                direct_degrade
                or self._failure_scan_streak >= self.config.scan_failure_degrade_threshold
            )

            if should_degrade:
                self._set_state_locked(WatchtowerState.DEGRADED)
            elif (
                self._state == WatchtowerState.DEGRADED
                and self._failure_scan_streak == 0
                and self._clean_scan_streak >= self.config.recovery_clean_scan_threshold
            ):
                recovered = self._set_state_locked(WatchtowerState.ACTIVE)
                if recovered:
                    logger.info(
                        "[%s] Watchtower recovered DEGRADED -> ACTIVE after %d consecutive clean scans",
                        self.config.node_id,
                        self._clean_scan_streak,
                    )

        return ScanResult(
            alerts=findings,
            decision=copy.deepcopy(decision),
            accepted=True,
            dropped_reason=None,
        )

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

        result = self.scan_event({
            "kind": "dependency",
            "dependency_name": payload.module_id,
            "dependency_status": "online",
            "version": payload.version,
        })
        if not result.accepted:
            logger.warning("Module registration scan dropped module_id=%s reason=%s", payload.module_id, result.dropped_reason)

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

        result = self.scan_event({
            "kind": "dependency",
            "dependency_name": payload.module_id,
            "dependency_status": payload.status,
        })
        if not result.accepted:
            logger.warning("Module heartbeat scan dropped module_id=%s reason=%s", payload.module_id, result.dropped_reason)

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

        result = self.scan_event({
            "kind": "dependency",
            "dependency_name": payload.name,
            "dependency_status": payload.status,
            "latency_ms": payload.latency_ms,
            "version": payload.version,
        })
        if not result.accepted:
            logger.warning("Dependency report scan dropped dependency=%s reason=%s", payload.name, result.dropped_reason)

        return snapshot

    def module_snapshot(self) -> dict[str, Any]:
        now = _now()
        with self._lock:
            modules = copy.deepcopy(self.modules)

        for module in modules.values():
            last = module.get("last_heartbeat_ts")
            try:
                stale = last is None or (now - float(last)) > self.config.module_stale_seconds
            except (TypeError, ValueError):
                stale = True

            module["stale"] = stale
            module["computed_status"] = "stale" if (
                stale and module.get("status") not in {"offline", "down", "failed"}
            ) else module.get("status", "unknown")

        return {
            "module_count": len(modules),
            "stale_after_seconds": self.config.module_stale_seconds,
            "modules": list(modules.values()),
        }

    def dependency_snapshot(self) -> dict[str, Any]:
        now = _now()
        with self._lock:
            dependencies = copy.deepcopy(self.dependencies)

        for dep in dependencies.values():
            last = dep.get("last_report_ts")
            try:
                stale = last is None or (now - float(last)) > self.config.dependency_stale_seconds
            except (TypeError, ValueError):
                stale = True

            dep["stale"] = stale
            dep["computed_status"] = "stale" if (
                stale and dep.get("status") not in {"offline", "down", "failed", "timeout"}
            ) else dep.get("status", "unknown")

        return {
            "dependency_count": len(dependencies),
            "stale_after_seconds": self.config.dependency_stale_seconds,
            "dependencies": list(dependencies.values()),
        }

    def readiness_from_snapshots(self, modules: dict[str, Any], dependencies: dict[str, Any]) -> dict[str, Any]:
        module_records = modules.get("modules", [])
        dependency_records = dependencies.get("dependencies", [])

        stale_modules = [
            item["module_id"] for item in module_records
            if item.get("computed_status") == "stale"
        ]
        bad_modules = [
            item["module_id"] for item in module_records
            if item.get("status") in {"down", "offline", "failed", "degraded"}
        ]

        stale_dependencies = [
            item["name"] for item in dependency_records
            if item.get("computed_status") == "stale"
        ]
        bad_dependencies = [
            item["name"] for item in dependency_records
            if item.get("status") in {"down", "offline", "failed", "timeout"}
        ]

        with self._lock:
            state = self._state
            total_failures = self._total_scan_failures
            failure_scan_streak = self._failure_scan_streak
            clean_scan_streak = self._clean_scan_streak
            dropped_event_count = self._dropped_event_count
            last_decision = copy.deepcopy(self._last_decision)

        recovery_blocked = (
            failure_scan_streak > 0
            and clean_scan_streak < self.config.recovery_clean_scan_threshold
        )

        ready = (
            state == WatchtowerState.ACTIVE
            and not stale_modules
            and not bad_modules
            and not bad_dependencies
            and not stale_dependencies
            and not recovery_blocked
        )

        return {
            "ready": ready,
            "node_id": self.config.node_id,
            "state": state.value,
            "module_count": modules.get("module_count", 0),
            "dependency_count": dependencies.get("dependency_count", 0),
            "stale_modules": stale_modules,
            "bad_modules": bad_modules,
            "stale_dependencies": stale_dependencies,
            "bad_dependencies": bad_dependencies,
            "last_decision": last_decision,
            "recovery": {
                "failure_scan_streak": failure_scan_streak,
                "clean_scan_streak": clean_scan_streak,
                "required_clean_scans": self.config.recovery_clean_scan_threshold,
                "recovery_blocked": recovery_blocked,
            },
            "scan_failures": {
                "total": total_failures,
                "failure_scan_streak": failure_scan_streak,
            },
            "dropped_events": {
                "total": dropped_event_count,
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
            failure_scan_streak = self._failure_scan_streak
            clean_scan_streak = self._clean_scan_streak
            dropped_event_count = self._dropped_event_count
            last_failure_ts = self._last_scan_failure_ts
            last_decision = copy.deepcopy(self._last_decision)

        return {
            "node_id": self.config.node_id,
            "state": state.value,
            "environment": self.config.environment,
            "uptime_seconds": int(_now() - self.created_ts),
            "ready": readiness["ready"],
            "version": VERSION,
            "config": self.config.to_dict(),
            "scan_failures": {
                "total": total_failures,
                "failure_scan_streak": failure_scan_streak,
                "clean_scan_streak": clean_scan_streak,
                "last_failure_ts": last_failure_ts,
            },
            "dropped_events": {
                "total": dropped_event_count,
            },
            "last_decision": last_decision,
            "modules": modules,
            "dependencies": dependencies,
            "readiness": readiness,
            "towers": [tower.status() for tower in tower_snapshot],
        }

    def recent_event_snapshot(self, limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(limit, self.config.max_recent_events, self.config.recent_query_limit))
        with self._lock:
            events = list(self.recent_events)[-limit:]
        return {
            "count": len(events),
            "limit": limit,
            "events": events,
        }


# =============================================================================
# Node factory
# =============================================================================

def build_node() -> WatchtowerNode:
    node_id = os.getenv("S43_WATCHTOWER_NODE_ID", "sentinel43-watchtower")
    config = WatchtowerConfig.default_sentinel_octagon(node_id)
    node = WatchtowerNode(config)
    node.start()  # raises RuntimeError if transition fails
    return node


def get_node() -> WatchtowerNode:
    return _get_or_create_node()


# =============================================================================
# Admin auth
# =============================================================================

def _require_admin_token(token: str | None) -> None:
    expected = os.getenv("S43_ADMIN_TOKEN")
    if not expected or not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized.")


# =============================================================================
# Internal-service auth (Pass 1 — direct Watchtower exposure)
# =============================================================================

_SERVICE_TOKEN_ENV = "S43_WATCHTOWER_SERVICE_TOKEN"


def _require_service_token(
    authorization: str | None = Header(default=None),
) -> None:
    """
    Authenticate an internal Sentinel-43 service on the Watchtower
    operational and mutation routes.

    Every legitimate caller of these routes is a service, never a browser or
    a human operator: the API bridge (core/api/main.py's _watchtower_request),
    FenrirHunter, and the s34_auth reporter. They authenticate with a shared
    secret supplied as ``Authorization: Bearer <S43_WATCHTOWER_SERVICE_TOKEN>``,
    compared in constant time.

    Fails closed with 503 when the token is not configured on this server, so
    a misconfigured deployment cannot silently fall back to accepting
    anonymous callers — that anonymous-mutation gap is exactly what Pass 1
    closes (see RELEASE_FINDINGS.md F-04). ``/watchtower/health`` and
    ``/watchtower/ready`` are deliberately left unauthenticated: they are the
    liveness/readiness probe targets for Docker and Kubernetes, carry no
    credentials, and expose only this node's own state — not the module or
    dependency registry, event ring buffer, or analysis surface.

    The token value is never echoed into any response body or error detail.
    """
    expected = os.getenv(_SERVICE_TOKEN_ENV, "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Watchtower internal-service authentication is not configured on this server.",
        )

    header = (authorization or "").strip()
    if not header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    token = header[len("Bearer "):].strip()
    # Compare as bytes: secrets.compare_digest raises TypeError on a str with
    # non-ASCII characters, which a client could send to force a 500.
    if not token or not secrets.compare_digest(
        token.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service token.",
        )


# =============================================================================
# Router / App factory
# =============================================================================

def create_watchtower_router(node: WatchtowerNode) -> APIRouter:
    router = APIRouter(prefix="/watchtower")

    # Every route below except /health and /ready requires the internal
    # service token (Pass 1). /health and /ready stay open for probes.
    _service_auth = [Depends(_require_service_token)]

    # /health and /ready are the only unauthenticated routes (probe targets
    # for Docker and Kubernetes). Their bodies are intentionally minimal —
    # just a coarse status and the HTTP status code a probe actually reads
    # (Pass 1, F-03). The full node state, version, module/dependency
    # registry, stale-module names and recovery counters are on the
    # service-token-gated /status endpoint, not here.
    @router.get("/health")
    def health_check() -> JSONResponse:
        state = node.state
        if state == WatchtowerState.ACTIVE:
            http_code, svc_status = status.HTTP_200_OK, "ok"
        elif state == WatchtowerState.DEGRADED:
            http_code, svc_status = status.HTTP_503_SERVICE_UNAVAILABLE, "degraded"
        elif state == WatchtowerState.FAILED:
            http_code, svc_status = status.HTTP_503_SERVICE_UNAVAILABLE, "failed"
        else:
            http_code, svc_status = status.HTTP_503_SERVICE_UNAVAILABLE, "initializing"

        return JSONResponse(status_code=http_code, content={"status": svc_status})

    @router.get("/ready")
    def ready_check() -> JSONResponse:
        result = node.readiness()
        ready = bool(result["ready"])
        http_code = status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse(status_code=http_code, content={
            "status": "ready" if ready else "not_ready",
        })

    @router.get("/status", dependencies=_service_auth)
    def node_status() -> dict[str, Any]:
        return node.get_status()

    @router.get("/modules", dependencies=_service_auth)
    def modules_status() -> dict[str, Any]:
        return node.module_snapshot()

    @router.post("/modules/register", dependencies=_service_auth)
    def register_module(payload: ModuleRegisterRequest) -> dict[str, Any]:
        return {"status": "registered", "module": node.register_module(payload)}

    @router.post("/modules/heartbeat", dependencies=_service_auth)
    def module_heartbeat(payload: ModuleHeartbeatRequest) -> dict[str, Any]:
        return {"status": "heartbeat_accepted", "module": node.heartbeat_module(payload)}

    @router.get("/dependencies", dependencies=_service_auth)
    def dependencies_status() -> dict[str, Any]:
        return node.dependency_snapshot()

    @router.post("/dependencies/report", dependencies=_service_auth)
    def report_dependency(payload: DependencyReportRequest) -> dict[str, Any]:
        return {"status": "dependency_report_accepted", "dependency": node.report_dependency(payload)}

    @router.get("/events/recent", dependencies=_service_auth)
    def recent_events(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, Any]:
        return node.recent_event_snapshot(limit)

    @router.post("/analyze", dependencies=_service_auth)
    def analyze_event(payload: AnalyzeRequest) -> dict[str, Any]:
        try:
            result = node.scan_event(payload.event)
            return {
                "accepted": result.accepted,
                "dropped_reason": result.dropped_reason,
                "alerts": result.alerts,
                "alert_count": len(result.alerts),
                "decision": result.decision,
            }
        except Exception as exc:
            logger.exception("Analyze failed: %s", exc)
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/state/{state_name}", dependencies=_service_auth)
    def change_state(
        state_name: str,
        x_s43_admin_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        # Two gates: the service token (transport auth, same as every other
        # route) plus the stricter admin token for the state change itself.
        _require_admin_token(x_s43_admin_token)

        try:
            requested_state = WatchtowerState[state_name.upper()]
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid state: {state_name}") from exc

        previous_state = node.state
        applied = node.set_state(requested_state)
        current_state = node.state

        if not applied:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"State transition {previous_state.value} -> {requested_state.value} "
                    f"is not allowed. Node remains in state {current_state.value}."
                ),
            )

        return {
            "node_id": node.config.node_id,
            "previous_state": previous_state.value,
            "state": current_state.value,
            "applied": True,
            "manual_override": True,
            "note": "Admin state change bypasses automatic recovery hysteresis.",
        }

    return router


def create_api_app(node: WatchtowerNode) -> FastAPI:
    if not isinstance(node, WatchtowerNode):
        raise TypeError(f"node must be WatchtowerNode, got {type(node).__name__}")

    api = FastAPI(
        title="Sentinel-43 Watchtower",
        version=VERSION,
        description=(
            "Sentinel-43 hardened monitoring, octagon correlation, "
            "module registry, dependency, and alert analysis node."
        ),
        # Pass 1 (F-07): this is an internal-only service (no host port
        # publication in Compose, ClusterIP + NetworkPolicy in Kubernetes).
        # The interactive docs, schema, and OpenAPI JSON were served
        # anonymously and enumerated the entire route surface — disable them.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    watchtower_router = create_watchtower_router(node)
    api.include_router(watchtower_router)

    @api.get("/")
    def root() -> dict[str, Any]:
        # Minimal banner only — no version (CVE-matching aid) and no route
        # enumeration (that was a free map of the surface for an anonymous
        # caller). Operational detail lives on the token-gated /status.
        return {"service": "sentinel-43-watchtower", "status": "online"}

    return api


# =============================================================================
# Lazy module-level singletons
#
# Fix #10: _SINGLETON_LOCK changed from threading.Lock() to threading.RLock().
#
# The deadlock sequence was:
#   1. uvicorn resolves `core.monitoring.watchtower:app`
#   2. Python calls module __getattr__("app")
#   3. __getattr__ calls _get_or_create_app()
#   4. _get_or_create_app() acquires _SINGLETON_LOCK (Lock — non-reentrant)
#   5. _get_or_create_app() calls _get_or_create_node()
#   6. _get_or_create_node() tries to acquire _SINGLETON_LOCK again
#   7. Same thread, non-reentrant lock → blocks forever
#   8. uvicorn process alive as PID 1, port 9100 never bound, zero logs
#
# threading.RLock (reentrant lock) allows the same thread to acquire it
# multiple times. The fix requires no other logic changes.
# =============================================================================

_NODE_SINGLETON: WatchtowerNode | None = None
_APP_SINGLETON: FastAPI | None = None
_SINGLETON_LOCK = threading.RLock()  # Fix #10: was threading.Lock() — caused deadlock on startup


def _get_or_create_node() -> WatchtowerNode:
    global _NODE_SINGLETON
    if _NODE_SINGLETON is None:
        with _SINGLETON_LOCK:
            if _NODE_SINGLETON is None:
                _NODE_SINGLETON = build_node()
    return _NODE_SINGLETON


def _get_or_create_app() -> FastAPI:
    global _APP_SINGLETON
    if _APP_SINGLETON is None:
        with _SINGLETON_LOCK:
            if _APP_SINGLETON is None:
                _APP_SINGLETON = create_api_app(_get_or_create_node())
    return _APP_SINGLETON


def __getattr__(name: str) -> Any:
    if name == "NODE":
        node = _get_or_create_node()
        globals()["NODE"] = node
        return node
    if name == "app":
        app_instance = _get_or_create_app()
        globals()["app"] = app_instance
        return app_instance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# =============================================================================
# Entry point
# =============================================================================

def main() -> None:
    node = _get_or_create_node()
    uvicorn.run(
        "core.monitoring.watchtower:app",
        host=node.config.host,
        port=node.config.port,
        reload=False,
        log_level=os.getenv("S43_LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()


__all__ = [
    "VERSION",
    "TowerThresholdProfile",
    "tower_thresholds_for",
    "WatchtowerState",
    "TowerSlot",
    "TowerType",
    "AlertSeverity",
    "CoordinatorDecision",
    "ScanResult",
    "TowerConfig",
    "WatchtowerConfig",
    "WatchtowerSegment",
    "WatchtowerNode",
    "AnalyzeRequest",
    "ModuleRegisterRequest",
    "ModuleHeartbeatRequest",
    "DependencyReportRequest",
    "build_node",
    "get_node",
    "create_watchtower_router",
    "create_api_app",
]
