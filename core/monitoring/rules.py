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
Sentinel-43 Rules Engine
v0.2.0

Clean rule/threshold layer for Watchtower, API health evaluation, and the new
security-node stack:

  - SpartaCore integrity / node-auth status
  - SentinelFirewall edge-defense status
  - Jormungandr cryptographic audit / threat posture status
  - Combined security-stack health evaluation

The rules engine remains intentionally dependency-light and import-safe. It does
not import the security modules directly, because rules should evaluate reported
status payloads instead of creating runtime coupling between Watchtower, API,
firewall, and monitoring internals. Otherwise the dependency graph becomes a
spiderweb wearing a trench coat.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger("SentinelRules")

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-core:9100").rstrip("/")
RULES_MODULE_ID = os.getenv("S43_RULES_MODULE_ID", "sentinel43-rules")

# Prefer S43_* naming, but keep legacy SENTINEL_VERSION for compatibility.
RULES_VERSION = os.getenv("S43_RULES_VERSION", os.getenv("SENTINEL_VERSION", "0.2.0"))


# =============================================================================
# Environment helpers
# =============================================================================

def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "Invalid value %r for %s, falling back to default %s",
            raw,
            name,
            default,
        )
        return default


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = int(raw)
        if not lo <= value <= hi:
            raise ValueError(f"out of [{lo},{hi}]")
        return value
    except ValueError:
        logger.warning(
            "Invalid value %r for %s, falling back to default %s",
            raw,
            name,
            default,
        )
        return default


WATCHTOWER_TIMEOUT = _float_env("S43_WATCHTOWER_TIMEOUT", 2.0)
REGISTRATION_RETRY_SECONDS = _float_env("S43_RULES_REGISTRATION_RETRY_SECONDS", 30.0)

# Security-node rule thresholds. These are intentionally environment-tunable so
# beta can be strict without hardcoding production assumptions into the module.
SPARTA_BLOCKED_CLIENTS_WARN = _int_env("S43_RULES_SPARTA_BLOCKED_CLIENTS_WARN", 1, 0, 1_000_000)
SPARTA_BLOCKED_CLIENTS_FAIL = _int_env("S43_RULES_SPARTA_BLOCKED_CLIENTS_FAIL", 25, 1, 1_000_000)
SPARTA_AUTH_CLIENTS_WARN = _int_env("S43_RULES_SPARTA_TRACKED_AUTH_CLIENTS_WARN", 25, 0, 1_000_000)

FIREWALL_BLOCK_RATE_WARN = _float_env("S43_RULES_FIREWALL_BLOCK_RATE_WARN", 25.0)
FIREWALL_BLOCK_RATE_FAIL = _float_env("S43_RULES_FIREWALL_BLOCK_RATE_FAIL", 75.0)
FIREWALL_TRACKED_IPS_WARN = _int_env("S43_RULES_FIREWALL_TRACKED_IPS_WARN", 1_000, 1, 10_000_000)
FIREWALL_DROPPED_REPORTS_WARN = _int_env("S43_RULES_FIREWALL_DROPPED_REPORTS_WARN", 1, 0, 10_000_000)
FIREWALL_DROPPED_REPORTS_FAIL = _int_env("S43_RULES_FIREWALL_DROPPED_REPORTS_FAIL", 500, 1, 10_000_000)

JORM_THREAT_SCORE_WARN = _int_env("S43_RULES_JORM_THREAT_SCORE_WARN", 10, 0, 1_000_000)
JORM_THREAT_SCORE_FAIL = _int_env("S43_RULES_JORM_THREAT_SCORE_FAIL", 40, 1, 1_000_000)
JORM_DROPPED_MONITORING_WARN = _int_env("S43_RULES_JORM_DROPPED_MONITORING_WARN", 1, 0, 10_000_000)
JORM_DROPPED_MONITORING_FAIL = _int_env("S43_RULES_JORM_DROPPED_MONITORING_FAIL", 500, 1, 10_000_000)


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val) if val is not None else default
    except (ValueError, TypeError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        if val is None:
            return default
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_str(val: Any, default: str = "") -> str:
    if val is None:
        return default
    try:
        return str(val)
    except Exception:
        return default


def _safe_bool(val: Any, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        lowered = val.strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
    if isinstance(val, (int, float)):
        return bool(val)
    return default


def _ensure_dict(val: Any) -> dict[str, Any]:
    return val if isinstance(val, dict) else {}


def _status_from_verification(value: Any) -> bool:
    """Accept either bools or dicts like {'valid': true}."""
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return _safe_bool(value.get("valid"), False)
    return False


# =============================================================================
# Watchtower telemetry
# =============================================================================

def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{WATCHTOWER_URL}{path}"
    headers = {"Content-Type": "application/json"}

    data = None
    if payload is not None:
        try:
            data = json.dumps(payload, default=str).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return {
                "error": "watchtower_payload_serialization_error",
                "detail": str(exc),
            }

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            if not body:
                return {"status_code": response.status}

            parsed = json.loads(body)
            if isinstance(parsed, dict):
                parsed.setdefault("status_code", response.status)
                return parsed

            return {"status_code": response.status, "body": parsed}

    except urllib.error.HTTPError as exc:
        try:
            with exc:
                detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)

        return {
            "error": "watchtower_http_error",
            "status_code": exc.code,
            "detail": detail,
        }
    except Exception as exc:
        return {
            "error": "watchtower_unreachable",
            "detail": str(exc),
        }


def _report_rule_dependency(status: str, details: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = {
            "name": RULES_MODULE_ID,
            "status": status,
            "version": RULES_VERSION,
            "details": {
                "timestamp": utc_now(),
                **details,
            },
        }
        return _watchtower_request("POST", "/watchtower/dependencies/report", payload)
    except Exception as exc:
        return {"error": "telemetry_reporting_failed", "detail": str(exc)}


def _report_rule_event(status: str, details: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = {
            "event": {
                "kind": "runtime",
                "source": RULES_MODULE_ID,
                "status": status,
                "details": {
                    "timestamp": utc_now(),
                    **details,
                },
            }
        }
        return _watchtower_request("POST", "/watchtower/analyze", payload)
    except Exception as exc:
        return {"error": "telemetry_reporting_failed", "detail": str(exc)}


# =============================================================================
# Rule models
# =============================================================================

class ThresholdProfile(str, Enum):
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


@dataclass(frozen=True)
class RuleResult:
    name: str
    passed: bool
    message: str
    severity: str = "info"
    details: dict[str, Any] | None = None


@dataclass(frozen=True)
class Thresholds:
    error_rate_warn: float
    error_rate_fail: float
    cpu_warn: float
    cpu_fail: float
    memory_warn: float
    memory_fail: float
    dependency_timeout_seconds: float


def thresholds_for(profile: ThresholdProfile | str = ThresholdProfile.DEV) -> Thresholds:
    clean_profile = ThresholdProfile.DEV
    try:
        if isinstance(profile, str):
            clean_profile = ThresholdProfile(profile.lower())
        elif isinstance(profile, ThresholdProfile):
            clean_profile = profile
    except ValueError:
        _report_rule_dependency(
            status="degraded",
            details={
                "event": "invalid_threshold_profile",
                "profile": str(profile),
            },
        )

    if clean_profile == ThresholdProfile.PROD:
        return Thresholds(
            error_rate_warn=0.03,
            error_rate_fail=0.08,
            cpu_warn=75.0,
            cpu_fail=90.0,
            memory_warn=75.0,
            memory_fail=90.0,
            dependency_timeout_seconds=2.0,
        )

    if clean_profile == ThresholdProfile.TEST:
        return Thresholds(
            error_rate_warn=0.10,
            error_rate_fail=0.25,
            cpu_warn=85.0,
            cpu_fail=95.0,
            memory_warn=85.0,
            memory_fail=95.0,
            dependency_timeout_seconds=5.0,
        )

    return Thresholds(
        error_rate_warn=0.15,
        error_rate_fail=0.35,
        cpu_warn=90.0,
        cpu_fail=98.0,
        memory_warn=90.0,
        memory_fail=98.0,
        dependency_timeout_seconds=10.0,
    )


RuleCallable = Callable[[dict[str, Any]], RuleResult]


# =============================================================================
# Rule registry
# =============================================================================

class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, RuleCallable] = {}
        self._registered_with_watchtower = False
        self._next_registration_attempt = 0.0
        self._lock = threading.Lock()

    def _register_with_watchtower_if_needed(self) -> None:
        with self._lock:
            if self._registered_with_watchtower:
                return

            now = time.monotonic()
            if now < self._next_registration_attempt:
                return

        payload = {
            "module_id": RULES_MODULE_ID,
            "module_type": "rules-engine",
            "version": RULES_VERSION,
            "endpoint": None,
            "capabilities": [
                "api_health_rule",
                "dependency_health_rule",
                "resource_pressure_rule",
                "sparta_core_rule",
                "sentinel_firewall_rule",
                "jormungandr_rule",
                "security_stack_rule",
                "threshold_profile_evaluation",
                "rule_failure_reporting",
            ],
            "metadata": {"timestamp": utc_now()},
        }

        result = _watchtower_request("POST", "/watchtower/modules/register", payload)

        with self._lock:
            if "error" in result:
                logger.warning("Watchtower module registration failed: %s", result)
                self._registered_with_watchtower = False
                self._next_registration_attempt = time.monotonic() + REGISTRATION_RETRY_SECONDS
            else:
                self._registered_with_watchtower = True

    def register(self, name: str, rule: RuleCallable) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Rule name cannot be empty.")
        if not callable(rule):
            raise TypeError("rule must be callable")

        with self._lock:
            self._rules[name] = rule

    def unregister(self, name: str) -> None:
        with self._lock:
            self._rules.pop(name, None)

    def get(self, name: str) -> RuleCallable | None:
        with self._lock:
            return self._rules.get(name)

    def list_rules(self) -> list[str]:
        with self._lock:
            return sorted(self._rules.keys())

    def run(self, name: str, payload: dict[str, Any]) -> RuleResult:
        self._register_with_watchtower_if_needed()

        rule = self.get(name)
        if rule is None:
            _report_rule_dependency(
                status="degraded",
                details={"event": "rule_not_registered", "rule": name},
            )
            return RuleResult(
                name=name,
                passed=False,
                message=f"Rule '{name}' is not registered.",
                severity="error",
                details={"available_rules": self.list_rules()},
            )

        if not isinstance(payload, dict):
            _report_rule_dependency(
                status="degraded",
                details={
                    "event": "invalid_rule_payload",
                    "rule": name,
                    "payload_type": type(payload).__name__,
                },
            )
            return RuleResult(
                name=name,
                passed=False,
                message="Rule payload must be a dictionary.",
                severity="error",
                details={"payload_type": type(payload).__name__},
            )

        try:
            result = rule(payload)
        except Exception as exc:
            logger.exception("Rule execution failed rule=%s error=%s", name, exc)
            _report_rule_dependency(
                status="degraded",
                details={
                    "event": "rule_execution_exception",
                    "rule": name,
                    "exception_type": type(exc).__name__,
                    "exception": str(exc),
                },
            )
            return RuleResult(
                name=name,
                passed=False,
                message=f"Rule '{name}' raised an exception: {exc}",
                severity="error",
                details={"exception_type": type(exc).__name__},
            )

        if not isinstance(result, RuleResult):
            _report_rule_dependency(
                status="degraded",
                details={
                    "event": "invalid_rule_result",
                    "rule": name,
                    "result_type": type(result).__name__,
                },
            )
            return RuleResult(
                name=name,
                passed=False,
                message=f"Rule '{name}' returned invalid result type.",
                severity="error",
                details={"result_type": type(result).__name__},
            )

        _report_rule_event(
            status="passed" if result.passed else "failed",
            details={
                "event": "rule_evaluated",
                "rule": name,
                "passed": result.passed,
                "severity": result.severity,
                "message": result.message,
                "details": result.details or {},
            },
        )
        return result


# =============================================================================
# Core rule logic
# =============================================================================

def api_health_rule(payload: dict[str, Any]) -> RuleResult:
    thresholds = thresholds_for(payload.get("profile", ThresholdProfile.DEV))

    if "error_rate" in payload:
        error_rate = _safe_float(payload.get("error_rate"), 0.0)
    elif "error_rate_percent" in payload:
        error_rate = _safe_float(payload.get("error_rate_percent"), 0.0) / 100.0
    else:
        error_rate = 0.0

    latency_seconds = _safe_float(payload.get("latency_seconds"), 0.0)

    if error_rate >= thresholds.error_rate_fail:
        return RuleResult(
            name="api_health",
            passed=False,
            message=f"API error rate failed threshold: {error_rate:.3f}",
            severity="error",
            details={"error_rate": error_rate, "threshold": thresholds.error_rate_fail},
        )

    if error_rate >= thresholds.error_rate_warn:
        return RuleResult(
            name="api_health",
            passed=True,
            message=f"API error rate warning threshold reached: {error_rate:.3f}",
            severity="warning",
            details={"error_rate": error_rate, "threshold": thresholds.error_rate_warn},
        )

    if latency_seconds >= thresholds.dependency_timeout_seconds:
        return RuleResult(
            name="api_health",
            passed=False,
            message=f"API latency exceeded timeout threshold: {latency_seconds:.3f}s",
            severity="error",
            details={"latency_seconds": latency_seconds, "threshold": thresholds.dependency_timeout_seconds},
        )

    return RuleResult(
        name="api_health",
        passed=True,
        message="API health within thresholds.",
        severity="info",
        details={"error_rate": error_rate, "latency_seconds": latency_seconds},
    )


def dependency_health_rule(payload: dict[str, Any]) -> RuleResult:
    status = _safe_str(payload.get("status"), "unknown").lower()
    name = _safe_str(payload.get("name"), "dependency")

    if status in {"down", "offline", "failed", "timeout"}:
        return RuleResult(
            name="dependency_health",
            passed=False,
            message=f"Dependency '{name}' is unhealthy: {status}",
            severity="error",
            details={"dependency": name, "status": status},
        )

    if status in {"degraded", "stale"}:
        return RuleResult(
            name="dependency_health",
            passed=True,
            message=f"Dependency '{name}' is degraded: {status}",
            severity="warning",
            details={"dependency": name, "status": status},
        )

    return RuleResult(
        name="dependency_health",
        passed=True,
        message=f"Dependency '{name}' is healthy.",
        severity="info",
        details={"dependency": name, "status": status},
    )


def resource_pressure_rule(payload: dict[str, Any]) -> RuleResult:
    thresholds = thresholds_for(payload.get("profile", ThresholdProfile.DEV))
    cpu = _safe_float(payload.get("cpu_percent"), 0.0)
    memory = _safe_float(payload.get("memory_percent"), 0.0)

    if cpu >= thresholds.cpu_fail or memory >= thresholds.memory_fail:
        return RuleResult(
            name="resource_pressure",
            passed=False,
            message=f"Resource pressure failed threshold cpu={cpu:.1f}% memory={memory:.1f}%",
            severity="error",
            details={
                "cpu_percent": cpu,
                "memory_percent": memory,
                "cpu_fail": thresholds.cpu_fail,
                "memory_fail": thresholds.memory_fail,
            },
        )

    if cpu >= thresholds.cpu_warn or memory >= thresholds.memory_warn:
        return RuleResult(
            name="resource_pressure",
            passed=True,
            message=f"Resource pressure warning cpu={cpu:.1f}% memory={memory:.1f}%",
            severity="warning",
            details={
                "cpu_percent": cpu,
                "memory_percent": memory,
                "cpu_warn": thresholds.cpu_warn,
                "memory_warn": thresholds.memory_warn,
            },
        )

    return RuleResult(
        name="resource_pressure",
        passed=True,
        message="Resource pressure within thresholds.",
        severity="info",
        details={"cpu_percent": cpu, "memory_percent": memory},
    )


# =============================================================================
# Security-node rules
# =============================================================================

def sparta_core_rule(payload: dict[str, Any]) -> RuleResult:
    """
    Evaluate SpartaCore status payloads from SpartaCore.get_status().

    Expected fields include:
      state, tamper_count, blocked_clients, tracked_auth_clients,
      watched_file_count, total_checks, event_log_entries.
    """
    state = _safe_str(payload.get("state"), "UNKNOWN").upper()
    tamper_count = _safe_int(payload.get("tamper_count"), 0)
    blocked_clients = _safe_int(payload.get("blocked_clients"), 0)
    tracked_auth_clients = _safe_int(payload.get("tracked_auth_clients"), 0)
    total_checks = _safe_int(payload.get("total_checks"), 0)
    watched_file_count = _safe_int(payload.get("watched_file_count"), 0)

    details = {
        "state": state,
        "tamper_count": tamper_count,
        "blocked_clients": blocked_clients,
        "tracked_auth_clients": tracked_auth_clients,
        "total_checks": total_checks,
        "watched_file_count": watched_file_count,
    }

    if state in {"COMPROMISED", "SHUTDOWN"}:
        return RuleResult(
            name="sparta_core",
            passed=False,
            message=f"SpartaCore is in terminal/degraded state: {state}",
            severity="critical",
            details=details,
        )

    if state == "LOCKDOWN":
        return RuleResult(
            name="sparta_core",
            passed=False,
            message="SpartaCore is in LOCKDOWN.",
            severity="error",
            details=details,
        )

    if tamper_count > 0:
        return RuleResult(
            name="sparta_core",
            passed=False,
            message=f"SpartaCore has recorded tamper events: {tamper_count}",
            severity="error",
            details=details,
        )

    if blocked_clients >= SPARTA_BLOCKED_CLIENTS_FAIL:
        return RuleResult(
            name="sparta_core",
            passed=False,
            message=f"SpartaCore blocked client count exceeded fail threshold: {blocked_clients}",
            severity="error",
            details={**details, "threshold": SPARTA_BLOCKED_CLIENTS_FAIL},
        )

    if blocked_clients >= SPARTA_BLOCKED_CLIENTS_WARN:
        return RuleResult(
            name="sparta_core",
            passed=True,
            message=f"SpartaCore is blocking suspicious clients: {blocked_clients}",
            severity="warning",
            details={**details, "threshold": SPARTA_BLOCKED_CLIENTS_WARN},
        )

    if tracked_auth_clients >= SPARTA_AUTH_CLIENTS_WARN:
        return RuleResult(
            name="sparta_core",
            passed=True,
            message=f"SpartaCore has elevated auth-failure tracking: {tracked_auth_clients}",
            severity="warning",
            details={**details, "threshold": SPARTA_AUTH_CLIENTS_WARN},
        )

    if watched_file_count > 0 and total_checks <= 0:
        return RuleResult(
            name="sparta_core",
            passed=True,
            message="SpartaCore has watched files but no integrity checks have completed yet.",
            severity="warning",
            details=details,
        )

    if state in {"INITIALIZING", "UNKNOWN"}:
        return RuleResult(
            name="sparta_core",
            passed=True,
            message=f"SpartaCore has not reached operational state yet: {state}",
            severity="warning",
            details=details,
        )

    return RuleResult(
        name="sparta_core",
        passed=True,
        message="SpartaCore integrity and node-auth status are within thresholds.",
        severity="info",
        details=details,
    )


def sentinel_firewall_rule(payload: dict[str, Any]) -> RuleResult:
    """
    Evaluate SentinelFirewall.get_stats() payloads from the pure ASGI firewall.
    """
    total_requests = _safe_int(payload.get("total_requests"), 0)
    blocked_count = _safe_int(payload.get("blocked_count"), 0)
    block_rate_percent = _safe_float(payload.get("block_rate_percent"), 0.0)
    tracked_ips = _safe_int(payload.get("tracked_ips"), 0)
    dropped_report_count = _safe_int(payload.get("dropped_report_count"), 0)
    reported_block_count = _safe_int(payload.get("reported_block_count"), 0)

    details = {
        "total_requests": total_requests,
        "blocked_count": blocked_count,
        "block_rate_percent": block_rate_percent,
        "tracked_ips": tracked_ips,
        "dropped_report_count": dropped_report_count,
        "reported_block_count": reported_block_count,
    }

    if dropped_report_count >= FIREWALL_DROPPED_REPORTS_FAIL:
        return RuleResult(
            name="sentinel_firewall",
            passed=False,
            message=f"Firewall monitoring drop count exceeded fail threshold: {dropped_report_count}",
            severity="error",
            details={**details, "threshold": FIREWALL_DROPPED_REPORTS_FAIL},
        )

    if total_requests > 0 and block_rate_percent >= FIREWALL_BLOCK_RATE_FAIL:
        return RuleResult(
            name="sentinel_firewall",
            passed=False,
            message=f"Firewall block rate exceeded fail threshold: {block_rate_percent:.2f}%",
            severity="error",
            details={**details, "threshold": FIREWALL_BLOCK_RATE_FAIL},
        )

    if dropped_report_count >= FIREWALL_DROPPED_REPORTS_WARN:
        return RuleResult(
            name="sentinel_firewall",
            passed=True,
            message=f"Firewall monitoring queue has dropped reports: {dropped_report_count}",
            severity="warning",
            details={**details, "threshold": FIREWALL_DROPPED_REPORTS_WARN},
        )

    if tracked_ips >= FIREWALL_TRACKED_IPS_WARN:
        return RuleResult(
            name="sentinel_firewall",
            passed=True,
            message=f"Firewall is tracking a high number of IPs: {tracked_ips}",
            severity="warning",
            details={**details, "threshold": FIREWALL_TRACKED_IPS_WARN},
        )

    if total_requests > 0 and block_rate_percent >= FIREWALL_BLOCK_RATE_WARN:
        return RuleResult(
            name="sentinel_firewall",
            passed=True,
            message=f"Firewall block rate warning threshold reached: {block_rate_percent:.2f}%",
            severity="warning",
            details={**details, "threshold": FIREWALL_BLOCK_RATE_WARN},
        )

    return RuleResult(
        name="sentinel_firewall",
        passed=True,
        message="SentinelFirewall status is within thresholds.",
        severity="info",
        details=details,
    )


def jormungandr_rule(payload: dict[str, Any]) -> RuleResult:
    """
    Evaluate JormungandrNode.get_summary() plus optional chain verification data.

    Payload can include:
      posture, security_mode, threat_score, epoch, mode,
      dropped_monitoring_events, reported_monitoring_events,
      verify_events, verify_threats.
    """
    posture = _safe_str(payload.get("posture"), "UNKNOWN").upper()
    security_mode = _safe_str(payload.get("security_mode"), "UNKNOWN")
    security_mode_clean = security_mode.lower()
    threat_score = _safe_int(payload.get("threat_score"), 0)
    dropped_monitoring = _safe_int(payload.get("dropped_monitoring_events"), 0)
    reported_monitoring = _safe_int(payload.get("reported_monitoring_events"), 0)

    verify_events_raw = payload.get("verify_events")
    verify_threats_raw = payload.get("verify_threats")
    verify_events_valid = True if verify_events_raw is None else _status_from_verification(verify_events_raw)
    verify_threats_valid = True if verify_threats_raw is None else _status_from_verification(verify_threats_raw)

    details = {
        "posture": posture,
        "security_mode": security_mode,
        "threat_score": threat_score,
        "dropped_monitoring_events": dropped_monitoring,
        "reported_monitoring_events": reported_monitoring,
        "verify_events_valid": verify_events_valid,
        "verify_threats_valid": verify_threats_valid,
    }

    if not verify_events_valid or not verify_threats_valid:
        return RuleResult(
            name="jormungandr",
            passed=False,
            message="Jormungandr audit hash-chain verification failed.",
            severity="critical",
            details={
                **details,
                "verify_events": verify_events_raw,
                "verify_threats": verify_threats_raw,
            },
        )

    if posture == "HOSTILE" or security_mode_clean == "lockdown" or threat_score >= JORM_THREAT_SCORE_FAIL:
        return RuleResult(
            name="jormungandr",
            passed=False,
            message=(
                "Jormungandr is in hostile/lockdown posture or threat score exceeded fail threshold."
            ),
            severity="error",
            details={**details, "threat_score_fail": JORM_THREAT_SCORE_FAIL},
        )

    if dropped_monitoring >= JORM_DROPPED_MONITORING_FAIL:
        return RuleResult(
            name="jormungandr",
            passed=False,
            message=f"Jormungandr dropped monitoring count exceeded fail threshold: {dropped_monitoring}",
            severity="error",
            details={**details, "threshold": JORM_DROPPED_MONITORING_FAIL},
        )

    if posture == "VIGILANT" or security_mode_clean == "elevated" or threat_score >= JORM_THREAT_SCORE_WARN:
        return RuleResult(
            name="jormungandr",
            passed=True,
            message="Jormungandr is elevated/vigilant but still within fail thresholds.",
            severity="warning",
            details={**details, "threat_score_warn": JORM_THREAT_SCORE_WARN},
        )

    if dropped_monitoring >= JORM_DROPPED_MONITORING_WARN:
        return RuleResult(
            name="jormungandr",
            passed=True,
            message=f"Jormungandr monitoring queue has dropped telemetry: {dropped_monitoring}",
            severity="warning",
            details={**details, "threshold": JORM_DROPPED_MONITORING_WARN},
        )

    if posture in {"UNKNOWN", ""}:
        return RuleResult(
            name="jormungandr",
            passed=True,
            message="Jormungandr posture is unknown or not yet reported.",
            severity="warning",
            details=details,
        )

    return RuleResult(
        name="jormungandr",
        passed=True,
        message="Jormungandr cryptographic audit posture is within thresholds.",
        severity="info",
        details=details,
    )


def security_stack_rule(payload: dict[str, Any]) -> RuleResult:
    """
    Combined evaluation for the new S43 security stack.

    Expected payload shape:
      {
        "sparta": {...SpartaCore.get_status()...},
        "firewall": {...SentinelFirewall.get_stats()...},
        "jormungandr": {
          ...JormungandrNode.get_summary(),
          "verify_events": jorm.verify_chain("events"),
          "verify_threats": jorm.verify_chain("threats"),
        }
      }
    """
    sparta_payload = _ensure_dict(payload.get("sparta"))
    firewall_payload = _ensure_dict(payload.get("firewall"))
    jorm_payload = _ensure_dict(payload.get("jormungandr"))

    results = {
        "sparta_core": sparta_core_rule(sparta_payload),
        "sentinel_firewall": sentinel_firewall_rule(firewall_payload),
        "jormungandr": jormungandr_rule(jorm_payload),
    }

    failed = [name for name, result in results.items() if not result.passed]
    warnings = [name for name, result in results.items() if result.passed and result.severity == "warning"]

    details = {
        name: {
            "passed": result.passed,
            "severity": result.severity,
            "message": result.message,
            "details": result.details or {},
        }
        for name, result in results.items()
    }

    if failed:
        return RuleResult(
            name="security_stack",
            passed=False,
            message=f"Security stack has failing components: {', '.join(failed)}",
            severity="error",
            details=details,
        )

    if warnings:
        return RuleResult(
            name="security_stack",
            passed=True,
            message=f"Security stack has warning components: {', '.join(warnings)}",
            severity="warning",
            details=details,
        )

    return RuleResult(
        name="security_stack",
        passed=True,
        message="Security stack is within thresholds.",
        severity="info",
        details=details,
    )


# =============================================================================
# Standard singleton instance generation
# =============================================================================

registry = RuleRegistry()
registry.register("api_health", api_health_rule)
registry.register("dependency_health", dependency_health_rule)
registry.register("resource_pressure", resource_pressure_rule)
registry.register("sparta_core", sparta_core_rule)
registry.register("sentinel_firewall", sentinel_firewall_rule)
registry.register("jormungandr", jormungandr_rule)
registry.register("security_stack", security_stack_rule)


__all__ = [
    "WATCHTOWER_URL",
    "WATCHTOWER_TIMEOUT",
    "RULES_MODULE_ID",
    "RULES_VERSION",
    "ThresholdProfile",
    "Thresholds",
    "RuleResult",
    "RuleCallable",
    "RuleRegistry",
    "registry",
    "thresholds_for",
    "api_health_rule",
    "dependency_health_rule",
    "resource_pressure_rule",
    "sparta_core_rule",
    "sentinel_firewall_rule",
    "jormungandr_rule",
    "security_stack_rule",
]
