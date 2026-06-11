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

Clean rule/threshold layer for Watchtower and API health evaluation.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger("SentinelRules")

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-core:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
RULES_MODULE_ID = os.getenv("S43_RULES_MODULE_ID", "sentinel43-rules")
RULES_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val) if val is not None else default
    except (ValueError, TypeError):
        return default


def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{WATCHTOWER_URL}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}

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
            with exc:  # Safely close internal response streams to prevent leak
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


def _report_rule_event(status: str, details: dict[str, Any]) -> dict[str, Any]:
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
            error_rate_warn=0.03, error_rate_fail=0.08,
            cpu_warn=75.0, cpu_fail=90.0,
            memory_warn=75.0, memory_fail=90.0,
            dependency_timeout_seconds=2.0,
        )

    if clean_profile == ThresholdProfile.TEST:
        return Thresholds(
            error_rate_warn=0.10, error_rate_fail=0.25,
            cpu_warn=85.0, cpu_fail=95.0,
            memory_warn=85.0, memory_fail=95.0,
            dependency_timeout_seconds=5.0,
        )

    return Thresholds(
        error_rate_warn=0.15, error_rate_fail=0.35,
        cpu_warn=90.0, cpu_fail=98.0,
        memory_warn=90.0, memory_fail=98.0,
        dependency_timeout_seconds=10.0,
    )


RuleCallable = Callable[[dict[str, Any]], RuleResult]


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, RuleCallable] = {}
        self._registered_with_watchtower = False

    def _register_with_watchtower_if_needed(self) -> None:
        if self._registered_with_watchtower:
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
                "threshold_profile_evaluation",
                "rule_failure_reporting",
            ],
            "metadata": {"timestamp": utc_now()},
        }

        result = _watchtower_request("POST", "/watchtower/modules/register", payload)
        if "error" in result:
            logger.warning("Watchtower module registration failed: %s", result)
            return

        self._registered_with_watchtower = True

    def register(self, name: str, rule: RuleCallable) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Rule name cannot be empty.")
        if not callable(rule):
            raise TypeError("rule must be callable")

        self._rules[name] = rule

    def unregister(self, name: str) -> None:
        self._rules.pop(name, None)

    def get(self, name: str) -> RuleCallable | None:
        return self._rules.get(name)

    def list_rules(self) -> list[str]:
        return sorted(self._rules.keys())

    def run(self, name: str, payload: dict[str, Any]) -> RuleResult:
        # Network side-effects safely deferred to actual evaluation cycles
        self._register_with_watchtower_if_needed()

        rule = self.get(name)
        if rule is None:
            _report_rule_dependency(status="degraded", details={"event": "rule_not_registered", "rule": name})
            return RuleResult(
                name=name, passed=False, message=f"Rule '{name}' is not registered.",
                severity="error", details={"available_rules": self.list_rules()}
            )

        if not isinstance(payload, dict):
            _report_rule_dependency(
                status="degraded", 
                details={"event": "invalid_rule_payload", "rule": name, "payload_type": type(payload).__name__}
            )
            return RuleResult(
                name=name, passed=False, message="Rule payload must be a dictionary.",
                severity="error", details={"payload_type": type(payload).__name__}
            )

        try:
            result = rule(payload)
        except Exception as exc:
            logger.exception("Rule execution failed rule=%s error=%s", name, exc)
            _report_rule_dependency(
                status="degraded",
                details={
                    "event": "rule_execution_exception", "rule": name,
                    "exception_type": type(exc).__name__, "exception": str(exc),
                },
            )
            return RuleResult(
                name=name, passed=False, message=f"Rule '{name}' raised an exception: {exc}",
                severity="error", details={"exception_type": type(exc).__name__}
            )

        if not isinstance(result, RuleResult):
            _report_rule_dependency(
                status="degraded",
                details={"event": "invalid_rule_result", "rule": name, "result_type": type(result).__name__}
            )
            return RuleResult(
                name=name, passed=False, message=f"Rule '{name}' returned invalid result type.",
                severity="error", details={"result_type": type(result).__name__}
            )

        _report_rule_event(
            status="passed" if result.passed else "failed",
            details={
                "event": "rule_evaluated", "rule": name, "passed": result.passed,
                "severity": result.severity, "message": result.message, "details": result.details or {},
            },
        )
        return result


# Core Rule Logic Definitions
def api_health_rule(payload: dict[str, Any]) -> RuleResult:
    thresholds = thresholds_for(payload.get("profile", ThresholdProfile.DEV))
    error_rate = _safe_float(payload.get("error_rate"), 0.0)
    latency_seconds = _safe_float(payload.get("latency_seconds"), 0.0)

    if error_rate >= thresholds.error_rate_fail:
        return RuleResult(
            name="api_health", passed=False,
            message=f"API error rate failed threshold: {error_rate:.3f}", severity="error",
            details={"error_rate": error_rate, "threshold": thresholds.error_rate_fail},
        )

    if error_rate >= thresholds.error_rate_warn:
        return RuleResult(
            name="api_health", passed=True,
            message=f"API error rate warning threshold reached: {error_rate:.3f}", severity="warning",
            details={"error_rate": error_rate, "threshold": thresholds.error_rate_warn},
        )

    if latency_seconds >= thresholds.dependency_timeout_seconds:
        return RuleResult(
            name="api_health", passed=False,
            message=f"API latency exceeded timeout threshold: {latency_seconds:.3f}s", severity="error",
            details={"latency_seconds": latency_seconds, "threshold": thresholds.dependency_timeout_seconds},
        )

    return RuleResult(
        name="api_health", passed=True, message="API health within thresholds.", severity="info",
        details={"error_rate": error_rate, "latency_seconds": latency_seconds},
    )


def dependency_health_rule(payload: dict[str, Any]) -> RuleResult:
    status = str(payload.get("status", "unknown")).lower()
    name = str(payload.get("name", "dependency"))

    if status in {"down", "offline", "failed", "timeout"}:
        return RuleResult(
            name="dependency_health", passed=False,
            message=f"Dependency '{name}' is unhealthy: {status}", severity="error",
            details={"dependency": name, "status": status},
        )

    if status in {"degraded", "stale"}:
        return RuleResult(
            name="dependency_health", passed=True,
            message=f"Dependency '{name}' is degraded: {status}", severity="warning",
            details={"dependency": name, "status": status},
        )

    return RuleResult(
        name="dependency_health", passed=True, message=f"Dependency '{name}' is healthy.", severity="info",
        details={"dependency": name, "status": status},
    )


def resource_pressure_rule(payload: dict[str, Any]) -> RuleResult:
    thresholds = thresholds_for(payload.get("profile", ThresholdProfile.DEV))
    cpu = _safe_float(payload.get("cpu_percent"), 0.0)
    memory = _safe_float(payload.get("memory_percent"), 0.0)

    if cpu >= thresholds.cpu_fail or memory >= thresholds.memory_fail:
        return RuleResult(
            name="resource_pressure", passed=False,
            message=f"Resource pressure failed threshold cpu={cpu:.1f}% memory={memory:.1f}%", severity="error",
            details={
                "cpu_percent": cpu, "memory_percent": memory,
                "cpu_fail": thresholds.cpu_fail, "memory_fail": thresholds.memory_fail,
            },
        )

    if cpu >= thresholds.cpu_warn or memory >= thresholds.memory_warn:
        return RuleResult(
            name="resource_pressure", passed=True,
            message=f"Resource pressure warning cpu={cpu:.1f}% memory={memory:.1f}%", severity="warning",
            details={
                "cpu_percent": cpu, "memory_percent": memory,
                "cpu_warn": thresholds.cpu_warn, "memory_warn": thresholds.memory_warn,
            },
        )

    return RuleResult(
        name="resource_pressure", passed=True, message="Resource pressure within thresholds.", severity="info",
        details={"cpu_percent": cpu, "memory_percent": memory},
    )


# Standard singleton instance generation
registry = RuleRegistry()
registry.register("api_health", api_health_rule)
registry.register("dependency_health", dependency_health_rule)
registry.register("resource_pressure", resource_pressure_rule)


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
]
