"""
Sentinel-43 Rules Engine

Clean rule/threshold layer for Watchtower and API health evaluation.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
RULES_MODULE_ID = os.getenv("S43_RULES_MODULE_ID", "sentinel43-rules")
RULES_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{WATCHTOWER_URL}{path}"
    data = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

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


def _report_rule_dependency(
    status: str,
    details: dict[str, Any],
) -> dict[str, Any]:
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


def _report_rule_event(
    status: str,
    details: dict[str, Any],
) -> dict[str, Any]:
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
    try:
        if isinstance(profile, str):
            profile = ThresholdProfile(profile.lower())
    except ValueError:
        _report_rule_dependency(
            status="degraded",
            details={
                "event": "invalid_threshold_profile",
                "profile": str(profile),
            },
        )
        profile = ThresholdProfile.DEV

    if profile == ThresholdProfile.PROD:
        return Thresholds(
            error_rate_warn=0.03,
            error_rate_fail=0.08,
            cpu_warn=75.0,
            cpu_fail=90.0,
            memory_warn=75.0,
            memory_fail=90.0,
            dependency_timeout_seconds=2.0,
        )

    if profile == ThresholdProfile.TEST:
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
            "metadata": {
                "timestamp": utc_now(),
            },
        }

        result = _watchtower_request("POST", "/watchtower/modules/register", payload)
        self._registered_with_watchtower = "error" not in result

    def register(self, name: str, rule: RuleCallable) -> None:
        self._register_with_watchtower_if_needed()

        if not name:
            _report_rule_dependency(
                status="degraded",
                details={"event": "empty_rule_name_registration"},
            )
            raise ValueError("Rule name cannot be empty.")

        if name in self._rules:
            _report_rule_dependency(
                status="degraded",
                details={
                    "event": "duplicate_rule_registration",
                    "rule": name,
                },
            )

        self._rules[name] = rule

        _report_rule_event(
            status="registered",
            details={
                "event": "rule_registered",
                "rule": name,
                "rule_count": len(self._rules),
            },
        )

    def get(self, name: str) -> RuleCallable | None:
        return self._rules.get(name)

    def list_rules(self) -> list[str]:
        return sorted(self._rules.keys())

    def run(self, name: str, payload: dict[str, Any]) -> RuleResult:
        self._register_with_watchtower_if_needed()

        rule = self.get(name)

        if rule is None:
            result = RuleResult(
                name=name,
                passed=False,
                message=f"Rule '{name}' is not registered.",
                severity="error",
            )

            _report_rule_dependency(
                status="degraded",
                details={
                    "event": "rule_not_registered",
                    "rule": name,
                },
            )

            return result