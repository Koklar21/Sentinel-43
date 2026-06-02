"""
Sentinel-43 Rules Engine

Clean rule/threshold layer for Watchtower and API health evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


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
    if isinstance(profile, str):
        profile = ThresholdProfile(profile.lower())

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

    def register(self, name: str, rule: RuleCallable) -> None:
        if not name:
            raise ValueError("Rule name cannot be empty.")
        self._rules[name] = rule

    def get(self, name: str) -> RuleCallable | None:
        return self._rules.get(name)

    def list_rules(self) -> list[str]:
        return sorted(self._rules.keys())

    def run(self, name: str, payload: dict[str, Any]) -> RuleResult:
        rule = self.get(name)
        if rule is None:
            return RuleResult(
                name=name,
                passed=False,
                message=f"Rule '{name}' is not registered.",
                severity="error",
            )
        return rule(payload)

    def run_all(self, payload: dict[str, Any]) -> list[RuleResult]:
        return [rule(payload) for rule in self._rules.values()]


def api_health_rule(payload: dict[str, Any]) -> RuleResult:
    status = str(payload.get("status", "")).lower()
    passed = status in {"ok", "online", "healthy", "active"}

    return RuleResult(
        name="api_health",
        passed=passed,
        message="API health check passed." if passed else "API health check failed.",
        severity="info" if passed else "critical",
        details={"status": status},
    )


def dependency_health_rule(payload: dict[str, Any]) -> RuleResult:
    unhealthy = payload.get("unhealthy_dependencies", [])

    passed = not unhealthy

    return RuleResult(
        name="dependency_health",
        passed=passed,
        message="All dependencies are healthy." if passed else "One or more dependencies are unhealthy.",
        severity="info" if passed else "warning",
        details={"unhealthy_dependencies": unhealthy},
    )


def resource_pressure_rule(payload: dict[str, Any]) -> RuleResult:
    profile = payload.get("profile", ThresholdProfile.DEV)
    thresholds = thresholds_for(profile)

    cpu = float(payload.get("cpu_percent", 0.0))
    memory = float(payload.get("memory_percent", 0.0))

    failed = cpu >= thresholds.cpu_fail or memory >= thresholds.memory_fail
    warned = cpu >= thresholds.cpu_warn or memory >= thresholds.memory_warn

    if failed:
        severity = "critical"
        passed = False
        message = "Resource pressure exceeded failure threshold."
    elif warned:
        severity = "warning"
        passed = True
        message = "Resource pressure exceeded warning threshold."
    else:
        severity = "info"
        passed = True
        message = "Resource pressure normal."

    return RuleResult(
        name="resource_pressure",
        passed=passed,
        message=message,
        severity=severity,
        details={
            "cpu_percent": cpu,
            "memory_percent": memory,
            "thresholds": thresholds.__dict__,
        },
    )


registry = RuleRegistry()
registry.register("api_health", api_health_rule)
registry.register("dependency_health", dependency_health_rule)
registry.register("resource_pressure", resource_pressure_rule)


__all__ = [
    "ThresholdProfile",
    "Thresholds",
    "RuleResult",
    "RuleRegistry",
    "RuleCallable",
    "thresholds_for",
    "registry",
]