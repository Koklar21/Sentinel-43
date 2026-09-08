# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Pure Sentinel-43 monitoring rules and registry.

This module intentionally performs no network I/O, environment reads,
self-registration, background work, or telemetry reporting.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final


class ThresholdProfile(StrEnum):
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


class RuleSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Thresholds:
    error_rate_warn: float
    error_rate_fail: float
    cpu_warn: float
    cpu_fail: float
    memory_warn: float
    memory_fail: float
    dependency_timeout_seconds: float

    sparta_blocked_clients_warn: int = 1
    sparta_blocked_clients_fail: int = 25
    sparta_auth_clients_warn: int = 25

    firewall_block_rate_warn: float = 25.0
    firewall_block_rate_fail: float = 75.0
    firewall_tracked_ips_warn: int = 1000
    firewall_dropped_reports_warn: int = 1
    firewall_dropped_reports_fail: int = 500

    def __post_init__(self) -> None:
        if not 0.0 <= self.error_rate_warn <= self.error_rate_fail <= 1.0:
            raise ValueError(
                "error-rate thresholds must satisfy "
                "0 <= warn <= fail <= 1"
            )

        if not 0.0 <= self.cpu_warn <= self.cpu_fail <= 100.0:
            raise ValueError(
                "CPU thresholds must satisfy "
                "0 <= warn <= fail <= 100"
            )

        if not 0.0 <= self.memory_warn <= self.memory_fail <= 100.0:
            raise ValueError(
                "memory thresholds must satisfy "
                "0 <= warn <= fail <= 100"
            )

        if self.dependency_timeout_seconds <= 0:
            raise ValueError(
                "dependency_timeout_seconds must be > 0"
            )


_PROFILE_THRESHOLDS: Final = MappingProxyType(
    {
        ThresholdProfile.DEV: Thresholds(
            error_rate_warn=0.15,
            error_rate_fail=0.35,
            cpu_warn=90.0,
            cpu_fail=98.0,
            memory_warn=90.0,
            memory_fail=98.0,
            dependency_timeout_seconds=10.0,
        ),
        ThresholdProfile.TEST: Thresholds(
            error_rate_warn=0.10,
            error_rate_fail=0.25,
            cpu_warn=85.0,
            cpu_fail=95.0,
            memory_warn=85.0,
            memory_fail=95.0,
            dependency_timeout_seconds=5.0,
        ),
        ThresholdProfile.PROD: Thresholds(
            error_rate_warn=0.03,
            error_rate_fail=0.08,
            cpu_warn=75.0,
            cpu_fail=90.0,
            memory_warn=75.0,
            memory_fail=90.0,
            dependency_timeout_seconds=2.0,
        ),
    }
)


@dataclass(frozen=True, slots=True)
class RuleResult:
    name: str
    passed: bool
    message: str
    severity: RuleSeverity = RuleSeverity.INFO
    details: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError(
                "rule result name must not be empty"
            )

        if not self.message.strip():
            raise ValueError(
                "rule result message must not be empty"
            )

        if (
            not self.passed
            and self.severity
            in {
                RuleSeverity.INFO,
                RuleSeverity.WARNING,
            }
        ):
            raise ValueError(
                "failed rules must use ERROR or CRITICAL severity"
            )


RuleCallable = Callable[
    [dict[str, Any]],
    RuleResult,
]


def thresholds_for(
    profile: ThresholdProfile | str = ThresholdProfile.DEV,
) -> Thresholds:
    try:
        normalized = (
            profile
            if isinstance(
                profile,
                ThresholdProfile,
            )
            else ThresholdProfile(
                str(
                    profile
                ).strip().lower()
            )
        )
    except ValueError as exc:
        raise ValueError(
            f"unknown threshold profile {profile!r}"
        ) from exc

    return _PROFILE_THRESHOLDS[
        normalized
    ]


def _float(
    payload: dict[str, Any],
    key: str,
    *,
    default: float = 0.0,
) -> float:
    value = payload.get(
        key,
        default,
    )

    try:
        return float(
            value
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(
            f"{key} must be numeric"
        ) from exc


def _int(
    payload: dict[str, Any],
    key: str,
    *,
    default: int = 0,
) -> int:
    value = payload.get(
        key,
        default,
    )

    try:
        return int(
            value
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(
            f"{key} must be an integer"
        ) from exc


def _str(
    payload: dict[str, Any],
    key: str,
    *,
    default: str = "",
) -> str:
    value = payload.get(
        key,
        default,
    )

    if value is None:
        return default

    return str(
        value
    ).strip()


def _verification_valid(
    value: Any,
) -> bool:
    if isinstance(
        value,
        bool,
    ):
        return value

    if isinstance(
        value,
        dict,
    ):
        return value.get(
            "valid"
        ) is True

    return False


def api_health_rule(
    payload: dict[str, Any],
) -> RuleResult:
    thresholds = thresholds_for(
        payload.get(
            "profile",
            ThresholdProfile.DEV,
        )
    )

    if "error_rate" in payload:
        error_rate = _float(
            payload,
            "error_rate",
        )
    elif "error_rate_percent" in payload:
        error_rate = (
            _float(
                payload,
                "error_rate_percent",
            )
            / 100.0
        )
    else:
        error_rate = 0.0

    latency_seconds = _float(
        payload,
        "latency_seconds",
    )

    if not 0.0 <= error_rate <= 1.0:
        raise ValueError(
            "error_rate must be between 0 and 1"
        )

    if latency_seconds < 0:
        raise ValueError(
            "latency_seconds must be >= 0"
        )

    if error_rate >= thresholds.error_rate_fail:
        return RuleResult(
            name="api_health",
            passed=False,
            message="API error rate exceeded fail threshold.",
            severity=RuleSeverity.ERROR,
            details={
                "error_rate": error_rate,
                "threshold": thresholds.error_rate_fail,
            },
        )

    if latency_seconds >= thresholds.dependency_timeout_seconds:
        return RuleResult(
            name="api_health",
            passed=False,
            message="API latency exceeded fail threshold.",
            severity=RuleSeverity.ERROR,
            details={
                "latency_seconds": latency_seconds,
                "threshold": thresholds.dependency_timeout_seconds,
            },
        )

    if error_rate >= thresholds.error_rate_warn:
        return RuleResult(
            name="api_health",
            passed=True,
            message="API error rate reached warning threshold.",
            severity=RuleSeverity.WARNING,
            details={
                "error_rate": error_rate,
                "threshold": thresholds.error_rate_warn,
            },
        )

    return RuleResult(
        name="api_health",
        passed=True,
        message="API health is within thresholds.",
        details={
            "error_rate": error_rate,
            "latency_seconds": latency_seconds,
        },
    )


def dependency_health_rule(
    payload: dict[str, Any],
) -> RuleResult:
    status = _str(
        payload,
        "status",
        default="unknown",
    ).lower()

    name = _str(
        payload,
        "name",
        default="dependency",
    )

    if status in {
        "down",
        "offline",
        "failed",
        "timeout",
        "unknown",
        "",
    }:
        return RuleResult(
            name="dependency_health",
            passed=False,
            message="Dependency is unavailable or unverified.",
            severity=RuleSeverity.ERROR,
            details={
                "dependency": name,
                "status": status,
            },
        )

    if status in {
        "degraded",
        "stale",
    }:
        return RuleResult(
            name="dependency_health",
            passed=True,
            message="Dependency is degraded.",
            severity=RuleSeverity.WARNING,
            details={
                "dependency": name,
                "status": status,
            },
        )

    return RuleResult(
        name="dependency_health",
        passed=True,
        message="Dependency is healthy.",
        details={
            "dependency": name,
            "status": status,
        },
    )


def resource_pressure_rule(
    payload: dict[str, Any],
) -> RuleResult:
    thresholds = thresholds_for(
        payload.get(
            "profile",
            ThresholdProfile.DEV,
        )
    )

    cpu = _float(
        payload,
        "cpu_percent",
    )

    memory = _float(
        payload,
        "memory_percent",
    )

    for name, value in (
        (
            "cpu_percent",
            cpu,
        ),
        (
            "memory_percent",
            memory,
        ),
    ):
        if not 0.0 <= value <= 100.0:
            raise ValueError(
                f"{name} must be between 0 and 100"
            )

    if (
        cpu >= thresholds.cpu_fail
        or memory >= thresholds.memory_fail
    ):
        return RuleResult(
            name="resource_pressure",
            passed=False,
            message="Resource pressure exceeded fail threshold.",
            severity=RuleSeverity.ERROR,
            details={
                "cpu_percent": cpu,
                "memory_percent": memory,
            },
        )

    if (
        cpu >= thresholds.cpu_warn
        or memory >= thresholds.memory_warn
    ):
        return RuleResult(
            name="resource_pressure",
            passed=True,
            message="Resource pressure reached warning threshold.",
            severity=RuleSeverity.WARNING,
            details={
                "cpu_percent": cpu,
                "memory_percent": memory,
            },
        )

    return RuleResult(
        name="resource_pressure",
        passed=True,
        message="Resource pressure is within thresholds.",
        details={
            "cpu_percent": cpu,
            "memory_percent": memory,
        },
    )


def sparta_core_rule(
    payload: dict[str, Any],
) -> RuleResult:
    thresholds = thresholds_for(
        payload.get(
            "profile",
            ThresholdProfile.DEV,
        )
    )

    state = _str(
        payload,
        "state",
        default="UNKNOWN",
    ).upper()

    tamper_count = _int(
        payload,
        "tamper_count",
    )

    blocked_clients = _int(
        payload,
        "blocked_clients",
    )

    tracked_auth_clients = _int(
        payload,
        "tracked_auth_clients",
    )

    watched_file_count = _int(
        payload,
        "watched_file_count",
    )

    total_checks = _int(
        payload,
        "total_checks",
    )

    details = {
        "state": state,
        "tamper_count": tamper_count,
        "blocked_clients": blocked_clients,
        "tracked_auth_clients": tracked_auth_clients,
        "watched_file_count": watched_file_count,
        "total_checks": total_checks,
    }

    if state in {
        "COMPROMISED",
        "SHUTDOWN",
        "LOCKDOWN",
        "UNKNOWN",
        "",
    }:
        return RuleResult(
            name="sparta_core",
            passed=False,
            message="SpartaCore is not in a verified operational state.",
            severity=RuleSeverity.ERROR,
            details=details,
        )

    if tamper_count > 0:
        return RuleResult(
            name="sparta_core",
            passed=False,
            message="SpartaCore has recorded tamper activity.",
            severity=RuleSeverity.ERROR,
            details=details,
        )

    if (
        blocked_clients
        >= thresholds.sparta_blocked_clients_fail
    ):
        return RuleResult(
            name="sparta_core",
            passed=False,
            message="SpartaCore blocked-client count exceeded fail threshold.",
            severity=RuleSeverity.ERROR,
            details=details,
        )

    if (
        blocked_clients
        >= thresholds.sparta_blocked_clients_warn
        or tracked_auth_clients
        >= thresholds.sparta_auth_clients_warn
        or (
            watched_file_count > 0
            and total_checks <= 0
        )
    ):
        return RuleResult(
            name="sparta_core",
            passed=True,
            message="SpartaCore is operational with warning conditions.",
            severity=RuleSeverity.WARNING,
            details=details,
        )

    return RuleResult(
        name="sparta_core",
        passed=True,
        message="SpartaCore status is within thresholds.",
        details=details,
    )


def sentinel_firewall_rule(
    payload: dict[str, Any],
) -> RuleResult:
    thresholds = thresholds_for(
        payload.get(
            "profile",
            ThresholdProfile.DEV,
        )
    )

    total_requests = _int(
        payload,
        "total_requests",
    )

    blocked_count = _int(
        payload,
        "blocked_count",
    )

    block_rate = _float(
        payload,
        "block_rate_percent",
    )

    tracked_ips = _int(
        payload,
        "tracked_ips",
    )

    dropped_reports = _int(
        payload,
        "dropped_report_count",
    )

    details = {
        "total_requests": total_requests,
        "blocked_count": blocked_count,
        "block_rate_percent": block_rate,
        "tracked_ips": tracked_ips,
        "dropped_report_count": dropped_reports,
    }

    if (
        dropped_reports
        >= thresholds.firewall_dropped_reports_fail
        or (
            total_requests > 0
            and block_rate
            >= thresholds.firewall_block_rate_fail
        )
    ):
        return RuleResult(
            name="sentinel_firewall",
            passed=False,
            message="SentinelFirewall exceeded a fail threshold.",
            severity=RuleSeverity.ERROR,
            details=details,
        )

    if (
        dropped_reports
        >= thresholds.firewall_dropped_reports_warn
        or tracked_ips
        >= thresholds.firewall_tracked_ips_warn
        or (
            total_requests > 0
            and block_rate
            >= thresholds.firewall_block_rate_warn
        )
    ):
        return RuleResult(
            name="sentinel_firewall",
            passed=True,
            message="SentinelFirewall has warning conditions.",
            severity=RuleSeverity.WARNING,
            details=details,
        )

    return RuleResult(
        name="sentinel_firewall",
        passed=True,
        message="SentinelFirewall status is within thresholds.",
        details=details,
    )


def jormungandr_rule(
    payload: dict[str, Any],
) -> RuleResult:
    """Evaluate the recoded encrypted audit mirror.

    Expected fields:
        epoch
        retained_key_epochs
        retained_records
        record_capacity
        last_record_hash
        verify_chain
    """
    epoch = _int(
        payload,
        "epoch",
    )

    retained_records = _int(
        payload,
        "retained_records",
    )

    record_capacity = _int(
        payload,
        "record_capacity",
    )

    last_hash = _str(
        payload,
        "last_record_hash",
    )

    verification = payload.get(
        "verify_chain"
    )

    verification_valid = _verification_valid(
        verification
    )

    details = {
        "epoch": epoch,
        "retained_records": retained_records,
        "record_capacity": record_capacity,
        "last_record_hash_present": bool(
            last_hash
        ),
        "verify_chain_valid": verification_valid,
    }

    if not verification_valid:
        return RuleResult(
            name="jormungandr",
            passed=False,
            message="Jormungandr retained hash chain could not be verified.",
            severity=RuleSeverity.CRITICAL,
            details=details,
        )

    if epoch < 1:
        return RuleResult(
            name="jormungandr",
            passed=False,
            message="Jormungandr has no active key epoch.",
            severity=RuleSeverity.ERROR,
            details=details,
        )

    if record_capacity < 1:
        return RuleResult(
            name="jormungandr",
            passed=False,
            message="Jormungandr record capacity is invalid.",
            severity=RuleSeverity.ERROR,
            details=details,
        )

    if retained_records > 0 and not last_hash:
        return RuleResult(
            name="jormungandr",
            passed=False,
            message="Jormungandr retained records without a chain anchor.",
            severity=RuleSeverity.ERROR,
            details=details,
        )

    return RuleResult(
        name="jormungandr",
        passed=True,
        message="Jormungandr encrypted audit mirror is internally consistent.",
        details=details,
    )


def security_stack_rule(
    payload: dict[str, Any],
) -> RuleResult:
    component_payloads = {
        "sparta_core": payload.get(
            "sparta"
        ),
        "sentinel_firewall": payload.get(
            "firewall"
        ),
        "jormungandr": payload.get(
            "jormungandr"
        ),
    }

    if not all(
        isinstance(
            item,
            dict,
        )
        for item in component_payloads.values()
    ):
        return RuleResult(
            name="security_stack",
            passed=False,
            message="Security stack status is incomplete.",
            severity=RuleSeverity.ERROR,
            details={
                "present_components": [
                    name
                    for name, item
                    in component_payloads.items()
                    if isinstance(
                        item,
                        dict,
                    )
                ],
            },
        )

    results = {
        "sparta_core": sparta_core_rule(
            component_payloads[
                "sparta_core"
            ]
        ),
        "sentinel_firewall": sentinel_firewall_rule(
            component_payloads[
                "sentinel_firewall"
            ]
        ),
        "jormungandr": jormungandr_rule(
            component_payloads[
                "jormungandr"
            ]
        ),
    }

    failures = [
        name
        for name, result
        in results.items()
        if not result.passed
    ]

    warnings = [
        name
        for name, result
        in results.items()
        if (
            result.passed
            and result.severity
            is RuleSeverity.WARNING
        )
    ]

    details = {
        name: {
            "passed": result.passed,
            "severity": result.severity.value,
            "message": result.message,
        }
        for name, result in results.items()
    }

    if failures:
        return RuleResult(
            name="security_stack",
            passed=False,
            message="Security stack has failing components.",
            severity=RuleSeverity.ERROR,
            details={
                "failing_components": failures,
                "components": details,
            },
        )

    if warnings:
        return RuleResult(
            name="security_stack",
            passed=True,
            message="Security stack has warning components.",
            severity=RuleSeverity.WARNING,
            details={
                "warning_components": warnings,
                "components": details,
            },
        )

    return RuleResult(
        name="security_stack",
        passed=True,
        message="Security stack is within thresholds.",
        details={
            "components": details
        },
    )


class RuleRegistry:
    """Thread-safe side-effect-free rule registry."""

    def __init__(
        self,
    ) -> None:
        self._rules: dict[
            str,
            RuleCallable,
        ] = {}

        self._lock = threading.RLock()

    def register(
        self,
        name: str,
        rule: RuleCallable,
    ) -> None:
        normalized = name.strip()

        if not normalized:
            raise ValueError(
                "rule name must not be empty"
            )

        if not callable(
            rule
        ):
            raise TypeError(
                "rule must be callable"
            )

        with self._lock:
            if normalized in self._rules:
                raise ValueError(
                    f"rule {normalized!r} is already registered"
                )

            self._rules[
                normalized
            ] = rule

    def unregister(
        self,
        name: str,
    ) -> None:
        with self._lock:
            self._rules.pop(
                name.strip(),
                None,
            )

    def get(
        self,
        name: str,
    ) -> RuleCallable | None:
        with self._lock:
            return self._rules.get(
                name.strip()
            )

    def list_rules(
        self,
    ) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self._rules
                )
            )

    def run(
        self,
        name: str,
        payload: dict[str, Any],
    ) -> RuleResult:
        if not isinstance(
            payload,
            dict,
        ):
            raise TypeError(
                "rule payload must be a dict"
            )

        rule = self.get(
            name
        )

        if rule is None:
            raise KeyError(
                f"rule {name!r} is not registered"
            )

        result = rule(
            payload
        )

        if not isinstance(
            result,
            RuleResult,
        ):
            raise TypeError(
                f"rule {name!r} returned an invalid result"
            )

        return result


def build_default_registry(
) -> RuleRegistry:
    registry = RuleRegistry()

    registry.register(
        "api_health",
        api_health_rule,
    )

    registry.register(
        "dependency_health",
        dependency_health_rule,
    )

    registry.register(
        "resource_pressure",
        resource_pressure_rule,
    )

    registry.register(
        "sparta_core",
        sparta_core_rule,
    )

    registry.register(
        "sentinel_firewall",
        sentinel_firewall_rule,
    )

    registry.register(
        "jormungandr",
        jormungandr_rule,
    )

    registry.register(
        "security_stack",
        security_stack_rule,
    )

    return registry


registry = build_default_registry()


__all__ = [
    "RuleCallable",
    "RuleRegistry",
    "RuleResult",
    "RuleSeverity",
    "ThresholdProfile",
    "Thresholds",
    "api_health_rule",
    "build_default_registry",
    "dependency_health_rule",
    "jormungandr_rule",
    "registry",
    "resource_pressure_rule",
    "security_stack_rule",
    "sentinel_firewall_rule",
    "sparta_core_rule",
    "thresholds_for",
]
