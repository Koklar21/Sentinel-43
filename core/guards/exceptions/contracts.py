from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Protocol, runtime_checkable


WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
CONTRACTS_MODULE_ID = os.getenv("S43_CONTRACTS_MODULE_ID", "sentinel43-contracts")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_request(payload: dict[str, Any]) -> None:
    try:
        request = urllib.request.Request(
            f"{WATCHTOWER_URL}/watchtower/analyze",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT)
    except Exception:
        pass


def report_contract_failure(
    *,
    expectation_name: str,
    category: str,
    severity: str,
    message: str,
    details: Mapping[str, Any] | None = None,
) -> None:
    payload = {
        "event": {
            "kind": "expectation",
            "source": CONTRACTS_MODULE_ID,
            "expectation_status": "failed",
            "expectation_name": expectation_name,
            "category": category,
            "severity": severity,
            "message": message,
            "failed_checks": 1,
            "details": dict(details or {}),
            "timestamp": utc_now(),
        }
    }

    _watchtower_request(payload)


def report_validation_exception(
    expectation_name: str,
    exc: Exception,
) -> None:
    report_contract_failure(
        expectation_name=expectation_name,
        category="contract",
        severity="critical",
        message=f"Validation exception: {exc}",
        details={
            "exception_type": type(exc).__name__,
        },
    )


class ExpectationCategory(str, Enum):
    CORE = "core"
    API = "api"
    DATA = "data"
    SERVICE = "service"
    SECURITY = "security"
    LOGGING = "logging"
    AUDIT = "audit"
    CONFIG = "config"
    RECOVERY = "recovery"
    CUSTOM = "custom"


class ExpectationSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True, frozen=True)
class ExpectationContext:
    """
    Runtime context passed into expectation validators.

    attributes:
        component: logical subsystem being evaluated
        operation: current action or workflow
        actor: user/service/process triggering the action
        environment: runtime environment (dev/test/prod/etc.)
        metadata: additional arbitrary context
    """
    component: str
    operation: str
    actor: str | None = None
    environment: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class ExpectationViolation:
    """
    Describes a single expectation failure.
    """
    expectation_name: str
    message: str
    category: ExpectationCategory
    severity: ExpectationSeverity
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class ExpectationResult:
    """
    Result returned by expectation validation.
    """
    passed: bool
    expectation_name: str
    category: ExpectationCategory
    severity: ExpectationSeverity
    message: str = ""
    violations: tuple[ExpectationViolation, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def success(
        cls,
        *,
        expectation_name: str,
        category: ExpectationCategory,
        severity: ExpectationSeverity = ExpectationSeverity.LOW,
        message: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> "ExpectationResult":
        return cls(
            passed=True,
            expectation_name=expectation_name,
            category=category,
            severity=severity,
            message=message,
            violations=(),
            metadata=metadata or {},
        )

    @classmethod
    def failure(
        cls,
        *,
        expectation_name: str,
        category: ExpectationCategory,
        severity: ExpectationSeverity,
        message: str,
        violations: tuple[ExpectationViolation, ...] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "ExpectationResult":
        safe_metadata = metadata or {}
        safe_violations = violations or ()

        report_contract_failure(
            expectation_name=expectation_name,
            category=category.value,
            severity=severity.value,
            message=message,
            details={
                "metadata": dict(safe_metadata),
                "violation_count": len(safe_violations),
                "violations": [
                    {
                        "expectation_name": violation.expectation_name,
                        "message": violation.message,
                        "category": violation.category.value,
                        "severity": violation.severity.value,
                        "details": dict(violation.details),
                    }
                    for violation in safe_violations
                ],
            },
        )

        return cls(
            passed=False,
            expectation_name=expectation_name,
            category=category,
            severity=severity,
            message=message,
            violations=safe_violations,
            metadata=safe_metadata,
        )


@runtime_checkable
class ExpectationContract(Protocol):
    """
    Protocol every expectation implementation should follow.
    """

    name: str
    category: ExpectationCategory
    severity: ExpectationSeverity
    description: str

    def validate(self, context: ExpectationContext) -> ExpectationResult:
        """
        Validate the expectation against the provided context.
        """
        ...