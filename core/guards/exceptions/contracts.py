from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, runtime_checkable


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
        return cls(
            passed=False,
            expectation_name=expectation_name,
            category=category,
            severity=severity,
            message=message,
            violations=violations or (),
            metadata=metadata or {},
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