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

"""Canonical expectation contract types for Sentinel-43.

This module defines expectation categories, severities, contexts, violations,
results, and the validation protocol.

It is intentionally side-effect free:
    - no Watchtower calls
    - no environment reads
    - no logging/reporting
    - no network I/O

Callers may report failed results after validation through the monitoring layer.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable


def _freeze_mapping(
    value: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    return MappingProxyType(
        dict(
            value
            or {}
        )
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


@dataclass(frozen=True, slots=True)
class ExpectationContext:
    """Runtime context supplied to an expectation validator."""

    component: str
    operation: str
    actor: str | None = None
    environment: str | None = None
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        component = self.component.strip()
        operation = self.operation.strip()

        if not component:
            raise ValueError(
                "component must not be empty"
            )

        if not operation:
            raise ValueError(
                "operation must not be empty"
            )

        object.__setattr__(
            self,
            "component",
            component,
        )

        object.__setattr__(
            self,
            "operation",
            operation,
        )

        if self.actor is not None:
            actor = self.actor.strip()

            object.__setattr__(
                self,
                "actor",
                actor or None,
            )

        if self.environment is not None:
            environment = (
                self.environment
                .strip()
                .lower()
            )

            object.__setattr__(
                self,
                "environment",
                environment or None,
            )

        object.__setattr__(
            self,
            "metadata",
            _freeze_mapping(
                self.metadata
            ),
        )


@dataclass(frozen=True, slots=True)
class ExpectationViolation:
    """One concrete violation produced by expectation validation."""

    expectation_name: str
    message: str
    category: ExpectationCategory
    severity: ExpectationSeverity
    details: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        name = self.expectation_name.strip()
        message = self.message.strip()

        if not name:
            raise ValueError(
                "expectation_name must not be empty"
            )

        if not message:
            raise ValueError(
                "message must not be empty"
            )

        object.__setattr__(
            self,
            "expectation_name",
            name,
        )

        object.__setattr__(
            self,
            "message",
            message,
        )

        object.__setattr__(
            self,
            "details",
            _freeze_mapping(
                self.details
            ),
        )


@dataclass(frozen=True, slots=True)
class ExpectationResult:
    """Immutable result returned by expectation validation."""

    passed: bool
    expectation_name: str
    category: ExpectationCategory
    severity: ExpectationSeverity
    message: str = ""
    violations: tuple[
        ExpectationViolation,
        ...
    ] = ()
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        name = self.expectation_name.strip()

        if not name:
            raise ValueError(
                "expectation_name must not be empty"
            )

        object.__setattr__(
            self,
            "expectation_name",
            name,
        )

        object.__setattr__(
            self,
            "metadata",
            _freeze_mapping(
                self.metadata
            ),
        )

        violations = tuple(
            self.violations
        )

        object.__setattr__(
            self,
            "violations",
            violations,
        )

        if self.passed and violations:
            raise ValueError(
                "passed results must not contain violations"
            )

        if not self.passed and not self.message.strip():
            raise ValueError(
                "failed results must include a message"
            )

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
        violations: tuple[
            ExpectationViolation,
            ...
        ] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "ExpectationResult":
        return cls(
            passed=False,
            expectation_name=expectation_name,
            category=category,
            severity=severity,
            message=message,
            violations=tuple(
                violations
                or ()
            ),
            metadata=metadata or {},
        )

    def safe_dict(
        self,
    ) -> dict[str, Any]:
        """Return a serialization-friendly representation."""
        return {
            "passed": self.passed,
            "expectation_name": self.expectation_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "violation_count": len(
                self.violations
            ),
            "violations": [
                {
                    "expectation_name": violation.expectation_name,
                    "message": violation.message,
                    "category": violation.category.value,
                    "severity": violation.severity.value,
                    "details": dict(
                        violation.details
                    ),
                }
                for violation
                in self.violations
            ],
            "metadata": dict(
                self.metadata
            ),
        }


@runtime_checkable
class ExpectationContract(Protocol):
    """Protocol implemented by every Sentinel-43 expectation."""

    name: str
    category: ExpectationCategory
    severity: ExpectationSeverity
    description: str

    def validate(
        self,
        context: ExpectationContext,
    ) -> ExpectationResult:
        ...


__all__ = [
    "ExpectationCategory",
    "ExpectationContext",
    "ExpectationContract",
    "ExpectationResult",
    "ExpectationSeverity",
    "ExpectationViolation",
]
