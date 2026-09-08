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

"""Concrete Sentinel-43 expectation implementations and profile sets."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from .contracts import (
    ExpectationCategory,
    ExpectationContext,
    ExpectationResult,
    ExpectationSeverity,
    ExpectationViolation,
)


_TRUE_FLAG_VALUES: Final[frozenset[str]] = frozenset(
    {
        "1",
        "true",
        "yes",
        "on",
        "ok",
        "ready",
        "healthy",
        "complete",
        "completed",
    }
)

_FALSE_FLAG_VALUES: Final[frozenset[str]] = frozenset(
    {
        "0",
        "false",
        "no",
        "off",
        "not_ready",
        "failed",
        "error",
        "incomplete",
    }
)

_OK_SERVICE_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "ok",
        "healthy",
        "ready",
        "200",
        "204",
    }
)


class BaseExpectation:
    """Base class for deterministic expectation validators."""

    name: str = "base.expectation"
    category: ExpectationCategory = ExpectationCategory.CUSTOM
    severity: ExpectationSeverity = ExpectationSeverity.MEDIUM
    description: str = "Base expectation"

    def _check(
        self,
        context: ExpectationContext,
    ) -> ExpectationViolation | None:
        raise NotImplementedError

    def validate(
        self,
        context: ExpectationContext,
    ) -> ExpectationResult:
        try:
            violation = self._check(
                context
            )

        except Exception as exc:
            return ExpectationResult.failure(
                expectation_name=self.name,
                category=self.category,
                severity=self.severity,
                message=(
                    f"{self.name} could not be evaluated"
                ),
                metadata={
                    "component": context.component,
                    "operation": context.operation,
                    "validation_error_type": type(
                        exc
                    ).__name__,
                },
            )

        metadata = {
            "component": context.component,
            "operation": context.operation,
        }

        if violation is None:
            return ExpectationResult.success(
                expectation_name=self.name,
                category=self.category,
                severity=self.severity,
                message=f"{self.name}: satisfied",
                metadata=metadata,
            )

        return ExpectationResult.failure(
            expectation_name=self.name,
            category=self.category,
            severity=self.severity,
            message=violation.message,
            violations=(
                violation,
            ),
            metadata=metadata,
        )


def _meta_flag(
    metadata: Mapping[str, Any],
    key: str,
) -> bool:
    value = metadata.get(
        key
    )

    if isinstance(
        value,
        bool,
    ):
        return value

    if isinstance(
        value,
        int,
    ):
        if value == 1:
            return True

        if value == 0:
            return False

        return False

    if isinstance(
        value,
        str,
    ):
        normalized = value.strip().lower()

        if normalized in _TRUE_FLAG_VALUES:
            return True

        if normalized in _FALSE_FLAG_VALUES:
            return False

    return False


class CoreStartupExpectation(BaseExpectation):
    """Core startup wiring must be complete before serving work."""

    name = "core.startup.completed"
    category = ExpectationCategory.CORE
    severity = ExpectationSeverity.CRITICAL
    description = (
        "Core startup wiring is complete."
    )

    def _check(
        self,
        context: ExpectationContext,
    ) -> ExpectationViolation | None:
        if _meta_flag(
            context.metadata,
            "core_started",
        ):
            return None

        return ExpectationViolation(
            expectation_name=self.name,
            message=(
                "core startup has not completed"
            ),
            category=self.category,
            severity=self.severity,
            details={
                "component": context.component
            },
        )


class AuditTraceExpectation(BaseExpectation):
    """Authoritative audit persistence must be available for the operation."""

    name = "audit.trace.available"
    category = ExpectationCategory.AUDIT
    severity = ExpectationSeverity.HIGH
    description = (
        "The operation has an authoritative persisted audit record."
    )

    def _check(
        self,
        context: ExpectationContext,
    ) -> ExpectationViolation | None:
        correlation_id = str(
            context.metadata.get(
                "audit_correlation_id",
                "",
            )
        ).strip()

        persisted = _meta_flag(
            context.metadata,
            "audit_persisted",
        )

        if (
            correlation_id
            and persisted
        ):
            return None

        return ExpectationViolation(
            expectation_name=self.name,
            message=(
                "authoritative audit trace is unavailable or unconfirmed"
            ),
            category=self.category,
            severity=self.severity,
            details={
                "operation": context.operation,
                "correlation_present": bool(
                    correlation_id
                ),
                "persisted": persisted,
            },
        )


class ServiceResponseExpectation(BaseExpectation):
    """A required downstream service returned a usable response."""

    name = "service.response.ok"
    category = ExpectationCategory.SERVICE
    severity = ExpectationSeverity.MEDIUM
    description = (
        "The recorded downstream service status is healthy."
    )

    def _check(
        self,
        context: ExpectationContext,
    ) -> ExpectationViolation | None:
        raw_status = context.metadata.get(
            "service_status"
        )

        status = str(
            raw_status
            if raw_status is not None
            else ""
        ).strip().lower()

        if status in _OK_SERVICE_STATUSES:
            return None

        return ExpectationViolation(
            expectation_name=self.name,
            message=(
                "downstream service status is not healthy"
            ),
            category=self.category,
            severity=self.severity,
            details={
                "component": context.component,
                "service_status": (
                    status
                    or "missing"
                ),
            },
        )


def get_basic_expectations(
) -> list[BaseExpectation]:
    """Minimum startup expectation set."""
    return [
        CoreStartupExpectation(),
    ]


def get_hardened_expectations(
) -> list[BaseExpectation]:
    """Startup plus authoritative audit and service-health expectations."""
    return [
        CoreStartupExpectation(),
        AuditTraceExpectation(),
        ServiceResponseExpectation(),
    ]


def get_sentinel43_expectations(
) -> list[BaseExpectation]:
    """Current Sentinel-43 expectation profile."""
    return [
        CoreStartupExpectation(),
        AuditTraceExpectation(),
        ServiceResponseExpectation(),
    ]


def get_default_expectations(
) -> list[BaseExpectation]:
    """Default expectation set used by validators."""
    return get_sentinel43_expectations()


__all__ = [
    "AuditTraceExpectation",
    "BaseExpectation",
    "CoreStartupExpectation",
    "ServiceResponseExpectation",
    "get_basic_expectations",
    "get_default_expectations",
    "get_hardened_expectations",
    "get_sentinel43_expectations",
]
