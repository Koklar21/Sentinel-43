# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/guards/exceptions/expectations.py
#
# Concrete expectation implementations + the default set.
#
# `__init__.py` and `validators.py` both import `BaseExpectation` and
# `get_default_expectations` from here; the module existed only by reference
# until now. Each expectation follows the ExpectationContract protocol in
# contracts.py: it carries name/category/severity/description and a
# validate(context) -> ExpectationResult method.
#
# The concrete checks are intentionally small and context-driven -- an
# expectation inspects ExpectationContext.metadata for the signal it is
# responsible for and reports success or a single violation. Callers that
# want richer checks subclass BaseExpectation and override `_check`.
# =============================================================================

from __future__ import annotations

from typing import Any, Mapping

from .contracts import (
    ExpectationCategory,
    ExpectationContext,
    ExpectationResult,
    ExpectationSeverity,
    ExpectationViolation,
)

__all__ = [
    "BaseExpectation",
    "CoreStartupExpectation",
    "AuditTraceExpectation",
    "ServiceResponseExpectation",
    "get_default_expectations",
    "get_basic_expectations",
    "get_hardened_expectations",
    "get_sentinel43_expectations",
]


class BaseExpectation:
    """
    Base class for expectation implementations (ExpectationContract-shaped).

    Subclasses set the four class attributes and implement ``_check`` to
    return ``None`` on success or an :class:`ExpectationViolation` on failure.
    ``validate`` wraps that into an :class:`ExpectationResult`.
    """

    name: str = "base.expectation"
    category: ExpectationCategory = ExpectationCategory.CUSTOM
    severity: ExpectationSeverity = ExpectationSeverity.MEDIUM
    description: str = "Base expectation"

    def _check(self, context: ExpectationContext) -> ExpectationViolation | None:
        raise NotImplementedError

    def validate(self, context: ExpectationContext) -> ExpectationResult:
        try:
            violation = self._check(context)
        except Exception as exc:  # noqa: BLE001 - never let a check crash the run
            return ExpectationResult.failure(
                expectation_name=self.name,
                category=self.category,
                severity=self.severity,
                message=f"{self.name} raised during validation: {exc}",
                metadata={"component": context.component, "operation": context.operation},
            )

        if violation is None:
            return ExpectationResult.success(
                expectation_name=self.name,
                category=self.category,
                severity=self.severity,
                message=f"{self.name}: satisfied",
            )

        return ExpectationResult.failure(
            expectation_name=self.name,
            category=self.category,
            severity=self.severity,
            message=violation.message,
            violations=(violation,),
            metadata={"component": context.component, "operation": context.operation},
        )


def _meta_flag(metadata: Mapping[str, Any], key: str) -> bool:
    value = metadata.get(key)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "ok", "ready"}
    return bool(value)


class CoreStartupExpectation(BaseExpectation):
    """The core has completed startup wiring before serving work."""

    name = "core.startup.completed"
    category = ExpectationCategory.CORE
    severity = ExpectationSeverity.CRITICAL
    description = "Core startup wiring finished (metadata['core_started'] is truthy)."

    def _check(self, context: ExpectationContext) -> ExpectationViolation | None:
        if _meta_flag(context.metadata, "core_started"):
            return None
        return ExpectationViolation(
            expectation_name=self.name,
            message="core startup has not completed (metadata['core_started'] is not set/truthy)",
            category=self.category,
            severity=self.severity,
            details={"component": context.component},
        )


class AuditTraceExpectation(BaseExpectation):
    """A durable audit trace is available for the current operation."""

    name = "audit.trace.available"
    category = ExpectationCategory.AUDIT
    severity = ExpectationSeverity.HIGH
    description = "An audit correlation id is present (metadata['audit_correlation_id'])."

    def _check(self, context: ExpectationContext) -> ExpectationViolation | None:
        cid = context.metadata.get("audit_correlation_id")
        if cid:
            return None
        return ExpectationViolation(
            expectation_name=self.name,
            message="no audit correlation id on the context -- the operation would not be traceable",
            category=self.category,
            severity=self.severity,
            details={"operation": context.operation},
        )


class ServiceResponseExpectation(BaseExpectation):
    """A downstream service call returned a usable response."""

    name = "service.response.ok"
    category = ExpectationCategory.SERVICE
    severity = ExpectationSeverity.MEDIUM
    description = "The recorded downstream status is OK (metadata['service_status'] in {ok,200,healthy})."

    _OK = {"ok", "healthy", "ready", "200", "204"}

    def _check(self, context: ExpectationContext) -> ExpectationViolation | None:
        status = str(context.metadata.get("service_status", "")).strip().lower()
        if status in self._OK:
            return None
        return ExpectationViolation(
            expectation_name=self.name,
            message=f"downstream service status is not OK: {status or '<missing>'}",
            category=self.category,
            severity=self.severity,
            details={"component": context.component, "service_status": status},
        )


# --------------------------------------------------------------------------- #
# Profile sets — bootstrap.py loads one of these by name ("basic" / "hardened"
# / "sentinel43"). Each returns freshly-constructed instances so a caller can
# register them without sharing state.
# --------------------------------------------------------------------------- #
def get_basic_expectations() -> list[BaseExpectation]:
    """Minimum viable checks: the core must have finished starting up."""
    return [CoreStartupExpectation()]


def get_hardened_expectations() -> list[BaseExpectation]:
    """Basic + auditability + downstream-service health."""
    return [
        CoreStartupExpectation(),
        AuditTraceExpectation(),
        ServiceResponseExpectation(),
    ]


def get_sentinel43_expectations() -> list[BaseExpectation]:
    """The full Sentinel-43 profile (currently == hardened)."""
    return get_hardened_expectations()


def get_default_expectations() -> list[BaseExpectation]:
    """The baseline expectation set used by validate_default_expectations()."""
    return get_hardened_expectations()
