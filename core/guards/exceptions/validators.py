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

"""Expectation validation helpers for Sentinel-43."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .contracts import (
    ExpectationContract,
    ExpectationContext,
    ExpectationResult,
    ExpectationSeverity,
)
from .expectations import get_default_expectations
from .exceptions import ExpectationFailed


@dataclass(frozen=True, slots=True)
class ValidationSummary:
    passed: bool
    total: int
    passed_count: int
    failed_count: int
    critical_failures: int
    high_failures: int
    medium_failures: int
    low_failures: int
    results: tuple[ExpectationResult, ...] = field(
        default_factory=tuple
    )

    def __post_init__(self) -> None:
        if self.total < 0:
            raise ValueError(
                "total must be >= 0"
            )

        if any(
            value < 0
            for value in (
                self.passed_count,
                self.failed_count,
                self.critical_failures,
                self.high_failures,
                self.medium_failures,
                self.low_failures,
            )
        ):
            raise ValueError(
                "summary counts must be >= 0"
            )

        if (
            self.passed_count
            + self.failed_count
            != self.total
        ):
            raise ValueError(
                "passed_count + failed_count must equal total"
            )

        if (
            self.critical_failures
            + self.high_failures
            + self.medium_failures
            + self.low_failures
            != self.failed_count
        ):
            raise ValueError(
                "severity failure counts must equal failed_count"
            )

        if self.passed != (
            self.failed_count == 0
        ):
            raise ValueError(
                "passed must reflect failed_count == 0"
            )

        if len(
            self.results
        ) != self.total:
            raise ValueError(
                "results length must equal total"
            )

    @property
    def failures(
        self,
    ) -> tuple[ExpectationResult, ...]:
        return tuple(
            result
            for result in self.results
            if not result.passed
        )

    @property
    def successes(
        self,
    ) -> tuple[ExpectationResult, ...]:
        return tuple(
            result
            for result in self.results
            if result.passed
        )


class ExpectationValidator:
    """Run a deterministic set of expectations against one context."""

    def __init__(
        self,
        expectations: Iterable[
            ExpectationContract
        ] | None = None,
    ) -> None:
        self._expectations: list[
            ExpectationContract
        ] = []

        if expectations is not None:
            self.register_many(
                expectations
            )

    @property
    def expectations(
        self,
    ) -> tuple[
        ExpectationContract,
        ...
    ]:
        return tuple(
            self._expectations
        )

    def register(
        self,
        expectation: ExpectationContract,
    ) -> None:
        name = str(
            expectation.name
        ).strip()

        if not name:
            raise ValueError(
                "expectation.name must not be empty"
            )

        if any(
            existing.name == name
            for existing in self._expectations
        ):
            raise ValueError(
                f"expectation {name!r} is already registered"
            )

        self._expectations.append(
            expectation
        )

    def register_many(
        self,
        expectations: Iterable[
            ExpectationContract
        ],
    ) -> None:
        materialized = list(
            expectations
        )

        batch_names: set[str] = set()

        for expectation in materialized:
            name = str(
                expectation.name
            ).strip()

            if not name:
                raise ValueError(
                    "expectation.name must not be empty"
                )

            if name in batch_names:
                raise ValueError(
                    f"duplicate expectation {name!r} in batch"
                )

            batch_names.add(
                name
            )

        existing_names = {
            expectation.name
            for expectation in self._expectations
        }

        collisions = sorted(
            batch_names
            & existing_names
        )

        if collisions:
            raise ValueError(
                "expectations already registered: "
                + ", ".join(
                    repr(
                        name
                    )
                    for name in collisions
                )
            )

        self._expectations.extend(
            materialized
        )

    def clear(
        self,
    ) -> None:
        self._expectations.clear()

    def validate(
        self,
        context: ExpectationContext,
    ) -> tuple[
        ExpectationResult,
        ...
    ]:
        return tuple(
            expectation.validate(
                context
            )
            for expectation
            in self._expectations
        )

    def validate_or_raise(
        self,
        context: ExpectationContext,
        *,
        stop_on_first_failure: bool = False,
    ) -> tuple[
        ExpectationResult,
        ...
    ]:
        results: list[
            ExpectationResult
        ] = []

        for expectation in self._expectations:
            result = expectation.validate(
                context
            )

            results.append(
                result
            )

            if (
                not result.passed
                and stop_on_first_failure
            ):
                raise ExpectationFailed(
                    "expectation validation failed",
                    details={
                        "expectation_name": result.expectation_name,
                        "severity": result.severity.value,
                    },
                )

        failures = [
            result
            for result in results
            if not result.passed
        ]

        if failures:
            raise ExpectationFailed(
                "one or more expectations failed",
                details={
                    "failed_expectations": [
                        result.expectation_name
                        for result in failures
                    ],
                    "failure_count": len(
                        failures
                    ),
                },
            )

        return tuple(
            results
        )


def summarize_results(
    results: Sequence[
        ExpectationResult
    ],
) -> ValidationSummary:
    materialized = tuple(
        results
    )

    passed_count = sum(
        1
        for result in materialized
        if result.passed
    )

    failed_results = [
        result
        for result in materialized
        if not result.passed
    ]

    critical_failures = sum(
        1
        for result in failed_results
        if result.severity
        is ExpectationSeverity.CRITICAL
    )

    high_failures = sum(
        1
        for result in failed_results
        if result.severity
        is ExpectationSeverity.HIGH
    )

    medium_failures = sum(
        1
        for result in failed_results
        if result.severity
        is ExpectationSeverity.MEDIUM
    )

    low_failures = sum(
        1
        for result in failed_results
        if result.severity
        is ExpectationSeverity.LOW
    )

    return ValidationSummary(
        passed=not failed_results,
        total=len(
            materialized
        ),
        passed_count=passed_count,
        failed_count=len(
            failed_results
        ),
        critical_failures=critical_failures,
        high_failures=high_failures,
        medium_failures=medium_failures,
        low_failures=low_failures,
        results=materialized,
    )


def validate_expectations(
    context: ExpectationContext,
    expectations: Iterable[
        ExpectationContract
    ],
) -> ValidationSummary:
    validator = ExpectationValidator(
        expectations
    )

    return summarize_results(
        validator.validate(
            context
        )
    )


def validate_default_expectations(
    context: ExpectationContext,
) -> ValidationSummary:
    return validate_expectations(
        context,
        get_default_expectations(),
    )


def has_critical_failures(
    results: Sequence[
        ExpectationResult
    ],
) -> bool:
    return any(
        not result.passed
        and result.severity
        is ExpectationSeverity.CRITICAL
        for result in results
    )


def filter_failed_results(
    results: Sequence[
        ExpectationResult
    ],
) -> tuple[
        ExpectationResult,
        ...
    ]:
    return tuple(
        result
        for result in results
        if not result.passed
    )


def filter_results_by_severity(
    results: Sequence[
        ExpectationResult
    ],
    severity: ExpectationSeverity,
) -> tuple[
        ExpectationResult,
        ...
    ]:
    return tuple(
        result
        for result in results
        if result.severity is severity
    )


def build_default_validator(
) -> ExpectationValidator:
    return ExpectationValidator(
        get_default_expectations()
    )


__all__ = [
    "ExpectationValidator",
    "ValidationSummary",
    "build_default_validator",
    "filter_failed_results",
    "filter_results_by_severity",
    "has_critical_failures",
    "summarize_results",
    "validate_default_expectations",
    "validate_expectations",
]
