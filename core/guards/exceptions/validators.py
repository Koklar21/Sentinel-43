from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .contracts import (
    ExpectationContract,
    ExpectationContext,
    ExpectationResult,
    ExpectationSeverity,
)
from .expectations import BaseExpectation, get_default_expectations


@dataclass(slots=True, frozen=True)
class ValidationSummary:
    """
    Aggregated result for a batch of expectation validations.
    """
    passed: bool
    total: int
    passed_count: int
    failed_count: int
    critical_failures: int
    high_failures: int
    medium_failures: int
    low_failures: int
    results: tuple[ExpectationResult, ...] = field(default_factory=tuple)

    @property
    def failures(self) -> tuple[ExpectationResult, ...]:
        return tuple(result for result in self.results if not result.passed)

    @property
    def successes(self) -> tuple[ExpectationResult, ...]:
        return tuple(result for result in self.results if result.passed)


class ExpectationValidator:
    """
    Runs one or more expectations against a runtime context.
    """

    def __init__(self, expectations: Iterable[ExpectationContract] | None = None) -> None:
        self._expectations: list[ExpectationContract] = list(expectations or [])

    @property
    def expectations(self) -> tuple[ExpectationContract, ...]:
        return tuple(self._expectations)

    def register(self, expectation: ExpectationContract) -> None:
        """
        Register a single expectation.
        """
        self._expectations.append(expectation)

    def register_many(self, expectations: Iterable[ExpectationContract]) -> None:
        """
        Register multiple expectations.
        """
        self._expectations.extend(expectations)

    def clear(self) -> None:
        """
        Remove all registered expectations.
        """
        self._expectations.clear()

    def validate(self, context: ExpectationContext) -> tuple[ExpectationResult, ...]:
        """
        Run all registered expectations against the provided context.
        """
        results: list[ExpectationResult] = []

        for expectation in self._expectations:
            result = expectation.validate(context)
            results.append(result)

        return tuple(results)

    def validate_or_raise(
        self,
        context: ExpectationContext,
        *,
        stop_on_first_failure: bool = False,
    ) -> tuple[ExpectationResult, ...]:
        """
        Run validations and raise an exception if any expectation fails.

        Uses the expectation's own validation result but raises a generic
        RuntimeError wrapper here so the caller can decide how to translate
        failures into domain-specific exceptions.
        """
        results: list[ExpectationResult] = []

        for expectation in self._expectations:
            result = expectation.validate(context)
            results.append(result)

            if not result.passed and stop_on_first_failure:
                raise RuntimeError(
                    f"Expectation validation failed early: "
                    f"{result.expectation_name} [{result.severity.value}] - {result.message}"
                )

        failed = [result for result in results if not result.passed]
        if failed:
            failed_names = ", ".join(result.expectation_name for result in failed)
            raise RuntimeError(
                f"Expectation validation failed for: {failed_names}"
            )

        return tuple(results)


def summarize_results(results: Sequence[ExpectationResult]) -> ValidationSummary:
    """
    Produce an aggregated summary from raw expectation results.
    """
    passed_count = 0
    failed_count = 0
    critical_failures = 0
    high_failures = 0
    medium_failures = 0
    low_failures = 0

    for result in results:
        if result.passed:
            passed_count += 1
            continue

        failed_count += 1

        if result.severity is ExpectationSeverity.CRITICAL:
            critical_failures += 1
        elif result.severity is ExpectationSeverity.HIGH:
            high_failures += 1
        elif result.severity is ExpectationSeverity.MEDIUM:
            medium_failures += 1
        elif result.severity is ExpectationSeverity.LOW:
            low_failures += 1

    return ValidationSummary(
        passed=failed_count == 0,
        total=len(results),
        passed_count=passed_count,
        failed_count=failed_count,
        critical_failures=critical_failures,
        high_failures=high_failures,
        medium_failures=medium_failures,
        low_failures=low_failures,
        results=tuple(results),
    )


def validate_expectations(
    context: ExpectationContext,
    expectations: Iterable[ExpectationContract],
) -> ValidationSummary:
    """
    Validate an explicit expectation set against a context and return a summary.
    """
    validator = ExpectationValidator(expectations)
    results = validator.validate(context)
    return summarize_results(results)


def validate_default_expectations(context: ExpectationContext) -> ValidationSummary:
    """
    Validate the built-in Sentinel-43 default expectation set.
    """
    validator = ExpectationValidator(get_default_expectations())
    results = validator.validate(context)
    return summarize_results(results)


def has_critical_failures(results: Sequence[ExpectationResult]) -> bool:
    """
    Fast check for critical failures in a result set.
    """
    return any(
        (not result.passed) and result.severity is ExpectationSeverity.CRITICAL
        for result in results
    )


def filter_failed_results(
    results: Sequence[ExpectationResult],
) -> tuple[ExpectationResult, ...]:
    """
    Return only failed expectation results.
    """
    return tuple(result for result in results if not result.passed)


def filter_results_by_severity(
    results: Sequence[ExpectationResult],
    severity: ExpectationSeverity,
) -> tuple[ExpectationResult, ...]:
    """
    Return results matching a specific severity.
    """
    return tuple(result for result in results if result.severity is severity)


def build_default_validator() -> ExpectationValidator:
    """
    Construct a validator preloaded with the default expectations.
    """
    return ExpectationValidator(get_default_expectations())