from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class SentinelError(Exception):
    """
    Base class for all Sentinel-43 custom errors.

    Provides a consistent structure for:
    - logging
    - audit events
    - API error translation
    - internal exception classification

    Notes:
    - We explicitly call Exception.__init__ in __post_init__ so that
      `args`, pickling, and traceback behavior remain correct.
    - We do NOT store a custom `cause` field. Use Python's built-in
      exception chaining via `raise ... from ...`.
    """

    code: str
    message: str
    details: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.code}: {self.message} | details={self.details}"
        return f"{self.code}: {self.message}"


# ---- Expectations (invariants / requirements) ----

class ExpectationFailed(SentinelError):
    """Raised when a required invariant or expectation is not met."""


class ConfigExpectationFailed(ExpectationFailed):
    """Raised when configuration expectations are invalid or incomplete."""


class AuthExpectationFailed(ExpectationFailed):
    """Raised when authentication expectations fail."""


class PolicyExpectationFailed(ExpectationFailed):
    """Raised when policy validation expectations fail."""


class DetectionExpectationFailed(ExpectationFailed):
    """Raised when detection pipeline expectations fail."""