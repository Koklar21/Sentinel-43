from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class SentinelError(Exception):
    """
    Base class for all Sentinel-43 custom errors.
    Keeps a consistent shape for logging/audit/API translation.
    """
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None
    cause: Optional[BaseException] = None

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


# ---- Expectations (invariants / requirements) ----

class ExpectationFailed(SentinelError):
    """Raised when a required invariant/expectation is not met."""
    pass


class ConfigExpectationFailed(ExpectationFailed):
    pass


class AuthExpectationFailed(ExpectationFailed):
    pass


class PolicyExpectationFailed(ExpectationFailed):
    pass


class DetectionExpectationFailed(ExpectationFailed):
    pass