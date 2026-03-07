from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any

from .contracts import ExpectationCategory, ExpectationSeverity


@dataclass(slots=True, frozen=True)
class ExpectationReport:
    """
    Lightweight report used for logging or API responses.
    """

    expectation_name: str
    category: ExpectationCategory
    severity: ExpectationSeverity
    passed: bool
    message: str
    metadata: Mapping[str, Any] | None = None