from __future__ import annotations

from typing import Iterable

from .contracts import ExpectationContract


def expectation_names(expectations: Iterable[ExpectationContract]) -> tuple[str, ...]:
    return tuple(e.name for e in expectations)


def expectation_categories(expectations: Iterable[ExpectationContract]) -> tuple[str, ...]:
    return tuple(e.category.value for e in expectations)