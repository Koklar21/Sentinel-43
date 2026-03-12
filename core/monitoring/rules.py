from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


def _clamp_int(name: str, value: Any, lo: int, hi: int) -> int:
    try:
        iv = int(value)
    except Exception as exc:
        raise ValueError(f"{name} must be an int in [{lo}, {hi}], got {value!r}") from exc
    if not (lo <= iv <= hi):
        raise ValueError(f"{name} must be in [{lo}, {hi}], got {iv}")
    return iv


@dataclass(frozen=True)
class ThresholdProfile:
    error_rate_percent: int
    expectation_fail_count: int
    stale_config_seconds: int


def thresholds_for(sensitivity: Any) -> ThresholdProfile:
    """
    Sensitivity 1..10
      1  = quieter
      10 = aggressive
    """
    s = _clamp_int("sensitivity", sensitivity, 1, 10)

    error_rate_percent = int(round(15 - (s - 1) * (10 / 9)))        # 15 -> 5
    expectation_fail_count = int(round(10 - (s - 1) * (7 / 9)))     # 10 -> 3
    stale_config_seconds = int(round(3600 - (s - 1) * (3000 / 9)))  # 3600 -> 600

    return ThresholdProfile(
        error_rate_percent=error_rate_percent,
        expectation_fail_count=expectation_fail_count,
        stale_config_seconds=stale_config_seconds,
    )


class RuleRegistry:
    """
    Registry for named watchtower rule callables.
    A rule callable should accept (event, thresholds) and return:
      - None if no alert condition exists
      - str reason if alert condition exists
    """

    def __init__(self) -> None:
        self._rules: Dict[str, Callable[..., Optional[str]]] = {}

    def register(self, name: str, rule: Callable[..., Optional[str]]) -> None:
        self._rules[name] = rule

    def get(self, name: str) -> Optional[Callable[..., Optional[str]]]:
        return self._rules.get(name)

    def has(self, name: str) -> bool:
        return name in self._rules

    def items(self):
        return self._rules.items()


registry = RuleRegistry()