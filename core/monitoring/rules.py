"""
Sentinel-43 Monitoring Rules

This module defines threshold profiles and rule infrastructure used by
the Watchtower monitoring system.

The purpose of this file is to separate behavioral policy from the
Watchtower runtime engine. Thresholds and rule logic live here so the
Watchtower remains focused on scanning and alert generation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


# ============================================================
# Utilities
# ============================================================
def _clamp_int(name: str, value: Any, lo: int, hi: int) -> int:
    try:
        iv = int(value)
    except Exception as exc:
        raise ValueError(f"{name} must be an int in [{lo}, {hi}], got {value!r}") from exc

    if not (lo <= iv <= hi):
        raise ValueError(f"{name} must be in [{lo}, {hi}], got {iv}")

    return iv


# ============================================================
# Threshold Profiles
# ============================================================
@dataclass(frozen=True)
class ThresholdProfile:
    """
    Threshold configuration derived from tower sensitivity.

    These values determine when Watchtower segments trigger alerts.
    """

    error_rate_percent: int
    expectation_fail_count: int
    stale_config_seconds: int


def thresholds_for(sensitivity: Any) -> ThresholdProfile:
    """
    Generate a threshold profile based on tower sensitivity.

    Sensitivity range:
        1 = conservative / quiet
        10 = aggressive / noisy
    """

    s = _clamp_int("sensitivity", sensitivity, 1, 10)

    # Higher sensitivity means lower tolerance thresholds
    error_rate_percent = int(round(15 - (s - 1) * (10 / 9)))        # 15 → 5
    expectation_fail_count = int(round(10 - (s - 1) * (7 / 9)))     # 10 → 3
    stale_config_seconds = int(round(3600 - (s - 1) * (3000 / 9)))  # 3600 → 600

    return ThresholdProfile(
        error_rate_percent=error_rate_percent,
        expectation_fail_count=expectation_fail_count,
        stale_config_seconds=stale_config_seconds,
    )


# ============================================================
# Rule Registry
# ============================================================
class RuleRegistry:
    """
    Registry for Watchtower rule callables.

    Rules can be registered dynamically by other Sentinel subsystems
    to extend monitoring behavior.

    A rule callable should accept:

        rule(event: dict, thresholds: ThresholdProfile) -> Optional[str]

    Return:
        None -> no alert condition
        str  -> alert reason
    """

    def __init__(self) -> None:
        self._rules: Dict[str, Callable[..., Optional[str]]] = {}

    def register(self, name: str, rule: Callable[..., Optional[str]]) -> None:
        if name in self._rules:
            raise ValueError(f"Rule '{name}' already registered")

        self._rules[name] = rule

    def get(self, name: str) -> Optional[Callable[..., Optional[str]]]:
        return self._rules.get(name)

    def has(self, name: str) -> bool:
        return name in self._rules

    def items(self):
        return self._rules.items()

    def list_rules(self):
        return list(self._rules.keys())


# Global registry used by Watchtower
registry = RuleRegistry()


# ============================================================
# Default Rule Hooks (optional extension point)
# ============================================================
def register_default_rules() -> None:
    """
    Hook point for registering built-in monitoring rules.

    Currently unused but intentionally included so the monitoring
    subsystem can grow without rewriting the Watchtower core.
    """
    pass


__all__ = [
    "ThresholdProfile",
    "thresholds_for",
    "RuleRegistry",
    "registry",
    "register_default_rules",
]