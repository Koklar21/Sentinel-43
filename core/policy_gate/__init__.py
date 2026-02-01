"""
Sentinel-43 Policy Gate

Deterministic policy evaluation layer.
No I/O, no side effects, no orchestration.
"""

from .policy_gate import (
    PolicyGate,
    PolicyContext,
    PolicyDecision,
    evaluate,
)

from .governance import (
    MODE_SHADOW,
    MODE_HUMAN_GATED,
    MODE_AUTONOMOUS_VETO,
)

__all__ = [
    "PolicyGate",
    "PolicyContext",
    "PolicyDecision",
    "evaluate",
    "MODE_SHADOW",
    "MODE_HUMAN_GATED",
    "MODE_AUTONOMOUS_VETO",
]