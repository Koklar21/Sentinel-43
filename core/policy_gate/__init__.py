"""
Sentinel-43 Policy Gate Package

Purpose:
- Governance-backed policy enforcement
- Risk gating across SHADOW / HUMAN_GATED / AUTONOMOUS_VETO
- Deterministic, auditable decision output

This package contains NO business logic and NO I/O.
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