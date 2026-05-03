"""
Sentinel-43 Policy Gate.

Deterministic policy evaluation layer.

No I/O.
No side effects.
No orchestration.
"""

from __future__ import annotations

from .governance import (
    ALLOWED_MODES,
    GOV_DECISION_ALLOW,
    GOV_DECISION_DENY,
    GOV_DECISION_OBSERVE,
    GOV_DECISION_REQUIRE_HUMAN,
    MODE_AUTONOMOUS_VETO,
    MODE_HUMAN_GATED,
    MODE_SHADOW,
    GovernanceDecision,
    evaluate_action,
    is_action_known,
    is_allowed_in_mode,
    is_always_denied,
    list_allowed_actions,
    requires_human_approval,
)

from .policy_gate import (
    STATUS_ALLOW,
    STATUS_DENY,
    STATUS_REQUIRES_HUMAN,
    STATUS_UNKNOWN_ACTION,
    PolicyContext,
    PolicyDecision,
    PolicyGate,
    evaluate,
)

__all__ = [
    # Policy gate
    "PolicyGate",
    "PolicyContext",
    "PolicyDecision",
    "evaluate",

    # Policy statuses
    "STATUS_ALLOW",
    "STATUS_DENY",
    "STATUS_REQUIRES_HUMAN",
    "STATUS_UNKNOWN_ACTION",

    # Modes
    "MODE_SHADOW",
    "MODE_HUMAN_GATED",
    "MODE_AUTONOMOUS_VETO",
    "ALLOWED_MODES",

    # Governance decisions
    "GOV_DECISION_ALLOW",
    "GOV_DECISION_DENY",
    "GOV_DECISION_REQUIRE_HUMAN",
    "GOV_DECISION_OBSERVE",

    # Governance helpers
    "GovernanceDecision",
    "evaluate_action",
    "is_action_known",
    "is_allowed_in_mode",
    "is_always_denied",
    "list_allowed_actions",
    "requires_human_approval",
]
