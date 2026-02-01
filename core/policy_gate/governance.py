"""
Policy Governance Definitions for Sentinel-43

This module is DATA-FIRST.

Responsibilities:
- Define what actions are allowed, gated, or denied
- Encode policy by operational mode
- Provide simple query helpers for the decision engine
- Be readable by humans and auditors

NO runtime side effects.
NO I/O.
NO logging.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set

# ----------------------------
# Policy Modes
# ----------------------------

MODE_SHADOW = "SHADOW"
MODE_HUMAN_GATED = "HUMAN_GATED"
MODE_AUTONOMOUS_VETO = "AUTONOMOUS_VETO"

ALLOWED_MODES: Set[str] = {
    MODE_SHADOW,
    MODE_HUMAN_GATED,
    MODE_AUTONOMOUS_VETO,
}

# ----------------------------
# Action Taxonomy
# ----------------------------
# Actions should be HIGH-LEVEL, not implementation-specific.
# These names become part of your audit record.

ACTION_READ = "read"
ACTION_WRITE = "write"
ACTION_DELETE = "delete"
ACTION_EXECUTE = "execute"
ACTION_QUARANTINE = "quarantine"
ACTION_ISOLATE = "isolate"
ACTION_SHUTDOWN = "shutdown"
ACTION_NETWORK_BLOCK = "network_block"
ACTION_PRIV_ESC = "privilege_escalation"

# ----------------------------
# Governance Rules
# ----------------------------

@dataclass(frozen=True)
class GovernanceRules:
    """
    Canonical policy ruleset.

    - always_deny: actions never allowed under any mode
    - human_required: actions requiring explicit human approval
    - allowed_by_mode: explicit allow-lists per mode
    """

    always_deny: Set[str]
    human_required: Set[str]
    allowed_by_mode: Dict[str, Set[str]]


# ----------------------------
# Default Governance
# ----------------------------

DEFAULT_GOVERNANCE = GovernanceRules(
    # Actions that are NEVER allowed, regardless of mode.
    always_deny={
        ACTION_PRIV_ESC,
    },

    # Actions that require human approval in HUMAN_GATED mode
    # and are blocked in AUTONOMOUS_VETO.
    human_required={
        ACTION_DELETE,
        ACTION_QUARANTINE,
        ACTION_ISOLATE,
        ACTION_SHUTDOWN,
        ACTION_NETWORK_BLOCK,
    },

    # Explicit allow-list per mode.
    allowed_by_mode={
        MODE_SHADOW: {
            # Shadow mode observes but never blocks.
            ACTION_READ,
            ACTION_WRITE,
            ACTION_DELETE,
            ACTION_EXECUTE,
            ACTION_QUARANTINE,
            ACTION_ISOLATE,
            ACTION_SHUTDOWN,
            ACTION_NETWORK_BLOCK,
        },

        MODE_HUMAN_GATED: {
            # Safe actions allowed automatically.
            ACTION_READ,
            ACTION_WRITE,
            ACTION_EXECUTE,
        },

        MODE_AUTONOMOUS_VETO: {
            # Extremely conservative autonomous actions.
            ACTION_READ,
            ACTION_WRITE,
        },
    },
)

# ----------------------------
# Query Helpers (used by policy_gate.py)
# ----------------------------

def is_action_known(action: str) -> bool:
    """Return True if the action exists anywhere in governance."""
    for s in DEFAULT_GOVERNANCE.allowed_by_mode.values():
        if action in s:
            return True
    return (
        action in DEFAULT_GOVERNANCE.always_deny
        or action in DEFAULT_GOVERNANCE.human_required
    )


def is_always_denied(action: str) -> bool:
    """Return True if the action is globally forbidden."""
    return action in DEFAULT_GOVERNANCE.always_deny


def requires_human_approval(action: str) -> bool:
    """Return True if the action requires human approval."""
    return action in DEFAULT_GOVERNANCE.human_required


def is_allowed_in_mode(action: str, mode: str) -> bool:
    """
    Return True if the action is explicitly allowed in the given mode.
    Does NOT consider human gating or global denial.
    """
    if mode not in ALLOWED_MODES:
        return False
    return action in DEFAULT_GOVERNANCE.allowed_by_mode.get(mode, set())


def list_allowed_actions(mode: str) -> List[str]:
    """Return sorted list of allowed actions for a given mode."""
    return sorted(DEFAULT_GOVERNANCE.allowed_by_mode.get(mode, set()))