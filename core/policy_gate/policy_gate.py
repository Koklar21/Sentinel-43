"""
Policy Gate (Decision Engine) for Sentinel-43

Responsibilities:
- Evaluate a requested action against governance rules
- Apply operational mode semantics:
    - SHADOW: never blocks, but records what *would* happen
    - HUMAN_GATED: high-risk actions require approval
    - AUTONOMOUS_VETO: high-risk actions are blocked automatically
- Return a stable decision object with reasons + tags

NO I/O.
NO networking.
Logging is optional and should be done by the caller using the returned decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .governance import (
    ALLOWED_MODES,
    MODE_AUTONOMOUS_VETO,
    MODE_HUMAN_GATED,
    MODE_SHADOW,
    is_action_known,
    is_allowed_in_mode,
    is_always_denied,
    requires_human_approval,
)

# ----------------------------
# Data Models
# ----------------------------

@dataclass(frozen=True)
class PolicyContext:
    """
    Context for a policy evaluation.

    Keep this SMALL and STABLE.
    Everything else belongs in metadata.
    """

    action: str
    actor_id: str = "unknown"
    tenant_id: str = "default"
    resource: str = "unknown"
    mode: str = MODE_SHADOW

    # Optional fields
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None

    # Catch-all (non-authoritative)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    """
    Policy evaluation result.

    allowed:
      - True: proceed automatically
      - False: do not proceed automatically
    status:
      - "ALLOW"
      - "DENY"
      - "REQUIRES_HUMAN"
      - "UNKNOWN_ACTION"
    """

    allowed: bool
    status: str
    mode: str
    action: str

    reasons: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # For SHADOW mode (what would have happened in a stricter mode)
    shadow_would_status: Optional[str] = None

    # Always include time for audit correlation (caller can override)
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Stable, JSON-safe representation."""
        return {
            "allowed": self.allowed,
            "status": self.status,
            "mode": self.mode,
            "action": self.action,
            "reasons": list(self.reasons),
            "tags": list(self.tags),
            "shadow_would_status": self.shadow_would_status,
            "evaluated_at": self.evaluated_at,
        }


# ----------------------------
# Core Evaluator
# ----------------------------

def evaluate(context: PolicyContext) -> PolicyDecision:
    """
    Evaluate a policy context against governance rules.

    This function is deterministic and side-effect free.
    """
    action = (context.action or "").strip().lower()
    mode = (context.mode or MODE_SHADOW).strip().upper()

    reasons: List[str] = []
    tags: List[str] = []

    if mode not in ALLOWED_MODES:
        # Fail safe: treat invalid mode as AUTONOMOUS_VETO
        tags.append("invalid_mode")
        reasons.append(f"Invalid mode '{context.mode}', defaulting to AUTONOMOUS_VETO behavior.")
        mode = MODE_AUTONOMOUS_VETO

    # Unknown action handling
    if not is_action_known(action):
        tags.append("unknown_action")
        reasons.append(f"Unknown action '{action}'.")
        # In SHADOW: allow but flag; otherwise deny by default.
        if mode == MODE_SHADOW:
            return PolicyDecision(
                allowed=True,
                status="UNKNOWN_ACTION",
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status="DENY",
            )
        return PolicyDecision(
            allowed=False,
            status="UNKNOWN_ACTION",
            mode=mode,
            action=action,
            reasons=reasons + ["Deny-by-default for unknown actions in non-shadow modes."],
            tags=tags + ["deny_by_default"],
        )

    # Global deny rules
    if is_always_denied(action):
        tags.append("always_denied")
        reasons.append(f"Action '{action}' is globally forbidden.")
        # Even SHADOW should not silently "allow" forbidden actions; but per spec SHADOW never blocks.
        if mode == MODE_SHADOW:
            return PolicyDecision(
                allowed=True,
                status="ALLOW",
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status="DENY",
            )
        return PolicyDecision(
            allowed=False,
            status="DENY",
            mode=mode,
            action=action,
            reasons=reasons,
            tags=tags,
        )

    # Mode allow-list check
    allowed_in_mode = is_allowed_in_mode(action, mode)
    if not allowed_in_mode:
        tags.append("not_allowed_in_mode")
        reasons.append(f"Action '{action}' is not allow-listed for mode {mode}.")

        if mode == MODE_SHADOW:
            # SHADOW never blocks, but records what would happen
            return PolicyDecision(
                allowed=True,
                status="ALLOW",
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status="DENY",
            )

        return PolicyDecision(
            allowed=False,
            status="DENY",
            mode=mode,
            action=action,
            reasons=reasons,
            tags=tags,
        )

    # Human approval rules
    if requires_human_approval(action):
        tags.append("human_required")
        reasons.append(f"Action '{action}' requires human approval.")

        if mode == MODE_SHADOW:
            # Would require human if not in shadow
            return PolicyDecision(
                allowed=True,
                status="ALLOW",
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status="REQUIRES_HUMAN",
            )

        if mode == MODE_HUMAN_GATED:
            return PolicyDecision(
                allowed=False,
                status="REQUIRES_HUMAN",
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
            )

        if mode == MODE_AUTONOMOUS_VETO:
            # Autonomous veto blocks human-required actions
            return PolicyDecision(
                allowed=False,
                status="DENY",
                mode=mode,
                action=action,
                reasons=reasons + ["AUTONOMOUS_VETO blocks human-required actions."],
                tags=tags + ["autonomous_veto"],
            )

    # If we reach here, it's allowed automatically in this mode
    return PolicyDecision(
        allowed=True,
        status="ALLOW",
        mode=mode,
        action=action,
        reasons=reasons,
        tags=tags,
    )


# ----------------------------
# Optional: OO wrapper
# ----------------------------

class PolicyGate:
    """
    Object wrapper for evaluate().

    Useful if you later want:
    - injected governance
    - decision hooks
    - metrics counters
    without changing call sites too much.
    """

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        return evaluate(context)