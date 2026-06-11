# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
Policy Gate (Decision Engine) for Sentinel-43.

Responsibilities:
- Evaluate requested actions against governance rules.
- Apply operational mode semantics:
    - SHADOW: never blocks, but records what would happen.
    - HUMAN_GATED: high-risk actions require approval.
    - AUTONOMOUS_VETO: high-risk actions are blocked automatically.
- Return stable policy decisions with reasons and tags.

No I/O.
No networking.
No logging.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable, Mapping

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


STATUS_ALLOW = "ALLOW"
STATUS_DENY = "DENY"
STATUS_REQUIRES_HUMAN = "REQUIRES_HUMAN"
STATUS_UNKNOWN_ACTION = "UNKNOWN_ACTION"


@dataclass(frozen=True)
class PolicyContext:
    """
    Context for a policy evaluation.

    Keep this small and stable. Extra caller-provided information belongs
    in metadata and should not be treated as authoritative.
    """

    action: str
    actor_id: str = "unknown"
    tenant_id: str = "default"
    resource: str = "unknown"
    mode: str = MODE_SHADOW

    request_id: str | None = None
    correlation_id: str | None = None

    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.action, str):
            raise TypeError("action must be a string")

        if not isinstance(self.actor_id, str):
            raise TypeError("actor_id must be a string")

        if not isinstance(self.tenant_id, str):
            raise TypeError("tenant_id must be a string")

        if not isinstance(self.resource, str):
            raise TypeError("resource must be a string")

        if not isinstance(self.mode, str):
            raise TypeError("mode must be a string")

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata)),
        )


@dataclass(frozen=True)
class PolicyDecision:
    """
    Policy evaluation result.

    allowed:
        True  -> caller may proceed automatically.
        False -> caller must not proceed automatically.

    status:
        ALLOW
        DENY
        REQUIRES_HUMAN
        UNKNOWN_ACTION
    """

    allowed: bool
    status: str
    mode: str
    action: str

    actor_id: str = "unknown"
    tenant_id: str = "default"
    resource: str = "unknown"

    request_id: str | None = None
    correlation_id: str | None = None

    reasons: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)

    shadow_would_status: str | None = None
    evaluated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """
        Return a stable, JSON-safe representation.
        """

        return {
            "allowed": self.allowed,
            "status": self.status,
            "mode": self.mode,
            "action": self.action,
            "actor_id": self.actor_id,
            "tenant_id": self.tenant_id,
            "resource": self.resource,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "reasons": list(self.reasons),
            "tags": list(self.tags),
            "shadow_would_status": self.shadow_would_status,
            "evaluated_at": self.evaluated_at,
        }


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _decision(
    *,
    context: PolicyContext,
    allowed: bool,
    status: str,
    mode: str,
    action: str,
    reasons: list[str],
    tags: list[str],
    evaluated_at: str,
    shadow_would_status: str | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        allowed=allowed,
        status=status,
        mode=mode,
        action=action,
        actor_id=context.actor_id,
        tenant_id=context.tenant_id,
        resource=context.resource,
        request_id=context.request_id,
        correlation_id=context.correlation_id,
        reasons=tuple(reasons),
        tags=tuple(tags),
        shadow_would_status=shadow_would_status,
        evaluated_at=evaluated_at,
    )


def evaluate(context: PolicyContext) -> PolicyDecision:
    """
    Evaluate a policy context against governance rules.

    This function is deterministic except for evaluated_at timestamp capture.
    It performs no I/O and has no side effects.
    """

    if not isinstance(context, PolicyContext):
        raise TypeError(
            f"context must be PolicyContext, got {type(context).__name__}"
        )

    evaluated_at = _utc_now_iso()

    action = context.action.strip().lower()
    mode = context.mode.strip().upper() or MODE_SHADOW

    reasons: list[str] = []
    tags: list[str] = []

    if not action:
        tags.append("empty_action")
        reasons.append("Action is empty.")

        if mode == MODE_SHADOW:
            return _decision(
                context=context,
                allowed=True,
                status=STATUS_UNKNOWN_ACTION,
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status=STATUS_DENY,
                evaluated_at=evaluated_at,
            )

        return _decision(
            context=context,
            allowed=False,
            status=STATUS_UNKNOWN_ACTION,
            mode=mode,
            action=action,
            reasons=reasons + ["Deny-by-default for empty action."],
            tags=tags + ["deny_by_default"],
            evaluated_at=evaluated_at,
        )

    if mode not in ALLOWED_MODES:
        tags.append("invalid_mode")
        reasons.append(
            f"Invalid mode '{mode}', defaulting to AUTONOMOUS_VETO behavior."
        )
        mode = MODE_AUTONOMOUS_VETO

    if not is_action_known(action):
        tags.append("unknown_action")
        reasons.append(f"Unknown action '{action}'.")

        if mode == MODE_SHADOW:
            return _decision(
                context=context,
                allowed=True,
                status=STATUS_UNKNOWN_ACTION,
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status=STATUS_DENY,
                evaluated_at=evaluated_at,
            )

        return _decision(
            context=context,
            allowed=False,
            status=STATUS_UNKNOWN_ACTION,
            mode=mode,
            action=action,
            reasons=reasons
            + ["Deny-by-default for unknown actions in non-shadow modes."],
            tags=tags + ["deny_by_default"],
            evaluated_at=evaluated_at,
        )

    if is_always_denied(action):
        tags.append("always_denied")
        reasons.append(f"Action '{action}' is globally forbidden.")

        if mode == MODE_SHADOW:
            return _decision(
                context=context,
                allowed=True,
                status=STATUS_ALLOW,
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status=STATUS_DENY,
                evaluated_at=evaluated_at,
            )

        return _decision(
            context=context,
            allowed=False,
            status=STATUS_DENY,
            mode=mode,
            action=action,
            reasons=reasons,
            tags=tags,
            evaluated_at=evaluated_at,
        )

    if not is_allowed_in_mode(action, mode):
        tags.append("not_allowed_in_mode")
        reasons.append(f"Action '{action}' is not allow-listed for mode {mode}.")

        if mode == MODE_SHADOW:
            return _decision(
                context=context,
                allowed=True,
                status=STATUS_ALLOW,
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status=STATUS_DENY,
                evaluated_at=evaluated_at,
            )

        return _decision(
            context=context,
            allowed=False,
            status=STATUS_DENY,
            mode=mode,
            action=action,
            reasons=reasons,
            tags=tags,
            evaluated_at=evaluated_at,
        )

    if requires_human_approval(action):
        tags.append("human_required")
        reasons.append(f"Action '{action}' requires human approval.")

        if mode == MODE_SHADOW:
            return _decision(
                context=context,
                allowed=True,
                status=STATUS_ALLOW,
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                shadow_would_status=STATUS_REQUIRES_HUMAN,
                evaluated_at=evaluated_at,
            )

        if mode == MODE_HUMAN_GATED:
            return _decision(
                context=context,
                allowed=False,
                status=STATUS_REQUIRES_HUMAN,
                mode=mode,
                action=action,
                reasons=reasons,
                tags=tags,
                evaluated_at=evaluated_at,
            )

        if mode == MODE_AUTONOMOUS_VETO:
            return _decision(
                context=context,
                allowed=False,
                status=STATUS_DENY,
                mode=mode,
                action=action,
                reasons=reasons
                + ["AUTONOMOUS_VETO blocks human-required actions."],
                tags=tags + ["autonomous_veto"],
                evaluated_at=evaluated_at,
            )

    return _decision(
        context=context,
        allowed=True,
        status=STATUS_ALLOW,
        mode=mode,
        action=action,
        reasons=reasons,
        tags=tags,
        evaluated_at=evaluated_at,
    )


class PolicyGate:
    """
    Object wrapper for evaluate().

    Accepts an injected evaluator callable for testing and extensibility.
    """

    def __init__(
        self,
        evaluator: Callable[[PolicyContext], PolicyDecision] = evaluate,
    ) -> None:
        if not callable(evaluator):
            raise TypeError("evaluator must be callable")

        self._evaluator = evaluator

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        if not isinstance(context, PolicyContext):
            raise TypeError(
                f"context must be PolicyContext, got {type(context).__name__}"
            )

        return self._evaluator(context)


__all__ = [
    "PolicyContext",
    "PolicyDecision",
    "PolicyGate",
    "evaluate",
    "STATUS_ALLOW",
    "STATUS_DENY",
    "STATUS_REQUIRES_HUMAN",
    "STATUS_UNKNOWN_ACTION",
]
