# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Pure governance policy definitions for Sentinel-43.

This module contains only action/mode policy evaluation.

It intentionally contains no:
    - audit storage
    - velocity limiting
    - environment reads
    - database access
    - transaction processing
    - authorization backend
    - autonomous execution
    - autonomous veto/enforcement
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Mapping


class GovernanceMode(StrEnum):
    SHADOW = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"


class GovernanceAction(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    QUARANTINE = "quarantine"
    ISOLATE = "isolate"
    SHUTDOWN = "shutdown"
    NETWORK_BLOCK = "network_block"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class GovernanceDecisionKind(StrEnum):
    OBSERVE = "OBSERVE"
    ALLOW = "ALLOW"
    REQUIRE_HUMAN = "REQUIRE_HUMAN"
    DENY = "DENY"


class GovernanceReason(StrEnum):
    SHADOW_OBSERVE_ONLY = "SHADOW_OBSERVE_ONLY"
    ALLOWED = "ALLOWED"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    ALWAYS_DENIED = "ALWAYS_DENIED"
    UNKNOWN_MODE = "UNKNOWN_MODE"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    NOT_ALLOWED_IN_MODE = "NOT_ALLOWED_IN_MODE"


@dataclass(frozen=True, slots=True)
class GovernanceRules:
    always_deny: frozenset[GovernanceAction]
    human_required: frozenset[GovernanceAction]
    allowed_by_mode: Mapping[
        GovernanceMode,
        frozenset[GovernanceAction],
    ]

    def __post_init__(self) -> None:
        allowed = {
            mode: frozenset(
                actions
            )
            for mode, actions
            in self.allowed_by_mode.items()
        }

        object.__setattr__(
            self,
            "allowed_by_mode",
            MappingProxyType(
                allowed
            ),
        )

        if set(
            allowed
        ) != set(
            GovernanceMode
        ):
            raise ValueError(
                "allowed_by_mode must define every GovernanceMode"
            )

        for action in self.always_deny:
            if not isinstance(
                action,
                GovernanceAction,
            ):
                raise TypeError(
                    "always_deny must contain GovernanceAction values"
                )

        for action in self.human_required:
            if not isinstance(
                action,
                GovernanceAction,
            ):
                raise TypeError(
                    "human_required must contain GovernanceAction values"
                )


DEFAULT_GOVERNANCE: Final[
    GovernanceRules
] = GovernanceRules(
    always_deny=frozenset(
        {
            GovernanceAction.PRIVILEGE_ESCALATION,
        }
    ),
    human_required=frozenset(
        {
            GovernanceAction.WRITE,
            GovernanceAction.DELETE,
            GovernanceAction.EXECUTE,
            GovernanceAction.QUARANTINE,
            GovernanceAction.ISOLATE,
            GovernanceAction.SHUTDOWN,
            GovernanceAction.NETWORK_BLOCK,
        }
    ),
    allowed_by_mode={
        GovernanceMode.SHADOW: frozenset(
            GovernanceAction
        ),
        GovernanceMode.HUMAN_GATED: frozenset(
            GovernanceAction
        ),
    },
)


@dataclass(frozen=True, slots=True)
class GovernanceDecision:
    decision: GovernanceDecisionKind
    reason: GovernanceReason
    action: GovernanceAction | None
    mode: GovernanceMode | None
    human_approved: bool = False


def _parse_action(
    action: GovernanceAction | str,
) -> GovernanceAction | None:
    if isinstance(
        action,
        GovernanceAction,
    ):
        return action

    try:
        return GovernanceAction(
            str(
                action
            ).strip().lower()
        )
    except ValueError:
        return None


def _parse_mode(
    mode: GovernanceMode | str,
) -> GovernanceMode | None:
    if isinstance(
        mode,
        GovernanceMode,
    ):
        return mode

    try:
        return GovernanceMode(
            str(
                mode
            ).strip().upper()
        )
    except ValueError:
        return None


def is_action_known(
    action: GovernanceAction | str,
) -> bool:
    return _parse_action(
        action
    ) is not None


def is_always_denied(
    action: GovernanceAction | str,
    *,
    rules: GovernanceRules = DEFAULT_GOVERNANCE,
) -> bool:
    parsed = _parse_action(
        action
    )

    return (
        parsed is not None
        and parsed in rules.always_deny
    )


def requires_human_approval(
    action: GovernanceAction | str,
    *,
    rules: GovernanceRules = DEFAULT_GOVERNANCE,
) -> bool:
    parsed = _parse_action(
        action
    )

    return (
        parsed is not None
        and parsed in rules.human_required
    )


def is_allowed_in_mode(
    action: GovernanceAction | str,
    mode: GovernanceMode | str,
    *,
    rules: GovernanceRules = DEFAULT_GOVERNANCE,
) -> bool:
    parsed_action = _parse_action(
        action
    )

    parsed_mode = _parse_mode(
        mode
    )

    if (
        parsed_action is None
        or parsed_mode is None
    ):
        return False

    if parsed_action in rules.always_deny:
        return False

    return (
        parsed_action
        in rules.allowed_by_mode[
            parsed_mode
        ]
    )


def list_allowed_actions(
    mode: GovernanceMode | str,
    *,
    rules: GovernanceRules = DEFAULT_GOVERNANCE,
) -> tuple[str, ...]:
    parsed_mode = _parse_mode(
        mode
    )

    if parsed_mode is None:
        return ()

    return tuple(
        sorted(
            action.value
            for action
            in rules.allowed_by_mode[
                parsed_mode
            ]
            if action
            not in rules.always_deny
        )
    )


def evaluate_action(
    *,
    action: GovernanceAction | str,
    mode: GovernanceMode | str,
    human_approved: bool = False,
    rules: GovernanceRules = DEFAULT_GOVERNANCE,
) -> GovernanceDecision:
    parsed_mode = _parse_mode(
        mode
    )

    if parsed_mode is None:
        return GovernanceDecision(
            decision=GovernanceDecisionKind.DENY,
            reason=GovernanceReason.UNKNOWN_MODE,
            action=_parse_action(
                action
            ),
            mode=None,
            human_approved=bool(
                human_approved
            ),
        )

    parsed_action = _parse_action(
        action
    )

    if parsed_action is None:
        return GovernanceDecision(
            decision=GovernanceDecisionKind.DENY,
            reason=GovernanceReason.UNKNOWN_ACTION,
            action=None,
            mode=parsed_mode,
            human_approved=bool(
                human_approved
            ),
        )

    if parsed_action in rules.always_deny:
        return GovernanceDecision(
            decision=GovernanceDecisionKind.DENY,
            reason=GovernanceReason.ALWAYS_DENIED,
            action=parsed_action,
            mode=parsed_mode,
            human_approved=bool(
                human_approved
            ),
        )

    if (
        parsed_action
        not in rules.allowed_by_mode[
            parsed_mode
        ]
    ):
        return GovernanceDecision(
            decision=GovernanceDecisionKind.DENY,
            reason=GovernanceReason.NOT_ALLOWED_IN_MODE,
            action=parsed_action,
            mode=parsed_mode,
            human_approved=bool(
                human_approved
            ),
        )

    if parsed_mode is GovernanceMode.SHADOW:
        return GovernanceDecision(
            decision=GovernanceDecisionKind.OBSERVE,
            reason=GovernanceReason.SHADOW_OBSERVE_ONLY,
            action=parsed_action,
            mode=parsed_mode,
            human_approved=False,
        )

    if (
        parsed_action
        in rules.human_required
        and not human_approved
    ):
        return GovernanceDecision(
            decision=GovernanceDecisionKind.REQUIRE_HUMAN,
            reason=GovernanceReason.HUMAN_APPROVAL_REQUIRED,
            action=parsed_action,
            mode=parsed_mode,
            human_approved=False,
        )

    return GovernanceDecision(
        decision=GovernanceDecisionKind.ALLOW,
        reason=GovernanceReason.ALLOWED,
        action=parsed_action,
        mode=parsed_mode,
        human_approved=bool(
            human_approved
        ),
    )


__all__ = [
    "DEFAULT_GOVERNANCE",
    "GovernanceAction",
    "GovernanceDecision",
    "GovernanceDecisionKind",
    "GovernanceMode",
    "GovernanceReason",
    "GovernanceRules",
    "evaluate_action",
    "is_action_known",
    "is_allowed_in_mode",
    "is_always_denied",
    "list_allowed_actions",
    "requires_human_approval",
]
