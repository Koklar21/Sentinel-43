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

"""Policy gate for Sentinel-43 governance.

Pure decision logic only:
    - no I/O
    - no logging
    - no networking
    - no autonomous enforcement
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .governance import (
    GovernanceAction,
    GovernanceDecisionKind,
    GovernanceMode,
    GovernanceReason,
    evaluate_action,
)


STATUS_ALLOW = "ALLOW"
STATUS_DENY = "DENY"
STATUS_REQUIRES_HUMAN = "REQUIRES_HUMAN"
STATUS_OBSERVE = "OBSERVE"
STATUS_UNKNOWN_ACTION = "UNKNOWN_ACTION"
STATUS_UNKNOWN_MODE = "UNKNOWN_MODE"


@dataclass(frozen=True, slots=True)
class PolicyContext:
    action: GovernanceAction | str
    actor_id: str
    tenant_id: str
    resource: str
    mode: GovernanceMode | str = GovernanceMode.SHADOW
    human_approved: bool = False
    request_id: str | None = None
    correlation_id: str | None = None
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        actor_id = str(
            self.actor_id
        ).strip()

        tenant_id = str(
            self.tenant_id
        ).strip()

        resource = str(
            self.resource
        ).strip()

        if not actor_id:
            raise ValueError(
                "actor_id must not be empty"
            )

        if not tenant_id:
            raise ValueError(
                "tenant_id must not be empty"
            )

        if not resource:
            raise ValueError(
                "resource must not be empty"
            )

        if (
            self.request_id is not None
            and not str(
                self.request_id
            ).strip()
        ):
            raise ValueError(
                "request_id must not be blank"
            )

        if (
            self.correlation_id is not None
            and not str(
                self.correlation_id
            ).strip()
        ):
            raise ValueError(
                "correlation_id must not be blank"
            )

        object.__setattr__(
            self,
            "actor_id",
            actor_id,
        )

        object.__setattr__(
            self,
            "tenant_id",
            tenant_id,
        )

        object.__setattr__(
            self,
            "resource",
            resource,
        )

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(
                dict(
                    self.metadata
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    status: str
    mode: str | None
    action: str | None
    actor_id: str
    tenant_id: str
    resource: str
    human_approved: bool
    request_id: str | None = None
    correlation_id: str | None = None
    reasons: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @property
    def allowed(
        self,
    ) -> bool:
        return self.status == STATUS_ALLOW

    @property
    def executable(
        self,
    ) -> bool:
        return self.status == STATUS_ALLOW

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "executable": self.executable,
            "status": self.status,
            "mode": self.mode,
            "action": self.action,
            "actor_id": self.actor_id,
            "tenant_id": self.tenant_id,
            "resource": self.resource,
            "human_approved": self.human_approved,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "reasons": list(
                self.reasons
            ),
            "tags": list(
                self.tags
            ),
        }


def evaluate(
    context: PolicyContext,
) -> PolicyDecision:
    if not isinstance(
        context,
        PolicyContext,
    ):
        raise TypeError(
            "context must be PolicyContext"
        )

    result = evaluate_action(
        action=context.action,
        mode=context.mode,
        human_approved=context.human_approved,
    )

    status_map = {
        GovernanceDecisionKind.ALLOW: STATUS_ALLOW,
        GovernanceDecisionKind.DENY: STATUS_DENY,
        GovernanceDecisionKind.REQUIRE_HUMAN: STATUS_REQUIRES_HUMAN,
        GovernanceDecisionKind.OBSERVE: STATUS_OBSERVE,
    }

    tags: list[str] = []

    if result.reason is GovernanceReason.UNKNOWN_ACTION:
        status = STATUS_UNKNOWN_ACTION
        tags.append(
            "unknown_action"
        )

    elif result.reason is GovernanceReason.UNKNOWN_MODE:
        status = STATUS_UNKNOWN_MODE
        tags.append(
            "unknown_mode"
        )

    else:
        status = status_map[
            result.decision
        ]

    if result.reason is GovernanceReason.ALWAYS_DENIED:
        tags.append(
            "always_denied"
        )

    if result.reason is GovernanceReason.HUMAN_APPROVAL_REQUIRED:
        tags.append(
            "human_required"
        )

    if result.reason is GovernanceReason.SHADOW_OBSERVE_ONLY:
        tags.append(
            "shadow_observe_only"
        )

    if result.reason is GovernanceReason.NOT_ALLOWED_IN_MODE:
        tags.append(
            "not_allowed_in_mode"
        )

    return PolicyDecision(
        status=status,
        mode=(
            result.mode.value
            if result.mode is not None
            else None
        ),
        action=(
            result.action.value
            if result.action is not None
            else None
        ),
        actor_id=context.actor_id,
        tenant_id=context.tenant_id,
        resource=context.resource,
        human_approved=result.human_approved,
        request_id=context.request_id,
        correlation_id=context.correlation_id,
        reasons=(
            result.reason.value,
        ),
        tags=tuple(
            tags
        ),
    )


class PolicyGate:
    def __init__(
        self,
        evaluator: Callable[
            [PolicyContext],
            PolicyDecision,
        ] = evaluate,
    ) -> None:
        if not callable(
            evaluator
        ):
            raise TypeError(
                "evaluator must be callable"
            )

        self._evaluator = evaluator

    def evaluate(
        self,
        context: PolicyContext,
    ) -> PolicyDecision:
        return self._evaluator(
            context
        )


__all__ = [
    "PolicyContext",
    "PolicyDecision",
    "PolicyGate",
    "STATUS_ALLOW",
    "STATUS_DENY",
    "STATUS_OBSERVE",
    "STATUS_REQUIRES_HUMAN",
    "STATUS_UNKNOWN_ACTION",
    "STATUS_UNKNOWN_MODE",
    "evaluate",
]
