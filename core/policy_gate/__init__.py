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

"""Sentinel-43 Policy Gate.

Deterministic policy evaluation layer. No I/O, no side effects, no
orchestration. This package re-exports the canonical enum-based governance
rules (``core.policy_gate.governance``) and the policy evaluator
(``core.policy_gate.policy_gate``).
"""

from __future__ import annotations

from .governance import (
    DEFAULT_GOVERNANCE,
    GovernanceAction,
    GovernanceDecision,
    GovernanceDecisionKind,
    GovernanceMode,
    GovernanceReason,
    GovernanceRules,
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
    STATUS_OBSERVE,
    STATUS_REQUIRES_HUMAN,
    STATUS_UNKNOWN_ACTION,
    STATUS_UNKNOWN_MODE,
    PolicyContext,
    PolicyDecision,
    PolicyGate,
    evaluate,
)

__all__ = [
    # Governance rules (canonical enum model)
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
    # Policy evaluator
    "PolicyContext",
    "PolicyDecision",
    "PolicyGate",
    "evaluate",
    "STATUS_ALLOW",
    "STATUS_DENY",
    "STATUS_OBSERVE",
    "STATUS_REQUIRES_HUMAN",
    "STATUS_UNKNOWN_ACTION",
    "STATUS_UNKNOWN_MODE",
]
