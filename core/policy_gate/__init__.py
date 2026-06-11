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
