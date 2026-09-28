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

"""Sentinel-43 human-governed transaction governance.

Advisory-first and human-gated: only SHADOW and HUMAN_GATED modes exist, and
there is no autonomous, timer-driven, or background execution path. The
authoritative audit writer is injected at composition time.
"""

from __future__ import annotations

from .composition import (
    build_heart_from_settings,
    build_orchestrator_from_settings,
    build_runtime_authority_from_settings,
)
from .heart import (
    ActionSink,
    DecisionPrincipal,
    HeartConfig,
    HeartDecision,
    ThreatGovernor,
    UnauthorizedDecision,
)
from .runtime_authority import Sentinel43RuntimeAuthority
from .orchestrator import (
    CallerContext,
    Decision,
    DecisionStatus,
    GovernanceMode,
    PendingReview,
    ReasonCode,
    SystemOrchestrator,
    TransactionContext,
)

__all__ = [
    "ActionSink",
    "CallerContext",
    "Decision",
    "DecisionStatus",
    "GovernanceMode",
    "HeartConfig",
    "HeartDecision",
    "PendingReview",
    "ReasonCode",
    "Sentinel43RuntimeAuthority",
    "SystemOrchestrator",
    "ThreatGovernor",
    "TransactionContext",
    "DecisionPrincipal",
    "UnauthorizedDecision",
    "build_heart_from_settings",
    "build_orchestrator_from_settings",
    "build_runtime_authority_from_settings",
]
