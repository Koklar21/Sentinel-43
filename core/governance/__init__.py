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

from .composition import build_orchestrator_from_settings
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
    "CallerContext",
    "Decision",
    "DecisionStatus",
    "GovernanceMode",
    "PendingReview",
    "ReasonCode",
    "SystemOrchestrator",
    "TransactionContext",
    "build_orchestrator_from_settings",
]
