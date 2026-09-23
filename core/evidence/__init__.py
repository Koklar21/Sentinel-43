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

"""Evidence provenance, relationships and decision eligibility.

An evidence layer, not a decision layer: it decides whether a record may be
COUNTED, never what response should be taken. The owner-designated engine
behind SystemOrchestrator remains the sole decision authority.
"""

from .ledger import (
    EVIDENCE_COMPONENT,
    MAX_PROPAGATION_NODES,
    EvidenceLedger,
    EvidenceLedgerUnavailable,
    InvalidEvidenceTransition,
    UnauthorizedEvidenceReview,
)
from .model import (
    ALLOWED_TRANSITIONS,
    DECISION_ELIGIBLE_STATES,
    HUMAN_DECIDED_STATES,
    IDENTITY_RELATIONSHIPS,
    LOCK_REASON_DETAIL,
    SERVER_ESTABLISHED_FIELDS,
    TERMINAL_STATES,
    EligibilityOutcome,
    EvidenceBundle,
    EvidenceRecord,
    EvidenceRelationship,
    EvidenceState,
    LockReason,
    ProducerTrust,
    RelationshipState,
    RelationshipType,
    ancestor_closure,
    content_hash,
    dependency_closure,
    evaluate_eligibility,
    is_valid_transition,
)

__all__ = [
    "ALLOWED_TRANSITIONS",
    "DECISION_ELIGIBLE_STATES",
    "EVIDENCE_COMPONENT",
    "HUMAN_DECIDED_STATES",
    "IDENTITY_RELATIONSHIPS",
    "LOCK_REASON_DETAIL",
    "MAX_PROPAGATION_NODES",
    "SERVER_ESTABLISHED_FIELDS",
    "TERMINAL_STATES",
    "EligibilityOutcome",
    "EvidenceBundle",
    "EvidenceLedger",
    "EvidenceLedgerUnavailable",
    "EvidenceRecord",
    "EvidenceRelationship",
    "EvidenceState",
    "InvalidEvidenceTransition",
    "LockReason",
    "ProducerTrust",
    "RelationshipState",
    "RelationshipType",
    "UnauthorizedEvidenceReview",
    "ancestor_closure",
    "content_hash",
    "dependency_closure",
    "evaluate_eligibility",
    "is_valid_transition",
]
