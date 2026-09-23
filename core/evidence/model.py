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

"""The evidence model: what was observed, what it is related to, and whether
it may influence a governed decision.

The distinction this module exists to hold is that **stored evidence and
decision-eligible evidence are not the same thing**. Sentinel-43 keeps
everything a trusted producer reports, and separately decides -- from durable
provenance, never from proximity in time -- whether a record is allowed to
count toward a governed decision.

This module is pure: states, reasons, relationship semantics, and the rules
that map provenance to eligibility. It performs no I/O, so the rules can be
read and tested on their own. Storage lives in
``core/sentinel43_core_db.py``; the decision authority remains
``SystemOrchestrator`` and the owner-designated engine behind it.

Nothing here chooses a response action. Eligibility answers "may this record
be counted?", never "what should be done?".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Mapping


class EvidenceState(StrEnum):
    """Where one evidence record stands with respect to governed use.

    The states a record can hold are deliberately few, and only two of them
    permit governed use: ELIGIBLE (provenance proved it) and HUMAN_RELEASED
    (an authenticated human decided it). Every other state means the record
    is retained and auditable but cannot count.
    """

    #: Stored, provenance not yet evaluated. Never counts.
    OBSERVED = "OBSERVED"
    #: Its own provenance checks out, but a required relationship has not
    #: been satisfied yet. Never counts.
    VERIFIED = "VERIFIED"
    #: Provenance and every required relationship are verified. Counts.
    ELIGIBLE = "ELIGIBLE"
    #: Held out of governed use for a recorded reason. Never counts.
    LOCKED = "LOCKED"
    #: An authenticated human reviewed it and released it for governed use.
    #: Counts, and stays distinguishable from ELIGIBLE forever.
    HUMAN_RELEASED = "HUMAN_RELEASED"
    #: An authenticated human refused it for governed use. Never counts.
    REJECTED = "REJECTED"
    #: Its freshness window passed. Never counts.
    EXPIRED = "EXPIRED"
    #: A record it depended on was invalidated, or it was disproved. Never
    #: counts.
    INVALIDATED = "INVALIDATED"


#: The only two states that may influence a governed decision. Everything
#: else is retained, visible and auditable, and counts for nothing.
DECISION_ELIGIBLE_STATES: Final[frozenset[EvidenceState]] = frozenset(
    {EvidenceState.ELIGIBLE, EvidenceState.HUMAN_RELEASED}
)

#: States a human decided. They are never recomputed away by the automatic
#: rules: only a human, or contradicting evidence, changes them.
HUMAN_DECIDED_STATES: Final[frozenset[EvidenceState]] = frozenset(
    {EvidenceState.HUMAN_RELEASED, EvidenceState.REJECTED}
)

#: Terminal for the automatic rules: recomputation does not lift these.
TERMINAL_STATES: Final[frozenset[EvidenceState]] = frozenset(
    {EvidenceState.REJECTED, EvidenceState.INVALIDATED}
)


class LockReason(StrEnum):
    """Why a record is not allowed to count. A lock without a reason is not
    a lock -- an operator has to be able to answer "why is Sentinel refusing
    to use this?" without reading logs."""

    MISSING_PARENT = "MISSING_PARENT"
    UNVERIFIED_RELATIONSHIP = "UNVERIFIED_RELATIONSHIP"
    INSUFFICIENT_CORROBORATION = "INSUFFICIENT_CORROBORATION"
    CONTRADICTED = "CONTRADICTED"
    STALE_DEPENDENCY = "STALE_DEPENDENCY"
    PRODUCER_TRUST_INSUFFICIENT = "PRODUCER_TRUST_INSUFFICIENT"
    MALFORMED_PROVENANCE = "MALFORMED_PROVENANCE"
    DEPENDENCY_INVALIDATED = "DEPENDENCY_INVALIDATED"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    #: Recorded before this model existed: provenance was never captured, so
    #: it cannot be reconstructed without inventing it.
    LEGACY_UNVERIFIED = "LEGACY_UNVERIFIED"
    EXPIRED = "EXPIRED"


#: Human-readable explanation per lock reason, for the API and dashboard.
LOCK_REASON_DETAIL: Final[Mapping[str, str]] = {
    LockReason.MISSING_PARENT: (
        "This record depends on evidence that has not been received."
    ),
    LockReason.UNVERIFIED_RELATIONSHIP: (
        "The relationship this record needs in order to support its parent "
        "has not been verified from provenance."
    ),
    LockReason.INSUFFICIENT_CORROBORATION: (
        "No independent producer has corroborated this record."
    ),
    LockReason.CONTRADICTED: (
        "Another record contradicts this one; both are held pending review."
    ),
    LockReason.STALE_DEPENDENCY: (
        "The evidence this record depends on is older than its freshness "
        "window allows."
    ),
    LockReason.PRODUCER_TRUST_INSUFFICIENT: (
        "The producer that reported this record is not trusted to have its "
        "evidence counted."
    ),
    LockReason.MALFORMED_PROVENANCE: (
        "The provenance this record carries could not be validated."
    ),
    LockReason.DEPENDENCY_INVALIDATED: (
        "Evidence this record depends on was invalidated."
    ),
    LockReason.HUMAN_REVIEW_REQUIRED: (
        "This record needs an authenticated human decision before it can be "
        "counted."
    ),
    LockReason.LEGACY_UNVERIFIED: (
        "Recorded before provenance was captured, so it cannot be verified "
        "without inventing the missing information."
    ),
    LockReason.EXPIRED: "This record's freshness window has passed.",
}


class RelationshipType(StrEnum):
    """How one record relates to another.

    Each type states a fact that can be PROVED from durable provenance.
    There is deliberately no "near in time" or "looks similar" type: time
    proximity is not identity and not causation, and a type that cannot be
    proved would be a way of laundering an assumption into a decision.
    """

    #: Both records carry the same server-established account identifier.
    SAME_ACCOUNT = "SAME_ACCOUNT"
    #: Both carry the same server-established session identifier.
    SAME_SESSION = "SAME_SESSION"
    #: Both carry the same verified device identifier.
    SAME_DEVICE = "SAME_DEVICE"
    #: Both carry the same request/correlation lineage.
    SAME_REQUEST_LINEAGE = "SAME_REQUEST_LINEAGE"
    #: Both belong to the same incident chain.
    SAME_INCIDENT = "SAME_INCIDENT"
    #: Both concern the same network subject (identity type + address).
    SAME_NETWORK_SUBJECT = "SAME_NETWORK_SUBJECT"
    #: The child was computed from the parent by this system.
    DERIVED_FROM = "DERIVED_FROM"
    #: The producer itself asserted the link, and the producer is trusted to
    #: assert it (out-of-band, not through payload content).
    PRODUCER_CONFIRMED = "PRODUCER_CONFIRMED"
    #: An independent producer reported the same underlying fact.
    CORROBORATES = "CORROBORATES"
    #: The records cannot both be true.
    CONTRADICTS = "CONTRADICTS"
    #: The child continues an activity the parent began, proved by one of the
    #: identity relationships above.
    CONTINUATION_OF = "CONTINUATION_OF"


#: Relationship types that establish that two records concern the SAME
#: principal or lineage. Only these can satisfy a dependency that asks "is
#: this really about the same thing?".
IDENTITY_RELATIONSHIPS: Final[frozenset[str]] = frozenset(
    {
        RelationshipType.SAME_ACCOUNT,
        RelationshipType.SAME_SESSION,
        RelationshipType.SAME_DEVICE,
        RelationshipType.SAME_REQUEST_LINEAGE,
        RelationshipType.SAME_INCIDENT,
        RelationshipType.PRODUCER_CONFIRMED,
    }
)


class RelationshipState(StrEnum):
    """Whether the relationship itself has been proved."""

    #: Asserted, not yet checked. Satisfies nothing.
    PROPOSED = "PROPOSED"
    #: Proved from provenance both records carry.
    VERIFIED = "VERIFIED"
    #: Checked and found false.
    REFUTED = "REFUTED"
    #: Was verified; the underlying facts changed.
    INVALIDATED = "INVALIDATED"


class ProducerTrust(StrEnum):
    """How much a producer's report is allowed to do.

    Set from in-process registration, never from payload content: a producer
    cannot describe itself as trusted.
    """

    #: Registered in-process. Its evidence may count.
    TRUSTED = "TRUSTED"
    #: Known, but its evidence is retained without counting.
    OBSERVED_ONLY = "OBSERVED_ONLY"
    #: Was trusted and no longer is. Existing evidence is re-evaluated.
    REVOKED = "REVOKED"


#: Provenance fields that must be server-established. A value that arrived in
#: a producer's payload may be stored, but it never appears here, because an
#: attacker who can choose these can manufacture correlation.
SERVER_ESTABLISHED_FIELDS: Final[tuple[str, ...]] = (
    "producer",
    "producer_trust",
    "ingested_at_ms",
    "account_id",
    "session_id",
    "device_id",
)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One thing a producer reported, with the provenance it arrived with."""

    evidence_id: str
    producer: str
    producer_trust: ProducerTrust
    event_type: str
    observed_at_ms: int
    ingested_at_ms: int
    content_hash: str

    #: Server-established identity, where the pipeline knew it.
    subject_type: str = ""
    subject_value: str = ""
    account_id: str = ""
    session_id: str = ""
    device_id: str = ""
    source_ip: str = ""
    correlation_id: str = ""

    #: The producer's own identifier for the underlying event, used to
    #: recognise a replay of the same report.
    source_event_id: str = ""
    #: After this, the record is stale for governed use. 0 means no expiry.
    expires_at_ms: int = 0

    state: EvidenceState = EvidenceState.OBSERVED
    lock_reason: str = ""
    #: Bumped on every material change, so a human decision can be bound to
    #: the exact version that was reviewed.
    version: int = 1

    def __post_init__(self) -> None:
        for name in ("evidence_id", "producer", "event_type", "content_hash"):
            value = str(getattr(self, name) or "").strip()
            if not value:
                raise ValueError(f"{name} must not be empty")
            object.__setattr__(self, name, value)

        if self.observed_at_ms < 0 or self.ingested_at_ms < 0:
            raise ValueError("timestamps must be >= 0")
        if self.expires_at_ms < 0:
            raise ValueError("expires_at_ms must be >= 0")

    @property
    def counts_toward_decisions(self) -> bool:
        return self.state in DECISION_ELIGIBLE_STATES

    @property
    def released_by_a_human(self) -> bool:
        """True when this record counts because a person decided it should,
        rather than because provenance proved it."""
        return self.state is EvidenceState.HUMAN_RELEASED


@dataclass(frozen=True, slots=True)
class EvidenceRelationship:
    """A claimed link between two records, and whether it has been proved."""

    relationship_id: str
    parent_evidence_id: str
    child_evidence_id: str
    relationship_type: RelationshipType
    #: When true, the child cannot be eligible until this is VERIFIED.
    required_for_eligibility: bool
    state: RelationshipState = RelationshipState.PROPOSED
    verification_method: str = ""
    created_at_ms: int = 0
    verified_at_ms: int = 0
    invalidated_reason: str = ""

    def __post_init__(self) -> None:
        if self.parent_evidence_id == self.child_evidence_id:
            raise ValueError("a record cannot be related to itself")
        for name in ("relationship_id", "parent_evidence_id", "child_evidence_id"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"{name} must not be empty")


@dataclass(frozen=True, slots=True)
class EligibilityOutcome:
    """The rules' verdict for one record, and why."""

    state: EvidenceState
    lock_reason: str = ""
    #: Relationships that would have to be verified for this to be eligible.
    missing_dependencies: tuple[str, ...] = ()
    #: Records that contradict this one.
    conflicts: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": str(self.state),
            "lock_reason": self.lock_reason,
            "lock_detail": self.detail
            or LOCK_REASON_DETAIL.get(self.lock_reason, ""),
            "missing_dependencies": list(self.missing_dependencies),
            "conflicts": list(self.conflicts),
            "counts_toward_decisions": self.state in DECISION_ELIGIBLE_STATES,
        }


def content_hash(payload: Mapping[str, Any]) -> str:
    """A canonical hash of what a producer reported.

    Two reports of the same underlying fact hash the same, which is how a
    replay is recognised. Key order and whitespace are normalised so that
    re-serialising cannot make one report look like two.
    """
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evaluate_eligibility(
    record: EvidenceRecord,
    relationships: tuple[EvidenceRelationship, ...],
    *,
    parents: Mapping[str, EvidenceRecord],
    now_ms: int,
    independent_producers: int = 0,
    required_producers: int = 1,
) -> EligibilityOutcome:
    """Decide whether one record may count, from provenance alone.

    This is the whole automatic rule set, in one readable place:

    1. a human decision stands until a human changes it, or until something
       contradicts it;
    2. a record whose producer is not trusted never counts;
    3. an expired record never counts;
    4. a contradicted record never counts;
    5. every relationship marked required must be VERIFIED, and the parent it
       points at must itself be countable;
    6. where independent corroboration is required, it must come from
       genuinely different producers.

    Nothing here looks at timestamp proximity, and nothing infers identity
    from a label: a relationship either was proved from provenance or it was
    not.
    """
    conflicts = tuple(
        rel.parent_evidence_id
        for rel in relationships
        if rel.relationship_type is RelationshipType.CONTRADICTS
        and rel.state is RelationshipState.VERIFIED
    )

    # A verified contradiction overrides everything, including a human
    # release: the person who released it had not seen this.
    if conflicts:
        return EligibilityOutcome(
            state=EvidenceState.LOCKED,
            lock_reason=LockReason.CONTRADICTED,
            conflicts=conflicts,
        )

    if record.state in TERMINAL_STATES:
        return EligibilityOutcome(state=record.state, lock_reason=record.lock_reason)

    if record.state is EvidenceState.HUMAN_RELEASED:
        return EligibilityOutcome(state=EvidenceState.HUMAN_RELEASED)

    if record.producer_trust is not ProducerTrust.TRUSTED:
        return EligibilityOutcome(
            state=EvidenceState.LOCKED,
            lock_reason=LockReason.PRODUCER_TRUST_INSUFFICIENT,
            detail=f"producer trust is {record.producer_trust}",
        )

    if record.expires_at_ms and now_ms >= record.expires_at_ms:
        return EligibilityOutcome(
            state=EvidenceState.EXPIRED, lock_reason=LockReason.EXPIRED
        )

    required = [rel for rel in relationships if rel.required_for_eligibility]
    missing: list[str] = []
    reason = ""

    for rel in required:
        parent = parents.get(rel.parent_evidence_id)
        if parent is None:
            missing.append(rel.parent_evidence_id)
            reason = reason or LockReason.MISSING_PARENT
            continue
        if rel.state is not RelationshipState.VERIFIED:
            missing.append(rel.parent_evidence_id)
            reason = reason or LockReason.UNVERIFIED_RELATIONSHIP
            continue
        if parent.state is EvidenceState.INVALIDATED:
            missing.append(rel.parent_evidence_id)
            reason = LockReason.DEPENDENCY_INVALIDATED
            continue
        if parent.state is EvidenceState.EXPIRED:
            missing.append(rel.parent_evidence_id)
            reason = reason or LockReason.STALE_DEPENDENCY
            continue
        if not parent.counts_toward_decisions:
            # The parent is itself held; a dependent cannot outrank it.
            missing.append(rel.parent_evidence_id)
            reason = reason or LockReason.MISSING_PARENT

    if missing:
        return EligibilityOutcome(
            state=EvidenceState.LOCKED,
            lock_reason=reason or LockReason.MISSING_PARENT,
            missing_dependencies=tuple(dict.fromkeys(missing)),
        )

    if required_producers > 1 and independent_producers < required_producers:
        return EligibilityOutcome(
            state=EvidenceState.LOCKED,
            lock_reason=LockReason.INSUFFICIENT_CORROBORATION,
            detail=(
                f"{independent_producers} independent producer(s); "
                f"{required_producers} required"
            ),
        )

    return EligibilityOutcome(state=EvidenceState.ELIGIBLE)


def dependency_closure(
    start: str,
    children_of: Mapping[str, tuple[str, ...]],
    *,
    max_nodes: int = 10_000,
) -> tuple[str, ...]:
    """Every record that depends on ``start``, directly or transitively.

    Iterative with a visited set, so a relationship cycle -- which the schema
    permits, because two records can each claim to continue the other --
    terminates instead of recursing forever. ``max_nodes`` bounds the walk so
    one pathological chain cannot stall ingestion.
    """
    seen: set[str] = set()
    order: list[str] = []
    stack = [start]

    while stack:
        current = stack.pop()
        for child in children_of.get(current, ()):  # noqa: SIM118
            if child in seen or child == start:
                continue
            seen.add(child)
            order.append(child)
            if len(order) >= max_nodes:
                return tuple(order)
            stack.append(child)

    return tuple(order)


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """What the orchestration authority is handed: what may count, and --
    separately -- what may not.

    The two never merge into one list. A caller that wants only countable
    evidence gets exactly that; a caller that wants to tell an operator what
    is being held can see it without any risk of it being counted.
    """

    eligible: tuple[EvidenceRecord, ...] = ()
    locked: tuple[EvidenceRecord, ...] = ()
    outcomes: Mapping[str, EligibilityOutcome] = field(default_factory=dict)

    @property
    def independent_producers(self) -> frozenset[str]:
        """Distinct producers among the records that may COUNT.

        Locked records are not in here, so a held record cannot quietly
        satisfy a corroboration threshold.
        """
        return frozenset(record.producer for record in self.eligible)

    @property
    def has_locked_evidence(self) -> bool:
        return bool(self.locked)

    def context_for_operator(self) -> list[dict[str, Any]]:
        """Why each held record is being held, for presentation only."""
        rows: list[dict[str, Any]] = []
        for record in self.locked:
            outcome = self.outcomes.get(record.evidence_id)
            rows.append(
                {
                    "evidence_id": record.evidence_id,
                    "producer": record.producer,
                    "event_type": record.event_type,
                    "state": str(record.state),
                    "lock_reason": record.lock_reason,
                    "lock_detail": LOCK_REASON_DETAIL.get(record.lock_reason, ""),
                    "missing_dependencies": list(
                        outcome.missing_dependencies if outcome else ()
                    ),
                    "conflicts": list(outcome.conflicts if outcome else ()),
                }
            )
        return rows


__all__ = [
    "DECISION_ELIGIBLE_STATES",
    "HUMAN_DECIDED_STATES",
    "IDENTITY_RELATIONSHIPS",
    "LOCK_REASON_DETAIL",
    "SERVER_ESTABLISHED_FIELDS",
    "TERMINAL_STATES",
    "EligibilityOutcome",
    "EvidenceBundle",
    "EvidenceRecord",
    "EvidenceRelationship",
    "EvidenceState",
    "LockReason",
    "ProducerTrust",
    "RelationshipState",
    "RelationshipType",
    "content_hash",
    "dependency_closure",
    "evaluate_eligibility",
]
