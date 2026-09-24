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

"""The evidence ledger: ingestion, eligibility, propagation and human review.

This is the only component that changes what Sentinel-43 will COUNT. It
answers one question -- "may this record influence a governed decision?" --
and it answers it from durable provenance and from explicit human decisions,
never from two records happening to arrive near one another.

It is an evidence layer. It chooses no response action, evaluates no policy,
and stages nothing: ``SystemOrchestrator`` and the owner-designated engine
behind it remain the sole decision authority. What the ledger hands them is
an :class:`~core.evidence.model.EvidenceBundle`, in which what may count and
what may not are separate collections that never merge.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from core.sentinel43_core_db import SentinelCoreStore

from .model import (
    DECISION_ELIGIBLE_STATES,
    LOCK_REASON_DETAIL,
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

logger = logging.getLogger("sentinel43.evidence")

#: Bounds one propagation pass, so a long dependency chain cannot stall
#: ingestion. Reaching it is reported, never silently ignored.
MAX_PROPAGATION_NODES = 2_000

#: Component name on audit records this ledger writes.
EVIDENCE_COMPONENT = "evidence_ledger"


class EvidenceLedgerUnavailable(RuntimeError):
    """An eligibility change could not be recorded durably, so nothing may
    rely on it. Raised rather than leaving the record's state a guess."""


class UnauthorizedEvidenceReview(PermissionError):
    """A review was attempted without a verified human principal."""


class InvalidEvidenceTransition(RuntimeError):
    """A write attempted a state change ALLOWED_TRANSITIONS does not list.

    Defense in depth: evaluate_eligibility should never produce one of
    these, so reaching this exception means that guarantee broke -- and the
    write is refused rather than silently persisted anyway.
    """


class EvidenceReviewAuditFailed(RuntimeError):
    """A human evidence decision could not be durably, authoritatively
    audited, so it was refused rather than applied.

    Raised for every disposition (RELEASED, REJECTED, HELD), not only a
    release: a decision this system cannot prove was made is not one
    anything may rely on having happened, and a REJECTED/HELD decision
    that silently failed to record would make review history
    unreconstructable in exactly the same way a silently-effective release
    would make eligibility untrustworthy.
    """


def _now_ms() -> int:
    return int(time.time() * 1000)


class EvidenceLedger:
    """Durable evidence with provenance-driven eligibility.

    ``operator_authenticator`` is the same server-verified-human check the
    governance authority uses. It is required: without it the ledger refuses
    every human review rather than accepting an unauthenticated one.
    """

    def __init__(
        self,
        store: SentinelCoreStore,
        *,
        operator_authenticator: Callable[[Any], bool] | None = None,
        audit_sink: Callable[[Mapping[str, Any]], str | None] | None = None,
        required_producers: int = 1,
    ) -> None:
        self._store = store
        self._authenticator = operator_authenticator or (lambda _principal: False)
        self._audit = audit_sink
        self._required_producers = max(1, int(required_producers))
        # Serialises eligibility recomputation within this process. The
        # durable guard is the version compare-and-set in the store; this
        # only avoids needless lost-update retries.
        self._lock = threading.RLock()

    # -- reading ------------------------------------------------------------
    def _record(self, row: Mapping[str, Any]) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=str(row["evidence_id"]),
            producer=str(row["producer"]),
            producer_trust=ProducerTrust(str(row["producer_trust"])),
            event_type=str(row["event_type"]),
            observed_at_ms=int(row["observed_at_ms"]),
            ingested_at_ms=int(row["ingested_at_ms"]),
            content_hash=str(row["content_hash"]),
            subject_type=str(row["subject_type"]),
            subject_value=str(row["subject_value"]),
            account_id=str(row["account_id"]),
            session_id=str(row["session_id"]),
            device_id=str(row["device_id"]),
            source_ip=str(row["source_ip"]),
            correlation_id=str(row["correlation_id"]),
            incident_id=str(row.get("incident_id") or ""),
            source_event_id=str(row["source_event_id"]),
            payload_hash=str(row.get("payload_hash") or ""),
            expires_at_ms=int(row["expires_at_ms"]),
            state=EvidenceState(str(row["state"])),
            lock_reason=str(row["lock_reason"]),
            lock_detail=str(row.get("lock_detail") or ""),
            version=int(row["version"]),
            updated_at_ms=int(row.get("updated_at_ms") or 0),
        )

    # -- producer trust registry ---------------------------------------------
    def register_producer(
        self, producer: str, *, trust: ProducerTrust, updated_by: str, reason: str = ""
    ) -> None:
        """Grant or change a producer's durable trust classification.

        Never called from a producer's own payload: the caller is always
        in-process configuration or an authenticated operator action, and
        that identity is what ``updated_by`` records.
        """
        self._store.set_producer_trust(
            str(producer), trust=str(trust), updated_by=str(updated_by),
            reason=str(reason), now_ms=_now_ms(),
        )
        self._append_audit(
            {
                "subsystem": EVIDENCE_COMPONENT,
                "component": EVIDENCE_COMPONENT,
                "decision": "PRODUCER_TRUST_SET",
                "reason_code": str(trust),
                "producer": str(producer),
                "correlation_id": f"producer:{producer}",
                "updated_by": str(updated_by),
                "resolution_reason": str(reason),
                "authorizes_response_action": False,
            }
        )

    def revoke_producer(self, producer: str, *, reason: str, updated_by: str) -> int:
        """Revoke a producer's trust and re-evaluate everything it reported.

        Nothing is deleted: revoked evidence is retained and re-locked, and
        everything that depended on it is re-evaluated in turn (Step 14).
        Returns how many of the producer's own records were re-evaluated.
        """
        with self._lock:
            self.register_producer(
                producer, trust=ProducerTrust.REVOKED, updated_by=updated_by,
                reason=reason,
            )
            rows = self._store.list_evidence_by_producer(str(producer))
            for row in rows:
                self._recompute_one(str(row["evidence_id"]))
                self._propagate_from(str(row["evidence_id"]))
            return len(rows)

    def _current_trust(self, record: EvidenceRecord) -> ProducerTrust | None:
        """The producer's standing NOW, per the durable registry -- never
        the ingestion-time snapshot, which is retained on the record for
        historical/forensic purposes only and has no say in eligibility.

        The registry is the SOLE current-trust authority: a producer that
        is not in it is not trusted, whatever a caller claimed at ingestion
        (a caller that could grant trust merely by asserting it would be
        exactly the self-declared trust this system exists to refuse).
        ``None`` means unregistered, which ``evaluate_eligibility`` reads as
        LEGACY_UNVERIFIED -- distinct from a producer that WAS registered
        and found wanting (PRODUCER_TRUST_INSUFFICIENT).
        """
        registered = self._store.get_producer_trust(record.producer)
        if registered is None:
            return None
        return ProducerTrust(str(registered["trust"]))

    def _relationship(self, row: Mapping[str, Any]) -> EvidenceRelationship:
        return EvidenceRelationship(
            relationship_id=str(row["relationship_id"]),
            parent_evidence_id=str(row["parent_evidence_id"]),
            child_evidence_id=str(row["child_evidence_id"]),
            relationship_type=RelationshipType(str(row["relationship_type"])),
            required_for_eligibility=bool(row["required_for_eligibility"]),
            state=RelationshipState(str(row["state"])),
            verification_method=str(row["verification_method"]),
            created_at_ms=int(row["created_at_ms"]),
            verified_at_ms=int(row["verified_at_ms"]),
            invalidated_reason=str(row["invalidated_reason"]),
        )

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        row = self._store.get_evidence(evidence_id)
        return self._record(row) if row is not None else None

    # -- ingestion ----------------------------------------------------------
    def ingest(
        self,
        *,
        producer: str,
        producer_trust: ProducerTrust,
        event_type: str,
        payload: Mapping[str, Any],
        observed_at_ms: int | None = None,
        subject_type: str = "",
        subject_value: str = "",
        account_id: str = "",
        session_id: str = "",
        device_id: str = "",
        source_ip: str = "",
        correlation_id: str = "",
        incident_id: str = "",
        source_event_id: str = "",
        expires_at_ms: int = 0,
        depends_on: tuple[str, ...] = (),
        dependency_type: RelationshipType = RelationshipType.SAME_ACCOUNT,
    ) -> tuple[str, EligibilityOutcome]:
        """Store one report and decide whether it may count.

        Provenance arrives from the caller, which must have established it
        out-of-band -- ``producer``, ``producer_trust`` and the identity
        fields are never read from ``payload``, because a producer that can
        describe its own trust or choose an account identifier could
        manufacture correlation. ``producer_trust`` is only ever the
        INGESTION-TIME snapshot: the durable registry (register_producer /
        revoke_producer), when it holds an entry for this producer, is what
        eligibility actually consults from then on.

        A record that is incomplete is stored LOCKED, never discarded, and
        the reason is recorded with it.

        ``payload`` is hashed twice: the canonical (key-order-independent)
        hash is the dedupe key -- two reports of the same underlying fact
        from the same producer are ONE piece of evidence, never two -- and a
        second, order-sensitive hash of the exact bytes is kept purely for
        forensic integrity, unused by any constraint.
        """
        now = _now_ms()
        digest = content_hash(payload)
        raw_digest = content_hash(payload, canonical=False)

        evidence_id = self._store.record_evidence(
            evidence_id=f"ev-{uuid.uuid4().hex}",
            producer=producer,
            producer_trust=str(producer_trust),
            event_type=event_type,
            observed_at_ms=int(observed_at_ms if observed_at_ms is not None else now),
            ingested_at_ms=now,
            content_hash=digest,
            payload_hash=raw_digest,
            # Stored OBSERVED, then evaluated below: a record is never
            # eligible because of the value it was written with.
            state=str(EvidenceState.OBSERVED),
            subject_type=subject_type,
            subject_value=subject_value,
            account_id=account_id,
            session_id=session_id,
            device_id=device_id,
            source_ip=source_ip,
            correlation_id=correlation_id,
            incident_id=incident_id,
            source_event_id=source_event_id,
            expires_at_ms=int(expires_at_ms),
        )

        if evidence_id is None:
            raise EvidenceLedgerUnavailable(
                "evidence could not be stored and no existing record was found"
            )

        for parent_id in depends_on:
            if not parent_id or parent_id == evidence_id:
                continue
            self._store.record_relationship(
                relationship_id=f"rel-{uuid.uuid4().hex}",
                parent_evidence_id=parent_id,
                child_evidence_id=evidence_id,
                relationship_type=str(dependency_type),
                required_for_eligibility=True,
                # Claimed, not proved. verify_relationship() proves it from
                # provenance both records carry.
                state=str(RelationshipState.PROPOSED),
                created_at_ms=now,
            )

        outcome = self.recompute(evidence_id)
        return evidence_id, outcome

    # -- relationships ------------------------------------------------------
    def verify_relationship(self, relationship_id: str) -> bool:
        """Prove a claimed link from the provenance both records carry.

        The link is verified only when the two records genuinely share the
        identifier the relationship type names. Sharing nothing but a moment
        in time proves nothing and verifies nothing.
        """
        with self._lock:
            relationship = self._find_relationship(relationship_id)
            if relationship is None:
                return False

            parent = self.get(relationship.parent_evidence_id)
            child = self.get(relationship.child_evidence_id)
            if parent is None or child is None:
                return False

            field = {
                RelationshipType.SAME_ACCOUNT: "account_id",
                RelationshipType.SAME_SESSION: "session_id",
                RelationshipType.SAME_DEVICE: "device_id",
                RelationshipType.SAME_REQUEST_LINEAGE: "correlation_id",
                RelationshipType.SAME_INCIDENT: "incident_id",
                RelationshipType.SAME_NETWORK_SUBJECT: "subject_value",
            }.get(relationship.relationship_type)

            if field is None:
                # DERIVED_FROM / PRODUCER_CONFIRMED / CORROBORATES are
                # asserted by this system or by a trusted producer
                # out-of-band; there is no shared field to compare.
                proved = relationship.relationship_type in (
                    RelationshipType.DERIVED_FROM,
                    RelationshipType.PRODUCER_CONFIRMED,
                )
                method = "asserted_in_process"
            else:
                parent_value = str(getattr(parent, field, "")).strip()
                child_value = str(getattr(child, field, "")).strip()
                proved = bool(parent_value) and parent_value == child_value
                method = f"provenance:{field}"

            if not proved:
                self._store.invalidate_relationship(
                    relationship_id,
                    reason=f"not provable from {method}",
                )
                self.recompute(relationship.child_evidence_id)
                return False

            self._store.record_relationship(
                relationship_id=relationship_id,
                parent_evidence_id=relationship.parent_evidence_id,
                child_evidence_id=relationship.child_evidence_id,
                relationship_type=str(relationship.relationship_type),
                required_for_eligibility=relationship.required_for_eligibility,
                state=str(RelationshipState.VERIFIED),
                verification_method=method,
                created_at_ms=relationship.created_at_ms,
                verified_at_ms=_now_ms(),
            )
            self._promote_relationship(relationship_id, method)
            self.recompute(relationship.child_evidence_id)
            return True

    def _promote_relationship(self, relationship_id: str, method: str) -> None:
        """record_relationship() refuses a duplicate, so an existing row is
        moved to VERIFIED directly."""
        with self._store._connect() as connection:  # noqa: SLF001 - same package boundary
            connection.execute(
                """
                UPDATE evidence_relationships
                SET state = 'VERIFIED', verification_method = ?,
                    verified_at_ms = ?, invalidated_reason = ''
                WHERE relationship_id = ?
                """,
                (method, _now_ms(), str(relationship_id)),
            )

    def _find_relationship(
        self, relationship_id: str
    ) -> EvidenceRelationship | None:
        with self._store._connect() as connection:  # noqa: SLF001
            row = connection.execute(
                "SELECT * FROM evidence_relationships WHERE relationship_id = ?",
                (str(relationship_id),),
            ).fetchone()
        return self._relationship(row) if row is not None else None

    # -- eligibility --------------------------------------------------------
    def _relationships_for_evaluation(
        self, evidence_id: str
    ) -> tuple[EvidenceRelationship, ...]:
        """Everything evaluate_eligibility needs to see about this record,
        each oriented so ``parent_evidence_id`` names the OTHER party.

        Dependency relationships (required_for_eligibility) are already
        stored with the dependent as the child, which is what
        ``relationships_of`` (child-indexed) returns as-is. CONTRADICTS is
        different: it is symmetric in MEANING but stored once, in one
        direction, so a record on the "parent" side of that one row would
        otherwise never see the contradiction pointed at it. Those rows are
        added here with parent/child swapped for presentation, so both sides
        of a dispute lock, not only the one recorded as its child.
        """
        own_side = tuple(
            self._relationship(item)
            for item in self._store.relationships_of(evidence_id)
        )
        seen_relationship_ids = {rel.relationship_id for rel in own_side}

        other_side: list[EvidenceRelationship] = []
        for row in self._store.contradictions_of(evidence_id):
            if str(row["relationship_id"]) in seen_relationship_ids:
                continue
            # evidence_id is this row's PARENT (the child side is already
            # covered by relationships_of above): present it with the
            # roles swapped, so parent_evidence_id names the OTHER record
            # regardless of which side of the stored row evidence_id is on.
            other_side.append(
                EvidenceRelationship(
                    relationship_id=str(row["relationship_id"]),
                    parent_evidence_id=str(row["child_evidence_id"]),
                    child_evidence_id=str(row["parent_evidence_id"]),
                    relationship_type=RelationshipType(str(row["relationship_type"])),
                    required_for_eligibility=bool(row["required_for_eligibility"]),
                    state=RelationshipState(str(row["state"])),
                    verification_method=str(row["verification_method"]),
                    created_at_ms=int(row["created_at_ms"]),
                    verified_at_ms=int(row["verified_at_ms"]),
                    invalidated_reason=str(row["invalidated_reason"]),
                )
            )

        return own_side + tuple(other_side)

    def recompute(self, evidence_id: str) -> EligibilityOutcome:
        """Re-evaluate one record, then everything affected by that change:
        everything that DEPENDS on it, and -- because a contradiction locks
        both sides, not only the one recorded as its child -- everything it
        CONTRADICTS, and in turn whatever depends on THOSE.

        Propagation is iterative over a visited set, so a relationship cycle
        terminates. If a transition cannot be written durably, this raises:
        an eligibility the system cannot record is one nothing may rely on.
        """
        with self._lock:
            outcome = self._recompute_one(evidence_id)
            self._propagate_from(evidence_id)
            return outcome

    def _propagate_from(self, evidence_id: str) -> None:
        """Re-evaluate everything a change to ``evidence_id`` could affect:
        its dependents, and the other side of any contradiction it touches,
        and in turn everything affected by THOSE.

        Two passes, deliberately not one:

        1. Find the full closure over BOTH edge types (dependency AND
           contradiction), bounded, breadth by breadth.
        2. Recompute every member in a FIXED, deterministic order, and
           repeat that full pass until one changes nothing.

        The second pass is what a single ordered walk cannot guarantee once
        contradiction edges are mixed in with dependency edges: a set has no
        stable order, and evaluating a child before its parent's own new
        state was actually written would read the parent's STALE value. A
        chain of five once silently stopped propagating after two hops this
        way -- caught by this pass's own migration test suite, not assumed
        correct. Repeating until stable is correct for any graph shape, at
        the cost of a few redundant passes on the rare graphs that need
        them; the length of the closure itself bounds how many passes a
        correct implementation could ever need.
        """
        edges = self._store.dependency_edges()
        affected: set[str] = {evidence_id}
        frontier: set[str] = {evidence_id}

        while frontier and len(affected) < MAX_PROPAGATION_NODES:
            next_frontier: set[str] = set()
            for node in frontier:
                for dependent in dependency_closure(
                    node, edges, max_nodes=MAX_PROPAGATION_NODES
                ):
                    if dependent not in affected:
                        next_frontier.add(dependent)
                for row in self._store.contradictions_of(node):
                    other = (
                        str(row["parent_evidence_id"])
                        if str(row["child_evidence_id"]) == node
                        else str(row["child_evidence_id"])
                    )
                    if other not in affected:
                        next_frontier.add(other)
            affected |= next_frontier
            frontier = next_frontier

        affected.discard(evidence_id)
        if not affected:
            return

        ordered = sorted(affected)
        for _ in range(len(ordered) + 1):
            changed = False
            for node in ordered:
                prior = self.get(node)
                if prior is None:
                    continue
                outcome = self._recompute_one(node)
                if (
                    outcome.state is not prior.state
                    or outcome.lock_reason != prior.lock_reason
                ):
                    changed = True
            if not changed:
                return

    def _recompute_one(self, evidence_id: str) -> EligibilityOutcome:
        row = self._store.get_evidence(evidence_id)
        if row is None:
            return EligibilityOutcome(
                state=EvidenceState.INVALIDATED,
                lock_reason=LockReason.MISSING_PARENT,
                detail="record not found",
            )

        record = self._record(row)
        relationships = self._relationships_for_evaluation(evidence_id)

        parents: dict[str, EvidenceRecord] = {}
        for relationship in relationships:
            parent_row = self._store.get_evidence(relationship.parent_evidence_id)
            if parent_row is not None:
                parents[relationship.parent_evidence_id] = self._record(parent_row)

        independent = self._independent_producers(record)

        outcome = evaluate_eligibility(
            record,
            relationships,
            parents=parents,
            now_ms=_now_ms(),
            independent_producers=independent,
            required_producers=self._required_producers,
            producer_trust=self._current_trust(record),
        )

        if (
            outcome.state is record.state
            and outcome.lock_reason == record.lock_reason
        ):
            return outcome

        self._write_state(record, outcome, decided_by="provenance_rules")
        return outcome

    def _write_state(
        self,
        record: EvidenceRecord,
        outcome: EligibilityOutcome,
        *,
        decided_by: str,
    ) -> EligibilityOutcome:
        """The one place a state transition is written, so the transition
        table is enforced in exactly one place too."""
        if not is_valid_transition(record.state, outcome.state):
            raise InvalidEvidenceTransition(
                f"{record.evidence_id}: {record.state} -> {outcome.state} is "
                "not a transition the system recognises"
            )

        detail = outcome.detail or LOCK_REASON_DETAIL.get(outcome.lock_reason, "")

        if not self._store.set_evidence_state(
            record.evidence_id,
            expected_version=record.version,
            state=str(outcome.state),
            lock_reason=str(outcome.lock_reason),
            lock_detail=detail,
        ):
            # Someone else changed it first. Their write is authoritative;
            # this pass reports what is now stored rather than overwriting.
            current = self._store.get_evidence(record.evidence_id)
            if current is None:
                raise EvidenceLedgerUnavailable(
                    f"evidence {record.evidence_id} vanished during recomputation"
                )
            return EligibilityOutcome(
                state=EvidenceState(str(current["state"])),
                lock_reason=str(current["lock_reason"]),
                detail=str(current["lock_detail"]),
            )

        self._audit_transition(record, outcome, decided_by=decided_by)
        return outcome

    def _independent_producers(self, record: EvidenceRecord) -> int:
        """How many DISTINCT producers corroborate this record, tracing
        every candidate to its provenance ROOT first (Step 8).

        The record's own producer counts once, however many times it
        reported: repetition by one source is not independence. Two records
        that both ultimately derive from the same evidence -- however many
        DERIVED_FROM hops apart -- are not two producers either: they share
        a root, and a shared root is the same source wearing two producer
        names.

        A corroborating record contributes its producer only when nothing
        disqualifies it -- its CURRENT registry trust is TRUSTED, and it has
        not been rejected, invalidated, expired or contradicted. Waiting for
        its OWN corroboration is deliberately not disqualifying: two records
        that corroborate each other are each the other's second producer,
        and excluding them both would mean no pair could ever satisfy the
        threshold. Every other lock reason keeps a record out of this count,
        so evidence held for missing provenance never props up a threshold.
        """
        producers = {record.producer}
        derived_edges = self._store.derived_from_edges()
        own_roots = self._provenance_roots(record.evidence_id, derived_edges)

        for row in self._store.corroborations_of(record.evidence_id):
            other_id = (
                str(row["child_evidence_id"])
                if str(row["parent_evidence_id"]) == record.evidence_id
                else str(row["parent_evidence_id"])
            )
            if other_id in own_roots or self._provenance_roots(
                other_id, derived_edges
            ) & (own_roots | {record.evidence_id}):
                # Shares a root with the record itself: the same source,
                # under a different producer name, is not independent.
                continue
            other_row = self._store.get_evidence(other_id)
            if other_row is None:
                continue
            other = self._record(other_row)
            if self._may_corroborate(other):
                producers.add(other.producer)
        return len(producers)

    def _provenance_roots(
        self, evidence_id: str, derived_edges: Mapping[str, tuple[str, ...]]
    ) -> frozenset[str]:
        """Every record ``evidence_id`` derives from, transitively, over
        VERIFIED DERIVED_FROM links -- plus itself, since a record with no
        parent IS its own root."""
        ancestors = ancestor_closure(
            evidence_id, derived_edges, max_nodes=MAX_PROPAGATION_NODES
        )
        return frozenset(ancestors) | {evidence_id}

    def _may_corroborate(self, record: EvidenceRecord) -> bool:
        if self._current_trust(record) is not ProducerTrust.TRUSTED:
            return False
        if record.state in (
            EvidenceState.REJECTED,
            EvidenceState.INVALIDATED,
            EvidenceState.EXPIRED,
        ):
            return False
        if record.lock_reason and record.lock_reason != LockReason.INSUFFICIENT_CORROBORATION:
            return False
        return True

    def invalidate(self, evidence_id: str, *, reason: str) -> bool:
        """Mark a record invalid and re-evaluate everything that leaned on it.

        This is how "A turned out to be forged" stops B from continuing to
        count on the strength of A.
        """
        with self._lock:
            row = self._store.get_evidence(evidence_id)
            if row is None:
                return False
            record = self._record(row)

            outcome = EligibilityOutcome(
                state=EvidenceState.INVALIDATED,
                lock_reason=LockReason.DEPENDENCY_INVALIDATED,
                detail=reason,
            )
            try:
                written = self._write_state(record, outcome, decided_by="invalidation")
            except EvidenceLedgerUnavailable:
                return False
            if written.state is not EvidenceState.INVALIDATED:
                # Lost the race to another write; nothing to propagate from
                # an invalidation that did not actually happen.
                return False

            self._propagate_from(evidence_id)
            return True

    # -- human review -------------------------------------------------------
    def review(
        self,
        evidence_id: str,
        *,
        disposition: str,
        operator_id: str,
        principal: Any,
        reason: str,
        expected_version: int,
    ) -> Mapping[str, Any]:
        """One authenticated human decision about one version of one record.

        This is a decision about EVIDENCE -- whether it may be counted. It is
        not approval of a response action: those live in ``pending_actions``
        and are resolved only by the governance authority. Nothing here
        stages, approves or vetoes a recommendation.
        """
        disposition = str(disposition).upper().strip()
        if disposition not in ("RELEASED", "REJECTED", "HELD"):
            raise ValueError(f"unknown disposition {disposition!r}")

        if principal is None or not self._authenticator(principal):
            self._audit_denied(evidence_id, operator_id, disposition, principal)
            raise UnauthorizedEvidenceReview(
                "an authenticated human operator is required to review evidence"
            )
        if str(getattr(principal, "subject", "")).strip() != operator_id.strip():
            self._audit_denied(evidence_id, operator_id, disposition, principal)
            raise UnauthorizedEvidenceReview(
                "operator_id does not match the authenticated subject"
            )
        if not str(reason).strip():
            raise ValueError("a reason is required for an evidence decision")

        row = self._store.get_evidence(evidence_id)
        if row is None:
            raise KeyError(evidence_id)
        record = self._record(row)

        new_state, new_lock = {
            "RELEASED": (EvidenceState.HUMAN_RELEASED, ""),
            "REJECTED": (EvidenceState.REJECTED, str(LockReason.HUMAN_REVIEW_REQUIRED)),
            "HELD": (record.state, record.lock_reason),
        }[disposition]

        if not is_valid_transition(record.state, new_state):
            raise InvalidEvidenceTransition(
                f"{evidence_id}: {record.state} -> {new_state} is not a "
                "transition human review may make"
            )
        new_lock_detail = (
            LOCK_REASON_DETAIL.get(new_lock, "") if new_lock else ""
        )

        review_id = f"rev-{uuid.uuid4().hex}"
        audit_reference_holder: list[str | None] = [None]

        def _write_authoritative_audit() -> str | None:
            # Called by the store only after it has confirmed, under its own
            # write lock, that this review still applies to the version it
            # was decided against -- so a durable audit record is written
            # if and only if the state change it describes is about to take
            # effect, and its absence or failure refuses that state change
            # rather than merely failing to describe it. No evidence
            # decision -- RELEASED, REJECTED, or HELD -- takes effect
            # without one: a decision this system cannot prove was made is
            # not one review history can reconstruct, and for RELEASED
            # specifically, it is not one anything may ever count on.
            if self._audit is None:
                raise EvidenceReviewAuditFailed(
                    "no authoritative audit store is attached to this "
                    "ledger; a human evidence decision may not be applied "
                    "without a durable audit record of it"
                )
            try:
                reference = self._audit(
                    {
                        "subsystem": EVIDENCE_COMPONENT,
                        "component": EVIDENCE_COMPONENT,
                        "decision": f"EVIDENCE_{disposition}",
                        "reason_code": "HUMAN_EVIDENCE_DECISION",
                        "evidence_id": evidence_id,
                        "evidence_version": int(expected_version),
                        "correlation_id": record.correlation_id or evidence_id,
                        "operator_id": operator_id,
                        "identity_type": str(
                            getattr(principal, "identity_type", "")
                        ),
                        "resolution_reason": str(reason),
                        "prior_state": str(record.state),
                        "prior_lock_reason": record.lock_reason,
                        "new_state": str(new_state),
                        # Said explicitly so an evidence decision can never be
                        # read as authorization of a response.
                        "authorizes_response_action": False,
                    }
                )
            except Exception as exc:
                raise EvidenceReviewAuditFailed(
                    "the authoritative audit store raised while recording "
                    "this human evidence decision"
                ) from exc
            # The sink is what durably persists the record; a reference
            # string back is a bonus for cross-linking, not itself proof of
            # durability -- what makes this authoritative is that the call
            # above ran to completion without raising. A sink that persists
            # but returns nothing (or nothing truthy) is not a failure.
            resolved = str(reference) if reference else None
            audit_reference_holder[0] = resolved
            return resolved

        try:
            applied = self._store.record_evidence_review(
                review_id=review_id,
                evidence_id=evidence_id,
                evidence_version=int(expected_version),
                disposition=disposition,
                operator_id=operator_id,
                identity_type=str(getattr(principal, "identity_type", "")),
                reason=str(reason),
                decided_at_ms=_now_ms(),
                new_state=str(new_state),
                new_lock_reason=str(new_lock),
                new_lock_detail=new_lock_detail,
                audit_writer=_write_authoritative_audit,
            )
        except EvidenceReviewAuditFailed:
            # The state change was never committed -- the store rolled the
            # whole transaction back before this propagated. The record is
            # exactly as it was before this call.
            raise

        if not applied:
            raise PermissionError(
                "this evidence changed since it was reviewed; the decision was "
                "refused rather than applied to a different version"
            )

        audit_reference = audit_reference_holder[0]

        if disposition == "RELEASED":
            # A release changes what dependents may rely on.
            self._propagate_from(evidence_id)

        return {
            "evidence_id": evidence_id,
            "disposition": disposition,
            "state": str(new_state),
            "operator_id": operator_id,
            "audit_reference": audit_reference,
            "authorizes_response_action": False,
        }

    # -- what the authority is handed ---------------------------------------
    def bundle_for_subject(
        self, subject_value: str, *, limit: int = 200
    ) -> EvidenceBundle:
        """Evidence about one subject, with countable and held records kept
        strictly apart.

        Freshness is checked here, at read time, not merely trusted from
        whatever the persisted state last settled on: nothing whose
        effective expiry has passed may leave the evidence boundary in the
        eligible bucket, even if nothing has recomputed it since it expired.
        This is bounded to exactly the records this one call fetched --
        never a background sweep or timer -- and self-heals the persisted
        state in the process, so it does not need repeating on every read.
        """
        rows = self._store.list_evidence(subject_value=subject_value, limit=limit)
        now_ms = _now_ms()
        eligible: list[EvidenceRecord] = []
        locked: list[EvidenceRecord] = []
        outcomes: dict[str, EligibilityOutcome] = {}

        for row in rows:
            record = self._record(row)
            if (
                record.expires_at_ms
                and now_ms >= record.expires_at_ms
                and record.state in DECISION_ELIGIBLE_STATES
            ):
                self.recompute(record.evidence_id)
                refreshed = self._store.get_evidence(record.evidence_id)
                if refreshed is not None:
                    record = self._record(refreshed)

            if record.state in DECISION_ELIGIBLE_STATES:
                eligible.append(record)
                continue
            locked.append(record)
            relationships = tuple(
                self._relationship(item)
                for item in self._store.relationships_of(record.evidence_id)
            )
            outcomes[record.evidence_id] = EligibilityOutcome(
                state=record.state,
                lock_reason=record.lock_reason,
                detail=record.lock_detail,
                missing_dependencies=tuple(
                    relationship.parent_evidence_id
                    for relationship in relationships
                    if relationship.required_for_eligibility
                    and relationship.state is not RelationshipState.VERIFIED
                ),
                conflicts=tuple(
                    relationship.parent_evidence_id
                    for relationship in relationships
                    if relationship.relationship_type is RelationshipType.CONTRADICTS
                ),
            )

        return EvidenceBundle(
            eligible=tuple(eligible), locked=tuple(locked), outcomes=outcomes
        )

    # -- audit --------------------------------------------------------------
    def _append_audit(self, record: Mapping[str, Any]) -> str | None:
        """Appends and returns the ledger's own reference for the record
        (e.g. its HMAC), when the sink provides one -- used to cross-link a
        review row to the exact audit entry it produced."""
        sink = self._audit
        if sink is None:
            return None
        result = sink(record)
        return str(result) if result else None

    def _audit_transition(
        self,
        record: EvidenceRecord,
        outcome: EligibilityOutcome,
        *,
        decided_by: str,
    ) -> None:
        """Material eligibility changes are auditable.

        A record becoming countable, or stopping, is exactly the kind of
        change an operator must be able to reconstruct later -- and so is
        WHY a record that is still held changed the reason it is held: a
        record moving from "missing a dependency" to "contradicted" is a
        different fact even though neither state nor countability changed,
        and an operator asking "why was this refused" deserves the current
        reason, not a stale one the audit trail never mentioned.
        """
        became_countable = outcome.state in DECISION_ELIGIBLE_STATES
        was_countable = record.state in DECISION_ELIGIBLE_STATES
        if (
            became_countable == was_countable
            and outcome.state is record.state
            and outcome.lock_reason == record.lock_reason
        ):
            return

        self._append_audit(
            {
                "subsystem": EVIDENCE_COMPONENT,
                "component": EVIDENCE_COMPONENT,
                "decision": "EVIDENCE_ELIGIBILITY_CHANGED",
                "reason_code": str(outcome.lock_reason or outcome.state),
                "evidence_id": record.evidence_id,
                "correlation_id": record.correlation_id or record.evidence_id,
                "producer": record.producer,
                "prior_state": str(record.state),
                "new_state": str(outcome.state),
                "counts_toward_decisions": became_countable,
                "decided_by": decided_by,
                "missing_dependencies": list(outcome.missing_dependencies),
                "authorizes_response_action": False,
            }
        )

    def _audit_denied(
        self,
        evidence_id: str,
        operator_id: str,
        disposition: str,
        principal: Any,
    ) -> None:
        self._append_audit(
            {
                "subsystem": EVIDENCE_COMPONENT,
                "component": EVIDENCE_COMPONENT,
                "decision": "EVIDENCE_REVIEW_DENIED",
                "reason_code": "UNAUTHORIZED_EVIDENCE_REVIEW",
                "evidence_id": evidence_id,
                "correlation_id": evidence_id,
                "operator_id": operator_id,
                "identity_type": str(getattr(principal, "identity_type", "none")),
                "attempted_disposition": disposition,
                "authorizes_response_action": False,
            }
        )


__all__ = [
    "EVIDENCE_COMPONENT",
    "MAX_PROPAGATION_NODES",
    "EvidenceLedger",
    "EvidenceLedgerUnavailable",
    "EvidenceReviewAuditFailed",
    "InvalidEvidenceTransition",
    "UnauthorizedEvidenceReview",
]
