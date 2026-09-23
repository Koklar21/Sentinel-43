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
    EligibilityOutcome,
    EvidenceBundle,
    EvidenceRecord,
    EvidenceRelationship,
    EvidenceState,
    LockReason,
    ProducerTrust,
    RelationshipState,
    RelationshipType,
    content_hash,
    dependency_closure,
    evaluate_eligibility,
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
        audit_sink: Callable[[Mapping[str, Any]], None] | None = None,
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
            source_event_id=str(row["source_event_id"]),
            expires_at_ms=int(row["expires_at_ms"]),
            state=EvidenceState(str(row["state"])),
            lock_reason=str(row["lock_reason"]),
            version=int(row["version"]),
        )

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
        manufacture correlation.

        A record that is incomplete is stored LOCKED, never discarded, and
        the reason is recorded with it.
        """
        now = _now_ms()
        digest = content_hash(payload)

        evidence_id = self._store.record_evidence(
            evidence_id=f"ev-{uuid.uuid4().hex}",
            producer=producer,
            producer_trust=str(producer_trust),
            event_type=event_type,
            observed_at_ms=int(observed_at_ms if observed_at_ms is not None else now),
            ingested_at_ms=now,
            content_hash=digest,
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
            source_event_id=source_event_id,
            expires_at_ms=int(expires_at_ms),
        )

        if evidence_id is None:
            raise EvidenceLedgerUnavailable(
                "evidence could not be stored and no existing record was found"
            )

        existing = self._store.get_evidence(evidence_id)
        if existing is not None and str(existing["content_hash"]) == digest:
            # A replay of the same producer's same report. It is ONE piece of
            # evidence: re-evaluate it, but never add a second record.
            pass

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
            child_rows = self._store.dependency_edges()  # cheap; bounded
            del child_rows

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
                RelationshipType.SAME_INCIDENT: "correlation_id",
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
    def recompute(self, evidence_id: str) -> EligibilityOutcome:
        """Re-evaluate one record, then everything that depends on it.

        Propagation is iterative over a visited set, so a relationship cycle
        terminates. If a transition cannot be written durably, this raises:
        an eligibility the system cannot record is one nothing may rely on.
        """
        with self._lock:
            outcome = self._recompute_one(evidence_id)

            edges = self._store.dependency_edges()
            for dependent in dependency_closure(
                evidence_id, edges, max_nodes=MAX_PROPAGATION_NODES
            ):
                self._recompute_one(dependent)

            return outcome

    def _recompute_one(self, evidence_id: str) -> EligibilityOutcome:
        row = self._store.get_evidence(evidence_id)
        if row is None:
            return EligibilityOutcome(
                state=EvidenceState.INVALIDATED,
                lock_reason=LockReason.MISSING_PARENT,
                detail="record not found",
            )

        record = self._record(row)
        relationships = tuple(
            self._relationship(item)
            for item in self._store.relationships_of(evidence_id)
        )

        parents: dict[str, EvidenceRecord] = {}
        for relationship in relationships:
            parent_row = self._store.get_evidence(relationship.parent_evidence_id)
            if parent_row is not None:
                parents[relationship.parent_evidence_id] = self._record(parent_row)

        independent = self._independent_producers(record, relationships)

        outcome = evaluate_eligibility(
            record,
            relationships,
            parents=parents,
            now_ms=_now_ms(),
            independent_producers=independent,
            required_producers=self._required_producers,
        )

        if (
            outcome.state is record.state
            and outcome.lock_reason == record.lock_reason
        ):
            return outcome

        if not self._store.set_evidence_state(
            evidence_id,
            expected_version=record.version,
            state=str(outcome.state),
            lock_reason=str(outcome.lock_reason),
        ):
            # Someone else changed it first. Their write is authoritative;
            # this pass reports what is now stored rather than overwriting.
            current = self._store.get_evidence(evidence_id)
            if current is None:
                raise EvidenceLedgerUnavailable(
                    f"evidence {evidence_id} vanished during recomputation"
                )
            return EligibilityOutcome(
                state=EvidenceState(str(current["state"])),
                lock_reason=str(current["lock_reason"]),
            )

        self._audit_transition(record, outcome, decided_by="provenance_rules")
        return outcome

    def _independent_producers(
        self,
        record: EvidenceRecord,
        relationships: tuple[EvidenceRelationship, ...],
    ) -> int:
        """How many DISTINCT producers corroborate this record.

        The record's own producer counts once, however many times it
        reported: repetition by one source is not independence.

        A corroborating record contributes its producer only when nothing
        disqualifies it -- its producer is trusted, and it has not been
        rejected, invalidated, expired or contradicted. Waiting for its OWN
        corroboration is deliberately not disqualifying: two records that
        corroborate each other are each the other's second producer, and
        excluding them both would mean no pair could ever satisfy the
        threshold. Every other lock reason keeps a record out of this count,
        so evidence held for missing provenance never props up a threshold.
        """
        del relationships  # corroboration is read symmetrically, below

        producers = {record.producer}
        for row in self._store.corroborations_of(record.evidence_id):
            other_id = (
                str(row["child_evidence_id"])
                if str(row["parent_evidence_id"]) == record.evidence_id
                else str(row["parent_evidence_id"])
            )
            other_row = self._store.get_evidence(other_id)
            if other_row is None:
                continue
            other = self._record(other_row)
            if self._may_corroborate(other):
                producers.add(other.producer)
        return len(producers)

    @staticmethod
    def _may_corroborate(record: EvidenceRecord) -> bool:
        if record.producer_trust is not ProducerTrust.TRUSTED:
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

            changed = self._store.set_evidence_state(
                evidence_id,
                expected_version=record.version,
                state=str(EvidenceState.INVALIDATED),
                lock_reason=str(LockReason.DEPENDENCY_INVALIDATED),
            )
            if not changed:
                return False

            self._audit_transition(
                record,
                EligibilityOutcome(
                    state=EvidenceState.INVALIDATED,
                    lock_reason=LockReason.DEPENDENCY_INVALIDATED,
                    detail=reason,
                ),
                decided_by="invalidation",
            )

            edges = self._store.dependency_edges()
            for dependent in dependency_closure(
                evidence_id, edges, max_nodes=MAX_PROPAGATION_NODES
            ):
                self._recompute_one(dependent)
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

        applied = self._store.record_evidence_review(
            review_id=f"rev-{uuid.uuid4().hex}",
            evidence_id=evidence_id,
            evidence_version=int(expected_version),
            disposition=disposition,
            operator_id=operator_id,
            identity_type=str(getattr(principal, "identity_type", "")),
            reason=str(reason),
            decided_at_ms=_now_ms(),
            new_state=str(new_state),
            new_lock_reason=str(new_lock),
        )

        if not applied:
            raise PermissionError(
                "this evidence changed since it was reviewed; the decision was "
                "refused rather than applied to a different version"
            )

        self._append_audit(
            {
                "subsystem": EVIDENCE_COMPONENT,
                "component": EVIDENCE_COMPONENT,
                "decision": f"EVIDENCE_{disposition}",
                "reason_code": "HUMAN_EVIDENCE_DECISION",
                "evidence_id": evidence_id,
                "evidence_version": int(expected_version),
                "correlation_id": record.correlation_id or evidence_id,
                "operator_id": operator_id,
                "identity_type": str(getattr(principal, "identity_type", "")),
                "resolution_reason": str(reason),
                "prior_state": str(record.state),
                "prior_lock_reason": record.lock_reason,
                "new_state": str(new_state),
                # Said explicitly so an evidence decision can never be read
                # as authorization of a response.
                "authorizes_response_action": False,
            }
        )

        if disposition == "RELEASED":
            # A release changes what dependents may rely on.
            edges = self._store.dependency_edges()
            for dependent in dependency_closure(
                evidence_id, edges, max_nodes=MAX_PROPAGATION_NODES
            ):
                self._recompute_one(dependent)

        return {
            "evidence_id": evidence_id,
            "disposition": disposition,
            "state": str(new_state),
            "operator_id": operator_id,
            "authorizes_response_action": False,
        }

    # -- what the authority is handed ---------------------------------------
    def bundle_for_subject(
        self, subject_value: str, *, limit: int = 200
    ) -> EvidenceBundle:
        """Evidence about one subject, with countable and held records kept
        strictly apart."""
        rows = self._store.list_evidence(subject_value=subject_value, limit=limit)
        eligible: list[EvidenceRecord] = []
        locked: list[EvidenceRecord] = []
        outcomes: dict[str, EligibilityOutcome] = {}

        for row in rows:
            record = self._record(row)
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
    def _append_audit(self, record: Mapping[str, Any]) -> None:
        sink = self._audit
        if sink is None:
            return
        sink(record)

    def _audit_transition(
        self,
        record: EvidenceRecord,
        outcome: EligibilityOutcome,
        *,
        decided_by: str,
    ) -> None:
        """Material eligibility changes are auditable.

        A record becoming countable, or stopping, is exactly the kind of
        change an operator must be able to reconstruct later.
        """
        became_countable = outcome.state in DECISION_ELIGIBLE_STATES
        was_countable = record.state in DECISION_ELIGIBLE_STATES
        if became_countable == was_countable and outcome.state is record.state:
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
    "UnauthorizedEvidenceReview",
]
