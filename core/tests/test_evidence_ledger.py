# =============================================================================
# Sentinel-43 -- evidence provenance, eligibility and the lock
#
# The invariant under test: STORED evidence and DECISION-ELIGIBLE evidence are
# not the same thing. Sentinel-43 keeps everything a trusted producer reports
# and separately decides, from durable provenance or from an explicit human
# decision, whether a record may COUNT toward a governed decision.
#
# Two records are never mutually supporting merely because they arrived near
# one another in time or look similar.
#
# Real SQLite store, real ledger, disposable temp storage. No network, no
# skips.
# =============================================================================
from __future__ import annotations

import sqlite3
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.evidence.ledger import (
    EvidenceLedger,
    InvalidEvidenceTransition,
    UnauthorizedEvidenceReview,
)
from core.evidence.model import (
    DECISION_ELIGIBLE_STATES,
    EligibilityOutcome,
    EvidenceRecord,
    EvidenceState,
    LockReason,
    ProducerTrust,
    RelationshipState,
    RelationshipType,
    content_hash,
    dependency_closure,
)
from core.sentinel43_core_db import CoreStoreConfig, SentinelCoreStore


def _stack(required_producers: int = 1):
    directory = Path(tempfile.mkdtemp(prefix="s43-evidence-"))
    store = SentinelCoreStore(CoreStoreConfig(db_path=directory / "heart.sqlite3"))
    store.initialize()
    audit: list[dict] = []
    ledger = EvidenceLedger(
        store,
        operator_authenticator=lambda principal: bool(
            getattr(principal, "is_human", False)
        ),
        audit_sink=audit.append,
        required_producers=required_producers,
    )
    return directory, store, ledger, audit


def _principal(subject: str = "evidence-op", is_human: bool = True):
    return SimpleNamespace(
        subject=subject,
        identity_type="operator" if is_human else "service:watchtower",
        is_human=is_human,
    )


def _ingest(ledger, **overrides):
    params = {
        "producer": "firewall",
        "producer_trust": ProducerTrust.TRUSTED,
        "event_type": "auth_failure",
        "payload": {"seq": overrides.pop("seq", 1)},
        "subject_value": "operator|203.0.113.10",
        "subject_type": "identity_source_ip",
    }
    params.update(overrides)
    return ledger.ingest(**params)


# ---------------------------------------------------------------------------
# Provenance decides eligibility, not proximity
# ---------------------------------------------------------------------------
def test_evidence_without_required_provenance_stays_locked():
    """B claims to depend on A. Until that claim is PROVED, B is retained and
    decision-locked -- it does not quietly strengthen anything."""
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, outcome = _ingest(
        ledger,
        producer="sparta",
        event_type="token_use",
        seq=2,
        account_id="acct-1",
        depends_on=(a,),
    )

    assert outcome.state is EvidenceState.LOCKED
    assert outcome.lock_reason == LockReason.UNVERIFIED_RELATIONSHIP
    assert outcome.missing_dependencies == (a,)
    # Retained, not discarded.
    assert store.get_evidence(b) is not None
    assert ledger.get(b).counts_toward_decisions is False


def test_proved_provenance_unlocks_eligibility():
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", event_type="token_use", seq=2,
        account_id="acct-1", depends_on=(a,),
    )

    relationship = store.relationships_of(b)[0]
    assert ledger.verify_relationship(relationship["relationship_id"]) is True
    assert ledger.get(b).state is EvidenceState.ELIGIBLE
    assert ledger.get(b).counts_toward_decisions is True


def test_unrelated_evidence_does_not_corroborate():
    """The headline case: a later token use from a DIFFERENT account does not
    support the earlier authentication failure, however close in time."""
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", event_type="token_use", seq=2,
        account_id="acct-OTHER", depends_on=(a,),
    )

    relationship = store.relationships_of(b)[0]
    assert ledger.verify_relationship(relationship["relationship_id"]) is False

    held = ledger.get(b)
    assert held.state is EvidenceState.LOCKED
    assert held.counts_toward_decisions is False
    # The claim is kept, marked as refuted, not deleted.
    stored = store.relationships_of(b)[0]
    assert stored["state"] == RelationshipState.INVALIDATED
    assert "not provable" in stored["invalidated_reason"]


def test_timestamp_proximity_alone_proves_nothing():
    """Two records one millisecond apart, with no shared provenance, have no
    verifiable relationship at all."""
    _, store, ledger, _ = _stack()
    now = int(time.time() * 1000)
    a, _ = _ingest(ledger, observed_at_ms=now, account_id="")
    b, outcome = _ingest(
        ledger, producer="sparta", seq=2, observed_at_ms=now + 1,
        account_id="", depends_on=(a,),
    )

    relationship = store.relationships_of(b)[0]
    assert ledger.verify_relationship(relationship["relationship_id"]) is False
    assert outcome.state is EvidenceState.LOCKED


# ---------------------------------------------------------------------------
# Repetition is not independence
# ---------------------------------------------------------------------------
def test_the_same_producer_reporting_twice_is_one_piece_of_evidence():
    _, store, ledger, _ = _stack()
    first, _ = _ingest(ledger, payload={"identical": True})
    second, _ = _ingest(ledger, payload={"identical": True})

    assert first == second
    assert store.count_evidence() == 1


def test_a_replay_cannot_multiply_confidence():
    """Independent corroboration counts PRODUCERS, not reports."""
    _, store, ledger, _ = _stack(required_producers=2)
    evidence_id, outcome = _ingest(ledger, payload={"once": True})
    for _ in range(5):
        _ingest(ledger, payload={"once": True})

    assert store.count_evidence() == 1
    assert outcome.state is EvidenceState.LOCKED
    assert outcome.lock_reason == LockReason.INSUFFICIENT_CORROBORATION
    assert ledger.get(evidence_id).counts_toward_decisions is False


def test_a_second_independent_producer_satisfies_corroboration():
    _, store, ledger, _ = _stack(required_producers=2)
    a, _ = _ingest(ledger, producer="firewall", payload={"fact": 1}, account_id="a1")
    b, _ = _ingest(
        ledger, producer="sparta", payload={"fact": 1}, account_id="a1",
    )
    assert store.record_relationship(
        relationship_id="rel-corroborates",
        parent_evidence_id=a,
        child_evidence_id=b,
        relationship_type=str(RelationshipType.CORROBORATES),
        required_for_eligibility=False,
        state=str(RelationshipState.VERIFIED),
        created_at_ms=int(time.time() * 1000),
    )
    ledger.recompute(a)
    ledger.recompute(b)
    assert ledger.get(b).state is EvidenceState.ELIGIBLE
    # Mutual: each is the other's second producer.
    assert ledger.get(a).state is EvidenceState.ELIGIBLE


# ---------------------------------------------------------------------------
# Dependency propagation
# ---------------------------------------------------------------------------
def test_invalidating_a_parent_relocks_its_dependents():
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-1", depends_on=(a,)
    )
    ledger.verify_relationship(store.relationships_of(b)[0]["relationship_id"])
    assert ledger.get(b).state is EvidenceState.ELIGIBLE

    assert ledger.invalidate(a, reason="producer compromised") is True

    dependent = ledger.get(b)
    assert dependent.state is EvidenceState.LOCKED
    assert dependent.lock_reason == LockReason.DEPENDENCY_INVALIDATED
    assert dependent.counts_toward_decisions is False


def test_propagation_reaches_a_whole_chain():
    _, store, ledger, _ = _stack()
    previous, _ = _ingest(ledger, account_id="acct-1")
    chain = [previous]
    for index in range(4):
        current, _ = _ingest(
            ledger, producer="sparta", seq=index + 2, account_id="acct-1",
            depends_on=(previous,),
        )
        ledger.verify_relationship(
            store.relationships_of(current)[0]["relationship_id"]
        )
        chain.append(current)
        previous = current

    assert all(ledger.get(item).counts_toward_decisions for item in chain)
    ledger.invalidate(chain[0], reason="forged")
    assert all(not ledger.get(item).counts_toward_decisions for item in chain)


def test_a_relationship_cycle_terminates():
    """Two records that each claim to continue the other must not make
    traversal recurse forever."""
    edges = {"A": ("B",), "B": ("C",), "C": ("A",)}
    assert set(dependency_closure("A", edges)) == {"B", "C"}

    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-1", depends_on=(a,)
    )
    assert store.record_relationship(
        relationship_id="rel-cycle",
        parent_evidence_id=b,
        child_evidence_id=a,
        relationship_type=str(RelationshipType.CONTINUATION_OF),
        required_for_eligibility=True,
        state=str(RelationshipState.PROPOSED),
        created_at_ms=int(time.time() * 1000),
    )
    # Terminates rather than hanging, and both remain held.
    ledger.recompute(a)
    assert ledger.get(a).counts_toward_decisions is False


def test_expired_evidence_stops_counting():
    _, _, ledger, _ = _stack()
    past = int(time.time() * 1000) - 1000
    evidence_id, outcome = _ingest(ledger, expires_at_ms=past)
    assert outcome.state is EvidenceState.EXPIRED
    assert ledger.get(evidence_id).counts_toward_decisions is False


def test_a_stale_parent_holds_its_dependent():
    _, store, ledger, _ = _stack()
    past = int(time.time() * 1000) - 1000
    a, _ = _ingest(ledger, account_id="acct-1", expires_at_ms=past)
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-1", depends_on=(a,)
    )
    ledger.verify_relationship(store.relationships_of(b)[0]["relationship_id"])

    held = ledger.get(b)
    assert held.state is EvidenceState.LOCKED
    assert held.lock_reason == LockReason.STALE_DEPENDENCY


# ---------------------------------------------------------------------------
# Producer trust
# ---------------------------------------------------------------------------
def test_an_untrusted_producer_reports_but_does_not_count():
    _, store, ledger, _ = _stack()
    evidence_id, outcome = _ingest(
        ledger, producer="unregistered", producer_trust=ProducerTrust.OBSERVED_ONLY
    )
    assert outcome.state is EvidenceState.LOCKED
    assert outcome.lock_reason == LockReason.PRODUCER_TRUST_INSUFFICIENT
    # Retained and auditable.
    assert store.get_evidence(evidence_id) is not None


def test_a_demoted_producer_loses_its_standing_on_recompute():
    """A producer proven compromised later must not leave its evidence
    counting."""
    _, store, ledger, _ = _stack()
    evidence_id, outcome = _ingest(ledger)
    assert outcome.state is EvidenceState.ELIGIBLE

    with store._connect() as connection:  # noqa: SLF001
        connection.execute(
            "UPDATE evidence SET producer_trust = ? WHERE evidence_id = ?",
            (str(ProducerTrust.REVOKED), evidence_id),
        )

    ledger.recompute(evidence_id)
    assert ledger.get(evidence_id).counts_toward_decisions is False
    assert ledger.get(evidence_id).lock_reason == LockReason.PRODUCER_TRUST_INSUFFICIENT


# ---------------------------------------------------------------------------
# Human governance of locked evidence
# ---------------------------------------------------------------------------
def test_a_human_can_release_locked_evidence_and_it_is_audited():
    _, store, ledger, audit = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-OTHER", depends_on=(a,)
    )
    assert ledger.get(b).state is EvidenceState.LOCKED

    record = ledger.get(b)
    result = ledger.review(
        b,
        disposition="RELEASED",
        operator_id="evidence-op",
        principal=_principal(),
        reason="confirmed the same operator out of band",
        expected_version=record.version,
    )

    assert result["state"] == EvidenceState.HUMAN_RELEASED
    released = ledger.get(b)
    assert released.counts_toward_decisions is True
    # ...and it stays distinguishable from evidence proved by provenance.
    assert released.released_by_a_human is True

    entry = [e for e in audit if e["decision"] == "EVIDENCE_RELEASED"][0]
    assert entry["operator_id"] == "evidence-op"
    assert entry["identity_type"] == "operator"
    assert entry["prior_lock_reason"] == LockReason.UNVERIFIED_RELATIONSHIP
    assert entry["authorizes_response_action"] is False


def test_a_release_does_not_rewrite_the_original_lock():
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-OTHER", depends_on=(a,)
    )
    record = ledger.get(b)
    ledger.review(
        b, disposition="RELEASED", operator_id="evidence-op",
        principal=_principal(), reason="verified out of band",
        expected_version=record.version,
    )

    review = store.reviews_of(b)[0]
    assert review["prior_state"] == EvidenceState.LOCKED
    assert review["prior_lock_reason"] == LockReason.UNVERIFIED_RELATIONSHIP
    assert review["disposition"] == "RELEASED"


def test_a_rejection_is_durable_and_not_lifted_by_recomputation():
    _, _, ledger, _ = _stack()
    evidence_id, _ = _ingest(ledger)
    record = ledger.get(evidence_id)
    ledger.review(
        evidence_id, disposition="REJECTED", operator_id="evidence-op",
        principal=_principal(), reason="misreported",
        expected_version=record.version,
    )

    assert ledger.get(evidence_id).state is EvidenceState.REJECTED
    ledger.recompute(evidence_id)
    assert ledger.get(evidence_id).state is EvidenceState.REJECTED
    assert ledger.get(evidence_id).counts_toward_decisions is False


@pytest.mark.parametrize(
    "principal",
    [None, _principal(is_human=False), _principal(subject="someone-else")],
)
def test_an_unauthenticated_or_mismatched_review_is_refused(principal):
    _, store, ledger, audit = _stack()
    evidence_id, _ = _ingest(ledger)
    record = ledger.get(evidence_id)

    with pytest.raises(UnauthorizedEvidenceReview):
        ledger.review(
            evidence_id, disposition="RELEASED", operator_id="evidence-op",
            principal=principal, reason="r", expected_version=record.version,
        )

    assert ledger.get(evidence_id).state is record.state
    assert store.reviews_of(evidence_id) == ()
    assert any(e["decision"] == "EVIDENCE_REVIEW_DENIED" for e in audit)


def test_a_review_of_a_stale_version_is_refused():
    """Resistant to replay: the decision is bound to the exact version the
    human saw."""
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-1", depends_on=(a,)
    )
    stale_version = ledger.get(b).version

    # B changes underneath the reviewer: its dependency is proved, so it
    # moves to ELIGIBLE and its version advances.
    ledger.verify_relationship(store.relationships_of(b)[0]["relationship_id"])
    assert ledger.get(b).version != stale_version

    with pytest.raises(PermissionError, match="changed since it was reviewed"):
        ledger.review(
            b, disposition="RELEASED", operator_id="evidence-op",
            principal=_principal(), reason="r", expected_version=stale_version,
        )


def test_a_review_requires_a_reason():
    _, _, ledger, _ = _stack()
    evidence_id, _ = _ingest(ledger)
    with pytest.raises(ValueError, match="reason is required"):
        ledger.review(
            evidence_id, disposition="RELEASED", operator_id="evidence-op",
            principal=_principal(), reason="   ",
            expected_version=ledger.get(evidence_id).version,
        )


def test_contradicting_evidence_overrides_a_human_release():
    """A person released it without having seen the contradiction. Once the
    contradiction is proved, the record stops counting again."""
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(ledger, producer="sparta", seq=2, account_id="acct-OTHER")
    record = ledger.get(b)
    ledger.review(
        b, disposition="RELEASED", operator_id="evidence-op",
        principal=_principal(), reason="believed related",
        expected_version=record.version,
    )
    assert ledger.get(b).counts_toward_decisions is True

    store.record_relationship(
        relationship_id="rel-contradicts",
        parent_evidence_id=a,
        child_evidence_id=b,
        relationship_type=str(RelationshipType.CONTRADICTS),
        required_for_eligibility=False,
        state=str(RelationshipState.VERIFIED),
        created_at_ms=int(time.time() * 1000),
    )
    ledger.recompute(b)

    held = ledger.get(b)
    assert held.state is EvidenceState.LOCKED
    assert held.lock_reason == LockReason.CONTRADICTED


def test_a_contradiction_locks_both_sides_not_only_its_stored_child():
    """The relationship row names one side "parent" and one "child" only
    because the table needs two columns -- CONTRADICTS is symmetric in
    MEANING. A verified contradiction must lock the record stored as the
    parent too, not only the one that happens to be the child, or half of
    a genuine dispute would keep counting."""
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, producer="identity-provider", payload={"device": "Y"})
    b, _ = _ingest(ledger, producer="firewall", payload={"device": "Z"})
    assert ledger.get(a).state is EvidenceState.ELIGIBLE
    assert ledger.get(b).state is EvidenceState.ELIGIBLE

    store.record_relationship(
        relationship_id="rel-symmetric-contradiction",
        parent_evidence_id=a,
        child_evidence_id=b,
        relationship_type=str(RelationshipType.CONTRADICTS),
        required_for_eligibility=False,
        state=str(RelationshipState.VERIFIED),
        created_at_ms=int(time.time() * 1000),
    )
    ledger.recompute(b)

    # b is the row's stored child: recomputing it directly always saw this.
    assert ledger.get(b).state is EvidenceState.LOCKED
    assert ledger.get(b).lock_reason == LockReason.CONTRADICTED
    # a is the row's stored PARENT -- this is what recompute(b) must now
    # also propagate to, since a was never "b's dependent".
    assert ledger.get(a).state is EvidenceState.LOCKED
    assert ledger.get(a).lock_reason == LockReason.CONTRADICTED


def test_a_contradiction_recomputed_from_its_other_side_also_locks_both():
    """The same fact, entered from the opposite direction: recomputing the
    row's PARENT must propagate to lock its stored child too."""
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, producer="identity-provider", payload={"device": "Y2"})
    b, _ = _ingest(ledger, producer="firewall", payload={"device": "Z2"})
    store.record_relationship(
        relationship_id="rel-symmetric-contradiction-2",
        parent_evidence_id=a,
        child_evidence_id=b,
        relationship_type=str(RelationshipType.CONTRADICTS),
        required_for_eligibility=False,
        state=str(RelationshipState.VERIFIED),
        created_at_ms=int(time.time() * 1000),
    )
    ledger.recompute(a)
    assert ledger.get(a).state is EvidenceState.LOCKED
    assert ledger.get(b).state is EvidenceState.LOCKED


def test_a_long_chain_propagates_in_full_not_only_the_first_two_hops():
    """A regression this pass's own rewrite of propagation introduced and
    caught: mixing dependency and contradiction edges into an unordered set
    let a child be evaluated before its parent's new state was actually
    written, so a five-deep chain silently stopped propagating after two
    hops. Propagation must reach every dependent, however long the chain."""
    _, store, ledger, _ = _stack()
    previous, _ = _ingest(ledger, account_id="acct-1")
    chain = [previous]
    for index in range(6):
        current, _ = _ingest(
            ledger, producer="sparta", seq=index + 2, account_id="acct-1",
            depends_on=(previous,),
        )
        ledger.verify_relationship(
            store.relationships_of(current)[0]["relationship_id"]
        )
        chain.append(current)
        previous = current

    assert all(ledger.get(item).counts_toward_decisions for item in chain)
    ledger.invalidate(chain[0], reason="forged")
    for depth, item in enumerate(chain):
        assert not ledger.get(item).counts_toward_decisions, (
            f"chain[{depth}] still counts after invalidating chain[0]"
        )


# ---------------------------------------------------------------------------
# Durability and concurrency
# ---------------------------------------------------------------------------
def test_locks_and_relationships_survive_a_restart():
    directory, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-OTHER", depends_on=(a,)
    )
    assert ledger.get(b).state is EvidenceState.LOCKED

    # A new process, against the same file.
    reopened = SentinelCoreStore(CoreStoreConfig(db_path=directory / "heart.sqlite3"))
    reopened.initialize()
    restarted = EvidenceLedger(reopened)

    record = restarted.get(b)
    assert record.state is EvidenceState.LOCKED
    assert record.lock_reason == LockReason.UNVERIFIED_RELATIONSHIP
    assert len(reopened.relationships_of(b)) == 1


def test_concurrent_ingestion_cannot_produce_conflicting_eligibility():
    import threading

    _, store, ledger, _ = _stack()
    results: list[str] = []
    errors: list[BaseException] = []

    def ingest_same() -> None:
        try:
            evidence_id, _ = _ingest(ledger, payload={"contended": True})
            results.append(evidence_id)
        except BaseException as exc:  # noqa: BLE001 - recorded and asserted
            errors.append(exc)

    threads = [threading.Thread(target=ingest_same) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert errors == []
    # One underlying fact, one record, one agreed state.
    assert len(set(results)) == 1
    assert store.count_evidence() == 1
    assert ledger.get(results[0]).state in DECISION_ELIGIBLE_STATES


def test_a_failed_eligibility_write_fails_closed(monkeypatch):
    """If the transition cannot be recorded durably, nothing may rely on it:
    the failure propagates and the stored state is left untouched."""
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, account_id="acct-1")
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-1", depends_on=(a,)
    )
    ledger.verify_relationship(store.relationships_of(b)[0]["relationship_id"])
    assert ledger.get(b).counts_toward_decisions is True
    before = ledger.get(a).state

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("durable store unavailable")

    monkeypatch.setattr(store, "set_evidence_state", unavailable)

    with pytest.raises(RuntimeError, match="durable store unavailable"):
        ledger.invalidate(a, reason="producer compromised")

    # Nothing silently changed, in either direction.
    assert ledger.get(a).state is before
    assert ledger.get(b).counts_toward_decisions is True


# ---------------------------------------------------------------------------
# The bundle handed to the decision authority
# ---------------------------------------------------------------------------
def test_the_bundle_keeps_countable_and_held_evidence_apart():
    _, store, ledger, _ = _stack()
    subject = "operator|203.0.113.77"
    eligible_id, _ = _ingest(ledger, subject_value=subject, account_id="acct-1")
    parent, _ = _ingest(ledger, subject_value=subject, seq=9, account_id="acct-1")
    locked_id, _ = _ingest(
        ledger, producer="sparta", seq=2, subject_value=subject,
        account_id="acct-OTHER", depends_on=(parent,),
    )

    bundle = ledger.bundle_for_subject(subject)
    eligible_ids = {record.evidence_id for record in bundle.eligible}
    locked_ids = {record.evidence_id for record in bundle.locked}

    assert eligible_id in eligible_ids
    assert locked_id in locked_ids
    assert eligible_ids & locked_ids == set()
    assert bundle.has_locked_evidence is True

    # Held records never contribute a producer to a corroboration count.
    assert "sparta" not in bundle.independent_producers

    context = bundle.context_for_operator()
    row = next(item for item in context if item["evidence_id"] == locked_id)
    assert row["lock_reason"] == LockReason.UNVERIFIED_RELATIONSHIP
    assert row["lock_detail"]
    assert row["missing_dependencies"] == [parent]


def test_content_hash_is_stable_across_key_order():
    assert content_hash({"a": 1, "b": 2}) == content_hash({"b": 2, "a": 1})
    assert content_hash({"a": 1}) != content_hash({"a": 2})


# ---------------------------------------------------------------------------
# What the decision authority is allowed to act on
#
# The authority stays the sole decision-maker. Attaching a ledger narrows
# what it will act on; it never moves a decision into the ledger.
# ---------------------------------------------------------------------------
def _authority_stack():
    """The production governance composition, plus an evidence ledger."""
    from core.audit import AuditConfig, AuditStore
    from core.governance import (
        build_heart_from_settings,
        build_orchestrator_from_settings,
    )

    directory = Path(tempfile.mkdtemp(prefix="s43-evidence-auth-"))
    audit = AuditStore(
        AuditConfig(sqlite_path=directory / "audit.sqlite3", signing_key="k" * 48)
    )
    audit.initialize()
    store = SentinelCoreStore(CoreStoreConfig(db_path=directory / "heart.sqlite3"))
    store.initialize()

    class GovernanceSettings:
        default_mode = "HUMAN_GATED"

    authority = build_orchestrator_from_settings(
        GovernanceSettings(), audit_store=audit
    )

    class Settings:
        default_mode = "HUMAN_GATED"
        velocity_window_seconds = 60
        velocity_limit = 100_000
        dedupe_ttl_seconds = 300
        corroboration_window_seconds = 300
        corroboration_min_signals_for_high = 2

    heart = build_heart_from_settings(
        Settings(),
        audit_store=audit,
        core_store=store,
        authority=authority,
        operator_authenticator=lambda principal: bool(
            getattr(principal, "is_human", False)
        ),
    )
    ledger = EvidenceLedger(
        store,
        operator_authenticator=lambda principal: bool(
            getattr(principal, "is_human", False)
        ),
        audit_sink=authority._append_audit,  # noqa: SLF001
    )
    return directory, audit, store, heart, authority, ledger


def _assessment(subject_ip: str = "203.0.113.50"):
    from core.detection.sentinel_threat_types import (
        ThreatAssessment,
        ThreatKind,
        ThreatSeverity,
        ThreatSourceKind,
    )

    return ThreatAssessment(
        identity="anonymous",
        source_ip=subject_ip,
        threat_kind=ThreatKind.DATA_EXFILTRATION,
        severity=ThreatSeverity.HIGH,
        source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
        score=50.0,
        indicators={"evidence_seq": 1, "evidence_sources": ["firewall", "sparta"]},
        supporting_tags=["t"],
        window_size=5,
    )


def _ingest_for(ledger, subject, **overrides):
    params = {
        "producer": "firewall",
        "producer_trust": ProducerTrust.TRUSTED,
        "event_type": "auth_failure",
        "payload": {"n": overrides.pop("n", 1)},
        "subject_value": subject,
    }
    params.update(overrides)
    return ledger.ingest(**params)


def test_locked_evidence_cannot_create_a_recommendation():
    """The subject has evidence, but all of it is held. Nothing is staged,
    and the recorded reason says exactly that."""
    _, audit, store, heart, authority, ledger = _authority_stack()
    subject = "anonymous|203.0.113.50"

    parent, _ = _ingest_for(ledger, subject, account_id="acct-1")
    _ingest_for(
        ledger, subject, producer="sparta", event_type="token_use", n=2,
        account_id="acct-OTHER", depends_on=(parent,),
    )
    ledger.invalidate(parent, reason="producer compromised")

    authority.attach_evidence_ledger(ledger)
    decision = heart.observe(_assessment())

    assert decision.status == "OBSERVED"
    assert decision.reason == "EVIDENCE_NOT_ELIGIBLE"
    assert store.count_actions() == 0

    record = [
        r
        for r in audit.get_records(component="heart", limit=200)
        if r.get("reason_code") == "EVIDENCE_NOT_ELIGIBLE"
    ][-1]
    assert record["evidence_gate"] == "enforced"
    assert record["eligible_evidence"] == []
    # Held evidence is still SHOWN -- it simply cannot be acted on.
    assert record["locked_evidence"]
    assert record["locked_evidence"][0]["lock_reason"]


def test_eligible_evidence_reaches_the_orchestration_authority():
    _, audit, store, heart, authority, ledger = _authority_stack()
    subject = "anonymous|203.0.113.51"

    _ingest_for(ledger, subject)
    authority.attach_evidence_ledger(ledger)

    decision = heart.observe(_assessment("203.0.113.51"))
    assert decision.status == "STAGED", decision
    assert store.count_actions() == 1

    staged = audit.get_records(component="heart", correlation_id=decision.action_id)[0]
    assert staged["evidence_gate"] == "enforced"
    assert staged["eligible_producers"] == ["firewall"]
    assert staged["locked_evidence"] == []


def test_eligible_and_locked_evidence_are_never_flattened_together():
    _, audit, store, heart, authority, ledger = _authority_stack()
    subject = "anonymous|203.0.113.52"

    _ingest_for(ledger, subject)
    parent, _ = _ingest_for(ledger, subject, n=9, account_id="acct-1")
    _ingest_for(
        ledger, subject, producer="sparta", event_type="token_use", n=2,
        account_id="acct-OTHER", depends_on=(parent,),
    )
    authority.attach_evidence_ledger(ledger)

    decision = heart.observe(_assessment("203.0.113.52"))
    assert decision.status == "STAGED", decision

    staged = audit.get_records(component="heart", correlation_id=decision.action_id)[0]
    eligible_ids = {row["evidence_id"] for row in staged["eligible_evidence"]}
    locked_ids = {row["evidence_id"] for row in staged["locked_evidence"]}

    assert eligible_ids and locked_ids
    assert eligible_ids & locked_ids == set()
    # The held record contributed nothing to what may count.
    assert "sparta" not in staged["eligible_producers"]


def test_a_human_released_record_is_marked_as_such_for_the_operator():
    """The authority can tell an operator that something counts because a
    person decided it, not because provenance proved it."""
    _, audit, store, heart, authority, ledger = _authority_stack()
    subject = "anonymous|203.0.113.53"

    parent, _ = _ingest_for(ledger, subject, account_id="acct-1")
    held, _ = _ingest_for(
        ledger, subject, producer="sparta", event_type="token_use", n=2,
        account_id="acct-OTHER", depends_on=(parent,),
    )
    ledger.review(
        held,
        disposition="RELEASED",
        operator_id="evidence-op",
        principal=_principal(),
        reason="confirmed out of band",
        expected_version=ledger.get(held).version,
    )

    authority.attach_evidence_ledger(ledger)
    decision = heart.observe(_assessment("203.0.113.53"))
    assert decision.status == "STAGED", decision

    staged = audit.get_records(component="heart", correlation_id=decision.action_id)[0]
    released = [
        row for row in staged["eligible_evidence"] if row["released_by_a_human"]
    ]
    assert len(released) == 1
    assert released[0]["evidence_id"] == held


def test_releasing_evidence_is_not_approving_a_response():
    """An evidence decision never authorizes an action: it is stored in its
    own table, audited as not authorizing, and leaves the recommendation
    awaiting a separate human decision."""
    from core.sentinel43_core_db import ActionStatus

    _, audit, store, heart, authority, ledger = _authority_stack()
    subject = "anonymous|203.0.113.54"

    # Untrusted producer: retained, not countable, until a human says so.
    evidence_id, _ = _ingest_for(
        ledger, subject, producer_trust=ProducerTrust.OBSERVED_ONLY
    )
    assert ledger.get(evidence_id).counts_toward_decisions is False

    result = ledger.review(
        evidence_id,
        disposition="RELEASED",
        operator_id="evidence-op",
        principal=_principal(),
        reason="trusted this one report",
        expected_version=ledger.get(evidence_id).version,
    )
    assert result["authorizes_response_action"] is False

    authority.attach_evidence_ledger(ledger)
    decision = heart.observe(_assessment("203.0.113.54"))
    assert decision.status == "STAGED", decision

    # The recommendation still needs its OWN human decision.
    assert store.get_status(decision.action_id) == ActionStatus.PENDING
    reviews = store.reviews_of(evidence_id)
    assert len(reviews) == 1
    assert reviews[0]["disposition"] == "RELEASED"


def test_the_ledger_never_stages_or_resolves_anything():
    """Structural: the evidence layer holds no decision verb."""
    import ast

    source = (
        Path(__file__).resolve().parents[1] / "evidence" / "ledger.py"
    ).read_text(encoding="utf-8")
    called = {
        node.func.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    forbidden = {
        "stage_recommendation",
        "resolve_recommendation",
        "insert_pending",
        "transition_status",
        "approve_action",
        "veto_action",
        "plan_response",
        "stage_directive",
    }
    assert called & forbidden == set()


def test_a_subject_with_no_recorded_evidence_degrades_instead_of_blocking():
    """An empty ledger for a subject is not evidence being withheld.

    Refusing there would turn a ledger that is not yet the source for a
    given path into an outage. The gate records that it had nothing to
    check, and the reporter's own rules still apply.
    """
    _, audit, store, heart, authority, ledger = _authority_stack()
    authority.attach_evidence_ledger(ledger)

    decision = heart.observe(_assessment("203.0.113.60"))
    assert decision.status == "STAGED", decision

    staged = audit.get_records(component="heart", correlation_id=decision.action_id)[0]
    assert staged["evidence_gate"] == "no_recorded_evidence"
    assert staged["eligible_evidence"] == []
    assert staged["locked_evidence"] == []


def test_holding_every_record_blocks_but_holding_none_does_not():
    """The difference the gate turns on, stated directly."""
    _, _, _, _, authority, ledger = _authority_stack()
    authority.attach_evidence_ledger(ledger)
    subject = "anonymous|203.0.113.61"

    permitted, context = authority._evidence_gate(subject)  # noqa: SLF001
    assert permitted is True and context["evidence_gate"] == "no_recorded_evidence"

    parent, _ = _ingest_for(ledger, subject, account_id="acct-1")
    _ingest_for(
        ledger, subject, producer="sparta", n=2, account_id="acct-OTHER",
        depends_on=(parent,),
    )
    ledger.invalidate(parent, reason="forged")

    permitted, context = authority._evidence_gate(subject)  # noqa: SLF001
    assert permitted is False
    assert context["evidence_gate"] == "enforced"
    assert len(context["locked_evidence"]) == 2


# ---------------------------------------------------------------------------
# Second architectural pass: transitions, producer registry, root-traced
# corroboration, migration, and the remaining Step-24 required cases.
# ---------------------------------------------------------------------------
def test_a_second_producer_alone_does_not_corroborate_with_itself():
    """Two DIFFERENT (non-replay) records from the SAME producer are not two
    independent producers, however they are linked."""
    _, store, ledger, _ = _stack(required_producers=2)
    first, _ = _ingest(ledger, payload={"a": 1})
    second, _ = _ingest(ledger, payload={"a": 2})
    store.record_relationship(
        relationship_id="rel-same-producer",
        parent_evidence_id=first,
        child_evidence_id=second,
        relationship_type=str(RelationshipType.CORROBORATES),
        required_for_eligibility=False,
        state=str(RelationshipState.VERIFIED),
        created_at_ms=int(time.time() * 1000),
    )
    ledger.recompute(second)
    held = ledger.get(second)
    assert held.state is EvidenceState.LOCKED
    assert held.lock_reason == LockReason.INSUFFICIENT_CORROBORATION


def test_two_records_from_the_same_root_do_not_corroborate():
    """A and B both descend (DERIVED_FROM) from the same source, under
    different producer names. They are not two producers -- they are one
    source told twice."""
    _, store, ledger, _ = _stack(required_producers=2)
    root, _ = _ingest(ledger, producer="root-detector", payload={"root": 1})

    a, _ = _ingest(ledger, producer="firewall", payload={"a": 1})
    b, _ = _ingest(ledger, producer="sparta", payload={"b": 1})
    now = int(time.time() * 1000)
    for child in (a, b):
        rel_id = f"rel-derived-{child}"
        store.record_relationship(
            relationship_id=rel_id,
            parent_evidence_id=root,
            child_evidence_id=child,
            relationship_type=str(RelationshipType.DERIVED_FROM),
            required_for_eligibility=False,
            state=str(RelationshipState.PROPOSED),
            created_at_ms=now,
        )
        assert ledger.verify_relationship(rel_id) is True

    store.record_relationship(
        relationship_id="rel-ab-corroborates",
        parent_evidence_id=a,
        child_evidence_id=b,
        relationship_type=str(RelationshipType.CORROBORATES),
        required_for_eligibility=False,
        state=str(RelationshipState.VERIFIED),
        created_at_ms=now,
    )
    ledger.recompute(a)
    ledger.recompute(b)

    # Both share root's producer set: {firewall} u {root-detector} still < 2
    # independent producers once the shared root is excluded.
    held = ledger.get(b)
    assert held.state is EvidenceState.LOCKED
    assert held.lock_reason == LockReason.INSUFFICIENT_CORROBORATION


def test_an_unverified_derived_from_claim_does_not_exclude_a_root():
    """Only a VERIFIED DERIVED_FROM link removes a candidate from
    corroboration -- an unproved claim of shared ancestry proves nothing."""
    _, store, ledger, _ = _stack(required_producers=2)
    root, _ = _ingest(ledger, producer="root-detector", payload={"root": 1})
    a, _ = _ingest(ledger, producer="firewall", payload={"a": 1})
    b, _ = _ingest(ledger, producer="sparta", payload={"b": 1})
    now = int(time.time() * 1000)

    # a IS derived from root (verified); b's claim is left unverified.
    rel_a = "rel-derived-a2"
    store.record_relationship(
        relationship_id=rel_a, parent_evidence_id=root, child_evidence_id=a,
        relationship_type=str(RelationshipType.DERIVED_FROM),
        required_for_eligibility=False, state=str(RelationshipState.PROPOSED),
        created_at_ms=now,
    )
    assert ledger.verify_relationship(rel_a) is True

    store.record_relationship(
        relationship_id="rel-ab-corroborates2", parent_evidence_id=a,
        child_evidence_id=b, relationship_type=str(RelationshipType.CORROBORATES),
        required_for_eligibility=False, state=str(RelationshipState.VERIFIED),
        created_at_ms=now,
    )
    ledger.recompute(a)
    ledger.recompute(b)
    # a's root is {root, a}; b is not derived from anything, so b's own root
    # is {b}. No shared root -- a IS an independent second producer for b.
    assert ledger.get(b).state is EvidenceState.ELIGIBLE


def test_a_producer_can_be_registered_and_looked_up():
    _, store, ledger, _ = _stack()
    ledger.register_producer(
        "firewall", trust=ProducerTrust.TRUSTED, updated_by="ops", reason="onboarded"
    )
    registered = store.get_producer_trust("firewall")
    assert registered["trust"] == "TRUSTED"
    assert registered["updated_by"] == "ops"


def test_registry_trust_overrides_the_ingestion_time_snapshot():
    """Once a producer is registered, the registry -- not the frozen
    snapshot -- is what eligibility consults."""
    _, store, ledger, _ = _stack()
    evidence_id, outcome = _ingest(ledger, producer="firewall")
    assert outcome.state is EvidenceState.ELIGIBLE  # no registry yet: snapshot wins

    ledger.register_producer(
        "firewall", trust=ProducerTrust.OBSERVED_ONLY, updated_by="ops",
        reason="downgraded pending review",
    )
    ledger.recompute(evidence_id)
    held = ledger.get(evidence_id)
    assert held.state is EvidenceState.LOCKED
    assert held.lock_reason == LockReason.PRODUCER_TRUST_INSUFFICIENT


def test_revoking_a_producer_re_locks_its_evidence_and_dependents():
    """Step 22.5: a trusted producer, later revoked. Nothing is deleted;
    everything it reported, and everything that leaned on it, is
    re-evaluated -- not just the one record a caller happens to touch."""
    _, store, ledger, _ = _stack()
    ledger.register_producer(
        "firewall", trust=ProducerTrust.TRUSTED, updated_by="ops"
    )
    root, _ = _ingest(ledger, producer="firewall", account_id="acct-1")
    dependent, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-1", depends_on=(root,)
    )
    ledger.verify_relationship(store.relationships_of(dependent)[0]["relationship_id"])
    assert ledger.get(root).counts_toward_decisions is True
    assert ledger.get(dependent).counts_toward_decisions is True

    affected = ledger.revoke_producer(
        "firewall", reason="compromised host", updated_by="ops"
    )
    assert affected == 1  # one record was firewall's own

    revoked_root = ledger.get(root)
    assert revoked_root.counts_toward_decisions is False
    assert revoked_root.lock_reason == LockReason.PRODUCER_TRUST_INSUFFICIENT
    # The dependent, from a DIFFERENT (still-trusted) producer, is also
    # re-evaluated because its support just disappeared.
    assert ledger.get(dependent).counts_toward_decisions is False


def test_revocation_is_durable_and_audited():
    _, store, ledger, audit = _stack()
    _ingest(ledger, producer="firewall")
    ledger.revoke_producer("firewall", reason="compromised", updated_by="ops")

    assert store.get_producer_trust("firewall")["trust"] == "REVOKED"
    assert any(e["decision"] == "PRODUCER_TRUST_SET" for e in audit)


def test_an_invalid_transition_is_refused_defensively():
    """Defense in depth: even a hand-built EligibilityOutcome that names a
    transition ALLOWED_TRANSITIONS does not list is refused, not written."""
    _, store, ledger, _ = _stack()
    evidence_id, _ = _ingest(ledger)
    record = ledger.get(evidence_id)
    assert record.state is EvidenceState.ELIGIBLE

    with pytest.raises(InvalidEvidenceTransition):
        ledger._write_state(  # noqa: SLF001 - exercising the guard directly
            record,
            EligibilityOutcome(state=EvidenceState.OBSERVED),
            decided_by="test",
        )
    # Refused, not silently applied.
    assert ledger.get(evidence_id).state is EvidenceState.ELIGIBLE


def test_review_refuses_a_transition_human_review_may_not_make():
    """A record a human already REJECTED is terminal for the automatic
    rules AND for a later human review: REJECTED has no allowed target in
    ALLOWED_TRANSITIONS, so a second review trying to RELEASE it is refused
    rather than applied. (HELD is always a same-state no-op and so can
    never violate the table -- this exercises a review that actually would.)
    """
    _, store, ledger, _ = _stack()
    evidence_id, _ = _ingest(ledger)
    record = ledger.get(evidence_id)
    ledger.review(
        evidence_id, disposition="REJECTED", operator_id="evidence-op",
        principal=_principal(), reason="misreported", expected_version=record.version,
    )
    rejected = ledger.get(evidence_id)
    with pytest.raises(InvalidEvidenceTransition):
        ledger.review(
            evidence_id, disposition="RELEASED", operator_id="evidence-op",
            principal=_principal(), reason="reconsidering",
            expected_version=rejected.version,
        )
    # Refused, not applied: still REJECTED.
    assert ledger.get(evidence_id).state is EvidenceState.REJECTED


def test_a_release_records_the_audit_ledgers_own_reference():
    """The review row is cross-linked to the exact audit entry it produced,
    not merely to a bare, unverifiable database value."""
    from core.audit import AuditConfig, AuditStore

    directory = Path(tempfile.mkdtemp(prefix="s43-evidence-auditref-"))
    audit_store = AuditStore(
        AuditConfig(sqlite_path=directory / "audit.sqlite3", signing_key="k" * 48)
    )
    audit_store.initialize()
    store = SentinelCoreStore(CoreStoreConfig(db_path=directory / "heart.sqlite3"))
    store.initialize()
    ledger = EvidenceLedger(
        store,
        operator_authenticator=lambda p: bool(getattr(p, "is_human", False)),
        audit_sink=audit_store.append,
    )

    evidence_id, _ = ledger.ingest(
        producer="firewall", producer_trust=ProducerTrust.TRUSTED,
        event_type="auth_failure", payload={"n": 1},
    )
    record = ledger.get(evidence_id)
    result = ledger.review(
        evidence_id, disposition="RELEASED", operator_id="evidence-op",
        principal=_principal(), reason="confirmed", expected_version=record.version,
    )
    assert result["audit_reference"]

    stored_review = store.reviews_of(evidence_id)[0]
    assert stored_review["audit_reference"] == result["audit_reference"]

    ledger_records = audit_store.get_records(component="evidence_ledger", limit=50)
    assert any(
        r.get("evidence_id") == evidence_id and r.get("decision") == "EVIDENCE_RELEASED"
        for r in ledger_records
    )


def test_direct_sql_tampering_does_not_survive_the_next_recompute():
    """A direct write to the state column is not something SQLite itself can
    prevent -- but eligibility is recomputed fresh from provenance every
    time, never trusted from the stored value, so the very next recompute
    corrects it back. It does not silently persist."""
    _, store, ledger, _ = _stack()
    parent, _ = _ingest(ledger, account_id="acct-1")
    dependent, _ = _ingest(
        ledger, producer="sparta", seq=2, account_id="acct-OTHER", depends_on=(parent,)
    )
    assert ledger.get(dependent).state is EvidenceState.LOCKED

    with store._connect() as connection:  # noqa: SLF001
        connection.execute(
            "UPDATE evidence SET state = 'ELIGIBLE', lock_reason = '' "
            "WHERE evidence_id = ?",
            (dependent,),
        )
    assert ledger.get(dependent).state is EvidenceState.ELIGIBLE  # tampered

    ledger.recompute(dependent)
    healed = ledger.get(dependent)
    assert healed.state is EvidenceState.LOCKED
    assert healed.lock_reason == LockReason.UNVERIFIED_RELATIONSHIP


def test_the_producer_trust_column_rejects_an_unknown_value():
    """The CHECK constraint, not only application code, refuses a value
    outside the vocabulary."""
    _, store, ledger, _ = _stack()
    with pytest.raises(sqlite3.IntegrityError):
        store.record_evidence(
            evidence_id="ev-bad-trust", producer="x", producer_trust="ALL_POWERFUL",
            event_type="t", observed_at_ms=1, ingested_at_ms=1, content_hash="h",
            state=str(EvidenceState.OBSERVED),
        )


def test_the_canonical_and_payload_hashes_differ_on_key_order():
    ordered = {"a": 1, "b": 2}
    reordered = {"b": 2, "a": 1}
    assert content_hash(ordered) == content_hash(reordered)  # canonical
    assert content_hash(ordered, canonical=False) != content_hash(
        reordered, canonical=False
    )


def test_evaluate_eligibility_locks_an_unregistered_producer_as_legacy():
    """The pure rule, exercised directly: no trust information at all (the
    ``None`` sentinel) is LEGACY_UNVERIFIED, distinct from a producer that
    WAS checked and found untrustworthy."""
    from core.evidence.model import evaluate_eligibility

    record = EvidenceRecord(
        evidence_id="e1", producer="ancient-source", producer_trust=ProducerTrust.TRUSTED,
        event_type="t", observed_at_ms=1, ingested_at_ms=1, content_hash="h",
        state=EvidenceState.OBSERVED,
    )
    outcome = evaluate_eligibility(
        record, (), parents={}, now_ms=2, producer_trust=None,
    )
    assert outcome.state is EvidenceState.LOCKED
    assert outcome.lock_reason == LockReason.LEGACY_UNVERIFIED


def test_incident_id_is_a_first_class_field_distinct_from_correlation_id():
    _, store, ledger, _ = _stack()
    evidence_id, _ = _ingest(
        ledger, correlation_id="corr-1", incident_id="INC-42"
    )
    record = ledger.get(evidence_id)
    assert record.correlation_id == "corr-1"
    assert record.incident_id == "INC-42"
    assert len(store.list_evidence(incident_id="INC-42")) == 1


def test_same_incident_verifies_against_incident_id_not_correlation_id():
    _, store, ledger, _ = _stack()
    a, _ = _ingest(ledger, incident_id="INC-1", correlation_id="corr-a")
    b, _ = _ingest(
        ledger, producer="sparta", seq=2, incident_id="INC-1", correlation_id="corr-b",
        depends_on=(a,), dependency_type=RelationshipType.SAME_INCIDENT,
    )
    relationship = store.relationships_of(b)[0]
    assert ledger.verify_relationship(relationship["relationship_id"]) is True
    assert ledger.get(b).state is EvidenceState.ELIGIBLE


# ---------------------------------------------------------------------------
# Approving a response does not release evidence; releasing evidence does
# not approve a response (the converse of an existing test -- Step 10).
# ---------------------------------------------------------------------------
def test_approving_a_recommendation_does_not_release_any_evidence():
    _, audit, store, heart, authority, ledger = _authority_stack()
    subject = "anonymous|203.0.113.62"
    ledger._authenticator = lambda p: bool(getattr(p, "is_human", False))  # noqa: SLF001

    evidence_id, _ = _ingest_for(ledger, subject)
    authority.attach_evidence_ledger(ledger)
    before_version = ledger.get(evidence_id).version
    before_state = ledger.get(evidence_id).state

    decision = heart.observe(_assessment("203.0.113.62"))
    assert decision.status == "STAGED", decision

    result = authority.resolve_recommendation(
        decision.action_id, approved=True, operator_id="heart-op",
        reason="reviewed", principal=_principal(subject="heart-op"),
    )
    assert result["outcome"] == "APPROVED"

    after = ledger.get(evidence_id)
    assert after.version == before_version
    assert after.state is before_state
    assert store.reviews_of(evidence_id) == ()


# ---------------------------------------------------------------------------
# Shadow Mode uses the SAME evidence eligibility path as HUMAN_GATED --
# locked evidence never enters its actual assessment (Step 13).
# ---------------------------------------------------------------------------
def test_shadow_mode_never_counts_locked_evidence_in_its_recommendation():
    from core.audit import AuditConfig, AuditStore
    from core.governance import build_heart_from_settings, build_orchestrator_from_settings

    directory = Path(tempfile.mkdtemp(prefix="s43-evidence-shadow-"))
    audit = AuditStore(
        AuditConfig(sqlite_path=directory / "audit.sqlite3", signing_key="k" * 48)
    )
    audit.initialize()
    store = SentinelCoreStore(CoreStoreConfig(db_path=directory / "heart.sqlite3"))
    store.initialize()

    class GovernanceSettings:
        default_mode = "SHADOW"

    authority = build_orchestrator_from_settings(GovernanceSettings(), audit_store=audit)

    class Settings:
        default_mode = "SHADOW"
        velocity_window_seconds = 60
        velocity_limit = 100_000
        dedupe_ttl_seconds = 300
        corroboration_window_seconds = 300
        corroboration_min_signals_for_high = 2

    heart = build_heart_from_settings(
        Settings(), audit_store=audit, core_store=store, authority=authority,
        operator_authenticator=lambda p: bool(getattr(p, "is_human", False)),
    )
    ledger = EvidenceLedger(store, audit_sink=authority._append_audit)  # noqa: SLF001
    subject = "anonymous|203.0.113.63"
    parent, _ = _ingest_for(ledger, subject, account_id="acct-1")
    _ingest_for(
        ledger, subject, producer="sparta", n=2, account_id="acct-OTHER",
        depends_on=(parent,),
    )
    ledger.invalidate(parent, reason="forged")
    authority.attach_evidence_ledger(ledger)

    decision = heart.observe(_assessment("203.0.113.63"))
    # SHADOW is advisory-only, so this is always OBSERVED -- the assertion
    # that matters is what the RECORDED reason is: evidence, not a stage.
    assert decision.status == "OBSERVED"

    records = audit.get_records(component="heart", limit=200)
    evidence_records = [
        r for r in records if r.get("reason_code") == "EVIDENCE_NOT_ELIGIBLE"
    ]
    assert evidence_records, "shadow mode must run through the same evidence gate"
    assert evidence_records[-1]["evidence_gate"] == "enforced"
    assert evidence_records[-1]["eligible_evidence"] == []


# ---------------------------------------------------------------------------
# Migration: a database built with the FIRST evidence schema keeps its data
# and gains the new columns safely (formalises the manual check this pass's
# work found a real ordering bug with).
# ---------------------------------------------------------------------------
def test_a_database_from_the_first_evidence_schema_migrates_safely():
    import importlib.util
    import subprocess
    import sys as _sys

    repo_root = Path(__file__).resolve().parents[2]
    old_source = subprocess.run(
        ["git", "show", "32e04dd~1:core/sentinel43_core_db.py"],
        cwd=repo_root, capture_output=True, check=True,
    ).stdout

    old_module_path = Path(tempfile.mkdtemp(prefix="s43-legacy-schema-")) / "old_db.py"
    old_module_path.write_bytes(old_source)

    spec = importlib.util.spec_from_file_location("s43_legacy_db", old_module_path)
    old = importlib.util.module_from_spec(spec)
    _sys.modules["s43_legacy_db"] = old
    spec.loader.exec_module(old)

    directory = Path(tempfile.mkdtemp(prefix="s43-legacy-db-"))
    legacy_path = directory / "legacy.sqlite3"
    legacy_store = old.SentinelCoreStore(old.CoreStoreConfig(db_path=legacy_path))
    legacy_store.initialize()
    legacy_store.record_evidence(
        evidence_id="LEGACY-1", producer="old-producer", producer_trust="TRUSTED",
        event_type="auth_failure", observed_at_ms=1000, ingested_at_ms=1000,
        content_hash="oldhash", state="ELIGIBLE",
    )
    del _sys.modules["s43_legacy_db"]

    migrated = SentinelCoreStore(CoreStoreConfig(db_path=legacy_path))
    migrated.initialize()  # must not raise -- this is the bug this test pins
    migrated.initialize()  # idempotent

    row = migrated.get_evidence("LEGACY-1")
    assert row is not None, "the legacy row must survive the migration"
    assert row["payload_hash"] == ""
    assert row["incident_id"] == ""
    assert row["lock_detail"] == ""
    assert row["updated_at_ms"] == 0
    assert migrated.list_producers() == ()

    # The new evidence path works on the migrated database too.
    ledger = EvidenceLedger(migrated)
    evidence_id, outcome = ledger.ingest(
        producer="firewall", producer_trust=ProducerTrust.TRUSTED,
        event_type="auth_failure", payload={"post_migration": True},
    )
    assert outcome.state is EvidenceState.ELIGIBLE
