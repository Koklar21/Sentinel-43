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

import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.evidence.ledger import (
    EvidenceLedger,
    UnauthorizedEvidenceReview,
)
from core.evidence.model import (
    DECISION_ELIGIBLE_STATES,
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
