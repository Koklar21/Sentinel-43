# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_event_reliability.py
#
# Contract coverage for the event delivery reliability layer
# (core/reliability.py): idempotency, bounded retry, dead-lettering and
# operator-controlled replay.
#
# The property that matters throughout: a failed delivery is NEVER reported
# as a success, and reliability machinery never becomes autonomous
# enforcement -- a retry re-attempts DELIVERY, and replay re-delivers an
# event; neither executes anything.
# =============================================================================

from __future__ import annotations

import pathlib
import tempfile

import pytest

from core.reliability import (
    DeadLetterStore,
    DeliveryState,
    EventReliabilityManager,
    FailureStage,
    IdempotencyLedger,
    ReliabilityMetrics,
    Retryability,
    RetryPolicy,
    classify_delivery_result,
    sanitize_for_record,
    sanitize_reason,
)

SECRET = "SECRET-token-must-never-persist"

_ENVELOPE = {
    "event_id": "ev-1",
    "correlation_id": "corr-1",
    "event_type": "fenrir.finding",
    "schema_version": "1.0",
    "source": "FenrirHunter",
    "source_identity": "service:fenrir",
    "created_at": "2026-01-01T00:00:00+00:00",
    "ingested_at": "2026-01-01T00:00:01+00:00",
}


def _store() -> DeadLetterStore:
    store = DeadLetterStore(
        sqlite_path=pathlib.Path(tempfile.mkdtemp()) / "dl.sqlite3"
    )
    store.initialize()
    return store


def _manager(store: DeadLetterStore | None = None, **kwargs):
    audits: list[dict] = []
    manager = EventReliabilityManager(
        dead_letter_store=store if store is not None else _store(),
        retry_policy=RetryPolicy(
            max_attempts=3,
            base_delay_seconds=0.001,
            max_delay_seconds=0.004,
            total_deadline_seconds=5.0,
        ),
        audit_sink=audits.append,
        sleep=lambda _delay: None,
        **kwargs,
    )
    return manager, audits


# --------------------------------------------------------------------------- #
# retryability classification
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "result,expected",
    [
        ({"status_code": 401, "error": "unauthorized"}, Retryability.TERMINAL),
        ({"status_code": 403, "error": "forbidden"}, Retryability.TERMINAL),
        ({"status_code": 400, "error": "bad"}, Retryability.TERMINAL),
        ({"status_code": 422, "error": "invalid"}, Retryability.TERMINAL),
        ({"status_code": 413, "error": "too big"}, Retryability.TERMINAL),
        ({"status_code": 503, "error": "down"}, Retryability.RETRYABLE),
        ({"status_code": 500, "error": "boom"}, Retryability.RETRYABLE),
        ({"status_code": 429, "error": "slow"}, Retryability.RETRYABLE),
        ({"error": "watchtower_timeout"}, Retryability.RETRYABLE),
        ({"error": "watchtower_unreachable"}, Retryability.RETRYABLE),
        ({"error": "watchtower_malformed_response"}, Retryability.TERMINAL),
    ],
)
def test_failure_classification(result, expected):
    assert classify_delivery_result(result).retryability is expected


def test_unknown_failure_shape_is_terminal_not_retried_forever():
    """Guessing an unrecognised error is transient is how a retry loop
    becomes infinite."""
    decision = classify_delivery_result({"error": "never_seen_before"})
    assert decision.retryability is Retryability.TERMINAL


def test_success_requires_both_no_error_and_a_success_status():
    assert classify_delivery_result({"status_code": 200}).ok
    # A 4xx body without an "error" key must not read as delivered.
    assert not classify_delivery_result({"status_code": 404}).ok


def test_non_mapping_result_is_terminal():
    assert not classify_delivery_result("nonsense").ok


# --------------------------------------------------------------------------- #
# retry policy bounds
# --------------------------------------------------------------------------- #

def test_backoff_is_capped_and_jittered():
    policy = RetryPolicy(
        max_attempts=6,
        base_delay_seconds=0.1,
        max_delay_seconds=1.0,
        jitter_ratio=0.25,
    )
    delays = [policy.delay_for(i) for i in range(1, 7)]
    assert all(0.0 <= d <= 1.0 for d in delays)
    assert delays[0] < delays[3]
    assert len({round(policy.delay_for(3), 9) for _ in range(20)}) > 1


def test_policy_rejects_unbounded_configuration():
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=999)
    with pytest.raises(ValueError):
        RetryPolicy(total_deadline_seconds=0)


# --------------------------------------------------------------------------- #
# idempotency
# --------------------------------------------------------------------------- #

def test_duplicate_delivery_is_not_analyzed_twice():
    manager, _ = _manager()
    calls = {"n": 0}

    def deliver():
        calls["n"] += 1
        return {"status_code": 200}

    first = manager.deliver(_ENVELOPE, deliver)
    second = manager.deliver(_ENVELOPE, deliver)

    assert first.state is DeliveryState.DELIVERED
    assert second.state is DeliveryState.DUPLICATE
    assert calls["n"] == 1, "a transport retry re-delivered the same event"


def test_duplicate_does_not_produce_a_second_alert():
    manager, _ = _manager()
    manager.deliver(_ENVELOPE, lambda: {"status_code": 200})
    manager.deliver(_ENVELOPE, lambda: {"status_code": 200})

    metrics = manager.metrics.snapshot()
    assert metrics["delivery_success"] == 1
    assert metrics["events_duplicate"] == 1


def test_distinct_events_are_not_collapsed():
    """Dedupe is by event_id, never payload -- two identical payloads can be
    genuinely separate findings."""
    manager, _ = _manager()
    manager.deliver({**_ENVELOPE, "event_id": "a"}, lambda: {"status_code": 200})
    outcome = manager.deliver(
        {**_ENVELOPE, "event_id": "b"}, lambda: {"status_code": 200}
    )
    assert outcome.state is DeliveryState.DELIVERED


def test_idempotency_ledger_is_bounded():
    ledger = IdempotencyLedger(max_entries=10, ttl_seconds=600)
    for index in range(50):
        ledger.check_and_register(f"ev-{index}")
    assert len(ledger) <= 10


def test_idempotency_ledger_rejects_unbounded_configuration():
    with pytest.raises(ValueError):
        IdempotencyLedger(max_entries=0)
    with pytest.raises(ValueError):
        IdempotencyLedger(ttl_seconds=0)


def test_event_without_identity_is_rejected_not_guessed():
    manager, _ = _manager()
    outcome = manager.deliver({"correlation_id": "c"}, lambda: {"status_code": 200})
    assert outcome.state is DeliveryState.FAILED_TERMINAL
    assert outcome.reason == "missing_event_id"


# --------------------------------------------------------------------------- #
# retry + dead-letter
# --------------------------------------------------------------------------- #

def test_transient_failure_is_retried_then_delivered():
    manager, _ = _manager()
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            return {"error": "watchtower_unreachable"}
        return {"status_code": 200}

    outcome = manager.deliver(_ENVELOPE, flaky)
    assert outcome.state is DeliveryState.DELIVERED
    assert outcome.attempts == 3


def test_retry_exhaustion_dead_letters():
    store = _store()
    manager, _ = _manager(store)

    outcome = manager.deliver(
        _ENVELOPE, lambda: {"error": "watchtower_unreachable"}
    )

    assert outcome.state is DeliveryState.DEAD_LETTERED
    assert outcome.attempts == 3
    record = store.get("ev-1")
    assert record is not None
    assert record.attempts == 3
    assert record.replay_status == "pending"


def test_authentication_failure_is_never_retried():
    """401 cannot succeed by waiting; retrying burns budget and can trip
    lockouts."""
    manager, _ = _manager()
    calls = {"n": 0}

    def unauthorized():
        calls["n"] += 1
        return {"status_code": 401, "error": "unauthorized"}

    outcome = manager.deliver(_ENVELOPE, unauthorized)
    assert calls["n"] == 1
    assert outcome.state is DeliveryState.DEAD_LETTERED


def test_authorization_failure_is_never_retried():
    manager, _ = _manager()
    calls = {"n": 0}

    def forbidden():
        calls["n"] += 1
        return {"status_code": 403, "error": "forbidden"}

    manager.deliver(_ENVELOPE, forbidden)
    assert calls["n"] == 1


def test_raising_transport_is_bounded_not_infinite():
    manager, _ = _manager()
    calls = {"n": 0}

    def explode():
        calls["n"] += 1
        raise ConnectionError("boom")

    outcome = manager.deliver(_ENVELOPE, explode)
    assert calls["n"] == 3
    assert outcome.state is DeliveryState.DEAD_LETTERED


def test_failed_delivery_is_never_reported_delivered():
    manager, _ = _manager()
    outcome = manager.deliver(_ENVELOPE, lambda: {"error": "watchtower_timeout"})
    assert outcome.delivered is False
    assert outcome.handled is False


# --------------------------------------------------------------------------- #
# dead-letter record safety + bounds
# --------------------------------------------------------------------------- #

def test_dead_letter_record_never_stores_credentials():
    store = _store()
    manager, _ = _manager(store)

    manager.deliver(
        {
            **_ENVELOPE,
            "token": SECRET,
            "authorization": f"Bearer {SECRET}",
            "password": "hunter2",
            "payload": {"api_key": SECRET},
        },
        lambda: {"error": "watchtower_unreachable"},
    )

    blob = str(store.get("ev-1").to_dict())
    assert SECRET not in blob
    assert "hunter2" not in blob


def test_sanitize_keeps_only_allowlisted_fields():
    record = sanitize_for_record(
        {**_ENVELOPE, "token": SECRET, "payload": {"x": 1}}
    )
    assert "token" not in record
    assert "payload" not in record
    assert record["event_id"] == "ev-1"


def test_sanitize_reason_is_bounded_and_single_line():
    reason = sanitize_reason("a" * 5000 + "\nsecond line")
    assert len(reason) <= 512
    assert "\n" not in reason


def test_dead_letter_store_is_bounded():
    store = DeadLetterStore(
        sqlite_path=pathlib.Path(tempfile.mkdtemp()) / "dl.sqlite3",
        max_rows=5,
    )
    store.initialize()

    for index in range(25):
        store.record_failure(
            envelope={**_ENVELOPE, "event_id": f"ev-{index}"},
            failure_stage=FailureStage.WATCHTOWER_DELIVERY,
            classification=Retryability.RETRYABLE,
            reason="unreachable",
            attempts=3,
        )

    assert store.counts()["total"] <= 5


def test_repeated_failure_updates_one_row_not_many():
    store = _store()
    for attempt in (1, 2, 3):
        store.record_failure(
            envelope=_ENVELOPE,
            failure_stage=FailureStage.WATCHTOWER_DELIVERY,
            classification=Retryability.RETRYABLE,
            reason="unreachable",
            attempts=attempt,
        )
    assert store.counts()["total"] == 1
    assert store.get("ev-1").attempts == 3


def test_store_requires_initialization():
    store = DeadLetterStore(
        sqlite_path=pathlib.Path(tempfile.mkdtemp()) / "dl.sqlite3"
    )
    with pytest.raises(RuntimeError):
        store.counts()


# --------------------------------------------------------------------------- #
# operator-controlled replay
# --------------------------------------------------------------------------- #

def test_replay_preserves_identity_and_provenance():
    store = _store()
    manager, _ = _manager(store)
    manager.deliver(_ENVELOPE, lambda: {"error": "watchtower_unreachable"})

    seen: dict = {}

    def redeliver(envelope):
        seen.update(envelope)
        return {"status_code": 200}

    outcome = manager.replay("ev-1", redeliver, operator="alice")

    assert outcome.state is DeliveryState.DELIVERED
    assert seen["event_id"] == "ev-1"
    assert seen["correlation_id"] == "corr-1"
    assert seen["source_identity"] == "service:fenrir"


def test_replayed_event_is_not_a_new_origination():
    store = _store()
    manager, _ = _manager(store)
    manager.deliver(_ENVELOPE, lambda: {"error": "watchtower_unreachable"})

    seen: dict = {}
    manager.replay(
        "ev-1",
        lambda env: (seen.update(env), {"status_code": 200})[1],
        operator="alice",
    )
    assert seen["replay_of"] == "ev-1"


def test_replay_requires_an_operator_identity():
    store = _store()
    manager, _ = _manager(store)
    manager.deliver(_ENVELOPE, lambda: {"error": "watchtower_unreachable"})

    with pytest.raises(ValueError):
        manager.replay("ev-1", lambda env: {"status_code": 200}, operator="")


def test_failed_replay_returns_to_dead_letter_not_a_loop():
    store = _store()
    manager, _ = _manager(store)
    manager.deliver(_ENVELOPE, lambda: {"error": "watchtower_unreachable"})

    calls = {"n": 0}

    def failing(_envelope):
        calls["n"] += 1
        return {"error": "watchtower_unreachable"}

    outcome = manager.replay("ev-1", failing, operator="alice")

    assert calls["n"] == 1, "replay must not loop"
    assert outcome.state is DeliveryState.DEAD_LETTERED
    assert store.get("ev-1").replay_status == "replay_failed"


def test_replay_of_unknown_event_is_terminal():
    store = _store()
    manager, _ = _manager(store)
    outcome = manager.replay(
        "nope", lambda env: {"status_code": 200}, operator="alice"
    )
    assert outcome.reason == "unknown_event_id"


def test_replay_is_recorded_for_audit():
    store = _store()
    manager, audits = _manager(store)
    manager.deliver(_ENVELOPE, lambda: {"error": "watchtower_unreachable"})
    manager.replay("ev-1", lambda env: {"status_code": 200}, operator="alice")

    replay_records = [a for a in audits if a.get("replay")]
    assert replay_records
    assert all(a["operator"] == "alice" for a in replay_records)
    assert all(a["event_id"] == "ev-1" for a in replay_records)


# --------------------------------------------------------------------------- #
# audit correlation + metrics
# --------------------------------------------------------------------------- #

def test_delivery_transitions_are_auditable_by_correlation_id():
    manager, audits = _manager()
    manager.deliver(_ENVELOPE, lambda: {"status_code": 200})

    assert audits
    assert all(a["event_category"] == "event_delivery" for a in audits)
    assert all(a["correlation_id"] == "corr-1" for a in audits)


def test_audit_failure_never_breaks_delivery():
    store = _store()
    manager = EventReliabilityManager(
        dead_letter_store=store,
        audit_sink=lambda payload: (_ for _ in ()).throw(RuntimeError("down")),
        sleep=lambda _d: None,
    )
    outcome = manager.deliver(_ENVELOPE, lambda: {"status_code": 200})
    assert outcome.state is DeliveryState.DELIVERED


def test_metrics_reject_unknown_high_cardinality_keys():
    metrics = ReliabilityMetrics()
    metrics.increment("event_id:ev-1-some-unbounded-value")
    assert "event_id:ev-1-some-unbounded-value" not in metrics.snapshot()


def test_metrics_track_the_delivery_path():
    store = _store()
    manager, _ = _manager(store)
    manager.deliver(_ENVELOPE, lambda: {"status_code": 200})
    manager.deliver(_ENVELOPE, lambda: {"status_code": 200})
    manager.deliver(
        {**_ENVELOPE, "event_id": "ev-2"},
        lambda: {"error": "watchtower_unreachable"},
    )

    snapshot = manager.metrics.snapshot()
    assert snapshot["events_received"] == 3
    assert snapshot["events_duplicate"] == 1
    assert snapshot["delivery_success"] == 1
    assert snapshot["delivery_dead_lettered"] == 1


def test_status_exposes_no_payloads_or_secrets():
    store = _store()
    manager, _ = _manager(store)
    manager.deliver(
        {**_ENVELOPE, "token": SECRET},
        lambda: {"error": "watchtower_unreachable"},
    )
    assert SECRET not in str(manager.status())


# --------------------------------------------------------------------------- #
# governance boundary
# --------------------------------------------------------------------------- #

def test_reliability_layer_exposes_no_executor():
    """Retries retry DELIVERY. Replay replays EVENTS. Neither executes a
    remediation or approves an action."""
    import re

    surface = [m for m in dir(EventReliabilityManager) if not m.startswith("_")]
    forbidden = [
        m
        for m in surface
        if re.search(r"(^|_)(execute|enforce|remediate|approve|apply)(_|$)", m)
    ]
    assert not forbidden, surface


def test_module_starts_no_threads_or_timers():
    import inspect

    import core.reliability as reliability

    source = inspect.getsource(reliability)
    assert "Thread(" not in source
    assert "Timer(" not in source
    assert "create_task" not in source
