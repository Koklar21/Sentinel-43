# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# dashboard/tests/test_dashboard_core_contract.py
#
# The contract between the dashboard and the restored core.
#
# Gaps this closes, found by tracing the dashboard against the current API:
#   - the dashboard read "/status" (which only ever says "online") and never
#     "/system/status", so it could not distinguish a subsystem that was
#     disabled on purpose from one that had failed
#   - decode_ws_message extracted only {type, payload}: no event_id, so one
#     logical event redelivered on reconnect or replay would render as a
#     second unrelated incident, and causal chains were invisible
#   - there was no client for the reliability / dead-letter surface at all
#
# The dashboard is a CLIENT of the runtime. It must not import core
# implementation modules or hold system truth of its own.
# =============================================================================

from __future__ import annotations

import pytest

from dashboard.services.health_client import (
    NON_FAULT_STATES,
    SUBSYSTEM_STATES,
    classify_runtime,
    summarize_subsystems,
)
from dashboard.services.reliability_client import (
    MAX_LIMIT,
    describe_failure,
    get_failed_events,
    request_replay,
    summarize_failed_events,
)
from dashboard.services.websocket_client import (
    SUPPORTED_EVENT_SCHEMA_VERSIONS,
    EventDeduplicator,
    decode_ws_message,
    extract_envelope,
)

import json


def _frame(**payload) -> str:
    return json.dumps({"type": "watchtower_event", "payload": payload})


# --------------------------------------------------------------------------- #
# the dashboard is a client, not part of the runtime
# --------------------------------------------------------------------------- #

def test_dashboard_does_not_import_core_implementation():
    """System truth lives in the API. The dashboard observes it."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*.py"):
        if "__pycache__" in str(path) or path.parent.name == "tests":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^\s*(from|import)\s+core[\s.]", text, re.M):
            offenders.append(path.name)

    assert not offenders, f"dashboard reaches into core: {offenders}"


def test_live_dashboard_advertises_only_supported_governance_modes():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    javascript = (root / "assets" / "js" / "dashboard.js").read_text(
        encoding="utf-8"
    )
    html = (root / "sentinel_43_dashboard.html").read_text(
        encoding="utf-8"
    )

    for source in (javascript, html):
        assert "AUTONOMOUS_VETO" not in source
        assert "ACTIVE_PLANNING" not in source

    assert 'SHADOW: "ADVISORY"' in javascript


# --------------------------------------------------------------------------- #
# canonical event envelope -- extracted at ONE boundary
# --------------------------------------------------------------------------- #

def test_envelope_is_extracted_from_the_frame():
    decoded = decode_ws_message(
        _frame(
            event_id="E1",
            correlation_id="C1",
            parent_event_id="P0",
            schema_version="1.0",
            source="FenrirHunter",
            source_identity="service:fenrir",
        )
    )
    envelope = decoded["envelope"]

    assert envelope["event_id"] == "E1"
    assert envelope["correlation_id"] == "C1"
    assert envelope["parent_event_id"] == "P0"
    assert envelope["source_identity"] == "service:fenrir"


def test_derived_event_is_recognisable():
    assert extract_envelope({"parent_event_id": "A"})["is_derived"] is True
    assert extract_envelope({"event_id": "A"})["is_derived"] is False


def test_unsupported_schema_version_is_flagged_not_silently_rendered():
    envelope = extract_envelope({"event_id": "E", "schema_version": "9.9"})
    assert envelope["schema_supported"] is False


def test_supported_schema_version_is_accepted():
    for version in SUPPORTED_EVENT_SCHEMA_VERSIONS:
        assert extract_envelope(
            {"schema_version": version}
        )["schema_supported"] is True


def test_payload_without_an_envelope_is_tolerated():
    """An older producer must not blind the dashboard."""
    envelope = extract_envelope({"message": "hello"})
    assert envelope["event_id"] == ""
    assert envelope["schema_supported"] is True


def test_malformed_frame_is_still_rejected_safely():
    """A bad frame must not yield a usable event."""
    for bad in ("not json", json.dumps({"type": 5, "payload": {}})):
        decoded = decode_ws_message(bad)
        assert decoded.get("type") != "watchtower_event"
        assert "envelope" not in decoded


# --------------------------------------------------------------------------- #
# duplicate display (§20)
# --------------------------------------------------------------------------- #

def test_same_event_is_not_rendered_twice():
    """A reconnect or an approved replay redelivers the same logical event."""
    dedupe = EventDeduplicator()
    envelope = extract_envelope({"event_id": "E1"})

    assert dedupe.is_duplicate(envelope) is False
    assert dedupe.is_duplicate(envelope) is True


def test_distinct_events_are_not_collapsed():
    dedupe = EventDeduplicator()
    assert dedupe.is_duplicate(extract_envelope({"event_id": "A"})) is False
    assert dedupe.is_duplicate(extract_envelope({"event_id": "B"})) is False


def test_identical_payloads_with_different_ids_both_render():
    """Dedupe is by event_id, never by payload text."""
    dedupe = EventDeduplicator()
    first = extract_envelope({"event_id": "A", "source": "Fenrir"})
    second = extract_envelope({"event_id": "B", "source": "Fenrir"})

    assert dedupe.is_duplicate(first) is False
    assert dedupe.is_duplicate(second) is False


def test_event_without_an_id_is_never_suppressed():
    """Dropping an unidentifiable event would lose a finding."""
    dedupe = EventDeduplicator()
    assert dedupe.is_duplicate(extract_envelope({})) is False
    assert dedupe.is_duplicate(extract_envelope({})) is False


def test_deduplicator_is_bounded():
    dedupe = EventDeduplicator(max_entries=10)
    for index in range(200):
        dedupe.is_duplicate({"event_id": f"E{index}"})
    assert len(dedupe) <= 10


# --------------------------------------------------------------------------- #
# subsystem lifecycle (§7, §8)
# --------------------------------------------------------------------------- #

def test_dashboard_knows_the_full_lifecycle_vocabulary():
    assert SUBSYSTEM_STATES == {
        "DISABLED", "STARTING", "ACTIVE", "DEGRADED",
        "UNAVAILABLE", "FAILED", "STOPPING", "STOPPED",
    }


@pytest.mark.parametrize(
    "state,faulted",
    [
        ("DISABLED", False),
        ("ACTIVE", False),
        ("STOPPED", False),
        ("DEGRADED", True),
        ("UNAVAILABLE", True),
        ("FAILED", True),
        ("STARTING", True),
    ],
)
def test_disabled_is_not_displayed_as_failed(state, faulted):
    summary = summarize_subsystems(
        {"subsystems": {"x": {"state": state}}}
    )
    assert summary["subsystems"]["x"]["faulted"] is faulted


def test_unknown_state_is_not_treated_as_healthy():
    summary = summarize_subsystems(
        {"subsystems": {"x": {"state": "BANANA"}}}
    )
    assert summary["subsystems"]["x"]["faulted"] is True
    assert summary["subsystems"]["x"]["known_state"] is False


def test_subsystems_are_bucketed_for_display():
    summary = summarize_subsystems(
        {
            "subsystems": {
                "fenrir": {"state": "DISABLED"},
                "sparta": {"state": "UNAVAILABLE", "reason": "missing_token"},
                "watchtower": {"state": "DEGRADED"},
                "monitoring_manager": {"state": "ACTIVE"},
            }
        }
    )
    assert summary["disabled"] == ["fenrir"]
    assert summary["failed"] == ["sparta"]
    assert summary["degraded"] == ["watchtower"]


def test_missing_subsystem_data_is_reported_not_faked():
    summary = summarize_subsystems({"data": {}})
    assert summary["available"] is False
    assert summary["subsystems"] == {}


def test_unconfigured_reason_survives_for_the_operator():
    summary = summarize_subsystems(
        {
            "subsystems": {
                "sparta": {
                    "state": "UNAVAILABLE",
                    "reason": "missing_token",
                    "missing": ["S43_SPARTA_NODE_TOKEN"],
                }
            }
        }
    )
    record = summary["subsystems"]["sparta"]
    assert record["reason"] == "missing_token"
    assert record["missing"] == ["S43_SPARTA_NODE_TOKEN"]


# --------------------------------------------------------------------------- #
# health vs readiness vs degraded (§8)
# --------------------------------------------------------------------------- #

def test_healthy_but_degraded_is_not_reported_as_fully_healthy():
    result = classify_runtime(
        {"ok": True}, {"ok": True, "data": {"degraded": ["watchtower"]}}
    )
    assert result["state"] == "DEGRADED"
    assert result["alive"] is True
    assert result["ready"] is True


def test_alive_but_not_ready_is_distinct():
    result = classify_runtime(
        {"ok": True}, {"ok": False, "data": {"blocking": ["audit_store"]}}
    )
    assert result["state"] == "NOT_READY"
    assert result["blocking"] == ["audit_store"]


def test_dead_api_is_unavailable():
    assert classify_runtime({"ok": False}, {"ok": False})["state"] == "UNAVAILABLE"


def test_fully_healthy_is_ready():
    assert classify_runtime({"ok": True}, {"ok": True})["state"] == "READY"


# --------------------------------------------------------------------------- #
# reliability / dead-letter view (§14, §15)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "status,fragment",
    [
        (401, "session"),
        (403, "not authorized"),
        (404, "No such"),
        (409, "replayable"),
        (429, "Rate limited"),
        (503, "unavailable"),
    ],
)
def test_failures_are_distinguished_not_all_server_offline(status, fragment):
    message = describe_failure({"ok": False, "status_code": status})
    assert fragment.lower() in message.lower()
    assert "offline" not in message.lower()


def test_unreachable_api_is_reported_as_unreachable():
    assert "unreachable" in describe_failure(
        {"ok": False, "status_code": None}
    ).lower()


def test_no_raw_body_or_traceback_is_surfaced():
    message = describe_failure(
        {"ok": False, "status_code": 500, "error": 'Traceback File "x.py"'}
    )
    assert "Traceback" not in message


@pytest.mark.parametrize("limit", [0, -1, MAX_LIMIT + 1, "abc"])
def test_bad_limit_is_rejected_before_reaching_the_api(limit):
    assert get_failed_events(limit=limit)["ok"] is False


def test_unknown_replay_status_is_rejected():
    assert get_failed_events(replay_status="nonsense")["ok"] is False


@pytest.mark.parametrize(
    "event_id", ["", "   ", "../../etc/passwd", "a" * 500, "bad id"]
)
def test_replay_rejects_a_malformed_event_id(event_id):
    result = request_replay(event_id)
    assert result["ok"] is False
    assert "invalid format" in result["error"]


def test_failed_event_rows_keep_identity_and_drop_unknown_fields():
    summary = summarize_failed_events(
        {
            "ok": True,
            "data": {
                "count": 1,
                "events": [
                    {
                        "event_id": "E1",
                        "correlation_id": "C1",
                        "failure_classification": "retryable",
                        "replay_status": "pending",
                        "unexpected_server_field": "should-not-render",
                    }
                ],
            },
        }
    )
    row = summary["events"][0]
    assert row["event_id"] == "E1"
    assert row["correlation_id"] == "C1"
    assert row["retryable"] is True
    assert "unexpected_server_field" not in row


def test_failed_event_view_reports_api_failure_without_crashing():
    summary = summarize_failed_events({"ok": False, "status_code": 503})
    assert summary["available"] is False
    assert summary["events"] == []
    assert summary["error"]


# --------------------------------------------------------------------------- #
# governance safety (§24)
# --------------------------------------------------------------------------- #

def test_reliability_client_exposes_no_approval_surface():
    """The dashboard transports a human decision. It does not make one.

    Asserted on the module's public API rather than its prose: there is no
    approve/enforce/schedule entry point to call at all.
    """
    import re

    import dashboard.services.reliability_client as client

    public = [name for name in dir(client) if not name.startswith("_")]
    forbidden = [
        name
        for name in public
        if re.search(
            r"(^|_)(approve|enforce|execute|remediate|schedule|autorun)(_|$)",
            name,
        )
    ]
    assert not forbidden, forbidden


def test_replay_performs_exactly_one_request():
    calls: list[str] = []

    class _Recording:
        def post(self, path, payload=None):
            calls.append(path)

            class _R:
                def to_dict(self_inner):
                    return {"ok": True, "status_code": 200, "data": {}}

            return _R()

    request_replay("E1", client=_Recording())
    assert len(calls) == 1
