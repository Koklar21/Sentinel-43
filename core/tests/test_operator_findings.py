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
#
# core/tests/test_operator_findings.py
#
# Post-merge baseline remediation, Section C.
#
# Baseline verification proved Fenrir and SpartaCore findings correctly
# reach the embedded MonitoringManager/WatchtowerNode (a real CRITICAL
# integrity alert was scored and changed the node's own state), but there
# was no authenticated operator-facing retrieval surface -- only raw
# container logs. GET /operator/findings is a bounded VIEW into the
# canonical state WatchtowerNode already maintains
# (recent_event_snapshot()), reused via MonitoringManager.recent_events();
# this is not a second findings database or event bus.
#
# This file proves, using the same direct-handler-invocation +
# _require_operator-patching pattern as test_watchtower_bridge_auth.py:
#   1. the route calls the canonical operator guard, and only serves data
#      after it passes (anonymous/unauthorized rejected, exactly like every
#      other operator route -- no new auth scheme);
#   2. Fenrir- and Sparta-shaped entries are both visible, tagged with a
#      correct subsystem label, and their finding content (severity,
#      threat_kind, confidence, integrity_status, etc.) survives;
#   3. only allowlisted fields are returned -- a raw producer field that is
#      not on the allowlist (e.g. something service-token-shaped) never
#      reaches the response;
#   4. source/severity/subsystem/event_type/since filters and the limit
#      bound all work correctly.
# =============================================================================

from __future__ import annotations

import asyncio
import os

import pytest
from fastapi import HTTPException
from starlette.requests import Request

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-operator-findings-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.main as main_module  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _request(*, authorization: str | None = None) -> Request:
    headers = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/operator/findings",
        "headers": headers,
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


class _FakeMonitoringManager:
    def __init__(self, events: list[dict]) -> None:
        self._events = events
        self.recent_events_calls: list[int] = []

    def recent_events(self, limit: int) -> dict:
        self.recent_events_calls.append(limit)
        events = self._events[-limit:]
        return {"count": len(events), "limit": limit, "events": events}


FENRIR_FINDING = {
    "id": "evt-fenrir-1",
    "event_id": "evt-fenrir-1",
    "kind": "security",
    "event_type": "fenrir.finding",
    "source": "fenrir",
    "source_identity": "service:fenrir",
    "correlation_id": "corr-1",
    "parent_event_id": "",
    "created_at": "2026-09-12T00:00:00+00:00",
    "ingested_at": "2026-09-12T00:00:01+00:00",
    "severity": "HIGH",
    "threat_kind": "credential_stuffing",
    "source_ip": "203.0.113.9",
    "indicators": ("ioc-1", "ioc-2"),
    "confidence": 0.91,
    # Not on the allowlist -- must never survive sanitization.
    "authorization": "Bearer super-secret-service-token",
    "service_token": "sk-should-never-appear",
}

SPARTA_LOG_EVENT = {
    "id": "evt-sparta-1",
    "event_id": "evt-sparta-1",
    "kind": "log",
    "source": "SpartaCore",
    "source_identity": "service:sparta-node",
    "correlation_id": "",
    "created_at": "2026-09-12T00:05:00+00:00",
    "integrity_status": "compromised",
    "missing_required_fields": False,
}

SPARTA_ALERT_WRAPPER = {
    "id": "alert-sparta-1",
    "kind": "watchtower_alerts",
    "source_event_id": "evt-sparta-1",
    "alerts": [
        {
            "alert_id": "a-1",
            "tower_id": "SE:LOGGING_AUDIT",
            "tower_name": "Audit Chain Watchtower",
            "reason": "Integrity compromise detected",
            "severity": "CRITICAL",
        }
    ],
    "coordinator_decision": {"decision": "REQUIRE_HUMAN", "classification": "CRITICAL_ALERT"},
    "created_ts": 1789178100.0,
}


@pytest.fixture
def deny_operator(monkeypatch):
    async def _deny(request):  # noqa: ANN001, ANN202
        raise HTTPException(status_code=401, detail="Authentication required")

    monkeypatch.setattr(main_module, "_require_operator", _deny)


@pytest.fixture
def allow_operator(monkeypatch):
    async def _allow(request):  # noqa: ANN001, ANN202
        return "test-operator"

    monkeypatch.setattr(main_module, "_require_operator", _allow)


@pytest.fixture
def wired_manager(monkeypatch, allow_operator):
    manager = _FakeMonitoringManager(
        [FENRIR_FINDING, SPARTA_LOG_EVENT, SPARTA_ALERT_WRAPPER]
    )
    monkeypatch.setattr(main_module.runtime, "monitoring_manager", manager)
    return manager


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

def test_anonymous_is_rejected(deny_operator):
    with pytest.raises(HTTPException) as exc_info:
        _run(main_module.operator_findings(_request()))
    assert exc_info.value.status_code == 401


def test_unavailable_manager_is_a_clean_503_not_a_crash(allow_operator, monkeypatch):
    monkeypatch.setattr(main_module.runtime, "monitoring_manager", None)
    with pytest.raises(HTTPException) as exc_info:
        _run(main_module.operator_findings(_request()))
    assert exc_info.value.status_code == 503


def test_authorized_operator_is_served(wired_manager):
    result = _run(main_module.operator_findings(_request(authorization="Bearer x")))
    assert result["count"] == 3


# ---------------------------------------------------------------------------
# Content / sanitization
# ---------------------------------------------------------------------------

def test_fenrir_finding_is_visible_with_correct_subsystem_and_content(wired_manager):
    result = _run(main_module.operator_findings(_request()))
    fenrir_entries = [f for f in result["findings"] if f.get("event_id") == "evt-fenrir-1"]
    assert len(fenrir_entries) == 1

    entry = fenrir_entries[0]
    assert entry["subsystem"] == "fenrir"
    assert entry["severity"] == "HIGH"
    assert entry["threat_kind"] == "credential_stuffing"
    assert entry["confidence"] == 0.91
    assert entry["indicators"] == ["ioc-1", "ioc-2"] or entry["indicators"] == ("ioc-1", "ioc-2")

    # Never present, regardless of what the raw entry happened to carry.
    assert "authorization" not in entry
    assert "service_token" not in entry


def test_sparta_log_event_and_alert_are_both_visible_with_correct_subsystem(wired_manager):
    result = _run(main_module.operator_findings(_request()))
    by_id = {f.get("id"): f for f in result["findings"]}

    log_entry = by_id["evt-sparta-1"]
    assert log_entry["subsystem"] == "sparta-node"
    assert log_entry["integrity_status"] == "compromised"

    alert_entry = by_id["alert-sparta-1"]
    assert alert_entry["alerts"][0]["severity"] == "CRITICAL"
    assert alert_entry["coordinator_decision"]["classification"] == "CRITICAL_ALERT"


def test_only_allowlisted_fields_are_ever_returned(wired_manager):
    result = _run(main_module.operator_findings(_request()))
    for entry in result["findings"]:
        for key in entry:
            assert key == "subsystem" or key in main_module._FINDING_ALLOWED_FIELDS


# ---------------------------------------------------------------------------
# Filtering / bounding
# ---------------------------------------------------------------------------

def test_source_filter(wired_manager):
    result = _run(
        main_module.operator_findings(_request(), source="SpartaCore")
    )
    assert all(f.get("source") == "SpartaCore" for f in result["findings"])
    assert len(result["findings"]) == 1


def test_severity_filter(wired_manager):
    result = _run(main_module.operator_findings(_request(), severity="HIGH"))
    assert len(result["findings"]) == 1
    assert result["findings"][0]["event_id"] == "evt-fenrir-1"


def test_subsystem_filter(wired_manager):
    result = _run(main_module.operator_findings(_request(), subsystem="sparta-node"))
    assert len(result["findings"]) == 1
    assert result["findings"][0]["subsystem"] == "sparta-node"


def test_limit_is_bounded_and_forwarded(wired_manager):
    result = _run(main_module.operator_findings(_request(), limit=999999))
    assert result["limit"] == 500
    assert wired_manager.recent_events_calls == [500]


def test_since_rejects_unparseable_values(wired_manager):
    with pytest.raises(HTTPException) as exc_info:
        _run(main_module.operator_findings(_request(), since="not-a-timestamp"))
    assert exc_info.value.status_code == 422


def test_since_filters_out_older_entries(wired_manager):
    # SPARTA_LOG_EVENT is created_at 2026-09-12T00:05:00+00:00; asking for
    # everything since 2026-09-12T00:04:00+00:00 must exclude the earlier
    # Fenrir finding (00:00:00) but keep the Sparta one.
    result = _run(
        main_module.operator_findings(_request(), since="2026-09-12T00:04:00+00:00")
    )
    ids = {f.get("id") for f in result["findings"]}
    assert "evt-fenrir-1" not in ids
    assert "evt-sparta-1" in ids
