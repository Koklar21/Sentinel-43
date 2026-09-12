# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_fenrir_monitoring_integration.py
#
# PR #276 final code-review remediation -- two Fenrir-to-monitoring findings:
#
#   - Both /watchtower/events and /internal/events/broadcast called
#     _notify_monitoring with only the provenance envelope, so
#     MonitoringManager saw that a Fenrir finding happened but never the
#     finding CONTENT (severity, threat_kind, source_ip, indicators,
#     confidence) that analysis/scoring actually needs.
#   - FenrirHunter.process_finding posts every finding to BOTH routes
#     concurrently with no shared event_id, so once both routes called
#     _notify_monitoring, MonitoringManager analyzed the same finding
#     twice under two different identities.
#
# Follows test_watchtower_bridge_auth.py's direct-handler-invocation
# pattern: no TestClient, no app boot. Route functions are called directly
# with a fake MonitoringManager recording what analyze_event() actually
# received.
# =============================================================================

from __future__ import annotations

import asyncio
import os

import pytest
from starlette.requests import Request

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault(
    "S43_JWT_SECRET", "test-secret-for-fenrir-monitoring-integration"
)
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.main as main_module  # noqa: E402
from core.api.main import InternalBroadcastBody  # noqa: E402

FENRIR_TOKEN = "test-fenrir-token-for-monitoring-integration"


def _run(coro):
    return asyncio.run(coro)


def _request(*, authorization: str | None = None) -> Request:
    headers = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/watchtower/events",
        "headers": headers,
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


class _RecordingMonitoringManager:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def analyze_event(self, event: dict) -> None:
        self.calls.append(dict(event))


@pytest.fixture
def fenrir_env(monkeypatch):
    monkeypatch.setenv("S43_FENRIR_API_TOKEN", FENRIR_TOKEN)

    def _traced_watchtower(method, path, payload=None):  # noqa: ANN001, ANN202
        return {"accepted": True, "status_code": 200}

    monitoring = _RecordingMonitoringManager()
    monkeypatch.setattr(main_module, "_watchtower_request", _traced_watchtower)
    monkeypatch.setattr(main_module.runtime, "monitoring_manager", monitoring)
    monkeypatch.setattr(main_module.runtime, "reliability", None)
    return monitoring


FINDING = {
    "kind": "security",
    "severity": "critical",
    "threat_kind": "port_scan",
    "source_ip": "203.0.113.7",
    "indicators": ["ioc-1", "ioc-2"],
    "confidence": 0.91,
}


# --------------------------------------------------------------------------- #
# defect: finding content lost between Fenrir and MonitoringManager
# --------------------------------------------------------------------------- #

def test_watchtower_events_route_preserves_finding_content(fenrir_env):
    monitoring = fenrir_env
    result = _run(
        main_module.watchtower_ingest_event(
            {**FINDING, "event_id": "ev-1"},
            _request(authorization=f"Bearer {FENRIR_TOKEN}"),
        )
    )
    assert result["ok"] is True
    assert len(monitoring.calls) == 1

    event = monitoring.calls[0]
    assert event["severity"] == "critical"
    assert event["threat_kind"] == "port_scan"
    assert event["source_ip"] == "203.0.113.7"
    assert event["indicators"] == ("ioc-1", "ioc-2")
    assert abs(event["confidence"] - 0.91) < 1e-9


def test_finding_content_survives_full_normalization_into_a_typed_event(fenrir_env):
    """Not just present on the raw dict passed to analyze_event -- confirms
    it actually survives normalize_event()'s allowlist onto the typed
    SecurityEvent object MonitoringManager scans."""
    from core.monitoring.event_types import normalize_event

    monitoring = fenrir_env
    _run(
        main_module.watchtower_ingest_event(
            {**FINDING, "event_id": "ev-2"},
            _request(authorization=f"Bearer {FENRIR_TOKEN}"),
        )
    )
    event = normalize_event(monitoring.calls[0]).event
    assert event.severity == "critical"
    assert event.threat_kind == "port_scan"
    assert event.source_ip == "203.0.113.7"
    assert event.indicators == ("ioc-1", "ioc-2")


def test_correlation_and_source_identity_preserved_alongside_finding_content(fenrir_env):
    monitoring = fenrir_env
    _run(
        main_module.watchtower_ingest_event(
            {**FINDING, "event_id": "ev-3", "correlation_id": "corr-abc"},
            _request(authorization=f"Bearer {FENRIR_TOKEN}"),
        )
    )
    event = monitoring.calls[0]
    assert event["correlation_id"] == "corr-abc"
    assert event["event_id"] == "ev-3"
    assert event["source_identity"]


def test_no_auth_or_service_token_forwarded_into_monitoring(fenrir_env):
    monitoring = fenrir_env
    _run(
        main_module.watchtower_ingest_event(
            {**FINDING, "event_id": "ev-4"},
            _request(authorization=f"Bearer {FENRIR_TOKEN}"),
        )
    )
    blob = str(monitoring.calls[0])
    assert FENRIR_TOKEN not in blob
    assert "authorization" not in blob.lower()


def test_malformed_finding_fields_do_not_bypass_validation(fenrir_env):
    """Wrong-typed producer fields are dropped, not passed through raw."""
    monitoring = fenrir_env
    _run(
        main_module.watchtower_ingest_event(
            {
                "event_id": "ev-5",
                "kind": "security",
                "severity": {"nested": "not-a-string"},
                "indicators": "not-a-list",
                "confidence": "not-a-number",
            },
            _request(authorization=f"Bearer {FENRIR_TOKEN}"),
        )
    )
    event = monitoring.calls[0]
    assert "severity" not in event
    assert "indicators" not in event
    assert "confidence" not in event


# --------------------------------------------------------------------------- #
# defect: a Fenrir finding sent through both routes must be analyzed once
# --------------------------------------------------------------------------- #

def test_internal_broadcast_route_does_not_call_monitoring(fenrir_env):
    """The distribution-only route must never independently analyze."""
    monitoring = fenrir_env
    result = _run(
        main_module.internal_broadcast_event(
            InternalBroadcastBody(event_type="fenrir.finding", data=dict(FINDING)),
            _request(authorization=f"Bearer {FENRIR_TOKEN}"),
        )
    )
    assert result["ok"] is True
    assert monitoring.calls == []


def test_one_fenrir_finding_sent_through_both_routes_is_analyzed_exactly_once(fenrir_env):
    """Reproduces FenrirHunter.process_finding's real behavior: the same
    finding, with no shared event_id, posted to both routes concurrently."""
    monitoring = fenrir_env

    async def _post_to_both():
        return await asyncio.gather(
            main_module.watchtower_ingest_event(
                dict(FINDING), _request(authorization=f"Bearer {FENRIR_TOKEN}")
            ),
            main_module.internal_broadcast_event(
                InternalBroadcastBody(
                    event_type="fenrir.finding", data=dict(FINDING)
                ),
                _request(authorization=f"Bearer {FENRIR_TOKEN}"),
            ),
        )

    watchtower_result, broadcast_result = _run(_post_to_both())

    assert watchtower_result["ok"] is True
    assert broadcast_result["ok"] is True
    assert len(monitoring.calls) == 1, (
        "one logical Fenrir finding must cause exactly one monitoring "
        f"analysis; got {len(monitoring.calls)}"
    )
    # The one analysis that did happen still carries the finding content.
    assert monitoring.calls[0]["severity"] == "critical"


__all__: list[str] = []
