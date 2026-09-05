# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_watchtower_client.py
#
# DEFECT_INVENTORY.md D-15/D-16: 12 (actually 13 — core/runtime.py was an
# uncounted 13th) near-identical `_watchtower_request` helpers existed across
# the codebase. 10-11 of them built the outgoing request with no
# `Authorization` header, so every POST to a `_require_service_token`-
# protected Watchtower route (register/heartbeat/report/analyze) returned
# 401. `urllib.request.urlopen` raises `HTTPError` on that 401, and the
# caller's surrounding `except Exception` (bare `pass` in several cases)
# swallowed it silently -- the caller believed the report was delivered.
#
# This file tests the single canonical replacement
# (core/monitoring/watchtower_client.py) that all of those now delegate to:
#   1. the internal service token is attached when configured;
#   2. no Authorization header is sent when the token is unset (matches the
#      previous unauthenticated-probe behavior for /health and /ready);
#   3. a non-2xx response is surfaced as {"error": ...} -- never raises, and
#      never silently reports success;
#   4. an unreachable host is surfaced as {"error": "watchtower_unreachable"};
#   5. a successful 2xx response is parsed and returned with status_code set;
#   6. repeated failures against the same path are rate-limited to one
#      WARNING per suppression window, not one per call.
# =============================================================================

from __future__ import annotations

import http.server
import json
import threading
from contextlib import contextmanager

import pytest

import core.monitoring.watchtower_client as wt_client


@contextmanager
def _local_server(handler_factory):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_factory)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    """Records the last request's headers and always returns 200 + JSON."""

    received_auth_header: list[str | None] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        _RecordingHandler.received_auth_header.append(self.headers.get("Authorization"))
        body = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST  # noqa: N815 -- health/ready probes are GET

    def log_message(self, *args) -> None:  # silence test output
        pass


class _UnauthorizedHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        body = json.dumps({"detail": "not authenticated"}).encode("utf-8")
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(autouse=True)
def _isolate_module_state(monkeypatch):
    # WATCHTOWER_URL is read once at import time; point it at the fixture
    # server for the duration of each test via monkeypatch on the module
    # attribute rather than the env var (the attribute is what the function
    # actually reads).
    _RecordingHandler.received_auth_header = []
    monkeypatch.delenv("S43_WATCHTOWER_SERVICE_TOKEN", raising=False)
    wt_client._last_logged.clear()
    yield
    wt_client._last_logged.clear()


def test_token_attached_when_configured(monkeypatch):
    monkeypatch.setenv("S43_WATCHTOWER_SERVICE_TOKEN", "sekret-token")
    with _local_server(_RecordingHandler) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})

    assert "error" not in result
    assert result["status_code"] == 200
    assert _RecordingHandler.received_auth_header == ["Bearer sekret-token"]


def test_no_auth_header_when_token_unset(monkeypatch):
    with _local_server(_RecordingHandler) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request("GET", "/watchtower/health")

    assert "error" not in result
    assert _RecordingHandler.received_auth_header == [None]


def test_401_surfaced_as_error_never_raises_never_looks_like_success(monkeypatch, caplog):
    with _local_server(_UnauthorizedHandler) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        with caplog.at_level("WARNING", logger="core.monitoring.watchtower_client"):
            result = wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})

    assert result["error"] == "watchtower_http_error"
    assert result["status_code"] == 401
    assert any("401" in rec.message for rec in caplog.records)


def test_unreachable_host_surfaced_as_error(monkeypatch):
    # Nothing listens on this loopback port -- ECONNREFUSED, fast and
    # deterministic (same technique as test_break_glass_pg.py's DB-down case).
    monkeypatch.setattr(wt_client, "WATCHTOWER_URL", "http://127.0.0.1:1")
    result = wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})

    assert result["error"] == "watchtower_unreachable"


def test_repeated_failures_are_rate_limited_not_flooded(monkeypatch, caplog):
    monkeypatch.setattr(wt_client, "WATCHTOWER_URL", "http://127.0.0.1:1")
    with caplog.at_level("WARNING", logger="core.monitoring.watchtower_client"):
        for _ in range(5):
            wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})

    # All 5 calls fail, but only the first logs -- the rest are inside the
    # suppression window.
    assert len(caplog.records) == 1


def test_warning_resumes_after_suppression_window_elapses(monkeypatch, caplog):
    """
    The suppression window must never permanently conceal a continuing
    outage -- it only collapses a burst within one window into one log
    line. Simulates window expiry by rewinding the recorded last-log time
    rather than sleeping _LOG_SUPPRESS_SECONDS (60s) in a test.
    """
    monkeypatch.setattr(wt_client, "WATCHTOWER_URL", "http://127.0.0.1:1")
    with caplog.at_level("WARNING", logger="core.monitoring.watchtower_client"):
        wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})
        assert len(caplog.records) == 1

        # Still within the window -- suppressed.
        wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})
        assert len(caplog.records) == 1

        # Force the window to have elapsed.
        key = ("/watchtower/analyze", "unreachable")
        wt_client._last_logged[key] -= wt_client._LOG_SUPPRESS_SECONDS + 1

        wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})
        assert len(caplog.records) == 2, "a continuing outage must resurface after the window"
