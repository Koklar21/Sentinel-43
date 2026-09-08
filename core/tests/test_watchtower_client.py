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
import time
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


def _make_body_handler(
    *,
    status: int = 200,
    body: bytes = b"",
    declared_content_length: int | None = None,
    send_content_length: bool = True,
):
    """A handler factory that returns a fixed status/body, letting a test
    control exactly what Content-Length (if any) is declared -- including a
    declared length that lies about the actual body size, or none at all
    (simulating a chunked/undeclared-length response)."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            incoming = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(incoming)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if send_content_length:
                length = declared_content_length if declared_content_length is not None else len(body)
                self.send_header("Content-Length", str(length))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    return _Handler


def _make_slow_handler(delay_seconds: float):
    class _SlowHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            time.sleep(delay_seconds)
            body = json.dumps({"ok": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    return _SlowHandler


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
    # .invalid (RFC 2606) never resolves -- a fast, deterministic,
    # offline-safe getaddrinfo() failure. Deliberately NOT a loopback
    # connection-refused (127.0.0.1:1): on at least one supported OS in this
    # project's dev/CI matrix, connecting to an unbound low loopback port
    # does not fail fast with ECONNREFUSED -- it hangs until the socket
    # timeout, which is a *timeout*, not "unreachable". Conflating the two
    # was exactly the classification bug PR #257 fixed; this test must not
    # accidentally re-introduce that ambiguity by relying on OS-specific
    # refuse-vs-timeout behavior for an unbound port.
    monkeypatch.setattr(wt_client, "WATCHTOWER_URL", "http://s43-watchtower-does-not-exist.invalid:1")
    result = wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})

    assert result["error"] == "watchtower_unreachable"


def test_repeated_failures_are_rate_limited_not_flooded(monkeypatch, caplog):
    monkeypatch.setattr(wt_client, "WATCHTOWER_URL", "http://s43-watchtower-does-not-exist.invalid:1")
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
    monkeypatch.setattr(wt_client, "WATCHTOWER_URL", "http://s43-watchtower-does-not-exist.invalid:1")
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


# =============================================================================
# PR #257 blocker 3 additions: response/timeout bounds and error classification.
# =============================================================================

def test_timeout_classified_separately_from_unreachable(monkeypatch):
    with _local_server(_make_slow_handler(1.0)) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request(
            "POST", "/watchtower/analyze", {"event": {}}, timeout=0.05,
        )

    assert result["error"] == "watchtower_timeout"


def test_slow_response_within_timeout_still_succeeds(monkeypatch):
    with _local_server(_make_slow_handler(0.05)) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request(
            "POST", "/watchtower/analyze", {"event": {}}, timeout=5.0,
        )

    assert "error" not in result
    assert result["status_code"] == 200


def test_oversized_response_with_content_length_rejected_without_reading_body(monkeypatch):
    huge_body = b"x" * 5000
    handler = _make_body_handler(body=huge_body)
    with _local_server(handler) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request(
            "POST", "/watchtower/analyze", {"event": {}}, max_response_bytes=10,
        )

    assert result["error"] == "watchtower_response_too_large"
    assert "body" not in result


def test_oversized_response_without_content_length_rejected(monkeypatch):
    huge_body = b"y" * 5000
    handler = _make_body_handler(body=huge_body, send_content_length=False)
    with _local_server(handler) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request(
            "POST", "/watchtower/analyze", {"event": {}}, max_response_bytes=10,
        )

    assert result["error"] == "watchtower_response_too_large"


def test_oversized_http_error_body_handled_safely(monkeypatch):
    huge_body = b"z" * 5000
    handler = _make_body_handler(status=500, body=huge_body)
    with _local_server(handler) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request(
            "POST", "/watchtower/analyze", {"event": {}}, max_response_bytes=10,
        )

    assert result["error"] == "watchtower_http_error"
    assert result["status_code"] == 500
    assert "z" * 10 not in result["detail"]


def test_malformed_json_classified_separately_from_unreachable(monkeypatch):
    handler = _make_body_handler(body=b"not-json-at-all {")
    with _local_server(handler) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})

    assert result["error"] == "watchtower_malformed_response"
    assert result["status_code"] == 200


def test_non_dict_valid_json_is_not_an_error(monkeypatch):
    handler = _make_body_handler(body=b"[1, 2, 3]")
    with _local_server(handler) as base_url:
        monkeypatch.setattr(wt_client, "WATCHTOWER_URL", base_url)
        result = wt_client.watchtower_request("POST", "/watchtower/analyze", {"event": {}})

    assert "error" not in result
    assert result["body"] == [1, 2, 3]
    assert result["status_code"] == 200


def test_payload_serialization_failure_logs_warning(monkeypatch, caplog):
    with caplog.at_level("WARNING", logger="core.monitoring.watchtower_client"):
        result = wt_client.watchtower_request(
            "POST", "/watchtower/analyze", {"bad": object()},
        )

    assert result["error"] == "watchtower_payload_serialization_error"
    assert len(caplog.records) == 1


@pytest.mark.parametrize("bad_timeout", [0, -1.0, float("nan"), float("inf"), "2"])
def test_invalid_timeout_rejected_without_raising(bad_timeout):
    result = wt_client.watchtower_request(
        "POST", "/watchtower/analyze", {"event": {}}, timeout=bad_timeout,
    )
    assert result["error"] == "watchtower_invalid_timeout"


@pytest.mark.parametrize("bad_size", [0, -1, "100", 999_999_999_999])
def test_invalid_max_response_bytes_rejected_without_raising(bad_size):
    result = wt_client.watchtower_request(
        "POST", "/watchtower/analyze", {"event": {}}, max_response_bytes=bad_size,
    )
    assert result["error"] == "watchtower_invalid_max_response_bytes"


def test_token_and_payload_never_appear_in_logs(monkeypatch, caplog):
    secret_token = "sekret-do-not-log-me-9f8e7d6c"
    secret_payload_value = "payload-secret-should-not-leak-1a2b3c"
    monkeypatch.setenv("S43_WATCHTOWER_SERVICE_TOKEN", secret_token)
    monkeypatch.setattr(wt_client, "WATCHTOWER_URL", "http://s43-watchtower-does-not-exist.invalid:1")

    with caplog.at_level("WARNING", logger="core.monitoring.watchtower_client"):
        wt_client.watchtower_request(
            "POST", "/watchtower/analyze", {"note": secret_payload_value},
        )

    full_log_text = "\n".join(rec.message for rec in caplog.records)
    assert secret_token not in full_log_text
    assert secret_payload_value not in full_log_text
    assert "Bearer" not in full_log_text
