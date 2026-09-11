# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
# =============================================================================
#
# core/tests/test_watchtower_bridge_auth.py
#
# Pass 1 — direct Watchtower exposure, API-bridge side (RELEASE_FINDINGS
# F-01 / F-02).
#
# core/api/main.py's Watchtower bridge exposed the full core module registry
# on GET /watchtower/modules and an aggregated health/ready/status +
# local-registration snapshot on GET /watchtower/check, both with NO auth —
# while their siblings (api_watchtower_status) already required an operator.
# The two handlers were simply missing the `await _require_operator(request)`
# call.
#
# This file pins that call in place two ways:
#   1. an unauthenticated call raises HTTPException(401) — the guard runs;
#   2. the handler only reaches the Watchtower bridge (_watchtower_request)
#      once the guard is satisfied — proving auth is ordered first.
#
# It deliberately does NOT re-test JWT / password mechanics (test_jwt_auth.py
# owns that). _require_operator is patched to a pass/fail stub so this file
# isolates "does the route call the guard, and in the right order".
# =============================================================================

from __future__ import annotations

import asyncio
import os

import pytest
from fastapi import HTTPException
from starlette.requests import Request

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-watchtower-bridge-auth-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.main as main_module  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _request(*, authorization: str | None = None, password: str | None = None) -> Request:
    headers = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    if password is not None:
        headers.append((b"x-s43-password", password.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/watchtower/modules",
        "headers": headers,
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


BRIDGE_HANDLERS = (
    ("api_watchtower_modules", main_module.api_watchtower_modules),
    ("watchtower_check", main_module.watchtower_check),
)


@pytest.fixture
def deny_operator(monkeypatch):
    """_require_operator rejects every caller (simulates missing/invalid creds)."""
    async def _deny(request):  # noqa: ANN001, ANN202
        raise HTTPException(status_code=401, detail="Authentication required")

    monkeypatch.setattr(main_module, "_require_operator", _deny)


@pytest.fixture
def allow_operator_and_trace(monkeypatch):
    """
    _require_operator accepts, and _watchtower_request is replaced with a
    tracer so the test can assert it is only reached after auth.
    """
    calls: list[tuple] = []

    async def _allow(request):  # noqa: ANN001, ANN202
        calls.append(("auth", None, None))
        return "test-operator"

    def _traced_request(method, path, payload=None):  # noqa: ANN001, ANN202
        calls.append(("watchtower_request", method, path))
        return {"traced": True, "status_code": 200}

    async def _traced_health_check():  # main.py awaits watchtower_health_check()
        calls.append(("watchtower_health_check", None, None))
        return {"reachable": True, "response": {}}

    monkeypatch.setattr(main_module, "_require_operator", _allow)
    monkeypatch.setattr(main_module, "_watchtower_request", _traced_request)
    monkeypatch.setattr(main_module, "watchtower_health_check", _traced_health_check)
    return calls


# ---------------------------------------------------------------------------
# The guard runs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,handler", BRIDGE_HANDLERS)
def test_bridge_route_rejects_unauthenticated(deny_operator, name, handler):
    with pytest.raises(HTTPException) as exc_info:
        _run(handler(_request()))
    assert exc_info.value.status_code == 401, name


# ---------------------------------------------------------------------------
# The guard runs first
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,handler", BRIDGE_HANDLERS)
def test_bridge_route_reaches_watchtower_only_after_auth(allow_operator_and_trace, name, handler):
    result = _run(handler(_request(authorization="Bearer x", password="y")))
    calls = allow_operator_and_trace

    assert calls, f"{name}: handler made no traced calls"
    assert calls[0][0] == "auth", f"{name}: first action was {calls[0][0]}, expected auth"
    assert any(c[0] == "watchtower_request" for c in calls), (
        f"{name}: never reached the Watchtower bridge after auth"
    )
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# F-06: POST /watchtower/events is a service-token route (its only caller is
# FenrirHunter), not an operator route, and it forwards to the real
# Watchtower ingestion endpoint /watchtower/analyze.
# ---------------------------------------------------------------------------

FENRIR_TOKEN = "test-fenrir-service-token-for-events-route"


@pytest.fixture
def fenrir_events_env(monkeypatch):
    monkeypatch.setenv("S43_FENRIR_API_TOKEN", FENRIR_TOKEN)
    forwarded: list[tuple] = []

    def _traced_request(method, path, payload=None):  # noqa: ANN001, ANN202
        forwarded.append((method, path, payload))
        return {"accepted": True, "status_code": 200}

    async def _noop_broadcast(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        return None

    monkeypatch.setattr(main_module, "_watchtower_request", _traced_request)
    monkeypatch.setattr(main_module, "_broadcast_dashboard_event", _noop_broadcast)
    return forwarded


def test_events_route_rejects_anonymous(fenrir_events_env):
    with pytest.raises(HTTPException) as exc:
        _run(main_module.watchtower_ingest_event({"kind": "test"}, _request()))
    assert exc.value.status_code == 401


def test_events_route_rejects_operator_style_bearer(fenrir_events_env):
    # An operator JWT that is not the configured Fenrir token must not pass.
    with pytest.raises(HTTPException) as exc:
        _run(main_module.watchtower_ingest_event(
            {"kind": "test"}, _request(authorization="Bearer eyJhbGciOiJIUzI1NiJ9.fake.jwt")
        ))
    assert exc.value.status_code == 401


def test_events_route_fails_closed_when_token_unconfigured(monkeypatch):
    monkeypatch.delenv("S43_FENRIR_API_TOKEN", raising=False)
    with pytest.raises(HTTPException) as exc:
        _run(main_module.watchtower_ingest_event(
            {"kind": "test"}, _request(authorization=f"Bearer {FENRIR_TOKEN}")
        ))
    assert exc.value.status_code == 503


def test_events_route_accepts_fenrir_token_and_forwards_to_analyze(fenrir_events_env):
    result = _run(main_module.watchtower_ingest_event(
        {"kind": "security", "score": 91},
        _request(authorization=f"Bearer {FENRIR_TOKEN}"),
    ))
    assert result["ok"] is True
    assert fenrir_events_env, "handler never forwarded to the Watchtower"
    method, path, payload = fenrir_events_env[0]
    assert (method, path) == ("POST", "/watchtower/analyze")
    # The original producer fields must survive forwarding...
    event = payload["event"]
    assert event["kind"] == "security"
    assert event["score"] == 91
    # ...and the delivery identity must travel with it, so Watchtower and the
    # audit trail can correlate this event across the whole path.
    assert event["event_id"]
    assert event["correlation_id"]


__all__: list[str] = []
