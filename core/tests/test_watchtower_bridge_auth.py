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

    monkeypatch.setattr(main_module, "_require_operator", _allow)
    monkeypatch.setattr(main_module, "_watchtower_request", _traced_request)
    monkeypatch.setattr(main_module, "watchtower_health_check", lambda: {"reachable": True, "response": {}})
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


__all__: list[str] = []
