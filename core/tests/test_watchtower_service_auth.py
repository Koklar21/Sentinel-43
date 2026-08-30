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
# core/tests/test_watchtower_service_auth.py
#
# Pass 1 — direct Watchtower exposure.
#
# The Watchtower core (core/monitoring/watchtower.py, served on :9100) used to
# expose its entire operational surface anonymously: GET /status, /modules,
# /dependencies, /events/recent plus POST /analyze, /modules/register,
# /modules/heartbeat, /dependencies/report — anyone who could reach the port
# could read the whole monitoring state and forge module registrations,
# heartbeats, dependency reports and analysis events into it (RELEASE_FINDINGS
# F-04). Only POST /state/{name} had an auth check.
#
# This file proves the fix: every route except the two probe targets
# (/watchtower/health, /watchtower/ready) now requires the internal-service
# bearer token in S43_WATCHTOWER_SERVICE_TOKEN, the check runs before request
# body validation, an unconfigured token fails closed with 503, and the token
# value never leaks into a response body.
#
# _require_service_token reads S43_WATCHTOWER_SERVICE_TOKEN via os.getenv at
# call time (not a module constant), so monkeypatch.setenv inside a fixture is
# enough — no module reload needed. The Watchtower node/app is a lazy
# process-wide singleton; these tests only read state (or register throwaway
# modules that age out), so sharing it across tests is safe.
# =============================================================================

from __future__ import annotations

from typing import Generator

import pytest
from fastapi.testclient import TestClient

SERVICE_TOKEN = "test-watchtower-service-token-0123456789abcdef"
WRONG_TOKEN = "not-the-configured-watchtower-service-token-xxxx"

# Routes that must be reachable without any credential (probe targets).
OPEN_ROUTES = (
    ("GET", "/watchtower/health"),
    ("GET", "/watchtower/ready"),
)

# (method, path, body) for every route that must now require the service
# token. body is what to send once auth passes — chosen so the request is
# either valid (GET / AnalyzeRequest defaults) or schema-invalid (the
# register/heartbeat/report models have required fields), which lets the
# "auth runs before body validation" assertions below tell 401 from 422.
GUARDED_ROUTES = (
    ("GET", "/watchtower/status", None),
    ("GET", "/watchtower/modules", None),
    ("GET", "/watchtower/dependencies", None),
    ("GET", "/watchtower/events/recent", None),
    ("POST", "/watchtower/analyze", {"event": {"kind": "test"}}),
    ("POST", "/watchtower/modules/register", {}),
    ("POST", "/watchtower/modules/heartbeat", {}),
    ("POST", "/watchtower/dependencies/report", {}),
    ("POST", "/watchtower/state/DEGRADED", None),
)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def wt_client(monkeypatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("S43_WATCHTOWER_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("S43_ENV", "test")

    import core.monitoring.watchtower as wt

    with TestClient(wt.app) as client:
        yield client


@pytest.fixture
def wt_client_no_token(monkeypatch) -> Generator[TestClient, None, None]:
    monkeypatch.delenv("S43_WATCHTOWER_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("S43_ENV", "test")

    import core.monitoring.watchtower as wt

    with TestClient(wt.app) as client:
        yield client


# ---------------------------------------------------------------------------
# Probe targets stay open
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,path", OPEN_ROUTES)
def test_probe_routes_need_no_credential(wt_client: TestClient, method: str, path: str):
    response = wt_client.request(method, path)
    # 200 (ACTIVE / ready) or 503 (not converged) — either means the handler
    # ran. What must NOT happen is 401/503-auth-not-configured.
    assert response.status_code in (200, 503)
    assert "service token" not in response.text.lower()


def test_probe_routes_open_even_when_service_token_unconfigured(wt_client_no_token: TestClient):
    for method, path in OPEN_ROUTES:
        response = wt_client_no_token.request(method, path)
        assert response.status_code in (200, 503)


# ---------------------------------------------------------------------------
# Guarded routes reject anonymous callers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,path,body", GUARDED_ROUTES)
def test_guarded_route_rejects_anonymous(wt_client: TestClient, method: str, path: str, body):
    response = wt_client.request(method, path, json=body)
    assert response.status_code == 401, (method, path, response.text)


@pytest.mark.parametrize("method,path,body", GUARDED_ROUTES)
def test_guarded_route_rejects_wrong_token(wt_client: TestClient, method: str, path: str, body):
    response = wt_client.request(method, path, json=body, headers=_bearer(WRONG_TOKEN))
    assert response.status_code == 401, (method, path, response.text)


@pytest.mark.parametrize("method,path,body", GUARDED_ROUTES)
def test_guarded_route_rejects_non_bearer_scheme(wt_client: TestClient, method: str, path: str, body):
    response = wt_client.request(
        method, path, json=body, headers={"Authorization": SERVICE_TOKEN}
    )
    assert response.status_code == 401, (method, path, response.text)


# ---------------------------------------------------------------------------
# Auth runs before request-body validation
# ---------------------------------------------------------------------------

def test_anonymous_mutation_is_401_not_422(wt_client: TestClient):
    """
    POST /watchtower/modules/register with an empty body is schema-invalid
    (module_id is required). An anonymous caller must be turned away at auth
    (401) before the body is ever validated — never leaked a 422 that
    confirms the route is processing anonymous input.
    """
    response = wt_client.post("/watchtower/modules/register", json={})
    assert response.status_code == 401

    # With the token, the same empty body now reaches validation.
    ok = wt_client.post(
        "/watchtower/modules/register", json={}, headers=_bearer(SERVICE_TOKEN)
    )
    assert ok.status_code == 422


# ---------------------------------------------------------------------------
# Guarded routes accept the configured service token
# ---------------------------------------------------------------------------

def test_status_accepts_service_token(wt_client: TestClient):
    response = wt_client.get("/watchtower/status", headers=_bearer(SERVICE_TOKEN))
    assert response.status_code == 200
    body = response.json()
    assert body["node_id"]
    assert "modules" in body


def test_read_routes_accept_service_token(wt_client: TestClient):
    for path in ("/watchtower/modules", "/watchtower/dependencies", "/watchtower/events/recent"):
        response = wt_client.get(path, headers=_bearer(SERVICE_TOKEN))
        assert response.status_code == 200, (path, response.text)


def test_analyze_accepts_service_token(wt_client: TestClient):
    response = wt_client.post(
        "/watchtower/analyze",
        json={"event": {"kind": "security", "source": "test-suite"}},
        headers=_bearer(SERVICE_TOKEN),
    )
    assert response.status_code == 200
    assert "accepted" in response.json()


def test_module_register_roundtrip_with_token(wt_client: TestClient):
    response = wt_client.post(
        "/watchtower/modules/register",
        json={"module_id": "pass1-auth-test-module", "module_type": "test"},
        headers=_bearer(SERVICE_TOKEN),
    )
    assert response.status_code == 200
    assert response.json()["status"] == "registered"


# ---------------------------------------------------------------------------
# Fail closed when the token is not configured
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method,path,body", GUARDED_ROUTES)
def test_unconfigured_token_fails_closed_503(
    wt_client_no_token: TestClient, method: str, path: str, body
):
    # No token on the server: every guarded route must 503 (server
    # misconfigured), never fall open to anonymous access.
    anon = wt_client_no_token.request(method, path, json=body)
    assert anon.status_code == 503, (method, path, anon.text)

    # Presenting a token the server can't compare against is still 503, not
    # a misleading 401 that looks like a client credential mistake.
    with_token = wt_client_no_token.request(
        method, path, json=body, headers=_bearer(SERVICE_TOKEN)
    )
    assert with_token.status_code == 503, (method, path, with_token.text)


# ---------------------------------------------------------------------------
# The token never leaks
# ---------------------------------------------------------------------------

def test_token_absent_from_rejection_bodies(wt_client: TestClient):
    for token in ("", WRONG_TOKEN, SERVICE_TOKEN[:-1]):
        headers = _bearer(token) if token else {}
        response = wt_client.get("/watchtower/status", headers=headers)
        assert response.status_code == 401
        assert SERVICE_TOKEN not in response.text
        assert token not in response.text or token == ""


def test_non_ascii_token_is_rejected_not_500(monkeypatch):
    """
    Starlette decodes inbound header bytes as latin-1, so a raw 0x80-0xFF
    byte in the Authorization header reaches the dependency as a str with a
    non-ASCII codepoint. secrets.compare_digest raises TypeError on such a
    str — the dependency must still return a clean 401, never a 500. (httpx
    refuses to send non-ASCII header values, so this is asserted against the
    dependency directly rather than over TestClient.)
    """
    import core.monitoring.watchtower as wt

    monkeypatch.setenv("S43_WATCHTOWER_SERVICE_TOKEN", SERVICE_TOKEN)

    with pytest.raises(Exception) as exc_info:
        wt._require_service_token(authorization="Bearer \xff\xfe not-ascii")

    # HTTPException with a 401, not an unhandled TypeError.
    assert getattr(exc_info.value, "status_code", None) == 401


def test_token_absent_from_503_body(wt_client_no_token: TestClient):
    response = wt_client_no_token.get(
        "/watchtower/status", headers=_bearer(SERVICE_TOKEN)
    )
    assert response.status_code == 503
    assert SERVICE_TOKEN not in response.text


__all__: list[str] = []
