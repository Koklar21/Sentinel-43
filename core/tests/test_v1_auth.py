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
# core/tests/test_v1_auth.py
#
# Auth boundary tests for the /v1 router (core/api/routers/routers.py).
#
# /v1 used to authenticate via its own third copy of JWT verification
# (core.api.deps.deps._verify_operator_jwt / require_operator) — separate
# from the verifier main.py's _get_operator() and dashboard_websocket() use
# (core.api.routers.auth.verify_jwt_token()). That copy also accepted a
# "scope" claim as an alternative to "role", which the canonical verifier
# does not. require_operator() now delegates to verify_jwt_token() directly,
# so this file exists to prove /v1 actually agrees with the rest of the API
# on the same bad/good token instead of asserting it in the abstract.
#
# test_jwt_auth.py already covers verify_jwt_token()'s claim-by-claim
# behavior exhaustively — this file only checks that /v1 wires it in
# correctly (auth required, valid token + password succeeds, missing
# password / bad role rejected).
#
# Environment isolation: verify_jwt_token() reads S43_JWT_SECRET/_ISSUER/
# _AUDIENCE from the environment at call time (not a cached module
# constant), so tests here set those values with monkeypatch.setenv() inside
# a per-test fixture rather than a module-level os.environ mutation read
# once at import time. monkeypatch auto-reverts after each test, so this
# file's JWT config can never leak into — or be silently overridden by —
# whatever other test module happened to import/run before or after it in
# the same pytest process. (See test_ws_auth.py's _ORIGINAL_ENV/
# teardown_module for the failure mode this avoids: a prior version of this
# file froze S43_JWT_SECRET into a module-level constant at import time,
# which broke under `pytest -q` at the repo root — passing in isolation but
# failing in the full suite — whenever a later-collected module's own
# direct os.environ[...] assignment changed the secret out from under it.)
# =============================================================================

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Generator

import jwt
import pytest
from fastapi.testclient import TestClient

ASSESS_URL = "/v1/assess"

JWT_SECRET = "test-secret-for-v1-auth-boundary-tests"
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "sentinel-43-test"
JWT_AUDIENCE = "sentinel-43-dashboard-test"
WRONG_SECRET = "a-completely-different-secret-for-v1-tests"

TEST_PASSWORD = "v1-boundary-test-password"

# core.api.main reads S43_JWT_SECRET/_ALGORITHM and S43_WS_REQUIRE_AUTH as
# module-level constants, frozen at import time (see main.py's
# _validate_security_config(), which runs during the FastAPI lifespan and
# raises RuntimeError if S43_WS_REQUIRE_AUTH=true but S43_JWT_SECRET is
# empty). The v1_auth_env fixture below uses monkeypatch, which only takes
# effect once a test runs — too late, since core.api.main gets imported
# (and its constants frozen) at module-collection time, before any fixture
# executes. Without this, whether these tests even manage to start the app
# depends on which other test module pytest happened to import first in the
# same session. setdefault (not direct assignment) so an already-configured
# ambient environment — e.g. a real .env loaded by conftest — wins instead
# of being clobbered.
os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", JWT_SECRET)
os.environ.setdefault("S43_JWT_ALGORITHM", JWT_ALGORITHM)
os.environ.setdefault("S43_JWT_ISSUER", JWT_ISSUER)
os.environ.setdefault("S43_JWT_AUDIENCE", JWT_AUDIENCE)

import core.api.routers.auth as auth_module  # noqa: E402
from core.api.main import app  # noqa: E402


async def _fake_reverify_password(username: str, password: str) -> bool:
    return bool(username) and password == TEST_PASSWORD


@pytest.fixture(autouse=True)
def v1_auth_env(monkeypatch) -> None:
    """Pin the exact JWT config this file's tokens are signed with for the
    duration of each test, regardless of what other test modules left in
    the environment before or after this one runs."""
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("S43_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", JWT_ALGORITHM)
    monkeypatch.setenv("S43_JWT_ISSUER", JWT_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE", JWT_AUDIENCE)
    monkeypatch.setattr(auth_module, "reverify_password", _fake_reverify_password)


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


def _build_token(
    *,
    secret: str = JWT_SECRET,
    algorithm: str = JWT_ALGORITHM,
    subject: str = "v1-test-operator",
    role: str | None = "operator",
    exp_offset_seconds: int = 3600,
) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 5,
        "exp": int(now.timestamp()) + exp_offset_seconds,
    }
    if role is not None:
        payload["role"] = role
    return jwt.encode(payload, secret, algorithm=algorithm)


def _bearer(token: str, password: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if password is not None:
        headers["X-S43-Password"] = password
    return headers


def test_v1_rejects_missing_token(client: TestClient):
    response = client.post(ASSESS_URL, json={})

    assert response.status_code == 401


def test_v1_rejects_forged_signature(client: TestClient):
    response = client.post(
        ASSESS_URL,
        json={},
        headers=_bearer(_build_token(secret=WRONG_SECRET), TEST_PASSWORD),
    )

    assert response.status_code == 401


def test_v1_rejects_valid_token_without_password(client: TestClient):
    """A structurally valid token is not enough on its own for /v1 either —
    same password re-verification gate as every other protected route."""
    response = client.post(
        ASSESS_URL,
        json={},
        headers=_bearer(_build_token()),
    )

    assert response.status_code == 401


def test_v1_rejects_unapproved_role(client: TestClient):
    """The consolidated verifier only recognizes 'role', not the old
    'scope' fallback — an unapproved role must still be rejected."""
    response = client.post(
        ASSESS_URL,
        json={},
        headers=_bearer(_build_token(role="guest"), TEST_PASSWORD),
    )

    assert response.status_code == 403


def test_v1_accepts_valid_token_and_password(client: TestClient):
    """A properly authenticated caller reaches the route handler itself --
    proven by getting the route's own deliberate 501 (POST /v1/assess is
    disposed as DEPRECATED, see core/api/routers/routers.py's module
    docstring and S43_BASELINE_VERIFICATION_REPORT.md Section I Defect 4),
    not an auth rejection. This file only owns the auth boundary; it does
    not assert anything about /v1/assess's own (deprecated) behavior."""
    response = client.post(
        ASSESS_URL,
        json={},
        headers=_bearer(_build_token(), TEST_PASSWORD),
    )

    assert response.status_code == 501, response.text
    assert response.json()["detail"]["error"]["code"] == "S43_V1_ASSESS_DEPRECATED"


__all__: list[str] = []
