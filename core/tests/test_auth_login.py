# =============================================================================
# Sentinel-43 — Auth Login Boundary Tests
#
# Purpose:
#   Verify the minimum authentication boundary before closed beta:
#   - valid credentials produce a JWT
#   - invalid credentials are rejected
#   - protected routes reject missing/bad/expired/forged tokens
#   - protected routes accept valid tokens
#
# Keep this boring. Boring auth tests are useful auth tests.
#
# Verified against core/api/routers/auth.py (2026 source):
#   - POST /auth/login takes a JSON body (LoginRequest is a bare Pydantic
#     model param, not Form(...)) — NOT form-encoded.
#   - LoginResponse fields are: token, token_type, subject, expires_at
#     (NOT access_token).
#   - There is no /auth/me. The verify endpoint is GET /auth/verify,
#     returning VerifyResponse: {valid, subject, role, expires_at}.
#   - Credentials are read from S43_OPERATOR_USERNAME and
#     S43_OPERATOR_PASSWORD_HASH (an Argon2id hash — see
#     core.auth.users.hash_password()). The login endpoint verifies the
#     typed password against that hash itself — send the plaintext
#     password, not the hash, in the login request.
#
# Consolidated verifier:
#   main.py no longer keeps its own JWT verifier. _get_operator() and
#   dashboard_websocket() both import and call auth.py's verify_jwt_token()
#   directly, so /watchtower/status, /auth/verify, and the WebSocket auth
#   frame all agree on status codes for the same bad token.
# =============================================================================

from __future__ import annotations

import importlib
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Generator

import jwt
import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Test environment setup
# ---------------------------------------------------------------------------
# Must be set BEFORE importing the FastAPI app instance — main.py's JWT_*
# constants are read as module-level constants at import time (confirmed
# pattern from test_jwt_auth.py). auth.py reads its own env vars at call
# time, so it doesn't have this constraint, but we set everything up front
# for consistency and so both verifiers see the same config.

from core.auth.users import hash_password  # noqa: E402

TEST_USERNAME = "admin"
TEST_PASSWORD = "ChangeMe_TestPassword_123!"
TEST_PASSWORD_HASH = hash_password(TEST_PASSWORD)

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-auth-boundary-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")
os.environ.setdefault("S43_JWT_ISSUER", "sentinel-43-test")
os.environ.setdefault("S43_JWT_AUDIENCE", "sentinel-43-dashboard-test")

# These are the actual env vars _validate_credentials() reads. The previous
# version of this file set S43_TEST_USERNAME / S43_TEST_PASSWORD, which
# auth.py never looks at — login would 503 ("credentials not configured"),
# not 401, masking the real test.
os.environ.setdefault("S43_OPERATOR_USERNAME", TEST_USERNAME)
os.environ.setdefault("S43_OPERATOR_PASSWORD_HASH", TEST_PASSWORD_HASH)

from core.api.main import app  # noqa: E402

# ---------------------------------------------------------------------------
# Globals & Configurations
# ---------------------------------------------------------------------------

LOGIN_URL = "/auth/login"
VERIFY_URL = "/auth/verify"
PROTECTED_URL = "/watchtower/status"

VALID_USERNAME = TEST_USERNAME
VALID_PASSWORD = TEST_PASSWORD  # plaintext — auth.py hashes it itself
JWT_SECRET = os.environ["S43_JWT_SECRET"]
JWT_ALGORITHM = os.environ["S43_JWT_ALGORITHM"]
JWT_ISSUER = os.environ["S43_JWT_ISSUER"]
JWT_AUDIENCE = os.environ["S43_JWT_AUDIENCE"]

WRONG_SECRET = "a-completely-different-secret-also-used-in-test-jwt-auth"

# ---------------------------------------------------------------------------
# setup_module -- re-applies this module's environment immediately before its
# first test. The setdefault() calls above run once, at collection time. If
# another module that mutates and later restores the same variables (e.g.
# test_ws_auth.py, whose teardown_module pops any variable that was unset when
# IT was imported and then reloads core.api.main) is collected first and runs
# first, that teardown removes the JWT/env values this module depends on, and
# the app's startup validation then fails before any assertion runs. Restoring
# the same values this module already captured, and reloading main so its
# module-level constants pick them up, makes this module independent of
# collection/execution order without changing any assertion or production code.
# ---------------------------------------------------------------------------

def setup_module(module: Any) -> None:
    os.environ["SENTINEL_ENV"] = "test"
    os.environ.setdefault("S43_ENV", "test")
    os.environ["S43_JWT_SECRET"] = JWT_SECRET
    os.environ["S43_JWT_ALGORITHM"] = JWT_ALGORITHM
    os.environ["S43_JWT_ISSUER"] = JWT_ISSUER
    os.environ["S43_JWT_AUDIENCE"] = JWT_AUDIENCE
    os.environ["S43_OPERATOR_USERNAME"] = TEST_USERNAME
    os.environ["S43_OPERATOR_PASSWORD_HASH"] = TEST_PASSWORD_HASH
    importlib.reload(sys.modules["core.api.main"])


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client() -> Generator[TestClient, None, None]:
    """Provides an isolated TestClient instance across the module lifecycle."""
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def login_user(
    client: TestClient,
    username: str = VALID_USERNAME,
    password: str = VALID_PASSWORD,
) -> Any:
    """LoginRequest is a bare Pydantic model — FastAPI expects a JSON body."""
    return client.post(
        LOGIN_URL,
        json={
            "username": username,
            "password": password,
        },
    )


def bearer(token: str, password: str | None = None) -> dict[str, str]:
    """
    Build request headers for a protected route. Every protected route now
    also requires X-S43-Password alongside the JWT — pass password to
    include it (typically VALID_PASSWORD for the "should succeed" case).
    """
    headers = {"Authorization": f"Bearer {token}"}
    if password is not None:
        headers["X-S43-Password"] = password
    return headers


def _build_token(
    *,
    secret: str = JWT_SECRET,
    algorithm: str = JWT_ALGORITHM,
    issuer: str | None = JWT_ISSUER,
    audience: str | None = JWT_AUDIENCE,
    subject: str | None = VALID_USERNAME,
    role: str | None = "operator",
    exp_offset_seconds: int = 3600,
    nbf_offset_seconds: int = -5,
) -> str:
    """
    Build a JWT with sub/exp/iss/aud/iat/nbf/role — the full set required
    by auth.py's verify_jwt_token(), which is the strictest of the two
    parallel verifiers. Satisfying this also satisfies main.py's looser
    requirements.
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + exp_offset_seconds,
        "nbf": int(now.timestamp()) + nbf_offset_seconds,
    }
    if issuer is not None:
        payload["iss"] = issuer
    if audience is not None:
        payload["aud"] = audience
    if subject is not None:
        payload["sub"] = subject
    if role is not None:
        payload["role"] = role

    return jwt.encode(payload, secret, algorithm=algorithm)


def make_expired_token() -> str:
    """All required claims present, but exp in the past."""
    return _build_token(exp_offset_seconds=-3600, nbf_offset_seconds=-7200)


def make_forged_token() -> str:
    """Structurally valid token signed with the wrong secret."""
    return _build_token(secret=WRONG_SECRET)


# ---------------------------------------------------------------------------
# Login Tests
# ---------------------------------------------------------------------------

def test_valid_login_returns_token(client: TestClient):
    response = login_user(client)

    assert response.status_code == 200, response.text

    data = response.json()
    assert "token" in data
    assert data["token"]
    assert isinstance(data["token"], str)
    assert data.get("token_type", "bearer").lower() == "bearer"
    assert data["subject"] == VALID_USERNAME
    assert data["expires_at"]


def test_invalid_password_returns_401(client: TestClient):
    response = login_user(client, password="wrong-password-because-humans-are-chaos")

    assert response.status_code == 401


def test_invalid_username_returns_401(client: TestClient):
    """
    Username mismatch must fail the same way as a password mismatch —
    both comparisons run unconditionally in _validate_credentials() before
    any error is raised, specifically to prevent timing-based enumeration
    of which field was wrong.
    """
    response = login_user(client, username="not-the-real-operator")

    assert response.status_code == 401


def test_missing_username_returns_422(client: TestClient):
    response = client.post(
        LOGIN_URL,
        json={"password": VALID_PASSWORD},
    )

    assert response.status_code == 422


def test_missing_password_returns_422(client: TestClient):
    response = client.post(
        LOGIN_URL,
        json={"username": VALID_USERNAME},
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Protected HTTP Route Tests (main.py's verifier, via /watchtower/status)
# ---------------------------------------------------------------------------

def test_protected_route_rejects_missing_token(client: TestClient):
    response = client.get(PROTECTED_URL)

    assert response.status_code == 401


def test_protected_route_rejects_malformed_token(client: TestClient):
    """Not a parseable JWT at all (DecodeError path)."""
    response = client.get(
        PROTECTED_URL,
        headers=bearer("this-is-not-a-real-jwt"),
    )

    assert response.status_code == 401


def test_protected_route_rejects_forged_signature(client: TestClient):
    """
    Structurally valid JWT — correct claims, correct shape — but signed
    with a key the server doesn't recognize (InvalidSignatureError path).
    Distinct failure mode from malformed garbage; both must land on 401.
    """
    response = client.get(
        PROTECTED_URL,
        headers=bearer(make_forged_token()),
    )

    assert response.status_code == 401


def test_protected_route_rejects_expired_token(client: TestClient):
    response = client.get(
        PROTECTED_URL,
        headers=bearer(make_expired_token()),
    )

    assert response.status_code == 401


def test_protected_route_accepts_valid_token(client: TestClient):
    login_response = login_user(client)
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["token"]

    response = client.get(
        PROTECTED_URL,
        headers=bearer(token, VALID_PASSWORD),
    )

    assert response.status_code == 200, response.text


def test_protected_route_rejects_valid_token_without_password(client: TestClient):
    """A valid JWT with no X-S43-Password header must still be rejected."""
    login_response = login_user(client)
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["token"]

    response = client.get(
        PROTECTED_URL,
        headers=bearer(token),
    )

    assert response.status_code == 401


def test_protected_route_rejects_valid_token_wrong_password(client: TestClient):
    login_response = login_user(client)
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["token"]

    response = client.get(
        PROTECTED_URL,
        headers=bearer(token, "definitely-not-the-password"),
    )

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# /auth/verify Tests (auth.py's own verifier — note the stricter claim
# requirements and 401-for-bad-role behavior described in the module
# docstring above)
# ---------------------------------------------------------------------------

def test_auth_verify_rejects_missing_token(client: TestClient):
    response = client.get(VERIFY_URL)

    assert response.status_code == 401


def test_auth_verify_rejects_malformed_authorization_header(client: TestClient):
    """No 'Bearer ' prefix — hits the malformed-header branch, not the JWT decode path."""
    response = client.get(
        VERIFY_URL,
        headers={"Authorization": "not-a-bearer-header"},
    )

    assert response.status_code == 401


def test_auth_verify_rejects_expired_token(client: TestClient):
    response = client.get(
        VERIFY_URL,
        headers=bearer(make_expired_token()),
    )

    assert response.status_code == 401


def test_auth_verify_accepts_valid_token(client: TestClient):
    login_response = login_user(client)
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["token"]

    response = client.get(
        VERIFY_URL,
        headers=bearer(token),
    )

    assert response.status_code == 200, response.text

    data = response.json()
    assert data["valid"] is True
    assert data["subject"] == VALID_USERNAME
    assert data["role"] == "operator"
    assert data["expires_at"]
