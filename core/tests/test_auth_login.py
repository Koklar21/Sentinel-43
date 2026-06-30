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
# ⚠ UNVERIFIED ASSUMPTION (see login_user() below):
#   This file assumes POST /auth/login takes OAuth2 form-encoded data
#   (username/password as form fields, not JSON body). This was NOT
#   confirmed against the actual core/api/routers/auth.py source.
#   If the real endpoint expects JSON, change `data={...}` to
#   `json={...}` in login_user() — every test below will fail on a
#   422/wrong-content-type if this guess is wrong, which will look
#   like an auth bug but isn't.
# =============================================================================

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Generator

import jwt
import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Test environment setup
# ---------------------------------------------------------------------------
# Must be set BEFORE importing the FastAPI app instance — JWT_SECRET,
# JWT_ALGORITHM, JWT_ISSUER, JWT_AUDIENCE are read as module-level
# constants at import time (confirmed pattern from test_jwt_auth.py).
#
# iss/aud are REQUIRED here, not optional — the verifier treats missing
# iss/aud as a hard rejection (MissingRequiredClaimError), same as a
# missing exp. Any manually-built token in this file that omits them
# will fail for "missing claim", not for whatever the test claims to
# verify. Every token builder below sets all four required claims plus
# nbf.

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-auth-boundary-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")
os.environ.setdefault("S43_JWT_ISSUER", "sentinel-43-test")
os.environ.setdefault("S43_JWT_AUDIENCE", "sentinel-43-dashboard-test")

os.environ.setdefault("S43_TEST_USERNAME", "admin")
os.environ.setdefault("S43_TEST_PASSWORD", "ChangeMe_TestPassword_123!")

from core.api.main import app  # noqa: E402

# ---------------------------------------------------------------------------
# Globals & Configurations
# ---------------------------------------------------------------------------

LOGIN_URL = "/auth/login"
ME_URL = "/auth/me"
PROTECTED_URL = "/watchtower/status"

VALID_USERNAME = os.environ["S43_TEST_USERNAME"]
VALID_PASSWORD = os.environ["S43_TEST_PASSWORD"]
JWT_SECRET = os.environ["S43_JWT_SECRET"]
JWT_ALGORITHM = os.environ["S43_JWT_ALGORITHM"]
JWT_ISSUER = os.environ["S43_JWT_ISSUER"]
JWT_AUDIENCE = os.environ["S43_JWT_AUDIENCE"]

WRONG_SECRET = "a-completely-different-secret-also-used-in-test-jwt-auth"

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
    """
    Login helper.

    ⚠ Uses data= (OAuth2PasswordRequestForm convention). UNVERIFIED against
    actual auth.py — swap to json={...} if the real endpoint takes a JSON body.
    """
    return client.post(
        LOGIN_URL,
        data={
            "username": username,
            "password": password,
        },
    )


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _build_token(
    *,
    secret: str = JWT_SECRET,
    algorithm: str = JWT_ALGORITHM,
    issuer: str | None = JWT_ISSUER,
    audience: str | None = JWT_AUDIENCE,
    subject: str | None = VALID_USERNAME,
    scope: str | None = "operator",
    exp_offset_seconds: int = 3600,
    nbf_offset_seconds: int = -5,
) -> str:
    """
    Build a JWT with all four required claims (iss/aud/sub/exp) plus nbf,
    by default. Pass None for issuer/audience/subject to test a specific
    missing-claim case if needed later.
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
    if scope is not None:
        payload["scope"] = scope

    return jwt.encode(payload, secret, algorithm=algorithm)


def make_expired_token() -> str:
    """A token with all required claims present, but exp in the past."""
    return _build_token(exp_offset_seconds=-3600, nbf_offset_seconds=-7200)


def make_forged_token() -> str:
    """A structurally valid token signed with the wrong secret."""
    return _build_token(secret=WRONG_SECRET)


# ---------------------------------------------------------------------------
# Login Tests
# ---------------------------------------------------------------------------

def test_valid_login_returns_access_token(client: TestClient):
    response = login_user(client)

    assert response.status_code == 200, response.text

    data = response.json()
    assert "access_token" in data
    assert data["access_token"]
    assert isinstance(data["access_token"], str)
    assert data.get("token_type", "bearer").lower() == "bearer"


def test_invalid_password_returns_401(client: TestClient):
    response = login_user(client, password="wrong-password-because-humans-are-chaos")

    assert response.status_code == 401


def test_missing_username_returns_422(client: TestClient):
    response = client.post(
        LOGIN_URL,
        data={"password": VALID_PASSWORD},
    )

    assert response.status_code == 422


def test_missing_password_returns_422(client: TestClient):
    response = client.post(
        LOGIN_URL,
        data={"username": VALID_USERNAME},
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Protected HTTP Route Tests
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

    token = login_response.json()["access_token"]

    response = client.get(
        PROTECTED_URL,
        headers=bearer(token),
    )

    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# /auth/me Tests
# ---------------------------------------------------------------------------

def test_auth_me_rejects_missing_token(client: TestClient):
    response = client.get(ME_URL)

    assert response.status_code == 401


def test_auth_me_accepts_valid_token(client: TestClient):
    login_response = login_user(client)
    assert login_response.status_code == 200, login_response.text

    token = login_response.json()["access_token"]

    response = client.get(
        ME_URL,
        headers=bearer(token),
    )

    assert response.status_code == 200, response.text

    data = response.json()
    assert isinstance(data, dict)
    assert any(
        key in data
        for key in ("username", "sub", "operator", "user")
    )
