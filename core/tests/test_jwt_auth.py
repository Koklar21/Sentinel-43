# =============================================================================
# Sentinel-43 — JWT Authentication Test Suite
#
# Covers _verify_jwt_token() and _get_operator() in core/api/main.py.
#
# Run with:
#   pytest tests/test_jwt_auth.py -v
#
# These tests set environment variables BEFORE importing core.api.main,
# because JWT_SECRET / JWT_ALGORITHM / JWT_ISSUER / JWT_AUDIENCE are read
# as module-level constants at import time. The module is reloaded inside
# the jwt_env fixture so each test run picks up the test configuration.
# =============================================================================

from __future__ import annotations

import importlib
import os
import time

import jwt as pyjwt
import pytest
from fastapi import HTTPException
from starlette.requests import Request


# =============================================================================
# Test Configuration
# =============================================================================

TEST_SECRET   = "test-secret-key-at-least-32-bytes-long-xxxx"
WRONG_SECRET  = "a-completely-different-secret-also-32-bytes!!"
TEST_ALGORITHM = "HS256"
TEST_ISSUER    = "sentinel-43-test"
TEST_AUDIENCE  = "sentinel-43-dashboard-test"


@pytest.fixture
def jwt_env(monkeypatch):
    """
    Set JWT environment variables and reload core.api.main so its
    module-level JWT_SECRET / JWT_ALGORITHM / JWT_ISSUER / JWT_AUDIENCE
    constants pick up the test values.

    SENTINEL_ENV is set to "test" so bootstrap_expectations() does not
    fail closed during the reload (test is in LOCAL_TEST_ENVIRONMENTS).
    """
    monkeypatch.setenv("SENTINEL_ENV",     "test")
    monkeypatch.setenv("S43_JWT_SECRET",    TEST_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", TEST_ALGORITHM)
    monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
    monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "false")
    monkeypatch.setenv("S43_ENABLE_TEST_INJECTION", "false")

    import core.api.main as main_module
    importlib.reload(main_module)

    yield main_module

    # Reload again after the test so later test modules don't inherit
    # this module's test-configured constants.
    importlib.reload(main_module)


@pytest.fixture
def prod_env(monkeypatch):
    """
    Same as jwt_env but with SENTINEL_ENV=production, so _get_operator()
    falls into the production path (no dev-operator fallback) while
    JWT_SECRET etc. are still configured.
    """
    monkeypatch.setenv("SENTINEL_ENV",     "production")
    monkeypatch.setenv("S43_JWT_SECRET",    TEST_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", TEST_ALGORITHM)
    monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
    monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
    monkeypatch.setenv("S43_ENABLE_TEST_INJECTION", "false")

    import core.api.main as main_module
    importlib.reload(main_module)

    yield main_module

    monkeypatch.setenv("SENTINEL_ENV", "test")
    importlib.reload(main_module)


# =============================================================================
# Token Builders
# =============================================================================

def _make_token(
    *,
    secret: str = TEST_SECRET,
    algorithm: str = TEST_ALGORITHM,
    issuer: str | None = TEST_ISSUER,
    audience: str | None = TEST_AUDIENCE,
    subject: str | None = "operator-1",
    role: str | None = "operator",
    exp_offset_seconds: int | None = 3600,
    extra_claims: dict | None = None,
) -> str:
    """
    Build a JWT with the given claims. Pass None for issuer / audience /
    subject / exp_offset_seconds to omit that claim entirely (used for
    "missing required claim" test cases).
    """
    claims: dict = {}

    if issuer is not None:
        claims["iss"] = issuer
    if audience is not None:
        claims["aud"] = audience
    if subject is not None:
        claims["sub"] = subject
    if role is not None:
        claims["role"] = role
    if exp_offset_seconds is not None:
        claims["exp"] = int(time.time()) + exp_offset_seconds

    if extra_claims:
        claims.update(extra_claims)

    return pyjwt.encode(claims, secret, algorithm=algorithm)


def _bearer_request(token: str | None) -> Request:
    """Build a minimal Starlette Request with an optional Authorization header."""
    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/actions/ACT-TEST-0000000000/approve",
        "headers": headers,
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


# =============================================================================
# _verify_jwt_token() — direct verification tests
# =============================================================================

class TestVerifyJwtToken:

    def test_valid_token_returns_claims(self, jwt_env):
        token = _make_token()
        claims = jwt_env._verify_jwt_token(token)

        assert claims["sub"] == "operator-1"
        assert claims["role"] == "operator"
        assert claims["iss"] == TEST_ISSUER
        assert claims["aud"] == TEST_AUDIENCE

    def test_expired_token_rejected(self, jwt_env):
        token = _make_token(exp_offset_seconds=-3600)  # expired 1 hour ago

        with pytest.raises(pyjwt.ExpiredSignatureError):
            jwt_env._verify_jwt_token(token)

    def test_wrong_issuer_rejected(self, jwt_env):
        token = _make_token(issuer="not-sentinel-43")

        with pytest.raises(pyjwt.InvalidIssuerError):
            jwt_env._verify_jwt_token(token)

    def test_wrong_audience_rejected(self, jwt_env):
        token = _make_token(audience="some-other-app")

        with pytest.raises(pyjwt.InvalidAudienceError):
            jwt_env._verify_jwt_token(token)

    def test_missing_subject_claim_rejected(self, jwt_env):
        token = _make_token(subject=None)

        with pytest.raises(pyjwt.MissingRequiredClaimError):
            jwt_env._verify_jwt_token(token)

    def test_missing_expiration_claim_rejected(self, jwt_env):
        """
        A token with no 'exp' claim must be rejected outright — not
        treated as non-expiring. This is enforced via
        options={"require": ["exp", "iss", "aud", "sub"]}.
        """
        token = _make_token(exp_offset_seconds=None)

        with pytest.raises(pyjwt.MissingRequiredClaimError):
            jwt_env._verify_jwt_token(token)

    def test_missing_issuer_claim_rejected(self, jwt_env):
        token = _make_token(issuer=None)

        with pytest.raises(pyjwt.MissingRequiredClaimError):
            jwt_env._verify_jwt_token(token)

    def test_missing_audience_claim_rejected(self, jwt_env):
        token = _make_token(audience=None)

        with pytest.raises(pyjwt.MissingRequiredClaimError):
            jwt_env._verify_jwt_token(token)

    def test_forged_signature_rejected(self, jwt_env):
        """Token signed with a different secret must fail signature verification."""
        token = _make_token(secret=WRONG_SECRET)

        with pytest.raises(pyjwt.InvalidSignatureError):
            jwt_env._verify_jwt_token(token)

    def test_alg_none_rejected(self, jwt_env):
        """
        A token using alg=none must never be accepted, regardless of what
        the token header claims. _verify_jwt_token() hardcodes the
        algorithm list from server config — it does not read alg from
        the token.
        """
        # PyJWT refuses to encode with "none" unless options are overridden,
        # which mirrors the fact that a real attacker would need to forge
        # the header by hand. We build the token manually to simulate that.
        import base64
        import json

        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "attacker",
            "role": "admin",
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": int(time.time()) + 3600,
        }

        def b64url(data: dict) -> str:
            raw = json.dumps(data).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        # alg=none tokens have an empty signature segment.
        forged_token = f"{b64url(header)}.{b64url(payload)}."

        with pytest.raises(pyjwt.PyJWTError):
            jwt_env._verify_jwt_token(forged_token)

    def test_wrong_algorithm_rejected(self, jwt_env):
        """
        A token signed with HS384 must be rejected when the server only
        accepts HS256 — even though HS384 is itself a legitimate algorithm.
        """
        token = _make_token(algorithm="HS384")

        with pytest.raises(pyjwt.InvalidAlgorithmError):
            jwt_env._verify_jwt_token(token)

    def test_malformed_token_rejected(self, jwt_env):
        """Not a three-segment JWT at all."""
        with pytest.raises(pyjwt.DecodeError):
            jwt_env._verify_jwt_token("this-is-not-a-jwt")

    def test_empty_string_rejected(self, jwt_env):
        with pytest.raises(pyjwt.DecodeError):
            jwt_env._verify_jwt_token("")

    def test_missing_secret_raises_invalid_key_error(self, jwt_env, monkeypatch):
        """
        If S43_JWT_SECRET is empty (e.g. misconfigured deployment that
        somehow bypassed bootstrap_expectations), _verify_jwt_token()
        must raise InvalidKeyError rather than silently accepting tokens.
        """
        monkeypatch.setattr(jwt_env, "JWT_SECRET", "")
        token = _make_token()

        with pytest.raises(pyjwt.InvalidKeyError):
            jwt_env._verify_jwt_token(token)


# =============================================================================
# _get_operator() — HTTP request-level tests
# =============================================================================

class TestGetOperatorDevEnvironment:
    """SENTINEL_ENV=test — dev-operator fallback applies."""

    def test_valid_token_returns_subject(self, jwt_env):
        token = _make_token(subject="alice")
        request = _bearer_request(token)

        assert jwt_env._get_operator(request) == "alice"

    def test_no_token_returns_dev_operator(self, jwt_env):
        request = _bearer_request(None)

        assert jwt_env._get_operator(request) == "dev-operator"

    def test_expired_token_returns_401(self, jwt_env):
        token = _make_token(exp_offset_seconds=-60)
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            jwt_env._get_operator(request)

        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_forged_token_returns_401(self, jwt_env):
        token = _make_token(secret=WRONG_SECRET)
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            jwt_env._get_operator(request)

        assert exc_info.value.status_code == 401

    def test_wrong_issuer_returns_401(self, jwt_env):
        token = _make_token(issuer="not-sentinel-43")
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            jwt_env._get_operator(request)

        assert exc_info.value.status_code == 401
        assert "issuer" in exc_info.value.detail.lower()

    def test_wrong_audience_returns_401(self, jwt_env):
        token = _make_token(audience="wrong-app")
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            jwt_env._get_operator(request)

        assert exc_info.value.status_code == 401
        assert "audience" in exc_info.value.detail.lower()

    def test_missing_role_claim_returns_403(self, jwt_env):
        """
        A valid, correctly signed token with no role/scope claim must be
        rejected with 403 — authentication succeeded but authorization
        did not.
        """
        token = _make_token(role=None)
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            jwt_env._get_operator(request)

        assert exc_info.value.status_code == 403
        assert "role" in exc_info.value.detail.lower()

    def test_unapproved_role_returns_403(self, jwt_env):
        """A role outside {operator, admin} must be rejected."""
        token = _make_token(role="guest")
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            jwt_env._get_operator(request)

        assert exc_info.value.status_code == 403

    def test_admin_role_accepted(self, jwt_env):
        token = _make_token(subject="root-admin", role="admin")
        request = _bearer_request(token)

        assert jwt_env._get_operator(request) == "root-admin"

    def test_scope_claim_accepted_as_alternative_to_role(self, jwt_env):
        """_get_operator() checks role OR scope for the authorization claim."""
        token = _make_token(role=None, extra_claims={"scope": "operator"})
        request = _bearer_request(token)

        assert jwt_env._get_operator(request) == "operator-1"

    def test_malformed_bearer_token_returns_401(self, jwt_env):
        request = _bearer_request("not-a-real-jwt")

        with pytest.raises(HTTPException) as exc_info:
            jwt_env._get_operator(request)

        assert exc_info.value.status_code == 401

    def test_missing_jwt_secret_returns_503(self, jwt_env, monkeypatch):
        """
        If the server is misconfigured (no signing key) even though
        a token was supplied, the failure must be visibly a server
        configuration error (503) — not silently treated as 401,
        which would look like the client's fault.
        """
        monkeypatch.setattr(jwt_env, "JWT_SECRET", "")
        token = _make_token()
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            jwt_env._get_operator(request)

        assert exc_info.value.status_code == 503


class TestGetOperatorProductionEnvironment:
    """SENTINEL_ENV=production — no dev-operator fallback."""

    def test_no_token_returns_401_in_production(self, prod_env):
        request = _bearer_request(None)

        with pytest.raises(HTTPException) as exc_info:
            prod_env._get_operator(request)

        assert exc_info.value.status_code == 401
        assert "authentication required" in exc_info.value.detail.lower()

    def test_valid_token_returns_subject_in_production(self, prod_env):
        token = _make_token(subject="prod-operator")
        request = _bearer_request(token)

        assert prod_env._get_operator(request) == "prod-operator"

    def test_empty_bearer_returns_401_in_production(self, prod_env):
        request = _bearer_request("")

        with pytest.raises(HTTPException) as exc_info:
            prod_env._get_operator(request)

        assert exc_info.value.status_code == 401


# =============================================================================
# Bootstrap fail-closed gate tests
# =============================================================================

class TestBootstrapExpectations:

    def test_passes_in_test_environment_with_no_config(self, monkeypatch):
        """LOCAL_TEST_ENVIRONMENTS must remain permissive even with zero JWT config."""
        monkeypatch.setenv("SENTINEL_ENV", "test")
        monkeypatch.delenv("S43_JWT_SECRET",    raising=False)
        monkeypatch.delenv("S43_JWT_ALGORITHM", raising=False)
        monkeypatch.delenv("S43_JWT_ISSUER",    raising=False)
        monkeypatch.delenv("S43_JWT_AUDIENCE",  raising=False)
        monkeypatch.delenv("S43_WS_REQUIRE_AUTH", raising=False)

        from core.bootstrap import bootstrap_expectations
        bootstrap_expectations()  # must not raise

    def test_production_with_no_jwt_secret_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.delenv("S43_JWT_SECRET", raising=False)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")

        from core.bootstrap import bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            bootstrap_expectations()

        assert "S43_JWT_SECRET" in str(exc_info.value)

    def test_production_with_short_secret_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", "too-short")
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")

        from core.bootstrap import bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            bootstrap_expectations()

        assert "32 bytes" in str(exc_info.value)

    def test_production_with_ws_auth_disabled_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "false")

        from core.bootstrap import bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            bootstrap_expectations()

        assert "S43_WS_REQUIRE_AUTH" in str(exc_info.value)

    def test_production_with_test_injection_enabled_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
        monkeypatch.setenv("S43_ENABLE_TEST_INJECTION", "true")

        from core.bootstrap import bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            bootstrap_expectations()

        assert "S43_ENABLE_TEST_INJECTION" in str(exc_info.value)

    def test_production_with_unapproved_algorithm_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "none")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")

        from core.bootstrap import bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            bootstrap_expectations()

        assert "S43_JWT_ALGORITHM" in str(exc_info.value)

    def test_production_with_full_valid_config_passes(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
        monkeypatch.setenv("S43_ENABLE_TEST_INJECTION", "false")

        from core.bootstrap import bootstrap_expectations
        bootstrap_expectations()  # must not raise