# =============================================================================
# Sentinel-43 — JWT Authentication Test Suite
#
# Covers verify_jwt_token() (core.api.routers.auth) and _get_operator()
# (core.api.main). main.py no longer keeps its own verifier — _get_operator()
# imports and calls verify_jwt_token() directly, so both are exercised here.
#
# Run with:
#   pytest tests/test_jwt_auth.py -v
#
# These tests set environment variables BEFORE importing core.api.main,
# because JWT_SECRET / JWT_ALGORITHM / SENTINEL_ENV / S43_WS_REQUIRE_AUTH are
# read as module-level constants at import time. The module is reloaded
# inside the jwt_env fixture so each test run picks up the test
# configuration. verify_jwt_token() itself reads S43_JWT_SECRET / _ISSUER /
# _AUDIENCE from the environment at call time, so it does not need a reload.
# =============================================================================

from __future__ import annotations

import asyncio
import importlib
import os
import time
from datetime import datetime, timezone

import jwt as pyjwt
import pytest
from fastapi import HTTPException
from starlette.requests import Request

import core.api.routers.auth as auth_module


def _run(coro):
    """Run an async dependency call synchronously for test assertions."""
    return asyncio.run(coro)


# =============================================================================
# Test Configuration
# =============================================================================

TEST_SECRET   = "test-secret-key-at-least-32-bytes-long-xxxx"
WRONG_SECRET  = "a-completely-different-secret-also-32-bytes!!"
TEST_ALGORITHM = "HS256"
TEST_ISSUER    = "sentinel-43-test"
TEST_AUDIENCE  = "sentinel-43-dashboard-test"

# Password used by _bearer_request()'s default X-S43-Password header. The
# jwt_env / prod_env fixtures monkeypatch reverify_password() to accept
# exactly this value, so these tests exercise JWT/claim logic without
# depending on real DB/env credential configuration.
TEST_PASSWORD = "correct-horse-battery-staple"


async def _fake_reverify_password(username: str, password: str) -> bool:
    return bool(username) and password == TEST_PASSWORD


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

    import core.api.routers.auth as auth_module
    monkeypatch.setattr(auth_module, "reverify_password", _fake_reverify_password)

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
    # These tests exercise the token+password contract in a production
    # environment, where legacy authentication is rejected unless it is
    # explicitly overridden.
    monkeypatch.setenv("S43_REJECT_LEGACY_AUTH", "false")

    import core.api.main as main_module
    importlib.reload(main_module)

    import core.api.routers.auth as auth_module
    monkeypatch.setattr(auth_module, "reverify_password", _fake_reverify_password)

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
    include_iat: bool = True,
    include_nbf: bool = True,
    extra_claims: dict | None = None,
) -> str:
    """
    Build a JWT with the given claims. Pass None for issuer / audience /
    subject / exp_offset_seconds (or include_iat / include_nbf = False) to
    omit that claim entirely (used for "missing required claim" test cases).

    verify_jwt_token() requires sub, exp, iss, aud, iat, nbf and role -- the
    canonical Sentinel-43 access-token claim set -- so a well-formed token
    carries iat and nbf by default.
    """
    now = int(time.time())
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
        claims["exp"] = now + exp_offset_seconds
    if include_iat:
        claims["iat"] = now
    if include_nbf:
        claims["nbf"] = now

    if extra_claims:
        claims.update(extra_claims)

    return pyjwt.encode(claims, secret, algorithm=algorithm)


def _bearer_request(
    token: str | None, *, password: str | None = TEST_PASSWORD
) -> Request:
    """
    Build a minimal Starlette Request with an optional Authorization header
    and an optional X-S43-Password header. password=None omits the header
    entirely (used to test the "password missing" case); it defaults to
    TEST_PASSWORD, which the fixture-patched reverify_password() accepts.
    """
    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    if password is not None:
        headers.append((b"x-s43-password", password.encode()))

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
# verify_jwt_token() — direct verification tests
#
# core.api.main no longer keeps its own JWT verifier; _get_operator() and
# dashboard_websocket() both call core.api.routers.auth.verify_jwt_token()
# directly. That function raises HTTPException itself (with the status code
# and message baked in) rather than letting raw pyjwt exceptions escape, so
# these tests assert against HTTPException instead of pyjwt exception types.
# =============================================================================

class TestVerifyJwtToken:

    def test_valid_token_returns_claims(self, jwt_env):
        token = _make_token()
        claims = auth_module.verify_jwt_token(token)

        assert claims["sub"] == "operator-1"
        assert claims["role"] == "operator"
        assert claims["iss"] == TEST_ISSUER
        assert claims["aud"] == TEST_AUDIENCE

    def test_expired_token_rejected(self, jwt_env):
        token = _make_token(exp_offset_seconds=-3600)  # expired 1 hour ago

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_wrong_issuer_rejected(self, jwt_env):
        token = _make_token(issuer="not-sentinel-43")

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401
        assert "issuer" in exc_info.value.detail.lower()

    def test_wrong_audience_rejected(self, jwt_env):
        token = _make_token(audience="some-other-app")

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401
        assert "audience" in exc_info.value.detail.lower()

    def test_missing_subject_claim_rejected(self, jwt_env):
        token = _make_token(subject=None)

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401

    def test_missing_expiration_claim_rejected(self, jwt_env):
        """
        A token with no 'exp' claim must be rejected outright — not
        treated as non-expiring. This is enforced via
        options={"require": ["sub", "exp", "iss", "aud"]}.
        """
        token = _make_token(exp_offset_seconds=None)

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401

    def test_missing_issuer_claim_rejected(self, jwt_env):
        token = _make_token(issuer=None)

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401

    def test_missing_audience_claim_rejected(self, jwt_env):
        token = _make_token(audience=None)

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401

    def test_forged_signature_rejected(self, jwt_env):
        """Token signed with a different secret must fail signature verification."""
        token = _make_token(secret=WRONG_SECRET)

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401

    def test_alg_none_rejected(self, jwt_env):
        """
        A token using alg=none must never be accepted, regardless of what
        the token header claims. verify_jwt_token() hardcodes the
        algorithm list from server config — it does not read alg from
        the token.
        """
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

        forged_token = f"{b64url(header)}.{b64url(payload)}."

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(forged_token)
        assert exc_info.value.status_code == 401

    def test_wrong_algorithm_rejected(self, jwt_env):
        """
        A token signed with HS384 must be rejected when the server only
        accepts HS256 — even though HS384 is itself a legitimate algorithm.
        """
        token = _make_token(algorithm="HS384", secret="x" * 64)

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 401

    def test_malformed_token_rejected(self, jwt_env):
        """Not a three-segment JWT at all."""
        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token("this-is-not-a-jwt")
        assert exc_info.value.status_code == 401

    def test_empty_string_rejected(self, jwt_env):
        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token("")
        assert exc_info.value.status_code == 401

    def test_missing_secret_raises_503(self, jwt_env, monkeypatch):
        """
        If S43_JWT_SECRET is empty (e.g. misconfigured deployment that
        somehow bypassed bootstrap_expectations), verify_jwt_token() must
        fail closed with a 503 rather than silently accepting tokens.

        verify_jwt_token() reads S43_JWT_SECRET from the environment at
        call time (not from a cached module constant), so the secret is
        cleared via monkeypatch.setenv rather than monkeypatch.setattr.
        """
        monkeypatch.setenv("S43_JWT_SECRET", "")
        token = _make_token()

        with pytest.raises(HTTPException) as exc_info:
            auth_module.verify_jwt_token(token)
        assert exc_info.value.status_code == 503


# =============================================================================
# _get_operator() — HTTP request-level tests
# =============================================================================

class TestGetOperatorDevEnvironment:
    """SENTINEL_ENV=test — dev-operator fallback applies."""

    def test_valid_token_returns_subject(self, jwt_env):
        token = _make_token(subject="alice")
        request = _bearer_request(token)

        assert _run(jwt_env._get_operator(request)) == "alice"

    def test_no_token_returns_dev_operator(self, jwt_env, monkeypatch):
        # The dev-operator fallback is now opt-in: it needs both the caller to
        # pass allow_local_fallback=True and S43_ALLOW_DEV_OPERATOR_FALLBACK.
        monkeypatch.setattr(jwt_env, "ALLOW_DEV_OPERATOR_FALLBACK", True)
        request = _bearer_request(None)

        assert (
            _run(jwt_env._get_operator(request, allow_local_fallback=True))
            == "dev-operator"
        )

    def test_no_token_without_fallback_opt_in_is_401(self, jwt_env):
        # Default: no token and no explicit fallback opt-in -> rejected.
        request = _bearer_request(None)
        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))
        assert exc_info.value.status_code == 401

    def test_valid_token_missing_password_returns_401(self, jwt_env):
        """A valid, correctly-scoped JWT with no X-S43-Password header must
        still be rejected — the JWT alone is no longer sufficient."""
        token = _make_token(subject="alice")
        request = _bearer_request(token, password=None)

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 401
        assert "password" in exc_info.value.detail.lower()

    def test_valid_token_wrong_password_returns_401(self, jwt_env):
        token = _make_token(subject="alice")
        request = _bearer_request(token, password="not-the-right-password")

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 401
        assert "password" in exc_info.value.detail.lower()

    def test_expired_token_returns_401(self, jwt_env):
        token = _make_token(exp_offset_seconds=-60)
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_forged_token_returns_401(self, jwt_env):
        token = _make_token(secret=WRONG_SECRET)
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 401

    def test_wrong_issuer_returns_401(self, jwt_env):
        token = _make_token(issuer="not-sentinel-43")
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 401
        assert "issuer" in exc_info.value.detail.lower()

    def test_wrong_audience_returns_401(self, jwt_env):
        token = _make_token(audience="wrong-app")
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 401
        assert "audience" in exc_info.value.detail.lower()

    def test_missing_role_claim_is_rejected(self, jwt_env):
        """
        `role` is a required JWT claim (verify_jwt_token's `require` list), so a
        token without it is not a legitimately-issued Sentinel-43 token: it is
        rejected as an invalid token (401), not merely unauthorized (403).
        """
        token = _make_token(role=None)
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 401

    def test_unapproved_role_returns_403(self, jwt_env):
        """A role outside {operator, admin} must be rejected."""
        token = _make_token(role="guest")
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 403

    def test_admin_role_accepted(self, jwt_env):
        token = _make_token(subject="root-admin", role="admin")
        request = _bearer_request(token)

        assert _run(jwt_env._get_operator(request)) == "root-admin"

    def test_malformed_bearer_token_returns_401(self, jwt_env):
        request = _bearer_request("not-a-real-jwt")

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 401

    def test_missing_jwt_secret_returns_503(self, jwt_env, monkeypatch):
        """
        If the server is misconfigured (no signing key) even though
        a token was supplied, the failure must be visibly a server
        configuration error (503) — not silently treated as 401,
        which would look like the client's fault.

        verify_jwt_token() (imported from routers.auth) reads
        S43_JWT_SECRET from the environment at call time, so the secret
        is cleared via monkeypatch.setenv rather than monkeypatch.setattr
        on the main module.
        """
        monkeypatch.setenv("S43_JWT_SECRET", "")
        token = _make_token()
        request = _bearer_request(token)

        with pytest.raises(HTTPException) as exc_info:
            _run(jwt_env._get_operator(request))

        assert exc_info.value.status_code == 503


class TestGetOperatorProductionEnvironment:
    """SENTINEL_ENV=production — no dev-operator fallback."""

    def test_no_token_returns_401_in_production(self, prod_env):
        request = _bearer_request(None)

        with pytest.raises(HTTPException) as exc_info:
            _run(prod_env._get_operator(request))

        assert exc_info.value.status_code == 401
        assert "authentication required" in exc_info.value.detail.lower()

    def test_valid_token_returns_subject_in_production(self, prod_env):
        token = _make_token(subject="prod-operator")
        request = _bearer_request(token)

        assert _run(prod_env._get_operator(request)) == "prod-operator"

    def test_empty_bearer_returns_401_in_production(self, prod_env):
        request = _bearer_request("")

        with pytest.raises(HTTPException) as exc_info:
            _run(prod_env._get_operator(request))

        assert exc_info.value.status_code == 401


# =============================================================================
# Bootstrap fail-closed gate tests
#
# core.bootstrap.validate_bootstrap_expectations() was made environment-free:
# it validates an already-loaded settings mapping (the composition root owns
# the env reads -- see core.api.main._bootstrap_settings()). These tests build
# that mapping the same way and assert on the canonical field names.
# =============================================================================

_TRUE = {"1", "true", "yes", "on"}


def _bootstrap_from_env() -> dict:
    """Mirror core.api.main._bootstrap_settings(): env -> settings mapping."""
    def _b(name: str) -> bool:
        return os.getenv(name, "").strip().lower() in _TRUE

    return {
        "env": os.getenv("SENTINEL_ENV", "production"),
        "jwt_secret": os.getenv("S43_JWT_SECRET", ""),
        "jwt_algorithm": os.getenv("S43_JWT_ALGORITHM", "HS256"),
        "jwt_issuer": os.getenv("S43_JWT_ISSUER", "sentinel-43"),
        "jwt_audience": os.getenv("S43_JWT_AUDIENCE", "sentinel-43-dashboard"),
        "auth_pepper": os.getenv("S43_AUTH_PEPPER", ""),
        "ws_require_auth": _b("S43_WS_REQUIRE_AUTH"),
        "enable_test_injection": _b("S43_ENABLE_TEST_INJECTION"),
    }


class TestBootstrapExpectations:

    def test_passes_in_test_environment_with_no_config(self, monkeypatch):
        """LOCAL_TEST_ENVIRONMENTS must remain permissive even with zero JWT config."""
        monkeypatch.setenv("SENTINEL_ENV", "test")
        for v in ("S43_JWT_SECRET", "S43_JWT_ALGORITHM", "S43_JWT_ISSUER",
                  "S43_JWT_AUDIENCE", "S43_WS_REQUIRE_AUTH", "S43_AUTH_PEPPER"):
            monkeypatch.delenv(v, raising=False)

        from core.bootstrap import validate_bootstrap_expectations
        validate_bootstrap_expectations(_bootstrap_from_env())  # must not raise

    def test_production_with_no_jwt_secret_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.delenv("S43_JWT_SECRET", raising=False)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
        monkeypatch.setenv("S43_AUTH_PEPPER", "a" * 64)

        from core.bootstrap import validate_bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            validate_bootstrap_expectations(_bootstrap_from_env())

        assert "jwt_secret" in str(exc_info.value)

    def test_production_with_short_secret_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", "too-short")
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
        monkeypatch.setenv("S43_AUTH_PEPPER", "a" * 64)

        from core.bootstrap import validate_bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            validate_bootstrap_expectations(_bootstrap_from_env())

        assert "32 bytes" in str(exc_info.value)

    def test_production_with_ws_auth_disabled_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "false")
        monkeypatch.setenv("S43_AUTH_PEPPER", "a" * 64)

        from core.bootstrap import validate_bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            validate_bootstrap_expectations(_bootstrap_from_env())

        assert "ws_require_auth" in str(exc_info.value)

    def test_production_with_test_injection_enabled_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
        monkeypatch.setenv("S43_ENABLE_TEST_INJECTION", "true")
        monkeypatch.setenv("S43_AUTH_PEPPER", "a" * 64)

        from core.bootstrap import validate_bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            validate_bootstrap_expectations(_bootstrap_from_env())

        assert "enable_test_injection" in str(exc_info.value)

    def test_production_with_unapproved_algorithm_raises(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "none")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
        monkeypatch.setenv("S43_AUTH_PEPPER", "a" * 64)

        from core.bootstrap import validate_bootstrap_expectations

        with pytest.raises(RuntimeError) as exc_info:
            validate_bootstrap_expectations(_bootstrap_from_env())

        assert "jwt_algorithm" in str(exc_info.value)

    def test_production_with_full_valid_config_passes(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
        monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
        monkeypatch.setenv("S43_JWT_ISSUER",    TEST_ISSUER)
        monkeypatch.setenv("S43_JWT_AUDIENCE",  TEST_AUDIENCE)
        monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
        monkeypatch.setenv("S43_ENABLE_TEST_INJECTION", "false")
        monkeypatch.setenv("S43_AUTH_PEPPER", "a" * 64)

        from core.bootstrap import validate_bootstrap_expectations
        validate_bootstrap_expectations(_bootstrap_from_env())  # must not raise
