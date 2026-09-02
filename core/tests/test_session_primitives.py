# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is distributed under a dual-license model:
#   1. GNU Affero General Public License (AGPL v3.0)
#   2. Commercial License
# =============================================================================
#
# core/tests/test_session_primitives.py
#
# Pass 5A — authentication foundation. In-process (no database): the refresh
# credential primitives, the CSRF double-submit primitives, the new-style
# access-token claim helpers, and the backward-compatibility guarantees of
# _issue_token() / verify_jwt_token().
#
# The DB-backed session service logic (rotation / reuse / revocation / logout
# under real concurrency) is in test_session_layer_pg.py, which runs only
# against a disposable PostgreSQL.
# =============================================================================

from __future__ import annotations

import time

import jwt as pyjwt
import pytest
from fastapi import HTTPException

import core.api.routers.auth as auth_module
from core.auth import sessions as S

TEST_SECRET = "test-secret-key-at-least-32-bytes-long-xxxx"
TEST_ISSUER = "sentinel-43"
TEST_AUDIENCE = "sentinel-43-dashboard"


@pytest.fixture
def jwt_env(monkeypatch):
    monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("S43_JWT_ISSUER", TEST_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE", TEST_AUDIENCE)
    yield


# ---------------------------------------------------------------------------
# Refresh-credential primitives
# ---------------------------------------------------------------------------

class TestRefreshSecret:

    def test_generated_secret_has_256_bits_entropy(self):
        assert S.REFRESH_SECRET_ENTROPY_BITS == 256
        secret = S.generate_refresh_secret()
        # token_urlsafe(32) -> 32 random bytes, base64url ~43 chars, no padding
        assert isinstance(secret, str)
        assert 42 <= len(secret) <= 44
        assert "=" not in secret

    def test_generated_secrets_are_unique(self):
        seen = {S.generate_refresh_secret() for _ in range(1000)}
        assert len(seen) == 1000

    def test_hash_is_stable_and_hex_sha256(self):
        secret = S.generate_refresh_secret()
        h1 = S.hash_refresh_secret(secret)
        h2 = S.hash_refresh_secret(secret)
        assert h1 == h2
        assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1)

    def test_hash_does_not_contain_the_secret(self):
        secret = S.generate_refresh_secret()
        assert secret not in S.hash_refresh_secret(secret)

    def test_verify_matches_only_the_right_secret(self):
        secret = S.generate_refresh_secret()
        other = S.generate_refresh_secret()
        stored = S.hash_refresh_secret(secret)
        assert S.verify_refresh_hash(secret, stored) is True
        assert S.verify_refresh_hash(other, stored) is False

    def test_verify_fails_closed_on_bad_input(self):
        stored = S.hash_refresh_secret(S.generate_refresh_secret())
        assert S.verify_refresh_hash("", stored) is False
        assert S.verify_refresh_hash(None, stored) is False  # type: ignore[arg-type]
        assert S.verify_refresh_hash("x", "") is False
        assert S.verify_refresh_hash("x", None) is False  # type: ignore[arg-type]

    def test_hash_rejects_empty_secret(self):
        with pytest.raises(ValueError):
            S.hash_refresh_secret("")
        with pytest.raises(ValueError):
            S.hash_refresh_secret(None)  # type: ignore[arg-type]

    def test_optional_pepper_changes_the_digest(self, monkeypatch):
        secret = S.generate_refresh_secret()
        plain = S.hash_refresh_secret(secret)
        monkeypatch.setenv("S43_SESSION_HASH_PEPPER", "a-server-side-pepper-value")
        peppered = S.hash_refresh_secret(secret)
        assert peppered != plain
        # still self-consistent under the pepper
        assert S.verify_refresh_hash(secret, peppered) is True

    def test_refresh_ttl_env_clamped(self, monkeypatch):
        monkeypatch.delenv("S43_SESSION_REFRESH_TTL_SECONDS", raising=False)
        assert S.refresh_ttl_seconds() == 7 * 24 * 3600
        monkeypatch.setenv("S43_SESSION_REFRESH_TTL_SECONDS", "1")
        assert S.refresh_ttl_seconds() == 300           # floor
        monkeypatch.setenv("S43_SESSION_REFRESH_TTL_SECONDS", "99999999")
        assert S.refresh_ttl_seconds() == 30 * 24 * 3600  # ceiling
        monkeypatch.setenv("S43_SESSION_REFRESH_TTL_SECONDS", "not-an-int")
        assert S.refresh_ttl_seconds() == 7 * 24 * 3600   # fallback


# ---------------------------------------------------------------------------
# CSRF primitives
# ---------------------------------------------------------------------------

class TestCsrf:

    def test_token_generation_unique_and_urlsafe(self):
        seen = {S.generate_csrf_token() for _ in range(500)}
        assert len(seen) == 500
        for tok in list(seen)[:5]:
            assert "=" not in tok and len(tok) >= 40

    def test_match_requires_both_halves_equal(self):
        tok = S.generate_csrf_token()
        assert S.csrf_tokens_match(tok, tok) is True
        assert S.csrf_tokens_match(tok, tok + "x") is False

    def test_match_fails_closed_when_a_half_is_missing(self):
        tok = S.generate_csrf_token()
        assert S.csrf_tokens_match(None, tok) is False
        assert S.csrf_tokens_match(tok, None) is False
        assert S.csrf_tokens_match("", "") is False
        assert S.csrf_tokens_match(None, None) is False


# ---------------------------------------------------------------------------
# Access-token claim helpers
# ---------------------------------------------------------------------------

class TestClaimHelpers:

    def test_new_sid_is_canonical_uuid(self):
        sid = S.new_sid()
        assert S.SESSION_ID_RE.match(sid)

    def test_new_jti_unique(self):
        assert len({S.new_jti() for _ in range(500)}) == 500

    def test_claims_are_session_bound(self):
        assert S.claims_are_session_bound({"sid": S.new_sid()}) is True
        assert S.claims_are_session_bound({"sid": "not-a-uuid"}) is False
        assert S.claims_are_session_bound({"jti": S.new_jti()}) is False  # jti alone
        assert S.claims_are_session_bound({}) is False
        assert S.claims_are_session_bound("nonsense") is False
        assert S.claims_are_session_bound(None) is False

    def test_router_and_module_discriminator_agree(self):
        sid = S.new_sid()
        assert auth_module.token_is_session_bound({"sid": sid}) is True
        assert S.claims_are_session_bound({"sid": sid}) is True
        assert auth_module.token_is_session_bound({"sid": "x"}) is False


# ---------------------------------------------------------------------------
# _issue_token() / verify_jwt_token() — backward compatibility
# ---------------------------------------------------------------------------

class TestTokenIssuanceBackCompat:

    def test_legacy_issuance_is_byte_identical_shape(self, jwt_env):
        """No sid passed -> no sid/jti claims. This is /auth/login today."""
        token, _ = auth_module._issue_token("operator", "operator")
        claims = pyjwt.decode(
            token, TEST_SECRET, algorithms=["HS256"],
            audience=TEST_AUDIENCE, issuer=TEST_ISSUER,
        )
        assert "sid" not in claims
        assert "jti" not in claims
        assert set(claims) == {"sub", "username", "iss", "aud", "iat", "nbf", "exp", "role"}

    def test_legacy_token_verifies_and_is_not_session_bound(self, jwt_env):
        token, _ = auth_module._issue_token("operator", "operator")
        claims = auth_module.verify_jwt_token(token)
        assert auth_module.token_is_session_bound(claims) is False

    def test_new_style_token_carries_sid_and_jti(self, jwt_env):
        sid = S.new_sid()
        token, _ = auth_module._issue_token("operator", "admin", "uid-1", sid=sid)
        claims = auth_module.verify_jwt_token(token)
        assert claims["sid"] == sid
        assert claims["jti"]
        assert claims["user_id"] == "uid-1"
        assert claims["role"] == "admin"
        assert auth_module.token_is_session_bound(claims) is True

    def test_supplied_jti_is_used_when_wellformed(self, jwt_env):
        sid = S.new_sid()
        token, _ = auth_module._issue_token("operator", "operator", sid=sid, jti="my-jti_123")
        claims = auth_module.verify_jwt_token(token)
        assert claims["jti"] == "my-jti_123"

    def test_malformed_supplied_jti_is_replaced(self, jwt_env):
        sid = S.new_sid()
        token, _ = auth_module._issue_token("operator", "operator", sid=sid, jti="bad jti!")
        claims = auth_module.verify_jwt_token(token)
        assert claims["jti"] and claims["jti"] != "bad jti!"

    def test_issue_rejects_malformed_sid(self, jwt_env):
        with pytest.raises(HTTPException) as ei:
            auth_module._issue_token("operator", "operator", sid="not-a-uuid")
        assert ei.value.status_code == 500

    def test_verify_rejects_crafted_token_with_malformed_sid(self, jwt_env):
        forged = pyjwt.encode(
            {
                "sub": "operator", "role": "operator",
                "iss": TEST_ISSUER, "aud": TEST_AUDIENCE,
                "exp": int(time.time()) + 3600, "sid": "1234",
            },
            TEST_SECRET, algorithm="HS256",
        )
        with pytest.raises(HTTPException) as ei:
            auth_module.verify_jwt_token(forged)
        assert ei.value.status_code == 401

    def test_verify_rejects_crafted_token_with_malformed_jti(self, jwt_env):
        forged = pyjwt.encode(
            {
                "sub": "operator", "role": "operator",
                "iss": TEST_ISSUER, "aud": TEST_AUDIENCE,
                "exp": int(time.time()) + 3600, "jti": "has spaces",
            },
            TEST_SECRET, algorithm="HS256",
        )
        with pytest.raises(HTTPException) as ei:
            auth_module.verify_jwt_token(forged)
        assert ei.value.status_code == 401

    def test_verify_accepts_wellformed_jti_only_token(self, jwt_env):
        """A token with jti but no sid is legal (not session-bound)."""
        ok = pyjwt.encode(
            {
                "sub": "operator", "role": "operator",
                "iss": TEST_ISSUER, "aud": TEST_AUDIENCE,
                "exp": int(time.time()) + 3600, "jti": "abc_DEF-123",
            },
            TEST_SECRET, algorithm="HS256",
        )
        claims = auth_module.verify_jwt_token(ok)
        assert claims["jti"] == "abc_DEF-123"
        assert auth_module.token_is_session_bound(claims) is False


__all__: list[str] = []
