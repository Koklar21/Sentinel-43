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

import re
import time
import uuid as uuid_mod

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
        # S43_SESSION_HASH_PEPPER must supply at least 32 bytes of material.
        monkeypatch.setenv("S43_SESSION_HASH_PEPPER", "a-server-side-pepper-value-well-over-32-bytes-long")
        peppered = S.hash_refresh_secret(secret)
        assert peppered != plain
        # still self-consistent under the pepper
        assert S.verify_refresh_hash(secret, peppered) is True

    def test_refresh_ttl_env_out_of_range_falls_back_to_default(self, monkeypatch):
        default = 7 * 24 * 3600
        monkeypatch.delenv("S43_SESSION_REFRESH_TTL_SECONDS", raising=False)
        assert S.refresh_ttl_seconds() == default
        # Below the floor or above the ceiling -> reject the operator value and
        # use the documented default (it does not silently clamp).
        monkeypatch.setenv("S43_SESSION_REFRESH_TTL_SECONDS", "1")
        assert S.refresh_ttl_seconds() == default
        monkeypatch.setenv("S43_SESSION_REFRESH_TTL_SECONDS", "99999999")
        assert S.refresh_ttl_seconds() == default
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
        # A session-bound token carries BOTH a valid sid and a valid jti.
        assert S.claims_are_session_bound({"sid": S.new_sid(), "jti": S.new_jti()}) is True
        assert S.claims_are_session_bound({"sid": S.new_sid()}) is False        # sid alone
        assert S.claims_are_session_bound({"sid": "not-a-uuid", "jti": S.new_jti()}) is False
        assert S.claims_are_session_bound({"jti": S.new_jti()}) is False        # jti alone
        assert S.claims_are_session_bound({}) is False
        assert S.claims_are_session_bound("nonsense") is False
        assert S.claims_are_session_bound(None) is False

    def test_router_and_module_discriminator_agree(self):
        bound = {"sid": S.new_sid(), "jti": S.new_jti()}
        assert auth_module.token_is_session_bound(bound) is True
        assert S.claims_are_session_bound(bound) is True
        assert auth_module.token_is_session_bound({"sid": "x", "jti": "y"}) is False


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
        uid = str(uuid_mod.uuid4())  # _issue_token requires a UUID user_id
        token, _ = auth_module._issue_token("operator", "admin", uid, sid=sid)
        claims = auth_module.verify_jwt_token(token)
        assert claims["sid"] == sid
        assert claims["jti"]
        assert claims["user_id"] == uid
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

    def test_verify_rejects_jti_without_sid(self, jwt_env):
        """`jti` is only valid as part of a session-bound token (sid + jti).
        A token carrying jti but no sid is malformed and rejected."""
        _now = int(time.time())
        forged = pyjwt.encode(
            {
                "sub": "operator", "role": "operator",
                "iss": TEST_ISSUER, "aud": TEST_AUDIENCE,
                "iat": _now, "nbf": _now, "exp": _now + 3600,
                "jti": "abc_DEF-123",
            },
            TEST_SECRET, algorithm="HS256",
        )
        with pytest.raises(HTTPException) as ei:
            auth_module.verify_jwt_token(forged)
        assert ei.value.status_code == 401

    def test_session_bound_token_has_short_ttl(self, jwt_env, monkeypatch):
        """Approved target: session-bound access token TTL = 15 min (default
        900s). Legacy tokens keep the 8h default."""
        monkeypatch.delenv("S43_SESSION_ACCESS_TTL_SECONDS", raising=False)
        monkeypatch.delenv("S43_JWT_TTL_SECONDS", raising=False)
        legacy, legacy_exp = auth_module._issue_token("operator", "operator")
        bound, bound_exp = auth_module._issue_token(
            "operator", "operator", sid=S.new_sid()
        )
        now = time.time()
        assert 840 <= (bound_exp.timestamp() - now) <= 900
        assert (legacy_exp.timestamp() - now) > 3600  # still the long default

    def test_session_access_ttl_env_clamped(self, jwt_env, monkeypatch):
        monkeypatch.setenv("S43_SESSION_ACCESS_TTL_SECONDS", "5")
        _, exp = auth_module._issue_token("operator", "operator", sid=S.new_sid())
        assert exp.timestamp() - time.time() >= 55        # 60s floor
        monkeypatch.setenv("S43_SESSION_ACCESS_TTL_SECONDS", "999999")
        _, exp = auth_module._issue_token("operator", "operator", sid=S.new_sid())
        assert exp.timestamp() - time.time() <= 3600      # 1h ceiling


class TestNoCredentialLeak:
    """§23 — the session module must not put a refresh secret into a log
    record or an exception message on any failure path."""

    def test_session_exceptions_carry_only_the_sid(self):
        sid = uuid_mod.uuid4()
        for exc in (
            S.RefreshReuseError(sid),
            S.SessionExpiredError(sid),
            S.SessionRevokedError(sid),
            S.SessionOwnerInactiveError(sid),
        ):
            text = str(exc)
            assert str(sid) in text
            assert exc.sid == sid
            # once the (safe, random) sid is removed, nothing that looks like
            # an opaque 32+ char credential remains
            residue = text.replace(str(sid), "")
            assert not re.search(r"[A-Za-z0-9_-]{32,}", residue)

    def test_rotate_module_emits_no_log_records_on_failure_paths(self, caplog):
        """core.auth.sessions itself does no logging — failure classification
        is via typed exceptions, and the route layer (Pass 5B) owns audit
        logging with redaction. Assert the module stays silent so a secret
        can't leak through a stray log call here."""
        import logging as _logging

        secret = S.generate_refresh_secret()
        # verify_refresh_hash / csrf / hash helpers on bad input: no logging,
        # no secret echoed
        with caplog.at_level(_logging.DEBUG, logger="core.auth.sessions"):
            assert S.verify_refresh_hash(secret, "not-a-hash") is False
            assert S.csrf_tokens_match(secret, None) is False
            try:
                S.hash_refresh_secret("")
            except ValueError as e:
                assert secret not in str(e)
        assert caplog.records == []


__all__: list[str] = []
