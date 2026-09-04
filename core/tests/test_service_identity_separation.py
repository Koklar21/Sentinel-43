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
# core/tests/test_service_identity_separation.py
#
# Pass 5A §22 — regression tests for the human / service identity boundary.
# The browser-session foundation (jti/sid claims, refresh credentials, CSRF)
# must not create any path where:
#   * a human access JWT or a refresh credential satisfies a service verifier
#   * a service shared-secret token satisfies verify_jwt_token(), /auth/login,
#     or the session layer (create/rotate a human refresh session)
#
# These verifiers were already separate before Pass 5A (AUTH_ARCHITECTURE_
# PASS4.md §4). This suite pins that separation so a future change to the
# token model can't silently erode it.
# =============================================================================

from __future__ import annotations

import time

import jwt as pyjwt
import pytest
from fastapi import HTTPException
from starlette.requests import Request

import core.api.routers.auth as auth_module
from core.auth import sessions as S

TEST_SECRET = "test-secret-key-at-least-32-bytes-long-xxxx"
TEST_ISSUER = "sentinel-43"
TEST_AUDIENCE = "sentinel-43-dashboard"

SERVICE_TOKEN = "svc-" + "z" * 40           # shape of an opaque shared secret
ADMIN_TOKEN = "adm-" + "q" * 40


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("S43_JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("S43_JWT_ISSUER", TEST_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE", TEST_AUDIENCE)
    monkeypatch.setenv("S43_WATCHTOWER_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("S43_FENRIR_API_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("S43_ADMIN_TOKEN", ADMIN_TOKEN)
    yield


def _human_jwt(*, role: str = "operator", session_bound: bool = False) -> str:
    claims = {
        "sub": "operator",
        "username": "operator",
        "role": role,
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    if session_bound:
        claims["sid"] = S.new_sid()
        claims["jti"] = S.new_jti()
    return pyjwt.encode(claims, TEST_SECRET, algorithm="HS256")


def _fenrir_request(bearer: str | None) -> Request:
    headers = []
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    scope = {
        "type": "http", "method": "POST", "path": "/internal/events/broadcast",
        "headers": headers, "query_string": b"", "server": ("testserver", 80),
        "scheme": "http", "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


# ---------------------------------------------------------------------------
# human credential -> service verifier : must be rejected
# ---------------------------------------------------------------------------

class TestHumanCredentialCannotSatisfyServiceAuth:

    def test_human_jwt_rejected_by_watchtower_service_verifier(self, env):
        from core.monitoring.watchtower import _require_service_token
        for role in ("operator", "admin"):
            with pytest.raises(HTTPException) as ei:
                _require_service_token(authorization=f"Bearer {_human_jwt(role=role)}")
            assert ei.value.status_code == 401

    def test_session_bound_human_jwt_rejected_by_watchtower(self, env):
        from core.monitoring.watchtower import _require_service_token
        with pytest.raises(HTTPException) as ei:
            _require_service_token(authorization=f"Bearer {_human_jwt(session_bound=True)}")
        assert ei.value.status_code == 401

    def test_human_jwt_rejected_by_fenrir_service_verifier(self, env):
        import core.api.main as main_module
        with pytest.raises(HTTPException) as ei:
            main_module._require_fenrir_service_token(_fenrir_request(_human_jwt()))
        assert ei.value.status_code == 401

    def test_human_jwt_rejected_by_watchtower_admin_token(self, env):
        from core.monitoring.watchtower import _require_admin_token
        with pytest.raises(HTTPException) as ei:
            _require_admin_token(_human_jwt(role="admin"))
        assert ei.value.status_code == 401

    def test_refresh_credential_rejected_by_service_verifiers(self, env):
        from core.monitoring.watchtower import _require_service_token, _require_admin_token
        refresh = S.generate_refresh_secret()
        with pytest.raises(HTTPException):
            _require_service_token(authorization=f"Bearer {refresh}")
        with pytest.raises(HTTPException):
            _require_admin_token(refresh)

    def test_refresh_credential_is_not_a_jwt(self, env):
        with pytest.raises(HTTPException) as ei:
            auth_module.verify_jwt_token(S.generate_refresh_secret())
        assert ei.value.status_code == 401


# ---------------------------------------------------------------------------
# service token -> human verifiers / session layer : must be rejected
# ---------------------------------------------------------------------------

class TestServiceTokenCannotSatisfyHumanAuth:

    def test_service_token_rejected_by_verify_jwt_token(self, env):
        with pytest.raises(HTTPException) as ei:
            auth_module.verify_jwt_token(SERVICE_TOKEN)
        assert ei.value.status_code == 401

    def test_service_token_fails_login_credential_check(self, env, monkeypatch):
        # env-var operator path: a service token is neither the username nor
        # the password hash, so _validate_env_credentials must 401.
        monkeypatch.setenv("S43_OPERATOR_USERNAME", "operator")
        import hashlib
        monkeypatch.setenv(
            "S43_OPERATOR_PASSWORD_HASH",
            hashlib.sha256(b"the-real-password").hexdigest(),
        )
        with pytest.raises(HTTPException) as ei:
            auth_module._validate_env_credentials("operator", SERVICE_TOKEN)
        assert ei.value.status_code == 401

    def test_service_token_claims_are_not_session_bound(self, env):
        # There is no decode path that yields claims for a service token, but
        # the discriminator must also never treat a bare string as session-bound.
        assert auth_module.token_is_session_bound({}) is False
        assert S.claims_are_session_bound({"sid": SERVICE_TOKEN}) is False

    def test_service_token_cannot_be_hashed_into_an_existing_session(self, env):
        # A service token used as a refresh secret just produces an unrelated
        # digest — it can never collide with a real session's stored hash.
        real = S.generate_refresh_secret()
        assert S.hash_refresh_secret(SERVICE_TOKEN) != S.hash_refresh_secret(real)

    def test_service_verifiers_do_not_touch_the_human_token_machinery(self):
        """Guard rail: a service verifier authenticates by constant-time
        secret compare only. It must never call verify_jwt_token() (would let
        a signed human JWT in) nor _issue_token() (would mint a human token
        for a machine caller)."""
        import inspect
        from core.monitoring import watchtower as wt
        import core.api.main as main_module

        for fn in (wt._require_service_token, wt._require_admin_token,
                   main_module._require_fenrir_service_token):
            src = inspect.getsource(fn)
            assert "verify_jwt_token" not in src, fn.__name__
            assert "_issue_token" not in src, fn.__name__
            assert "compare_digest" in src, fn.__name__


# ---------------------------------------------------------------------------
# sanity: the service verifier DOES accept its own token (boundary is a
# boundary, not a blanket deny)
# ---------------------------------------------------------------------------

def test_service_verifier_accepts_its_own_token(env):
    from core.monitoring.watchtower import _require_service_token
    # no exception
    _require_service_token(authorization=f"Bearer {SERVICE_TOKEN}")


# ===========================================================================
# SpartaCore /node service boundary (PR #254 activated this router).
#
# The /node router authenticates with Authorization: Bearer
# <S43_SPARTA_NODE_TOKEN> only -- a distinct machine identity. It must not be
# satisfiable by a human JWT or by any other service's token, and its own
# token must not satisfy a human or another-service verifier.
# ===========================================================================

SPARTA_NODE_TOKEN = "spn-" + "k" * 40          # distinct from SERVICE_TOKEN / ADMIN_TOKEN
SPARTA_TOKEN_SECRET = "sps-" + "m" * 40


def _sparta_config(*, node_api_token: str = SPARTA_NODE_TOKEN):
    from core.monitoring.sparta_core import IntegrityConfig
    return IntegrityConfig(
        watched_files={},
        node_signature="test-node",
        node_api_token=node_api_token,
        token_secret=SPARTA_TOKEN_SECRET,
    )


def _sparta_request(bearer: str | None) -> Request:
    headers = []
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    scope = {
        "type": "http", "method": "GET", "path": "/node/status",
        "headers": headers, "query_string": b"", "server": ("testserver", 80),
        "scheme": "http", "client": ("127.0.0.1", 23456),
    }
    return Request(scope)


class TestSpartaNodeBoundary:
    """Nothing but the exact S43_SPARTA_NODE_TOKEN opens /node."""

    def _deny(self, bearer, *, header_value=None):
        from core.monitoring.sparta_core import _require_node_token, SpartaCore
        cfg = _sparta_config()
        auth = header_value if header_value is not None else (
            f"Bearer {bearer}" if bearer is not None else None)
        with pytest.raises(HTTPException) as ei:
            _require_node_token(auth, cfg)
        assert ei.value.status_code == 401
        # and through the full route guard (client blocking + failure logging)
        core = SpartaCore(cfg)
        try:
            with pytest.raises(HTTPException) as ei2:
                core.require_node_auth(_sparta_request(bearer), auth)
            assert ei2.value.status_code in (401, 429)
        finally:
            core.close()

    def test_A_no_credentials_denied(self, env):
        self._deny(None)

    def test_B_empty_token_denied(self, env):
        self._deny("", header_value="Bearer ")

    def test_C_incorrect_token_denied(self, env):
        self._deny("spn-" + "x" * 40)

    def test_D_malformed_header_denied(self, env):
        self._deny(None, header_value="Token abc123")          # not "Bearer "
        self._deny(None, header_value=SPARTA_NODE_TOKEN)       # scheme missing

    def test_E_operator_jwt_does_not_satisfy_sparta(self, env):
        self._deny(_human_jwt(role="operator"))

    def test_F_admin_jwt_does_not_satisfy_sparta(self, env):
        self._deny(_human_jwt(role="admin"))
        self._deny(_human_jwt(role="admin", session_bound=True))

    def test_I_watchtower_token_does_not_satisfy_sparta(self, env):
        self._deny(SERVICE_TOKEN)                              # = S43_WATCHTOWER_SERVICE_TOKEN

    def test_J_fenrir_token_does_not_satisfy_sparta(self, env):
        # fixture points S43_FENRIR_API_TOKEN at SERVICE_TOKEN; also try a
        # distinct fenrir-shaped value.
        self._deny(SERVICE_TOKEN)
        self._deny("fen-" + "y" * 40)

    def test_K_admin_env_token_does_not_satisfy_sparta(self, env):
        self._deny(ADMIN_TOKEN)

    def test_G_correct_sparta_token_is_accepted(self, env):
        from core.monitoring.sparta_core import _require_node_token
        _require_node_token(f"Bearer {SPARTA_NODE_TOKEN}", _sparta_config())  # no raise

    def test_missing_node_token_config_fails_closed_503_not_anonymous(self, env):
        from core.monitoring.sparta_core import _require_node_token
        for empty in ("", "   "):
            with pytest.raises(HTTPException) as ei:
                _require_node_token(f"Bearer {SPARTA_NODE_TOKEN}",
                                    _sparta_config(node_api_token=empty))
            # 503 -- never an anonymous 200
            assert ei.value.status_code == 503

    def test_sparta_verifier_uses_constant_time_compare_only(self, env):
        import inspect
        from core.monitoring import sparta_core as sc
        src = inspect.getsource(sc._require_node_token)
        assert "compare_digest" in src
        assert "verify_jwt_token" not in src
        assert "_issue_token" not in src
        assert "_validate_env_credentials" not in src


class TestSpartaTokenCannotSatisfyOtherIdentities:
    """The /node token must not open a human route or another service."""

    def test_L_sparta_token_rejected_by_verify_jwt_token(self, env):
        with pytest.raises(HTTPException) as ei:
            auth_module.verify_jwt_token(SPARTA_NODE_TOKEN)
        assert ei.value.status_code == 401

    def test_L_sparta_token_rejected_by_watchtower(self, env):
        from core.monitoring.watchtower import _require_service_token, _require_admin_token
        with pytest.raises(HTTPException):
            _require_service_token(authorization=f"Bearer {SPARTA_NODE_TOKEN}")
        with pytest.raises(HTTPException):
            _require_admin_token(SPARTA_NODE_TOKEN)

    def test_L_sparta_token_rejected_by_fenrir(self, env):
        import core.api.main as main_module
        with pytest.raises(HTTPException) as ei:
            main_module._require_fenrir_service_token(_fenrir_request(SPARTA_NODE_TOKEN))
        assert ei.value.status_code == 401

    def test_H_sparta_token_fails_env_login_credential_check(self, env, monkeypatch):
        monkeypatch.setenv("S43_OPERATOR_USERNAME", "operator")
        import hashlib
        monkeypatch.setenv("S43_OPERATOR_PASSWORD_HASH",
                           hashlib.sha256(b"the-real-password").hexdigest())
        with pytest.raises(HTTPException) as ei:
            auth_module._validate_env_credentials("operator", SPARTA_NODE_TOKEN)
        assert ei.value.status_code == 401

    def test_sparta_token_claims_are_not_session_bound(self, env):
        assert S.claims_are_session_bound({"sid": SPARTA_NODE_TOKEN}) is False


class TestSpartaPublicHealthDoesNotLeak:
    """/node/health is the one unauthenticated /node route. It must stay
    coarse unless the operator opts in with S43_SPARTA_PUBLIC_HEALTH_DETAIL."""

    def test_default_public_health_is_coarse(self, env):
        from core.monitoring.sparta_core import SpartaCore
        core = SpartaCore(_sparta_config())
        try:
            body = core.get_public_health()
        finally:
            core.close()
        assert set(body) <= {"status", "timestamp"}
        assert "node_signature" not in body
        assert body["status"] in ("ok", "degraded")

    def test_opt_in_detail_adds_only_signature_and_state(self, env, monkeypatch):
        from core.monitoring.sparta_core import IntegrityConfig, SpartaCore
        cfg = IntegrityConfig(
            watched_files={}, node_signature="test-node",
            node_api_token=SPARTA_NODE_TOKEN, token_secret=SPARTA_TOKEN_SECRET,
            public_health_detail=True,
        )
        core = SpartaCore(cfg)
        try:
            body = core.get_public_health()
        finally:
            core.close()
        # still no IPs / paths / creds / topology / env contents
        assert set(body) <= {"status", "state", "node_signature", "timestamp"}


__all__: list[str] = []
