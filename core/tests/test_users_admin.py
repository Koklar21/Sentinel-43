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
# core/tests/test_users_admin.py
#
# Isolated (non-live) coverage for the admin-managed account router
# (core/api/routers/users.py) and its require_admin gate
# (core/api/deps/deps.py).
#
# Same approach as test_bootstrap_isolated.py: run the real route code
# in-process against core.api.main.app, with core.auth.users' Postgres-backed
# functions swapped for an in-memory fake (see _FakeUserStore). This proves
# the router logic — admin gating, guard rails, status codes, the
# deactivate-blocks-login contract — on every test run without needing a
# database.
#
# JWT config: verify_jwt_token() / reverify_password() / _issue_token() all
# read S43_JWT_* from the environment at call time, so this file pins them
# with monkeypatch.setenv() inside the per-test fixture (plus os.environ
# .setdefault at import for the import-time freeze in core.api.main). That
# keeps this file's tokens valid regardless of what other test modules leave
# in the environment before or after it in the same pytest process.
# =============================================================================

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator, Generator

import jwt
import pytest
from fastapi.testclient import TestClient

JWT_SECRET = "test-secret-for-users-admin-tests"
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "sentinel-43-test"
JWT_AUDIENCE = "sentinel-43-dashboard-test"

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", JWT_SECRET)
os.environ.setdefault("S43_JWT_ALGORITHM", JWT_ALGORITHM)
os.environ.setdefault("S43_JWT_ISSUER", JWT_ISSUER)
os.environ.setdefault("S43_JWT_AUDIENCE", JWT_AUDIENCE)

import core.api.routers.users as users_router_module  # noqa: E402
import core.api.deps as api_deps_module  # noqa: E402
import core.auth.deps as auth_deps_module  # noqa: E402
import core.auth.users as users_module  # noqa: E402
import core.governance.identity as identity_module  # noqa: E402
from core.api.main import app  # noqa: E402
from core.auth.users import hash_password  # noqa: E402

USERS_URL = "/users"

ADMIN_NAME = "root-admin"
ADMIN_PW = "root-admin-password-1234"

# An env-var operator that is deliberately never a valid caller here. It
# only exists so the /auth/login fallback path (auth.py falls back to
# _validate_env_credentials when the DB has no matching user) returns a
# clean 401 instead of a 503 "credentials not configured". Must be a
# well-formed Argon2id hash — a legacy SHA-256 digest is rejected outright
# by _valid_argon2_hash() and would itself 503.
ENV_OPERATOR_NAME = "env-operator-unused"
ENV_OPERATOR_HASH = hash_password("env-operator-unused-password")


# ---------------------------------------------------------------------------
# In-memory fake replacing core.auth.users' Postgres-backed functions
# ---------------------------------------------------------------------------

@dataclass
class _FakeUser:
    username: str
    password: str  # plaintext — the fake does a direct compare, no Argon2
    role: str
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    is_active: bool = True
    email: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login_at: datetime | None = None


class _FakeUserStore:
    def __init__(self) -> None:
        self.users: dict[str, _FakeUser] = {}

    def seed(self, *, username: str, password: str, role: str, is_active: bool = True) -> _FakeUser:
        user = _FakeUser(username=username, password=password, role=role, is_active=is_active)
        self.users[username] = user
        return user

    async def count_active_admins(self, session=None) -> int:
        return sum(1 for u in self.users.values() if u.role == "admin" and u.is_active)

    async def get_user_by_username(self, session, username: str) -> _FakeUser | None:
        return self.users.get(username)

    async def get_user_by_id(self, session, user_id) -> _FakeUser | None:
        for user in self.users.values():
            if user.user_id == user_id:
                return user
        return None

    async def list_users(self, session) -> list[_FakeUser]:
        return sorted(self.users.values(), key=lambda u: u.created_at)

    async def create_user(
        self, session, *, username: str, password: str, role: str = "observer", email: str | None = None
    ) -> _FakeUser:
        user = _FakeUser(username=username, password=password, role=role, email=email)
        self.users[username] = user
        return user

    async def set_user_active(self, session, user: _FakeUser, *, is_active: bool) -> _FakeUser:
        user.is_active = is_active
        return user

    async def set_user_password(self, session, user: _FakeUser, *, password: str) -> _FakeUser:
        user.password = password
        return user

    async def authenticate_user(
        self, session, username: str, password: str
    ) -> _FakeUser | None:
        # Read-only, matches the Pass 3 signature (no update_last_login).
        user = self.users.get(username)
        if user is None or not user.is_active or user.password != password:
            return None
        return user


@dataclass
class _FakeSessionRow:
    sid: uuid.UUID = field(default_factory=uuid.uuid4)
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)


class _FakeSessionStore:
    """
    Drop-in replacement for core.auth.sessions.create_session() /
    resolve_live_session(). /auth/login creates a real server-side session
    for every DB-backed login (auth.py's _create_login_session()) — needed
    since the P0 security remediation pass made login() raise (503) rather
    than silently degrade to a legacy token when session creation fails; a
    DB-backed login in these tests must now actually succeed at it.
    """

    def __init__(self, user_store: _FakeUserStore) -> None:
        self.user_store = user_store
        self.rows: dict[uuid.UUID, _FakeSessionRow] = {}

    async def create_session(
        self, session, *, user_id, refresh_secret, client_ip=None,
        user_agent=None, ttl_seconds=None, now=None,
    ) -> _FakeSessionRow:
        row = _FakeSessionRow(user_id=user_id)
        self.rows[row.sid] = row
        return row

    async def resolve_live_session(self, session, sid):
        import core.auth.sessions as sessions_module

        row = self.rows.get(sid)
        if row is None:
            raise sessions_module.SessionError("unknown session")
        owner = next(
            (u for u in self.user_store.users.values() if u.user_id == row.user_id),
            None,
        )
        if owner is None or not owner.is_active:
            raise sessions_module.SessionError("owner inactive")
        return row, owner


class _FakeSession:
    """No-op stand-in for AsyncSession. The dict-backed fake store has no real
    transaction, so commit/rollback/flush are genuine no-ops here. get_bind()
    raises so core.auth.users._pg_advisory_xact_lock() correctly no-ops on a
    non-PostgreSQL bind."""

    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...
    async def flush(self) -> None: ...
    async def refresh(self, _obj) -> None: ...

    async def execute(self, *_args, **_kwargs):
        """The dict-backed fake store keeps no session rows, so the account
        mutation handlers' revoke_all_user_sessions() call finds nothing to
        revoke -- return an empty result rather than AttributeError."""
        class _EmptyResult:
            def scalars(self):
                return self

            def all(self):
                return []

            rowcount = 0

        return _EmptyResult()

    def get_bind(self):  # noqa: ANN201
        raise RuntimeError("fake session has no bind")


class _NullSessionCtx:
    async def __aenter__(self) -> _FakeSession:
        return _FakeSession()

    async def __aexit__(self, *exc_info: object) -> None:
        return None


def _fake_get_sessionmaker():
    return _NullSessionCtx


async def _fake_get_db_session() -> AsyncIterator[_FakeSession]:
    yield _FakeSession()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(monkeypatch) -> Generator[_FakeUserStore, None, None]:
    s = _FakeUserStore()
    session_store = _FakeSessionStore(s)

    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("S43_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("S43_JWT_ALGORITHM", JWT_ALGORITHM)
    monkeypatch.setenv("S43_JWT_ISSUER", JWT_ISSUER)
    monkeypatch.setenv("S43_JWT_AUDIENCE", JWT_AUDIENCE)
    monkeypatch.setenv("S43_OPERATOR_USERNAME", ENV_OPERATOR_NAME)
    monkeypatch.setenv("S43_OPERATOR_PASSWORD_HASH", ENV_OPERATOR_HASH)

    # Router reads remain direct; consequential mutations now live in the
    # authority-owned identity governance service.
    monkeypatch.setattr(users_router_module, "get_user_by_username", s.get_user_by_username)
    monkeypatch.setattr(users_router_module, "list_users", s.list_users)

    monkeypatch.setattr(identity_module, "count_active_admins", s.count_active_admins)
    monkeypatch.setattr(identity_module, "create_user", s.create_user)
    monkeypatch.setattr(identity_module, "get_user_by_id", s.get_user_by_id)
    monkeypatch.setattr(identity_module, "set_user_active", s.set_user_active)
    monkeypatch.setattr(identity_module, "set_user_password", s.set_user_password)

    async def _fake_lock(_session, _key):
        return None

    async def _fake_revoke(_session, _user_id, *, reason):
        return 0

    monkeypatch.setattr(identity_module, "_pg_advisory_xact_lock", _fake_lock)
    monkeypatch.setattr(identity_module, "revoke_all_user_sessions", _fake_revoke)

    # require_admin (core.api.deps.deps) and auth.py's reverify_password /
    # _validate_credentials import from core.auth.users at call time.
    monkeypatch.setattr(users_module, "get_user_by_username", s.get_user_by_username)
    monkeypatch.setattr(users_module, "authenticate_user", s.authenticate_user)
    monkeypatch.setattr(users_module, "get_sessionmaker", _fake_get_sessionmaker)
    # /auth/login creates a real server-side session for every DB-backed
    # login — fake that out too (see _FakeSessionStore).
    import core.auth.sessions as sessions_module
    monkeypatch.setattr(sessions_module, "create_session", session_store.create_session)
    monkeypatch.setattr(sessions_module, "resolve_live_session", session_store.resolve_live_session)

    authority = type(
        "_FakeAuthority",
        (),
        {
            "identity": identity_module.IdentityGovernanceService(
                audit_sink=lambda _payload: None
            )
        },
    )()
    app.dependency_overrides[auth_deps_module.get_db_session] = _fake_get_db_session
    app.dependency_overrides[users_router_module.get_runtime_authority] = lambda: authority
    app.dependency_overrides[api_deps_module.get_optional_runtime_authority] = lambda: authority
    yield s
    app.dependency_overrides.pop(auth_deps_module.get_db_session, None)
    app.dependency_overrides.pop(users_router_module.get_runtime_authority, None)
    app.dependency_overrides.pop(api_deps_module.get_optional_runtime_authority, None)


@pytest.fixture
def client(store: _FakeUserStore) -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _token(subject: str, role: str, *, exp_offset_seconds: int = 3600) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "username": subject,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 5,
        "exp": int(now.timestamp()) + exp_offset_seconds,
        "role": role,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _auth_headers(subject: str, password: str, role: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token(subject, role)}",
        "X-S43-Password": password,
    }


def _seed_admin(store: _FakeUserStore) -> _FakeUser:
    return store.seed(username=ADMIN_NAME, password=ADMIN_PW, role="admin")


def _admin_headers() -> dict[str, str]:
    return _auth_headers(ADMIN_NAME, ADMIN_PW, "admin")


# ---------------------------------------------------------------------------
# Auth boundary
# ---------------------------------------------------------------------------

def test_create_requires_authentication(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.post(USERS_URL, json={"username": "new-op", "password": "new-op-pw-1234"})
    assert response.status_code == 401


def test_create_rejects_valid_token_without_password_header(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.post(
        USERS_URL,
        json={"username": "new-op", "password": "new-op-pw-1234"},
        headers={"Authorization": f"Bearer {_token(ADMIN_NAME, 'admin')}"},
    )
    assert response.status_code == 401


def test_observer_cannot_create_users(client: TestClient, store: _FakeUserStore):
    store.seed(username="observer-1", password="observer-1-pw-1234", role="observer")
    response = client.post(
        USERS_URL,
        json={"username": "x", "password": "x-password-1234"},
        headers=_auth_headers("observer-1", "observer-1-pw-1234", "observer"),
    )
    assert response.status_code == 403


def test_observer_cannot_list_users(client: TestClient, store: _FakeUserStore):
    store.seed(username="observer-1", password="observer-1-pw-1234", role="observer")
    response = client.get(
        USERS_URL,
        headers=_auth_headers("observer-1", "observer-1-pw-1234", "observer"),
    )
    assert response.status_code == 403


def test_demoted_admin_loses_access_immediately(client: TestClient, store: _FakeUserStore):
    """require_admin checks the live DB row, not the JWT 'role' claim: a
    token minted while the caller was an admin stops working the moment the
    account is demoted, without waiting for the token to expire."""
    admin = _seed_admin(store)
    admin.role = "observer"  # corrupted/demoted out of band; token still says "admin"
    response = client.get(USERS_URL, headers=_admin_headers())
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def test_admin_creates_observer_account(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.post(
        USERS_URL,
        json={"username": "analyst-1", "password": "analyst-1-pw-1234"},
        headers=_admin_headers(),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["username"] == "analyst-1"
    assert body["role"] == "observer"
    assert body["is_active"] is True
    assert "analyst-1" in store.users
    assert "password" not in body and "password_hash" not in body


def test_admin_cannot_create_second_admin_account(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.post(
        USERS_URL,
        json={"username": "second-admin", "password": "second-admin-pw-1234", "role": "admin"},
        headers=_admin_headers(),
    )
    assert response.status_code == 422
    assert "second-admin" not in store.users


def test_create_rejects_duplicate_username(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    store.seed(username="taken", password="taken-pw-1234", role="observer")
    response = client.post(
        USERS_URL,
        json={"username": "taken", "password": "different-pw-1234"},
        headers=_admin_headers(),
    )
    assert response.status_code == 409


def test_create_rejects_short_password(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.post(
        USERS_URL,
        json={"username": "shorty", "password": "short"},
        headers=_admin_headers(),
    )
    assert response.status_code == 422


def test_create_rejects_unknown_role(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.post(
        USERS_URL,
        json={"username": "weird", "password": "weird-pw-1234", "role": "superuser"},
        headers=_admin_headers(),
    )
    assert response.status_code == 422


def test_create_rejects_blank_username(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.post(
        USERS_URL,
        json={"username": "   ", "password": "whitespace-pw-1234"},
        headers=_admin_headers(),
    )
    assert response.status_code == 422


def test_new_observer_can_log_in(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    create = client.post(
        USERS_URL,
        json={"username": "fresh-op", "password": "fresh-op-pw-1234"},
        headers=_admin_headers(),
    )
    assert create.status_code == 201

    login = client.post("/auth/login", json={"username": "fresh-op", "password": "fresh-op-pw-1234"})
    assert login.status_code == 200, login.text
    assert login.json()["subject"] == "fresh-op"


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

def test_list_returns_every_account(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    store.seed(username="op-a", password="op-a-pw-1234", role="observer")
    store.seed(username="op-b", password="op-b-pw-1234", role="observer", is_active=False)

    response = client.get(USERS_URL, headers=_admin_headers())
    assert response.status_code == 200, response.text
    rows = response.json()
    assert {r["username"] for r in rows} == {ADMIN_NAME, "op-a", "op-b"}
    assert all("password" not in r and "password_hash" not in r for r in rows)
    inactive = next(r for r in rows if r["username"] == "op-b")
    assert inactive["is_active"] is False


# ---------------------------------------------------------------------------
# Update: deactivate / reactivate / role
# ---------------------------------------------------------------------------

def test_deactivate_account_blocks_login(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    target = store.seed(username="revoke-me", password="revoke-me-pw-1234", role="observer")

    assert client.post(
        "/auth/login", json={"username": "revoke-me", "password": "revoke-me-pw-1234"}
    ).status_code == 200

    patch = client.patch(
        f"{USERS_URL}/{target.user_id}",
        json={"is_active": False},
        headers=_admin_headers(),
    )
    assert patch.status_code == 200, patch.text
    assert patch.json()["is_active"] is False

    assert client.post(
        "/auth/login", json={"username": "revoke-me", "password": "revoke-me-pw-1234"}
    ).status_code == 401


def test_reactivate_account_restores_login(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    target = store.seed(
        username="back-again", password="back-again-pw-1234", role="observer", is_active=False
    )

    patch = client.patch(
        f"{USERS_URL}/{target.user_id}",
        json={"is_active": True},
        headers=_admin_headers(),
    )
    assert patch.status_code == 200, patch.text
    assert patch.json()["is_active"] is True

    assert client.post(
        "/auth/login", json={"username": "back-again", "password": "back-again-pw-1234"}
    ).status_code == 200


def test_observer_cannot_be_promoted_to_admin(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    target = store.seed(username="promote-me", password="promote-me-pw-1234", role="observer")

    patch = client.patch(
        f"{USERS_URL}/{target.user_id}",
        json={"role": "admin"},
        headers=_admin_headers(),
    )
    assert patch.status_code == 422
    assert store.users["promote-me"].role == "observer"


def test_patch_unknown_user_id_returns_404(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.patch(
        f"{USERS_URL}/{uuid.uuid4()}",
        json={"is_active": False},
        headers=_admin_headers(),
    )
    assert response.status_code == 404


def test_patch_malformed_user_id_returns_422(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.patch(
        f"{USERS_URL}/not-a-uuid",
        json={"is_active": False},
        headers=_admin_headers(),
    )
    assert response.status_code == 422


def test_patch_empty_body_returns_422(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    target = store.seed(username="op", password="op-password-1234", role="observer")
    response = client.patch(
        f"{USERS_URL}/{target.user_id}", json={}, headers=_admin_headers()
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Update: last-admin / self guard rails
# ---------------------------------------------------------------------------

def test_cannot_deactivate_own_account(client: TestClient, store: _FakeUserStore):
    admin = _seed_admin(store)
    response = client.patch(
        f"{USERS_URL}/{admin.user_id}",
        json={"is_active": False},
        headers=_admin_headers(),
    )
    assert response.status_code == 409


def test_cannot_demote_the_last_admin(client: TestClient, store: _FakeUserStore):
    admin = _seed_admin(store)
    response = client.patch(
        f"{USERS_URL}/{admin.user_id}",
        json={"role": "observer"},
        headers=_admin_headers(),
    )
    assert response.status_code == 422
    assert store.users[ADMIN_NAME].role == "admin"


def test_self_demotion_refused_even_when_store_has_another_admin(client: TestClient, store: _FakeUserStore):
    admin = _seed_admin(store)
    store.seed(username="co-admin", password="co-admin-pw-1234", role="admin")

    response = client.patch(
        f"{USERS_URL}/{admin.user_id}",
        json={"role": "observer"},
        headers=_admin_headers(),
    )
    assert response.status_code == 422
    assert store.users[ADMIN_NAME].role == "admin"


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

def test_admin_resets_account_password(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    target = store.seed(username="forgot", password="old-password-1234", role="observer")

    response = client.post(
        f"{USERS_URL}/{target.user_id}/password",
        json={"new_password": "brand-new-password-1234"},
        headers=_admin_headers(),
    )
    assert response.status_code == 200, response.text

    assert client.post(
        "/auth/login", json={"username": "forgot", "password": "old-password-1234"}
    ).status_code == 401
    assert client.post(
        "/auth/login", json={"username": "forgot", "password": "brand-new-password-1234"}
    ).status_code == 200


def test_password_reset_rejects_short_password(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    target = store.seed(username="forgot", password="old-password-1234", role="observer")

    response = client.post(
        f"{USERS_URL}/{target.user_id}/password",
        json={"new_password": "short"},
        headers=_admin_headers(),
    )
    assert response.status_code == 422


def test_password_reset_unknown_user_returns_404(client: TestClient, store: _FakeUserStore):
    _seed_admin(store)
    response = client.post(
        f"{USERS_URL}/{uuid.uuid4()}/password",
        json={"new_password": "brand-new-password-1234"},
        headers=_admin_headers(),
    )
    assert response.status_code == 404


__all__: list[str] = []
