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
# core/tests/test_bootstrap_isolated.py
#
# Isolated (non-live) coverage for the first-run bootstrap flow.
#
# core/tests/test_bootstrap.py exercises /bootstrap/status and
# /bootstrap/admin against an already-running container over real HTTP,
# because bootstrap.py talks to Postgres via a hostname (s43-db) that only
# resolves inside the Docker network. That's the right test for "does the
# real deployment work," but it has a permanent blind spot: the one test
# that actually creates the first admin (test_first_run_bootstrap_flow_
# creates_admin) can only ever pass once per deployment. On this machine
# that already happened, so it now skips forever — the most important path
# in the whole auth system stopped being exercised.
#
# This file closes that gap by running the same flow entirely in-process
# against core.api.main.app, with core.auth.users' DB-backed functions
# replaced by an in-memory fake store (see _FakeUserStore below) instead of
# a real Postgres connection. This is not a replacement for test_bootstrap.py
# — it doesn't prove the real DATABASE_URL/Postgres wiring works — it proves
# the bootstrap.py + auth.py route logic (gating, status codes, JWT
# issuance, protected-route access) is correct, on every test run, forever.
#
# Fake store, not a real SQLite DB: core.auth.users.User is a SQLAlchemy
# ORM model bound to Postgres-specific behavior (Uuid columns, async
# engine). Standing up aiosqlite (not currently a dependency) just to get
# an async DB session would add a new package for a test-only path, and the
# route logic being tested here doesn't touch SQL — count_active_admins(),
# create_user(), get_user_by_username(), and authenticate_user() are called
# by name from bootstrap.py / auth.py, so monkeypatching those call sites
# with in-memory equivalents exercises the exact same route code without
# needing a database at all.
# =============================================================================

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator, Generator

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-isolated-bootstrap-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")
os.environ.setdefault("S43_JWT_ISSUER", "sentinel-43-test")
os.environ.setdefault("S43_JWT_AUDIENCE", "sentinel-43-dashboard-test")

import core.api.routers.bootstrap as bootstrap_module  # noqa: E402
import core.auth.deps as auth_deps_module  # noqa: E402
import core.auth.sessions as sessions_module  # noqa: E402
import core.auth.users as users_module  # noqa: E402
from core.api.main import app  # noqa: E402

PROTECTED_URL = "/watchtower/status"


# ---------------------------------------------------------------------------
# In-memory fake replacing core.auth.users' Postgres-backed functions
# ---------------------------------------------------------------------------

@dataclass
class _FakeUser:
    username: str
    password_hash: str
    role: str
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    is_active: bool = True
    email: str | None = None
    last_login_at: datetime | None = None


class _FakeUserStore:
    """Drop-in replacement for the handful of core.auth.users functions that
    bootstrap.py and auth.py call by name, backed by a plain dict instead of
    Postgres. Reset per-test via the fresh_user_store fixture below so no
    state leaks between tests."""

    def __init__(self) -> None:
        self.users: dict[str, _FakeUser] = {}

    async def init_models(self) -> None:
        return None

    async def count_active_admins(self, session=None) -> int:
        return sum(1 for u in self.users.values() if u.role == "admin" and u.is_active)

    async def get_user_by_username(self, session, username: str) -> _FakeUser | None:
        return self.users.get(username)

    async def create_user(
        self,
        session,
        *,
        username: str,
        password: str,
        role: str = "operator",
        email: str | None = None,
    ) -> _FakeUser:
        user = _FakeUser(
            username=username,
            password_hash=users_module.hash_password(password),
            role=role,
            email=email,
        )
        self.users[username] = user
        return user

    async def create_first_admin(
        self, session, *, username: str, password: str, email: str | None = None
    ) -> _FakeUser:
        # Mirrors core.auth.users.create_first_admin: gate on the count and
        # the username, raise the same exceptions. The advisory lock is a
        # no-op here (single-threaded dict store); the real cross-process
        # behaviour is covered by test_bootstrap_concurrency.py.
        if await self.count_active_admins(session) > 0:
            raise users_module.FirstAdminExistsError()
        if await self.get_user_by_username(session, username) is not None:
            raise users_module.UsernameTakenError(username)
        return await self.create_user(
            session, username=username, password=password, role="admin", email=email
        )

    async def authenticate_user(
        self, session, username: str, password: str
    ) -> _FakeUser | None:
        user = self.users.get(username)
        if user is None or not user.is_active:
            return None
        if not users_module.verify_password(password, user.password_hash):
            return None
        return user

    async def record_login(self, session, user: _FakeUser) -> None:
        user.last_login_at = datetime.now(timezone.utc)


@dataclass
class _FakeSessionRow:
    sid: uuid.UUID = field(default_factory=uuid.uuid4)
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)


class _FakeSessionStore:
    """
    Drop-in replacement for core.auth.sessions.create_session() /
    resolve_live_session() — the pieces of the server-side session layer
    that /auth/login and the per-request session check touch. Needed since
    the P0 security remediation pass made login() raise (503) instead of
    silently degrading to a legacy token when session creation fails; a
    DB-backed login in these tests must now actually succeed at creating a
    session, not rely on that failure path.
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
    """No-op AsyncSession stand-in — the dict store has no real transaction."""

    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...
    async def flush(self) -> None: ...
    async def refresh(self, _obj) -> None: ...

    def get_bind(self):  # noqa: ANN201
        raise RuntimeError("fake session has no bind")


async def _fake_get_db_session() -> AsyncIterator[_FakeSession]:
    yield _FakeSession()


class _NullSession:
    """Stands in for the sessionmaker context used by auth.py's
    reverify_password() / _validate_credentials()."""

    async def __aenter__(self) -> _FakeSession:
        return _FakeSession()

    async def __aexit__(self, *exc_info: object) -> None:
        return None


def _fake_get_sessionmaker():
    """
    Replaces core.auth.users.get_sessionmaker(). auth.py's reverify_password()
    / _validate_credentials() call get_sessionmaker() directly (not via the
    get_db_session dependency), so it needs its own patch to avoid touching
    a real (unconfigured) DATABASE_URL in these tests.
    """
    return _NullSession


@pytest.fixture
def fresh_user_store(monkeypatch) -> _FakeUserStore:
    """
    Point bootstrap.py's module-level imports and auth.py's call-time
    imports at a fresh, empty fake store for the duration of one test.

    bootstrap.py imports count_active_admins/create_user/get_user_by_username
    /init_models at module load time, so they're patched on
    bootstrap_module directly. auth.py re-imports authenticate_user from
    core.auth.users inside each function call (see reverify_password() /
    _validate_credentials()), so patching users_module.authenticate_user is
    enough for those call sites to pick up the fake.
    """
    store = _FakeUserStore()
    session_store = _FakeSessionStore(store)

    monkeypatch.setattr(bootstrap_module, "count_active_admins", store.count_active_admins)
    monkeypatch.setattr(bootstrap_module, "create_first_admin", store.create_first_admin)
    monkeypatch.setattr(bootstrap_module, "init_models", store.init_models)
    monkeypatch.setattr(users_module, "authenticate_user", store.authenticate_user)
    monkeypatch.setattr(users_module, "record_login", store.record_login)
    monkeypatch.setattr(users_module, "get_sessionmaker", _fake_get_sessionmaker)
    # /auth/login creates a real server-side session for every DB-backed
    # login (see auth.py's _create_login_session()) — fake that out too, the
    # same way the user store is faked, rather than letting it fail.
    monkeypatch.setattr(sessions_module, "create_session", session_store.create_session)
    monkeypatch.setattr(sessions_module, "resolve_live_session", session_store.resolve_live_session)

    app.dependency_overrides[auth_deps_module.get_db_session] = _fake_get_db_session
    yield store
    app.dependency_overrides.pop(auth_deps_module.get_db_session, None)


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_status_reports_uninitialized_with_no_admins(client, fresh_user_store):
    response = client.get("/bootstrap/status")

    assert response.status_code == 200
    assert response.json() == {"initialized": False}


def test_admin_rejects_short_password(client, fresh_user_store):
    response = client.post(
        "/bootstrap/admin",
        json={"username": "pwtest", "password": "short"},
    )

    assert response.status_code == 422


def test_admin_rejects_missing_username(client, fresh_user_store):
    response = client.post(
        "/bootstrap/admin",
        json={"password": "a-perfectly-long-enough-password"},
    )

    assert response.status_code == 422


def test_first_run_flow_creates_admin_logs_in_and_reaches_protected_route(
    client, fresh_user_store
):
    """
    The full path test_bootstrap.py's live equivalent can no longer cover on
    this deployment: uninitialized -> create first admin -> status flips ->
    second create refused -> new admin logs in -> token works on a
    protected route.
    """
    assert client.get("/bootstrap/status").json()["initialized"] is False

    username = "bootstrap-isolated-admin"
    password = "a-perfectly-long-enough-password-123"

    create_response = client.post(
        "/bootstrap/admin",
        json={"username": username, "password": password},
    )
    assert create_response.status_code == 201, create_response.text
    body = create_response.json()
    assert body["username"] == username
    assert body["role"] == "admin"

    assert client.get("/bootstrap/status").json()["initialized"] is True

    second_response = client.post(
        "/bootstrap/admin",
        json={"username": "second-admin", "password": password},
    )
    assert second_response.status_code == 409

    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login_response.status_code == 200, login_response.text
    login_data = login_response.json()
    token = login_data["token"]
    assert login_data["subject"] == username

    verify_response = client.get(
        "/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["role"] == "admin"

    protected_response = client.get(
        PROTECTED_URL,
        headers={"Authorization": f"Bearer {token}", "X-S43-Password": password},
    )
    assert protected_response.status_code == 200, protected_response.text


__all__: list[str] = []
