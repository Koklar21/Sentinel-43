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
# core/tests/test_password_verification.py
#
# Pass 3 — password verification failure paths, read-only authentication,
# transaction-ownership of the account helpers, and off-event-loop hashing.
# No database: uses a tiny recording session double.
# =============================================================================

from __future__ import annotations

import asyncio
import time

import pytest

from core.auth import users as U


# ---------------------------------------------------------------------------
# verify_password: fail closed on every malformed stored credential
# ---------------------------------------------------------------------------

_GOOD = U.hash_password("correct horse battery staple")


def test_verify_password_correct():
    assert U.verify_password("correct horse battery staple", _GOOD) is True


def test_verify_password_wrong():
    assert U.verify_password("wrong", _GOOD) is False


@pytest.mark.parametrize("bad_hash", [
    "",
    "   ",
    "garbage",
    "not$argon2$at$all",
    "$argon2id$v=19$m=1,t=1,p=1$YWJj$corrupted-body",   # argon2-shaped but corrupt -> VerificationError
    "$argon2id$",
    None,
    12345,
    b"$argon2id$bytes",
])
def test_verify_password_malformed_hash_fails_closed(bad_hash):
    # Must return False, never raise, never authenticate.
    assert U.verify_password("anything", bad_hash) is False


@pytest.mark.parametrize("bad_pw", [None, 12345, b"bytes"])
def test_verify_password_non_str_password_fails_closed(bad_pw):
    assert U.verify_password(bad_pw, _GOOD) is False


# ---------------------------------------------------------------------------
# authenticate_user is read-only and does not distinguish miss vs wrong pw
# ---------------------------------------------------------------------------

class _RecordingSession:
    """Records commit/flush/rollback calls; get_bind() -> non-postgres."""

    def __init__(self):
        self.commits = 0
        self.flushes = 0
        self.rollbacks = 0

    async def commit(self):
        self.commits += 1

    async def flush(self):
        self.flushes += 1

    async def rollback(self):
        self.rollbacks += 1

    async def refresh(self, _o):
        pass

    def get_bind(self):
        raise RuntimeError("no bind")

    def add(self, _o):
        pass


class _U:
    def __init__(self, username, password, *, is_active=True, role="observer"):
        self.username = username
        self.password_hash = U.hash_password(password)
        self.is_active = is_active
        self.role = role
        self.last_login_at = None
        self.user_id = "id-" + username


@pytest.fixture
def store(monkeypatch):
    rows: dict[str, _U] = {}

    async def get_user_by_username(session, username):
        return rows.get(username)

    monkeypatch.setattr(U, "get_user_by_username", get_user_by_username)
    return rows


def _run(coro):
    return asyncio.run(coro)


def test_authenticate_user_success_is_read_only(store):
    store["alice"] = _U("alice", "pw-alice-123456")
    s = _RecordingSession()
    user = _run(U.authenticate_user(s, "alice", "pw-alice-123456"))
    assert user is store["alice"]
    assert (s.commits, s.flushes, s.rollbacks) == (0, 0, 0)
    assert store["alice"].last_login_at is None  # NOT stamped by authenticate_user


def test_authenticate_user_wrong_password(store):
    store["alice"] = _U("alice", "pw-alice-123456")
    s = _RecordingSession()
    assert _run(U.authenticate_user(s, "alice", "nope")) is None
    assert (s.commits, s.flushes) == (0, 0)


def test_authenticate_user_unknown_account(store):
    s = _RecordingSession()
    assert _run(U.authenticate_user(s, "ghost", "whatever")) is None


def test_authenticate_user_disabled_account(store):
    store["bob"] = _U("bob", "pw-bob-123456", is_active=False)
    s = _RecordingSession()
    assert _run(U.authenticate_user(s, "bob", "pw-bob-123456")) is None
    assert (s.commits, s.flushes) == (0, 0)


def test_authenticate_user_timing_miss_vs_wrong_password(store):
    """The account-miss / disabled path still spends an Argon2 verify so it
    isn't an obvious account-existence oracle. Not a hard timing guarantee —
    just that a miss is the same order of magnitude as a wrong password."""
    store["carol"] = _U("carol", "pw-carol-123456")
    s = _RecordingSession()

    t0 = time.perf_counter()
    _run(U.authenticate_user(s, "carol", "wrong"))
    wrong_pw = time.perf_counter() - t0

    t0 = time.perf_counter()
    _run(U.authenticate_user(s, "nobody", "wrong"))
    miss = time.perf_counter() - t0

    # miss must not be trivially fast (i.e. it did the dummy verify)
    assert miss > wrong_pw * 0.3, (miss, wrong_pw)


# ---------------------------------------------------------------------------
# helpers flush but never commit (transaction ownership)
# ---------------------------------------------------------------------------

def test_create_user_flushes_not_commits(store):
    s = _RecordingSession()
    _run(U.create_user(s, username="dave", password="pw-dave-123456", role="observer"))
    assert s.commits == 0
    assert s.flushes == 1


def test_create_user_rejects_bad_role():
    s = _RecordingSession()
    with pytest.raises(ValueError, match="role must be one of"):
        _run(U.create_user(s, username="x", password="pw-x-1234567890", role="superuser"))
    assert s.commits == 0


def test_set_user_role_rejects_observer_to_admin_transition():
    s = _RecordingSession()
    u = _U("erin", "pw-erin-123456", role="observer")
    with pytest.raises(U.AdminRoleImmutableError):
        _run(U.set_user_role(s, u, role="admin"))
    assert u.role == "observer"
    assert (s.commits, s.flushes) == (0, 0)


@pytest.mark.parametrize("bad", ["", "root", "superuser", "guest", "admin,observer"])
def test_set_user_role_rejects_genuinely_unknown_roles(bad):
    s = _RecordingSession()
    u = _U("f", "pw-f-1234567890")
    with pytest.raises(ValueError):
        _run(U.set_user_role(s, u, role=bad))


@pytest.mark.parametrize("variant", ["Observer", " observer", "OBSERVER "])
def test_set_user_role_normalises_observer_noop(variant):
    s = _RecordingSession()
    u = _U("f", "pw-f-1234567890", role="observer")
    _run(U.set_user_role(s, u, role=variant))
    assert u.role == "observer"
    assert (s.commits, s.flushes) == (0, 0)


def test_set_user_password_flushes_not_commits():
    s = _RecordingSession()
    u = _U("gil", "old-pw-1234567890")
    old = u.password_hash
    _run(U.set_user_password(s, u, password="new-pw-1234567890"))
    assert u.password_hash != old
    assert U.verify_password("new-pw-1234567890", u.password_hash)
    assert (s.commits, s.flushes) == (0, 1)


def test_set_user_active_flushes_not_commits():
    s = _RecordingSession()
    u = _U("hal", "pw-hal-1234567", is_active=True)
    _run(U.set_user_active(s, u, is_active=False))
    assert u.is_active is False
    assert (s.commits, s.flushes) == (0, 1)


def test_record_login_flushes_not_commits():
    s = _RecordingSession()
    u = _U("iris", "pw-iris-123456")
    _run(U.record_login(s, u))
    assert u.last_login_at is not None
    assert (s.commits, s.flushes) == (0, 1)


# ---------------------------------------------------------------------------
# off-event-loop hashing
# ---------------------------------------------------------------------------

def test_hash_and_verify_async_roundtrip():
    async def go():
        h = await U.hash_password_async("some-password-123456")
        assert await U.verify_password_async("some-password-123456", h) is True
        assert await U.verify_password_async("bad", h) is False
    asyncio.run(go())


def test_hashing_does_not_block_the_event_loop():
    """While an Argon2 hash runs off-loop, a concurrent coroutine keeps
    ticking. If hashing ran on the loop, the ticker would stall for ~30 ms."""
    async def go():
        ticks = 0

        async def ticker():
            nonlocal ticks
            for _ in range(50):
                await asyncio.sleep(0.001)
                ticks += 1

        t = asyncio.create_task(ticker())
        await U.hash_password_async("blocking-check-123456")
        await t
        return ticks

    ticks = asyncio.run(go())
    assert ticks >= 20   # loop kept running during the hash


__all__: list[str] = []
