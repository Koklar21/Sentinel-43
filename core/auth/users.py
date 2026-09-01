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
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
File: core/auth/users.py

Local operator/admin account system, backed by Postgres via SQLAlchemy's
async engine (asyncpg driver). This replaces the single S43_OPERATOR_USERNAME
/ S43_OPERATOR_PASSWORD_HASH env-var account with a real multi-row users
table, so the bootstrap flow (core/api/routers/bootstrap.py) can gate
first-run admin creation on count_active_admins() == 0 rather than assuming
exactly one operator identity exists.

Password hashing uses Argon2id (argon2-cffi) rather than the bare SHA-256
scheme the env-var path used — Argon2 is a memory-hard KDF designed for
credential storage; SHA-256 is not and was only ever a stopgap.

DATABASE_URL is read directly from the environment (postgresql+asyncpg://...,
see docker-compose.yml) rather than through core/config/settings.py's
Settings class, matching how core/api/main.py and core/bootstrap.py already
read their own config directly rather than going through that module.

The engine and sessionmaker are created lazily and cached at module level —
this file has zero import-time side effects (no DB connection attempted on
import), matching core/security/jwt_constants.py's zero-dependency stance.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError
from sqlalchemy import Boolean, DateTime, String, Uuid, func, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# =============================================================================
# Model
# =============================================================================

# Kept identical to _APPROVED_ROLES in core/api/main.py and
# core/api/routers/auth.py — a user row with any other role value is a data
# problem, not a new role, until those call sites are updated too.
APPROVED_ROLES: frozenset[str] = frozenset({"operator", "admin"})

# Stable 63-bit key for the bootstrap/last-admin advisory lock. Arbitrary but
# fixed forever: "S43B" (0x53343342) high word + a tag in the low word. Every
# process/replica that mutates the "how many active admins exist" invariant
# takes THIS lock, so first-admin creation and last-admin demotion/
# deactivation are serialized cluster-wide. See _pg_advisory_xact_lock().
ADMIN_INVARIANT_LOCK_KEY: int = 0x5334334200000001


# =============================================================================
# Account-layer exceptions — framework-agnostic (no HTTPException here; the
# routers translate these to status codes).
# =============================================================================

class AccountError(Exception):
    """Base for expected, caller-handled account-operation failures."""


class FirstAdminExistsError(AccountError):
    """create_first_admin() found an active admin already — initialization is done."""


class UsernameTakenError(AccountError):
    def __init__(self, username: str) -> None:
        super().__init__(f"username already exists: {username!r}")
        self.username = username


class LastAdminError(AccountError):
    """The change would leave the deployment with zero active admins."""


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    email: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="operator")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


# =============================================================================
# Engine / session factory
# =============================================================================

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Expected "
            "postgresql+asyncpg://s43:<password>@s43-db:5432/s43 — see "
            "docker-compose.yml."
        )
    return url


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(_database_url(), pool_pre_ping=True)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def init_models() -> None:
    """
    Create the users table if it doesn't exist yet. Idempotent — safe to
    call on every startup. There is no migration tool in this project yet;
    this is create-if-missing, not a schema migration path.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# =============================================================================
# Password hashing
#
# Argon2id is memory-hard by design (~34 ms / ~64 MiB per hash or verify with
# the argon2-cffi defaults). Running that on the asyncio event loop stalls the
# whole worker for the duration, and reverify_password() calls verify on EVERY
# protected request — so the async helpers below push the work to a bounded
# thread pool (asyncio.to_thread -> the default ThreadPoolExecutor,
# max_workers = min(32, cpu+4)). The sync functions are kept for non-async
# callers (e.g. a future CLI) and for tests.
# =============================================================================

_ph = PasswordHasher()

# Fixed dummy hash. authenticate_user() verifies against this on the
# account-miss / inactive path so an unknown or disabled account does not
# return visibly faster than a wrong password on a real active account.
_DUMMY_HASH = _ph.hash("s43-timing-equalizer-not-a-real-password")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Pure predicate: True iff `password` matches `password_hash`. Any failure —
    wrong password, structurally invalid hash, corrupt hash body, a None/non-str
    stored value — returns False (fail closed), never raises. A malformed
    stored credential must not authenticate and must not crash the caller.
    """
    try:
        return _ph.verify(password_hash, password)
    except (VerificationError, InvalidHash, TypeError, AttributeError):
        return False


async def hash_password_async(password: str) -> str:
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, password_hash: str) -> bool:
    return await asyncio.to_thread(verify_password, password, password_hash)


# =============================================================================
# Queries
# =============================================================================

async def count_active_admins(session: AsyncSession) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(User)
        .where(User.role == "admin", User.is_active.is_(True))
    )
    return int(result.scalar_one())


async def get_user_by_username(session: AsyncSession, username: str) -> Optional[User]:
    result = await session.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_id(session: AsyncSession, user_id: uuid.UUID) -> Optional[User]:
    result = await session.execute(select(User).where(User.user_id == user_id))
    return result.scalar_one_or_none()


async def list_users(session: AsyncSession) -> list[User]:
    """All user rows, oldest first. Small table (operators/admins for one
    deployment), so no pagination — the admin UI shows the whole list."""
    result = await session.execute(select(User).order_by(User.created_at))
    return list(result.scalars().all())


# =============================================================================
# Transaction ownership
#
# The helpers below do NOT commit. They validate, mutate ORM state, and
# flush() only when they need a DB-assigned result or want an IntegrityError
# to surface inside the caller's transaction. The REQUEST / SERVICE that calls
# them owns the transaction: it commits on complete success and rolls back on
# any failure (core/auth/deps.py::get_db_session rolls back on exception;
# routers commit explicitly). This lets a caller compose several helper calls
# into one atomic operation — e.g. PATCH /users changing role AND is_active is
# now one transaction, not two.
# =============================================================================

async def _pg_advisory_xact_lock(session: AsyncSession, key: int) -> None:
    """
    Take a PostgreSQL transaction-scoped advisory lock (auto-released on
    COMMIT or ROLLBACK). Blocks until acquired. No-op on any non-PostgreSQL
    backend — advisory locks are a PostgreSQL feature and the in-memory fakes
    used by the isolated test suites don't model cross-process concurrency.
    """
    try:
        dialect = session.get_bind().dialect.name
    except Exception:
        dialect = ""
    if dialect != "postgresql":
        return
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": key})


async def create_user(
    session: AsyncSession,
    *,
    username: str,
    password: str,
    role: str = "operator",
    email: str | None = None,
) -> User:
    """Add a new user to `session` and flush (assigning user_id / created_at
    and surfacing a unique-constraint violation as IntegrityError now, inside
    the caller's transaction). Does NOT commit — the caller does."""
    if role not in APPROVED_ROLES:
        raise ValueError(f"role must be one of {sorted(APPROVED_ROLES)}")

    user = User(
        username=username,
        email=email,
        password_hash=await hash_password_async(password),
        role=role,
    )
    session.add(user)
    await session.flush()
    return user


async def create_first_admin(
    session: AsyncSession,
    *,
    username: str,
    password: str,
    email: str | None = None,
) -> User:
    """
    Create the first admin account, exactly once under concurrency.

    Serialized cluster-wide by ADMIN_INVARIANT_LOCK_KEY (a PostgreSQL
    transaction advisory lock): a second concurrent caller blocks on the lock
    until the first commits, then sees count_active_admins() > 0 and gets
    FirstAdminExistsError. The lock is held through the INSERT because neither
    this function nor create_user() commits — the caller (POST /bootstrap/admin)
    owns the transaction.

    Raises FirstAdminExistsError / UsernameTakenError; the caller maps both to
    409. Does NOT commit.
    """
    await _pg_advisory_xact_lock(session, ADMIN_INVARIANT_LOCK_KEY)

    if await count_active_admins(session) > 0:
        raise FirstAdminExistsError()
    if await get_user_by_username(session, username) is not None:
        raise UsernameTakenError(username)

    return await create_user(
        session, username=username, password=password, role="admin", email=email
    )


async def authenticate_user(
    session: AsyncSession, username: str, password: str
) -> Optional[User]:
    """
    Read-only. Returns the User on success; None on any failure (unknown
    username, inactive account, wrong password) — callers must not distinguish
    these to the client. Performs NO write and NO commit: recording a login
    timestamp is the caller's job (see
    core.api.routers.auth._validate_credentials).

    On the account-miss / inactive path it still performs one Argon2 verify
    (against a fixed dummy hash) so the response time does not obviously reveal
    whether an account exists or is active.
    """
    user = await get_user_by_username(session, username)
    if user is None or not user.is_active:
        await verify_password_async(password, _DUMMY_HASH)
        return None
    if not await verify_password_async(password, user.password_hash):
        return None
    return user


async def record_login(session: AsyncSession, user: User) -> None:
    """Stamp last_login_at = now on `user`. Does NOT commit — the login route
    commits. Only /auth/login calls this; the per-request reverify path
    (reverify_password) deliberately does not."""
    user.last_login_at = datetime.now(timezone.utc)
    await session.flush()


async def set_user_active(
    session: AsyncSession, user: User, *, is_active: bool
) -> User:
    """Deactivate (is_active=False) or reactivate an account. A deactivated
    user cannot log in and cannot pass reverify_password() on subsequent
    requests — authenticate_user() returns None for `not user.is_active`
    before the password is even checked. Does NOT commit."""
    user.is_active = is_active
    await session.flush()
    return user


async def set_user_role(session: AsyncSession, user: User, *, role: str) -> User:
    """Does NOT commit."""
    if role not in APPROVED_ROLES:
        raise ValueError(f"role must be one of {sorted(APPROVED_ROLES)}")
    user.role = role
    await session.flush()
    return user


async def set_user_password(
    session: AsyncSession, user: User, *, password: str
) -> User:
    """Overwrite the stored Argon2id hash. Used by the admin password-reset
    endpoint; there is no self-service "change my password" flow yet. Does
    NOT commit."""
    user.password_hash = await hash_password_async(password)
    await session.flush()
    return user


__all__ = [
    "ADMIN_INVARIANT_LOCK_KEY",
    "APPROVED_ROLES",
    "AccountError",
    "Base",
    "FirstAdminExistsError",
    "LastAdminError",
    "User",
    "UsernameTakenError",
    "authenticate_user",
    "count_active_admins",
    "create_first_admin",
    "create_user",
    "get_engine",
    "get_sessionmaker",
    "get_user_by_id",
    "get_user_by_username",
    "hash_password",
    "hash_password_async",
    "init_models",
    "list_users",
    "record_login",
    "set_user_active",
    "set_user_password",
    "set_user_role",
    "verify_password",
    "verify_password_async",
    "_pg_advisory_xact_lock",
]
