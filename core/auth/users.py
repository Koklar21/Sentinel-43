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

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from sqlalchemy import Boolean, DateTime, String, Uuid, func, select
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
# =============================================================================

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHash):
        return False


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


async def create_user(
    session: AsyncSession,
    *,
    username: str,
    password: str,
    role: str = "operator",
    email: str | None = None,
) -> User:
    if role not in APPROVED_ROLES:
        raise ValueError(f"role must be one of {sorted(APPROVED_ROLES)}")

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def authenticate_user(
    session: AsyncSession, username: str, password: str, *, update_last_login: bool = True
) -> Optional[User]:
    """
    Returns the User on success, None on any failure (unknown username,
    inactive account, or wrong password) — callers must not distinguish
    these cases in the response they send to the client.

    update_last_login=False skips the last_login_at write/commit. Used by
    core.api.routers.auth.reverify_password(), which calls this on every
    protected request (not just at login) to satisfy the per-request
    password re-verification gate — without this flag, that would mean an
    Argon2 verify plus a DB write on every single request, and
    "last_login_at" would stop meaning "last login".
    """
    user = await get_user_by_username(session, username)
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None

    if update_last_login:
        user.last_login_at = datetime.now(timezone.utc)
        await session.commit()
    return user


async def set_user_active(
    session: AsyncSession, user: User, *, is_active: bool
) -> User:
    """Deactivate (is_active=False) or reactivate an account. A deactivated
    user cannot log in and cannot pass reverify_password() on subsequent
    requests — authenticate_user() rejects `not user.is_active` before the
    password is even checked."""
    user.is_active = is_active
    await session.commit()
    await session.refresh(user)
    return user


async def set_user_role(session: AsyncSession, user: User, *, role: str) -> User:
    if role not in APPROVED_ROLES:
        raise ValueError(f"role must be one of {sorted(APPROVED_ROLES)}")
    user.role = role
    await session.commit()
    await session.refresh(user)
    return user


async def set_user_password(
    session: AsyncSession, user: User, *, password: str
) -> User:
    """Overwrite the stored Argon2id hash. Used by the admin password-reset
    endpoint; there is no self-service "change my password" flow yet."""
    user.password_hash = hash_password(password)
    await session.commit()
    await session.refresh(user)
    return user


__all__ = [
    "APPROVED_ROLES",
    "Base",
    "User",
    "authenticate_user",
    "count_active_admins",
    "create_user",
    "get_engine",
    "get_sessionmaker",
    "get_user_by_id",
    "get_user_by_username",
    "hash_password",
    "init_models",
    "list_users",
    "set_user_active",
    "set_user_password",
    "set_user_role",
    "verify_password",
]
