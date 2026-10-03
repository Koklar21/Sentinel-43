# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 local operator/admin account persistence.

Responsibilities:
    - SQLAlchemy user model
    - lazy async engine/sessionmaker creation
    - Argon2id hashing and verification
    - first-admin concurrency invariant
    - account lookup and mutation helpers

This module is framework-agnostic. HTTP translation belongs in API routers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Final

from argon2 import PasswordHasher
from argon2 import Type as Argon2Type
from argon2 import extract_parameters
from argon2.exceptions import InvalidHash, VerificationError
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    MetaData,
    String,
    Uuid,
    func,
    select,
    text,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

APPROVED_ROLES: Final[frozenset[str]] = frozenset(
    {"client", "observer", "admin"}
)

ADMIN_INVARIANT_LOCK_KEY: Final[int] = 0x5334334200000001

_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)
_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)

# Explicit Argon2id posture. Do not inherit library defaults silently.
ARGON2_TIME_COST: Final[int] = 3
ARGON2_MEMORY_COST_KIB: Final[int] = 65_536
ARGON2_PARALLELISM: Final[int] = 4
ARGON2_HASH_LEN: Final[int] = 32
ARGON2_SALT_LEN: Final[int] = 16

_ARGON2_MAX_ENCODED_LEN: Final[int] = 512
_ARGON2_MIN_MEMORY_COST_KIB: Final[int] = 8 * 1024
_ARGON2_MAX_MEMORY_COST_KIB: Final[int] = 1024 * 1024
_ARGON2_MIN_TIME_COST: Final[int] = 1
_ARGON2_MAX_TIME_COST: Final[int] = 32
_ARGON2_MIN_PARALLELISM: Final[int] = 1
_ARGON2_MAX_PARALLELISM: Final[int] = 16
_ARGON2_MIN_SALT_LEN: Final[int] = 16
_ARGON2_MIN_HASH_LEN: Final[int] = 16

_ARGON2ID_STRICT_RE: Final[re.Pattern[str]] = re.compile(
    r"^\$argon2id\$v=19\$m=[1-9][0-9]{0,9},t=[1-9][0-9]{0,4},p=[1-9][0-9]{0,3}"
    r"\$[A-Za-z0-9+/]{11,64}\$[A-Za-z0-9+/]{22,86}$"
)


# =============================================================================
# Exceptions
# =============================================================================

class AccountError(Exception):
    """Base for expected account-layer failures."""


class FirstAdminExistsError(AccountError):
    """Raised when first-admin bootstrap has already been completed."""


class BootstrapClaimUnavailableError(AccountError):
    """Raised when the first-admin claim cannot be serialized on this backend.

    Outside local/test the one-time claim is only accepted where concurrent
    claims are serialized (the PostgreSQL advisory lock). Refusing is safer
    than letting two racing claims both observe an empty account store.
    """


class UsernameTakenError(AccountError):
    def __init__(self, username: str) -> None:
        super().__init__(
            f"username already exists: {username!r}"
        )
        self.username = username


class LastAdminError(AccountError):
    """Raised when a mutation would remove the sole administrator."""


class AdminRoleImmutableError(AccountError):
    """Raised when normal account code attempts to create/change admin role."""


# =============================================================================
# SQLAlchemy model
# =============================================================================

NAMING_CONVENTION: Final[dict[str, str]] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(
        naming_convention=NAMING_CONVENTION
    )


class User(Base):
    __tablename__ = "users"

    __table_args__ = (
        CheckConstraint(
            "role IN ('client', 'observer', 'admin')",
            name="role",
        ),
        Index(
            "uq_users_single_admin",
            "role",
            unique=True,
            postgresql_where=text("role = 'admin'"),
            sqlite_where=text("role = 'admin'"),
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    username: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )

    email: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        nullable=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="observer",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(
            timezone.utc
        ),
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


# =============================================================================
# Environment / DB factory
# =============================================================================

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None
# Reentrant: get_sessionmaker() holds this while calling get_engine(), which
# re-acquires it. A plain Lock deadlocks on that first cold call.
_factory_lock = threading.RLock()


def _environment() -> str:
    raw = (
        os.getenv("SENTINEL_ENV")
        or os.getenv("S43_ENV")
        or "production"
    ).strip().lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "prod": "production",
        "stage": "staging",
    }

    return aliases.get(
        raw,
        raw,
    )


def _is_local() -> bool:
    return _environment() in _LOCAL_ENVIRONMENTS


def _env_bool(
    name: str,
    default: bool,
    *,
    strict: bool,
) -> bool:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    normalized = raw.strip().lower()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    if strict:
        raise RuntimeError(
            f"{name} must be boolean; got {raw!r}"
        )

    logger.warning(
        "Invalid boolean for %s=%r; using default %s",
        name,
        raw,
        default,
    )
    return default


def _database_url() -> str:
    url = os.getenv(
        "DATABASE_URL",
        "",
    ).strip()

    if not url:
        raise RuntimeError(
            "DATABASE_URL is not configured"
        )

    if not url.startswith(
        (
            "postgresql+asyncpg://",
            "sqlite+aiosqlite://",
        )
    ):
        raise RuntimeError(
            "DATABASE_URL must use a supported async SQLAlchemy driver"
        )

    return url


def get_engine() -> AsyncEngine:
    global _engine

    if _engine is None:
        with _factory_lock:
            if _engine is None:
                _engine = create_async_engine(
                    _database_url(),
                    pool_pre_ping=True,
                )

    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker

    if _sessionmaker is None:
        with _factory_lock:
            if _sessionmaker is None:
                _sessionmaker = async_sessionmaker(
                    get_engine(),
                    expire_on_commit=False,
                )

    return _sessionmaker


async def dispose_engine() -> None:
    """Dispose the cached engine during application shutdown."""
    global _engine, _sessionmaker

    with _factory_lock:
        engine = _engine
        _engine = None
        _sessionmaker = None

    if engine is not None:
        await engine.dispose()


def clear_db_factories_for_tests() -> None:
    """Clear cached DB factories. Tests must dispose active engines first."""
    global _engine, _sessionmaker

    with _factory_lock:
        _engine = None
        _sessionmaker = None


def _schema_create_all_enabled() -> bool:
    """Permit create_all only as an explicit local/test convenience."""
    configured = os.getenv(
        "S43_SCHEMA_CREATE_ALL"
    )

    if configured is None:
        return _is_local()

    return _env_bool(
        "S43_SCHEMA_CREATE_ALL",
        False,
        strict=not _is_local(),
    )


async def init_models() -> None:
    """Create tables only when explicitly permitted in local/test environments."""
    if not _schema_create_all_enabled():
        logger.debug(
            "init_models(): create_all disabled; schema must be migrated externally"
        )
        return

    if not _is_local():
        raise RuntimeError(
            "S43_SCHEMA_CREATE_ALL is not permitted outside local/test"
        )

    engine = get_engine()

    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.create_all
        )


# =============================================================================
# Password hashing
# =============================================================================

_ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    type=Argon2Type.ID,
)

# Created from the exact same configured PasswordHasher used for real accounts.
_DUMMY_HASH = _ph.hash(
    "s43-timing-equalizer-not-a-real-password"
)


def hash_password(
    password: str,
) -> str:
    if not isinstance(
        password,
        str,
    ) or not password:
        raise ValueError(
            "password must not be empty"
        )

    return _ph.hash(
        password
    )


def verify_password(
    password: str,
    password_hash: str,
) -> bool:
    try:
        return bool(
            _ph.verify(
                password_hash,
                password,
            )
        )

    except (
        VerificationError,
        InvalidHash,
        TypeError,
        AttributeError,
    ):
        return False


async def hash_password_async(
    password: str,
) -> str:
    return await asyncio.to_thread(
        hash_password,
        password,
    )


async def verify_password_async(
    password: str,
    password_hash: str,
) -> bool:
    return await asyncio.to_thread(
        verify_password,
        password,
        password_hash,
    )


def is_valid_argon2id_hash(
    value: object,
) -> bool:
    """Validate configured Argon2id hashes before handing them to verification."""
    if (
        not isinstance(
            value,
            str,
        )
        or not value
        or len(
            value
        )
        > _ARGON2_MAX_ENCODED_LEN
    ):
        return False

    if not _ARGON2ID_STRICT_RE.fullmatch(
        value
    ):
        return False

    try:
        params = extract_parameters(
            value
        )
    except Exception:
        return False

    if params.type is not Argon2Type.ID:
        return False

    if not (
        _ARGON2_MIN_MEMORY_COST_KIB
        <= params.memory_cost
        <= _ARGON2_MAX_MEMORY_COST_KIB
    ):
        return False

    if not (
        _ARGON2_MIN_TIME_COST
        <= params.time_cost
        <= _ARGON2_MAX_TIME_COST
    ):
        return False

    if not (
        _ARGON2_MIN_PARALLELISM
        <= params.parallelism
        <= _ARGON2_MAX_PARALLELISM
    ):
        return False

    if params.salt_len < _ARGON2_MIN_SALT_LEN:
        return False

    if params.hash_len < _ARGON2_MIN_HASH_LEN:
        return False

    return True


# =============================================================================
# Queries
# =============================================================================

async def count_active_admins(
    session: AsyncSession,
) -> int:
    result = await session.execute(
        select(
            func.count()
        )
        .select_from(
            User
        )
        .where(
            User.role == "admin",
            User.is_active.is_(
                True
            ),
        )
    )

    return int(
        result.scalar_one()
    )


async def bootstrap_claimed(
    session: AsyncSession,
) -> bool:
    """True once the first-admin claim has committed.

    The claim creates the first account in an empty store, and no code path
    deletes accounts (they are deactivated or demoted instead), so "any
    account exists" records that bootstrap has completed. Unlike the
    active-admin count, it does not revert when every admin is deactivated --
    that state is a lockout to recover, not a fresh install. It is not a
    separate consumed-bootstrap marker: deleting every account row directly
    in the database reopens bootstrap.
    """
    result = await session.execute(
        select(
            User.user_id
        ).limit(
            1
        )
    )

    return result.scalar_one_or_none() is not None


async def get_user_by_username(
    session: AsyncSession,
    username: str,
) -> User | None:
    result = await session.execute(
        select(
            User
        ).where(
            User.username
            == username
        )
    )

    return result.scalar_one_or_none()


async def get_user_by_id(
    session: AsyncSession,
    user_id: uuid.UUID,
) -> User | None:
    result = await session.execute(
        select(
            User
        ).where(
            User.user_id
            == user_id
        )
    )

    return result.scalar_one_or_none()


async def list_users(
    session: AsyncSession,
    *,
    limit: int = 500,
) -> list[User]:
    if not 1 <= limit <= 500:
        raise ValueError(
            "limit must be between 1 and 500"
        )

    result = await session.execute(
        select(
            User
        )
        .order_by(
            User.created_at,
            User.user_id,
        )
        .limit(
            limit
        )
    )

    return list(
        result.scalars().all()
    )


# =============================================================================
# Concurrency invariant
# =============================================================================

async def _pg_advisory_xact_lock(
    session: AsyncSession,
    key: int,
) -> bool:
    """Take a transaction-scoped advisory lock; False when none was taken."""
    try:
        bind = session.get_bind()
        dialect_name = bind.dialect.name
    except Exception:
        dialect_name = ""

    if dialect_name != "postgresql":
        return False

    await session.execute(
        text(
            "SELECT pg_advisory_xact_lock(:key)"
        ),
        {
            "key": key
        },
    )
    return True


# =============================================================================
# Mutations
# =============================================================================

def _validate_role(
    role: str,
) -> str:
    normalized = str(
        role
    ).strip().lower()

    if normalized not in APPROVED_ROLES:
        raise ValueError(
            f"role must be one of {sorted(APPROVED_ROLES)}"
        )

    return normalized


async def create_user(
    session: AsyncSession,
    *,
    username: str,
    password: str,
    role: str = "observer",
    email: str | None = None,
) -> User:
    normalized_role = _validate_role(
        role
    )
    if normalized_role == "admin":
        raise AdminRoleImmutableError(
            "administrator role may only be created by first-run bootstrap"
        )

    user = User(
        username=username,
        email=email,
        password_hash=await hash_password_async(
            password
        ),
        role=normalized_role,
    )

    session.add(
        user
    )
    await session.flush()

    return user


async def create_first_admin(
    session: AsyncSession,
    *,
    username: str,
    password: str,
    email: str | None = None,
) -> User:
    locked = await _pg_advisory_xact_lock(
        session,
        ADMIN_INVARIANT_LOCK_KEY,
    )

    # Closed once any account exists -- not merely while an active admin
    # exists -- so deactivating every admin cannot reopen it.
    if await bootstrap_claimed(
        session
    ):
        raise FirstAdminExistsError()

    if not locked and not _is_local():
        raise BootstrapClaimUnavailableError()

    if await get_user_by_username(
        session,
        username,
    ) is not None:
        raise UsernameTakenError(
            username
        )

    user = User(
        username=username,
        email=email,
        password_hash=await hash_password_async(
            password
        ),
        role="admin",
    )
    session.add(user)
    await session.flush()
    return user


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str,
) -> User | None:
    user = await get_user_by_username(
        session,
        username,
    )

    if (
        user is None
        or not user.is_active
    ):
        await verify_password_async(
            password,
            _DUMMY_HASH,
        )
        return None

    if not await verify_password_async(
        password,
        user.password_hash,
    ):
        return None

    return user


async def record_login(
    session: AsyncSession,
    user: User,
) -> None:
    user.last_login_at = (
        datetime.now(
            timezone.utc
        )
    )

    await session.flush()


async def set_user_active(
    session: AsyncSession,
    user: User,
    *,
    is_active: bool,
) -> User:
    user.is_active = bool(
        is_active
    )

    await session.flush()
    return user


async def set_user_role(
    session: AsyncSession,
    user: User,
    *,
    role: str,
) -> User:
    normalized = _validate_role(role)
    current = str(user.role).strip().lower()
    if normalized == current:
        return user
    if "admin" in {current, normalized}:
        raise AdminRoleImmutableError(
            "administrator role is immutable after first-run bootstrap"
        )
    user.role = normalized
    await session.flush()
    return user


async def set_user_password(
    session: AsyncSession,
    user: User,
    *,
    password: str,
) -> User:
    user.password_hash = (
        await hash_password_async(
            password
        )
    )

    await session.flush()
    return user


__all__ = [
    "ADMIN_INVARIANT_LOCK_KEY",
    "APPROVED_ROLES",
    "AccountError",
    "AdminRoleImmutableError",
    "Base",
    "BootstrapClaimUnavailableError",
    "FirstAdminExistsError",
    "LastAdminError",
    "NAMING_CONVENTION",
    "User",
    "UsernameTakenError",
    "_pg_advisory_xact_lock",
    "authenticate_user",
    "bootstrap_claimed",
    "clear_db_factories_for_tests",
    "count_active_admins",
    "create_first_admin",
    "create_user",
    "dispose_engine",
    "get_engine",
    "get_sessionmaker",
    "get_user_by_id",
    "get_user_by_username",
    "hash_password",
    "hash_password_async",
    "init_models",
    "is_valid_argon2id_hash",
    "list_users",
    "record_login",
    "set_user_active",
    "set_user_password",
    "set_user_role",
    "verify_password",
    "verify_password_async",
]
