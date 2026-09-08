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

"""Sentinel-43 admin-managed account routes.

All routes are admin-gated. This module owns account-management guard rails,
while the auth/users layer remains responsible for persistence primitives.

Security invariants:
    - no public self-service registration
    - caller cannot deactivate their own account
    - deployment may never lose its final active admin
    - role/active changes are committed atomically
    - security-sensitive account changes revoke live sessions in the same
      transaction and fail closed if revocation cannot be completed
"""

from __future__ import annotations

import logging
import uuid
from typing import Final

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.deps import get_db_session
from ...auth.users import (
    ADMIN_INVARIANT_LOCK_KEY,
    APPROVED_ROLES,
    User,
    _pg_advisory_xact_lock,
    count_active_admins,
    create_user,
    get_user_by_id,
    get_user_by_username,
    list_users,
    set_user_active,
    set_user_password,
    set_user_role,
)
from ..deps import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_admin)],
)

MAX_USERNAME_LEN: Final[int] = 128
MIN_PASSWORD_LEN: Final[int] = 12
MAX_PASSWORD_LEN: Final[int] = 1024
MAX_EMAIL_LEN: Final[int] = 255
MAX_LIST_USERS: Final[int] = 500


# =============================================================================
# Models
# =============================================================================

class StrictRequestModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class CreateUserRequest(StrictRequestModel):
    username: str = Field(
        ...,
        min_length=1,
        max_length=MAX_USERNAME_LEN,
    )
    password: str = Field(
        ...,
        min_length=MIN_PASSWORD_LEN,
        max_length=MAX_PASSWORD_LEN,
    )
    role: str = Field(default="operator")
    email: str | None = Field(
        default=None,
        max_length=MAX_EMAIL_LEN,
    )

    @field_validator("role")
    @classmethod
    def normalize_role(cls, value: str) -> str:
        cleaned = value.strip().lower()

        if cleaned not in APPROVED_ROLES:
            raise ValueError(
                f"role must be one of {sorted(APPROVED_ROLES)}"
            )

        return cleaned

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("username must not be blank")
        return cleaned

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str | None) -> str | None:
        if value is None:
            return None

        cleaned = value.strip().lower()
        return cleaned or None


class UpdateUserRequest(StrictRequestModel):
    is_active: bool | None = Field(default=None)
    role: str | None = Field(default=None)

    @field_validator("role")
    @classmethod
    def normalize_role(cls, value: str | None) -> str | None:
        if value is None:
            return None

        cleaned = value.strip().lower()

        if cleaned not in APPROVED_ROLES:
            raise ValueError(
                f"role must be one of {sorted(APPROVED_ROLES)}"
            )

        return cleaned

    @model_validator(mode="after")
    def require_change(self) -> "UpdateUserRequest":
        if self.is_active is None and self.role is None:
            raise ValueError(
                "Provide at least one of: is_active, role"
            )

        return self


class ResetPasswordRequest(StrictRequestModel):
    new_password: str = Field(
        ...,
        min_length=MIN_PASSWORD_LEN,
        max_length=MAX_PASSWORD_LEN,
    )


class UserResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        from_attributes=False,
    )

    user_id: str
    username: str
    email: str | None
    role: str
    is_active: bool
    created_at: str
    last_login_at: str | None


# =============================================================================
# Helpers
# =============================================================================

def _serialize(user: User) -> UserResponse:
    if user.created_at is None:
        # A persisted user without creation time is a data-integrity problem,
        # not something the API should quietly serialize as an empty string.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User record is incomplete.",
        )

    return UserResponse(
        user_id=str(user.user_id),
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=bool(user.is_active),
        created_at=user.created_at.isoformat(),
        last_login_at=(
            user.last_login_at.isoformat()
            if user.last_login_at is not None
            else None
        ),
    )


def _parse_user_id(raw: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(raw))
    except (ValueError, AttributeError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_id must be a UUID.",
        ) from exc


async def _revoke_sessions(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    reason: str,
) -> None:
    """Revoke every live session for a security-sensitive account change.

    This operation is part of the caller's transaction. Failure is fatal to the
    account mutation so the database cannot commit a password/role/active-state
    change while leaving stale authenticated sessions alive.
    """
    from ...auth.sessions import revoke_all_user_sessions

    try:
        await revoke_all_user_sessions(
            session,
            user_id,
            reason=reason,
        )
    except Exception as exc:
        logger.error(
            "Session revocation failed for user_id=%s reason=%s",
            user_id,
            reason,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session revocation service is unavailable.",
        ) from exc


async def _would_orphan_admins(
    session: AsyncSession,
    target: User,
    *,
    new_is_active: bool | None,
    new_role: str | None,
) -> bool:
    if not (
        bool(target.is_active)
        and str(target.role).lower() == "admin"
    ):
        return False

    effective_is_active = (
        bool(target.is_active)
        if new_is_active is None
        else bool(new_is_active)
    )

    effective_role = (
        str(target.role).lower()
        if new_role is None
        else new_role
    )

    if effective_is_active and effective_role == "admin":
        return False

    return await count_active_admins(session) <= 1


async def _rollback_safely(session: AsyncSession) -> None:
    try:
        await session.rollback()
    except Exception:
        logger.exception("User-management transaction rollback failed")


# =============================================================================
# Routes
# =============================================================================

@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_account(
    body: CreateUserRequest,
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Create a new operator/admin account."""

    # Friendly conflict pre-check. The DB uniqueness constraint remains the
    # authoritative race-safe enforcement.
    if await get_user_by_username(
        session,
        body.username,
    ) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        )

    try:
        user = await create_user(
            session,
            username=body.username,
            password=body.password,
            role=body.role,
            email=body.email,
        )
        await session.commit()

    except IntegrityError as exc:
        await _rollback_safely(session)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "An account with that username or email already exists."
            ),
        ) from exc

    except HTTPException:
        await _rollback_safely(session)
        raise

    except Exception:
        await _rollback_safely(session)
        raise

    return _serialize(user)


@router.get(
    "",
    response_model=list[UserResponse],
)
async def list_accounts(
    limit: int = Query(
        default=100,
        ge=1,
        le=MAX_LIST_USERS,
    ),
    session: AsyncSession = Depends(get_db_session),
) -> list[UserResponse]:
    """List admin-visible accounts with a bounded response size."""

    users = await list_users(session)
    return [
        _serialize(user)
        for user in users[:limit]
    ]


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
)
async def update_account(
    user_id: str,
    body: UpdateUserRequest,
    admin: str = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Update account activation state and/or role."""

    parsed_id = _parse_user_id(user_id)

    target = await get_user_by_id(
        session,
        parsed_id,
    )

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account with that user_id.",
        )

    if (
        target.username == admin
        and body.is_active is False
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You cannot deactivate your own account.",
        )

    new_role = body.role

    touches_admin_count = (
        (
            body.is_active is not None
            and str(target.role).lower() == "admin"
        )
        or (
            new_role is not None
            and (
                str(target.role).lower() == "admin"
                or new_role == "admin"
            )
        )
    )

    try:
        if touches_admin_count:
            await _pg_advisory_xact_lock(
                session,
                ADMIN_INVARIANT_LOCK_KEY,
            )

        if await _would_orphan_admins(
            session,
            target,
            new_is_active=body.is_active,
            new_role=new_role,
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Cannot deactivate or demote the last active admin."
                ),
            )

        role_changed = (
            new_role is not None
            and new_role != str(target.role).lower()
        )

        deactivated = (
            body.is_active is False
            and bool(target.is_active)
        )

        if role_changed:
            target = await set_user_role(
                session,
                target,
                role=new_role,
            )

        if (
            body.is_active is not None
            and bool(body.is_active) != bool(target.is_active)
        ):
            target = await set_user_active(
                session,
                target,
                is_active=body.is_active,
            )

        # Any role change or deactivation invalidates current authentication
        # context. Do this before commit in the same transaction.
        if deactivated:
            await _revoke_sessions(
                session,
                target.user_id,
                reason="account_disabled",
            )
        elif role_changed:
            await _revoke_sessions(
                session,
                target.user_id,
                reason="role_changed",
            )

        await session.commit()

    except HTTPException:
        await _rollback_safely(session)
        raise

    except IntegrityError as exc:
        await _rollback_safely(session)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account update conflicted with existing data.",
        ) from exc

    except Exception:
        await _rollback_safely(session)
        raise

    return _serialize(target)


@router.post(
    "/{user_id}/password",
    response_model=UserResponse,
)
async def reset_account_password(
    user_id: str,
    body: ResetPasswordRequest,
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Reset an account password and revoke every existing session."""

    parsed_id = _parse_user_id(user_id)

    target = await get_user_by_id(
        session,
        parsed_id,
    )

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account with that user_id.",
        )

    try:
        target = await set_user_password(
            session,
            target,
            password=body.new_password,
        )

        await _revoke_sessions(
            session,
            target.user_id,
            reason="password_reset",
        )

        await session.commit()

    except HTTPException:
        await _rollback_safely(session)
        raise

    except Exception:
        await _rollback_safely(session)
        raise

    return _serialize(target)


__all__ = ["router"]
