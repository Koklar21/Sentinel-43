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
# core/api/routers/users.py
#
# Admin-managed operator/admin accounts.
#
# Provides (all gated by require_admin — an authenticated operator whose
# users-table row is an active 'admin'; see core/api/deps/deps.py):
#   POST   /users                  — create an operator or admin account
#   GET    /users                  — list all accounts
#   PATCH  /users/{user_id}        — deactivate/reactivate, or change role
#   POST   /users/{user_id}/password — reset an account's password
#
# This is the supported path for adding users after first-run setup.
# /bootstrap/admin (core/api/routers/bootstrap.py) only ever creates the
# FIRST admin and then refuses forever; every account after that is created
# here by an existing admin. There is intentionally no public self-service
# registration — this is a security console, not a signup form.
#
# Guard rails enforced here (not in core/auth/users.py, which stays a thin
# data layer):
#   - an admin cannot deactivate their own account (log out instead)
#   - the last active admin cannot be deactivated or demoted, so a
#     deployment can never be left with zero admins and no way back in
#     short of raw SQL. Self-demotion IS allowed while another admin remains.
#
# Known gap (same shape as core/api/routers/bootstrap.py's): the last-admin
# check reads count_active_admins() and then writes without a DB-level lock,
# so two concurrent PATCHes each demoting a different one of the final two
# admins could both pass the check before either commits. Low severity — a
# deliberate multi-admin action on a single deployment — and closing it
# needs an advisory lock; not done here.
# =============================================================================

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
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

# require_admin gates the whole router. Routes that need the caller's
# identity (update_account, for the self-deactivation guard) also take it as
# an explicit parameter — FastAPI runs the dependency once either way.
router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_admin)],
)

MAX_USERNAME_LEN = 128
MIN_PASSWORD_LEN = 12  # keep in sync with core/api/routers/bootstrap.py
MAX_PASSWORD_LEN = 1024
MAX_EMAIL_LEN = 255


# =============================================================================
# Models
# =============================================================================

class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=MAX_USERNAME_LEN)
    password: str = Field(..., min_length=MIN_PASSWORD_LEN, max_length=MAX_PASSWORD_LEN)
    role: str = Field(default="operator")
    email: str | None = Field(default=None, max_length=MAX_EMAIL_LEN)


class UpdateUserRequest(BaseModel):
    is_active: bool | None = Field(default=None)
    role: str | None = Field(default=None)


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(
        ..., min_length=MIN_PASSWORD_LEN, max_length=MAX_PASSWORD_LEN
    )


class UserResponse(BaseModel):
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
    return UserResponse(
        user_id=str(user.user_id),
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=bool(user.is_active),
        created_at=user.created_at.isoformat() if user.created_at is not None else "",
        last_login_at=(
            user.last_login_at.isoformat() if user.last_login_at is not None else None
        ),
    )


def _validate_role(role: str) -> str:
    if role not in APPROVED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"role must be one of {sorted(APPROVED_ROLES)}.",
        )
    return role


def _parse_user_id(raw: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(raw))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_id must be a UUID.",
        )


async def _would_orphan_admins(
    session: AsyncSession,
    target: User,
    *,
    new_is_active: bool | None,
    new_role: str | None,
) -> bool:
    """
    True if applying (new_is_active, new_role) to `target` would drop the
    deployment to zero active admins. Checked before the change is written.
    """
    if not (target.is_active and target.role == "admin"):
        return False

    effective_is_active = target.is_active if new_is_active is None else new_is_active
    effective_role = target.role if new_role is None else new_role
    if effective_is_active and effective_role == "admin":
        return False

    return await count_active_admins(session) <= 1


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
    """Create a new operator or admin account. Admin-only."""
    role = _validate_role(body.role)

    username = body.username.strip()
    if not username:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="username must not be blank.",
        )

    email = body.email.strip() if body.email else None

    if await get_user_by_username(session, username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        )

    try:
        user = await create_user(
            session,
            username=username,
            password=body.password,
            role=role,
            email=email,
        )
        await session.commit()
    except IntegrityError:
        # Unique-constraint race on username or email between the check above
        # and the flush inside create_user(). get_db_session() rolls back.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that username or email already exists.",
        )

    return _serialize(user)


@router.get("", response_model=list[UserResponse])
async def list_accounts(
    session: AsyncSession = Depends(get_db_session),
) -> list[UserResponse]:
    """List every account. Admin-only. Password hashes are never returned."""
    return [_serialize(u) for u in await list_users(session)]


@router.patch("/{user_id}", response_model=UserResponse)
async def update_account(
    user_id: str,
    body: UpdateUserRequest,
    admin: str = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """
    Deactivate/reactivate an account (is_active) and/or change its role.
    Admin-only. Refuses changes that would lock the caller out or remove
    the last remaining admin.
    """
    parsed_id = _parse_user_id(user_id)

    if body.is_active is None and body.role is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide at least one of: is_active, role.",
        )

    new_role = _validate_role(body.role) if body.role is not None else None

    target = await get_user_by_id(session, parsed_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account with that user_id.",
        )

    # Blanket footgun guard: deactivating your own account has no legitimate
    # use (just log out) and is an easy way to lock yourself out. Self-
    # *demotion* is allowed as long as another admin remains — that case is
    # covered by the last-admin check below, not here.
    if target.username == admin and body.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You cannot deactivate your own account.",
        )

    # If this change can move the active-admin count, serialize it against
    # every other admin-count-moving operation (including POST /bootstrap/admin)
    # with the same advisory lock, so the last-admin check below reads a count
    # nobody else can change until we commit or roll back. Without this, two
    # concurrent PATCHes each demoting a different one of the final two admins
    # both see count==2 and both succeed, leaving zero admins.
    touches_admin_count = (
        (body.is_active is not None and target.role == "admin")
        or (new_role is not None and (target.role == "admin" or new_role == "admin"))
    )
    if touches_admin_count:
        await _pg_advisory_xact_lock(session, ADMIN_INVARIANT_LOCK_KEY)

    if await _would_orphan_admins(
        session, target, new_is_active=body.is_active, new_role=new_role
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot deactivate or demote the last active admin.",
        )

    if new_role is not None and new_role != target.role:
        target = await set_user_role(session, target, role=new_role)
    if body.is_active is not None and bool(body.is_active) != bool(target.is_active):
        target = await set_user_active(session, target, is_active=body.is_active)

    await session.commit()
    return _serialize(target)


@router.post("/{user_id}/password", response_model=UserResponse)
async def reset_account_password(
    user_id: str,
    body: ResetPasswordRequest,
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Set a new password for an account. Admin-only."""
    parsed_id = _parse_user_id(user_id)

    target = await get_user_by_id(session, parsed_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account with that user_id.",
        )

    target = await set_user_password(session, target, password=body.new_password)
    await session.commit()
    return _serialize(target)


__all__ = ["router"]
