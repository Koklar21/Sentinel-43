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
#
# core/api/routers/bootstrap.py
#
# First-run admin account setup.
#
# Provides:
#   GET  /bootstrap/status  — is Sentinel-43 initialized (any active admin)?
#   POST /bootstrap/admin   — create the first admin account
#
# Both routes are intentionally unauthenticated — there is no operator to
# authenticate as before the first admin exists. /bootstrap/admin is the
# only route in the codebase allowed to create an "admin" role account
# with no bearer token; it is self-gating instead: it refuses with 409 the
# instant count_active_admins() > 0, so it is only exploitable as a
# privilege-escalation path during the single-admin window between first
# deploy and first setup. Deployments should complete /bootstrap/admin
# immediately after bringing the stack up for exactly this reason.
#
# Known gap: two concurrent POST /bootstrap/admin requests during that
# window could both pass the count_active_admins() == 0 check before
# either commits, creating two admins instead of refusing the second.
# Not fixed here (would need a DB-level advisory lock or a dedicated
# single-row lock table) — low severity for a first-run-only endpoint,
# but worth closing before this is exposed on a multi-replica deployment.
# =============================================================================

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.deps import get_db_session
from ...auth.users import count_active_admins, create_user, get_user_by_username, init_models

router = APIRouter(prefix="/bootstrap", tags=["bootstrap"])

MAX_USERNAME_LEN = 128
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 1024
MAX_EMAIL_LEN = 255


# =============================================================================
# Models
# =============================================================================

class BootstrapStatusResponse(BaseModel):
    initialized: bool


class BootstrapAdminRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=MAX_USERNAME_LEN)
    password: str = Field(..., min_length=MIN_PASSWORD_LEN, max_length=MAX_PASSWORD_LEN)
    email: str | None = Field(default=None, max_length=MAX_EMAIL_LEN)


class BootstrapAdminResponse(BaseModel):
    username: str
    role: str


# =============================================================================
# Routes
# =============================================================================

@router.get("/status", response_model=BootstrapStatusResponse)
async def bootstrap_status(
    session: AsyncSession = Depends(get_db_session),
) -> BootstrapStatusResponse:
    """
    Report whether Sentinel-43 has an active admin yet. The dashboard uses
    this to decide whether to show the first-run setup screen or the
    normal login screen.
    """
    await init_models()
    admins = await count_active_admins(session)
    return BootstrapStatusResponse(initialized=admins > 0)


@router.post(
    "/admin",
    response_model=BootstrapAdminResponse,
    status_code=status.HTTP_201_CREATED,
)
async def bootstrap_admin(
    body: BootstrapAdminRequest,
    session: AsyncSession = Depends(get_db_session),
) -> BootstrapAdminResponse:
    """
    Create the first admin account. Refuses once any active admin exists —
    this is the only thing standing between this route and being an
    unauthenticated privilege-escalation endpoint.
    """
    await init_models()

    if await count_active_admins(session) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Sentinel-43 already has an active admin. /bootstrap/admin only works on first run.",
        )

    username = body.username.strip()
    if not username:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="username must not be blank.",
        )

    if await get_user_by_username(session, username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        )

    email = body.email.strip() if body.email else None
    user = await create_user(
        session,
        username=username,
        password=body.password,
        role="admin",
        email=email,
    )

    return BootstrapAdminResponse(username=user.username, role=user.role)


__all__ = ["router"]
