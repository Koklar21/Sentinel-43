# =============================================================================
# Sentinel-43
# Copyright (c) 2026 Justin Armstrong
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Explicitly gated open-beta client enrollment.

This endpoint creates only the non-governance client role. It cannot create
observers, administrators, or operators, and it is disabled unless the
deployment explicitly enables open-beta enrollment.
"""

from __future__ import annotations

import os
from typing import Any, Final

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.deps import get_db_session
from ...auth.users import (
    BootstrapClaimUnavailableError,
    EnrollmentBeforeBootstrapError,
    UsernameTakenError,
    get_user_by_username,
)
from ...security_context import client_ip_of
from ..deps import get_runtime_authority
from ..origin_policy import require_state_change_origin

router = APIRouter(prefix="/enrollment", tags=["enrollment"])

MAX_USERNAME_LEN: Final[int] = 128
MIN_PASSWORD_LEN: Final[int] = 12
MAX_PASSWORD_LEN: Final[int] = 1024
MAX_EMAIL_LEN: Final[int] = 255
_TRUE: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on", "enabled"})


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    username: str = Field(..., min_length=1, max_length=MAX_USERNAME_LEN)
    password: str = Field(..., min_length=MIN_PASSWORD_LEN, max_length=MAX_PASSWORD_LEN)
    email: str | None = Field(default=None, max_length=MAX_EMAIL_LEN)

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


class EnrollmentResponse(BaseModel):
    user_id: str
    username: str
    role: str


def _enrollment_enabled() -> bool:
    raw = os.getenv("S43_OPEN_BETA_ENROLLMENT", "").strip().lower()
    return raw in _TRUE


@router.post("", response_model=EnrollmentResponse, status_code=status.HTTP_201_CREATED)
async def enroll_client(
    body: EnrollmentRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    authority: Any = Depends(get_runtime_authority),
) -> EnrollmentResponse:
    require_state_change_origin(request)

    if not _enrollment_enabled():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Enrollment is not available.",
        )

    if await get_user_by_username(session, body.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account enrollment conflict.",
        )

    actor = f"open-beta:{client_ip_of(request)}"
    try:
        user = await authority.identity.create_client_account(
            session,
            actor=actor,
            username=body.username,
            password=body.password,
            email=body.email,
        )
    except EnrollmentBeforeBootstrapError as exc:
        try:
            await session.rollback()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Enrollment is unavailable until first-admin bootstrap completes.",
        ) from exc
    except BootstrapClaimUnavailableError as exc:
        try:
            await session.rollback()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enrollment serialization is unavailable.",
        ) from exc
    except (UsernameTakenError, IntegrityError) as exc:
        try:
            await session.rollback()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account enrollment conflict.",
        ) from exc

    return EnrollmentResponse(
        user_id=str(user.user_id),
        username=user.username,
        role="client",
    )


__all__ = ["router"]
