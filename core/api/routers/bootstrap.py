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

"""Sentinel-43 first-run bootstrap routes.

These routes are intentionally unauthenticated because no operator identity
exists before the first administrator account is created.

Security invariants:
    - bootstrap may create exactly one initial active admin
    - concurrent bootstrap attempts are serialized by create_first_admin();
      outside local/test a backend that cannot serialize them refuses (503)
    - account creation is committed atomically; an interrupted claim leaves
      nothing behind and may be retried
    - schema/model initialization is owned by application startup, not by an
      unauthenticated HTTP request
    - bootstrap closes once the first account exists and no application path
      reopens it: deactivating or demoting every admin does NOT. It is not a
      separate consumed-bootstrap marker -- deleting every account row
      directly in the database reopens it

Open: the claim is not yet bound to a deployment authority -- whoever
reaches this route first on an empty store becomes the first admin. See
docs/BETA_RUNBOOK.md "Platform ownership".
"""

from __future__ import annotations

from typing import Any, Final

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from ...auth.deps import get_db_session
from ...auth.users import (
    BootstrapClaimUnavailableError,
    FirstAdminExistsError,
    UsernameTakenError,
    bootstrap_claimed,
)
from ..deps import get_runtime_authority

router = APIRouter(
    prefix="/bootstrap",
    tags=["bootstrap"],
)

MAX_USERNAME_LEN: Final[int] = 128
MIN_PASSWORD_LEN: Final[int] = 12
MAX_PASSWORD_LEN: Final[int] = 1024
MAX_EMAIL_LEN: Final[int] = 255


# =============================================================================
# Models
# =============================================================================

class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class BootstrapStatusResponse(StrictModel):
    initialized: bool


class BootstrapAdminRequest(StrictModel):
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
    email: str | None = Field(
        default=None,
        max_length=MAX_EMAIL_LEN,
    )

    @field_validator("username")
    @classmethod
    def validate_username(
        cls,
        value: str,
    ) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError(
                "username must not be blank"
            )

        return cleaned

    @field_validator("email")
    @classmethod
    def normalize_email(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip().lower()
        return cleaned or None


class BootstrapAdminResponse(StrictModel):
    username: str
    role: str


# =============================================================================
# Helpers
# =============================================================================

async def _rollback_safely(
    session: AsyncSession,
) -> None:
    try:
        await session.rollback()
    except Exception:
        # Bootstrap is a one-shot privileged path. If rollback itself fails,
        # propagate the original exception rather than hiding it behind
        # secondary logging behavior here.
        pass


# =============================================================================
# Routes
# =============================================================================

@router.get(
    "/status",
    response_model=BootstrapStatusResponse,
)
async def bootstrap_status(
    session: AsyncSession = Depends(
        get_db_session
    ),
) -> BootstrapStatusResponse:
    """Return whether the one-time first-admin claim has been completed."""
    return BootstrapStatusResponse(
        initialized=await bootstrap_claimed(
            session
        )
    )


@router.post(
    "/admin",
    response_model=BootstrapAdminResponse,
    status_code=status.HTTP_201_CREATED,
)
async def bootstrap_admin(
    body: BootstrapAdminRequest,
    session: AsyncSession = Depends(
        get_db_session
    ),
    authority: Any = Depends(
        get_runtime_authority
    ),
) -> BootstrapAdminResponse:
    """Create the single first-run administrator account."""

    try:
        user = await authority.identity.bootstrap_first_admin(
            session,
            username=body.username,
            password=body.password,
            email=body.email,
        )

    except FirstAdminExistsError as exc:
        await _rollback_safely(
            session
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Sentinel-43 is already initialized. "
                "Use the authenticated user-management API."
            ),
        ) from exc

    except UsernameTakenError as exc:
        await _rollback_safely(
            session
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        ) from exc

    except BootstrapClaimUnavailableError as exc:
        await _rollback_safely(
            session
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "First-admin bootstrap requires a PostgreSQL account store "
                "outside local/test."
            ),
        ) from exc

    except HTTPException:
        await _rollback_safely(
            session
        )
        raise

    except Exception:
        await _rollback_safely(
            session
        )
        raise

    return BootstrapAdminResponse(
        username=user.username,
        role=user.role,
    )


__all__ = ["router"]
