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

No operator identity exists before the first administrator account is created.
Outside local/dev/test, the one-time claim is therefore bound to a
deployment-owned bootstrap claim secret instead of being open to the first
network caller that reaches an empty account store.

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

The bootstrap claim token is not an operator credential and grants no access
after initialization. It only authorizes the one first-admin claim while the
account store is empty.
"""

from __future__ import annotations

import hmac
import os
from typing import Any, Final

from fastapi import APIRouter, Depends, HTTPException, Request, status
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
from ..origin_policy import is_local_environment, require_state_change_origin

router = APIRouter(
    prefix="/bootstrap",
    tags=["bootstrap"],
)

MAX_USERNAME_LEN: Final[int] = 128
MIN_PASSWORD_LEN: Final[int] = 12
MAX_PASSWORD_LEN: Final[int] = 1024
MAX_EMAIL_LEN: Final[int] = 255
BOOTSTRAP_TOKEN_HEADER: Final[str] = "X-S43-Bootstrap-Token"
BOOTSTRAP_TOKEN_ENV: Final[str] = "S43_BOOTSTRAP_CLAIM_TOKEN"
_MIN_BOOTSTRAP_TOKEN_LEN: Final[int] = 32

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
    claim_token_required: bool


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

def _require_bootstrap_claim(request: Request) -> None:
    """Authorize the first-admin claim without creating a pre-admin identity."""
    if is_local_environment():
        return

    expected = os.getenv(BOOTSTRAP_TOKEN_ENV, "")
    if len(expected) < _MIN_BOOTSTRAP_TOKEN_LEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "First-admin bootstrap is unavailable until "
                "S43_BOOTSTRAP_CLAIM_TOKEN is configured."
            ),
        )

    presented = request.headers.get(BOOTSTRAP_TOKEN_HEADER, "")
    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid first-admin bootstrap claim.",
        )


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
        ),
        claim_token_required=not is_local_environment(),
    )


@router.post(
    "/admin",
    response_model=BootstrapAdminResponse,
    status_code=status.HTTP_201_CREATED,
)
async def bootstrap_admin(
    body: BootstrapAdminRequest,
    request: Request,
    session: AsyncSession = Depends(
        get_db_session
    ),
    authority: Any = Depends(
        get_runtime_authority
    ),
) -> BootstrapAdminResponse:
    """Create the single first-run administrator account."""

    # Bootstrap is a state-changing browser operation just like login. Apply
    # the exact same Origin/Referer policy first so a deployment cannot create
    # the sole admin successfully and then reject that same browser at login.
    require_state_change_origin(request)
    _require_bootstrap_claim(request)

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
