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

"""FastAPI dependencies for Sentinel-43 account persistence."""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from .users import count_active_admins, get_sessionmaker


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """Yield one request-scoped database session."""
    sessionmaker = get_sessionmaker()

    async with sessionmaker() as session:
        try:
            yield session

        except Exception:
            await session.rollback()
            raise


async def require_initialized(
    session: AsyncSession = Depends(get_db_session),
) -> AsyncSession:
    """Require at least one active administrator."""
    if await count_active_admins(session) == 0:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sentinel-43 has not been initialized.",
        )

    return session


__all__ = [
    "get_db_session",
    "require_initialized",
]
