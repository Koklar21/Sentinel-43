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
File: core/auth/deps.py

FastAPI-specific wiring for core/auth/users.py. Kept separate from
users.py deliberately — users.py has zero framework dependencies (it can
be imported by non-FastAPI code, e.g. a future CLI admin-creation tool)
while this module is allowed to depend on FastAPI/Starlette.

require_initialized() re-checks the database on every call rather than
caching the result at process startup: the whole point of the bootstrap
flow is that a fresh deployment starts with zero admins and transitions to
initialized via POST /bootstrap/admin without a server restart. A
startup-cached check would keep serving 409s (or worse, keep allowing
bootstrap) until the process was restarted.
"""

from __future__ import annotations

from typing import AsyncIterator

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from .users import count_active_admins, get_sessionmaker


async def get_db_session() -> AsyncIterator[AsyncSession]:
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        yield session


async def require_initialized(
    session: AsyncSession = Depends(get_db_session),
) -> AsyncSession:
    """
    Dependency for any route that must not run before the first admin
    account exists. Raises 409 rather than 401/403 — this is a deployment
    state problem, not a credentials problem.
    """
    if await count_active_admins(session) == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Sentinel-43 has not been initialized yet. "
                "POST /bootstrap/admin to create the first admin account."
            ),
        )
    return session


__all__ = ["get_db_session", "require_initialized"]
