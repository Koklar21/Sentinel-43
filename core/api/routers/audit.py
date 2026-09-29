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

"""Sentinel-43 audit router health endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status

from ..deps import get_audit_health_status


router = APIRouter(
    prefix="/audit",
    tags=["audit"],
)


@router.get("/health")
def audit_health(
    response: Response,
    audit_store_health: str = Depends(get_audit_health_status),
) -> dict[str, str]:
    healthy = audit_store_health == "healthy"
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if healthy else "unhealthy",
        "module": "audit",
        "audit_store_health": audit_store_health,
    }


__all__ = ["router"]
