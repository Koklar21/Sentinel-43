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

from fastapi import APIRouter


router = APIRouter(
    prefix="/audit",
    tags=["audit"],
)


@router.get("/health")
def audit_health() -> dict[str, str]:
    return {
        "status": "ok",
        "module": "audit",
    }


__all__ = ["router"]
