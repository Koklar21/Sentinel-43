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

"""Canonical browser-origin policy for Sentinel-43.

The dashboard, login/bootstrap state changes, WebSocket handshake, and CORS
configuration must agree on the same origin set. Keep the supported local
Compose origins here so separate modules cannot silently drift apart.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, status


LOCAL_ENVIRONMENTS = frozenset(
    {"development", "dev", "local", "test", "testing"}
)

DEFAULT_LOCAL_ALLOWED_ORIGINS = (
    "https://localhost",
    "https://127.0.0.1",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
)

LOOPBACK_HTTP_ORIGIN_RE = re.compile(
    r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"
)


def environment_name() -> str:
    raw = (
        os.getenv("SENTINEL_ENV")
        or os.getenv("S43_ENV")
        or "production"
    )
    return raw.strip().lower()


def is_local_environment() -> bool:
    return environment_name() in LOCAL_ENVIRONMENTS


def configured_allowed_origins() -> frozenset[str]:
    """Return the effective browser-origin set.

    Local/dev/test always includes the canonical loopback origins required by
    the supported HTTPS Compose dashboard. Explicit local entries are additive,
    so an older .env cannot accidentally remove https://localhost or
    https://127.0.0.1 and strand first-admin bootstrap behind its own Origin
    guard.

    Non-local environments remain explicit and fail closed: absent or blank
    configuration yields an empty set, and no localhost origin is injected.
    """
    raw = os.getenv("S43_ALLOWED_ORIGINS", "")
    configured = frozenset(
        origin.strip()
        for origin in raw.split(",")
        if origin.strip()
    )

    if is_local_environment():
        return frozenset(DEFAULT_LOCAL_ALLOWED_ORIGINS) | configured

    return configured


def require_state_change_origin(request: Request) -> None:
    """Require an allowed Origin/Referer before browser state changes."""
    allowed = configured_allowed_origins()
    local = is_local_environment()

    if not local:
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Allowed origins are not configured.",
            )
        if "*" in allowed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Wildcard origin is not permitted.",
            )

    origin = request.headers.get("origin", "").strip()

    if origin:
        if origin not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Origin not allowed.",
            )
        return

    referer = request.headers.get("referer", "").strip()

    if referer:
        parsed = urlsplit(referer)
        if not (parsed.scheme and parsed.netloc):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Referer not allowed.",
            )

        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Referer not allowed.",
            )
        return

    if not local:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Origin validation required.",
        )


__all__ = [
    "DEFAULT_LOCAL_ALLOWED_ORIGINS",
    "LOCAL_ENVIRONMENTS",
    "LOOPBACK_HTTP_ORIGIN_RE",
    "configured_allowed_origins",
    "environment_name",
    "is_local_environment",
    "require_state_change_origin",
]
