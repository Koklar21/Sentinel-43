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

"""Sentinel-43 API package."""

from __future__ import annotations

from typing import Any


__all__ = ["app"]


def __getattr__(name: str) -> Any:
    """Lazily expose the FastAPI application without importing main at package load."""
    if name == "app":
        from .main import app

        return app

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )
