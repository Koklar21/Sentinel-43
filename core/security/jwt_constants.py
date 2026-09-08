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

"""Canonical JWT signing-algorithm allowlist."""

from __future__ import annotations

from typing import Final


APPROVED_JWT_ALGORITHMS: Final[frozenset[str]] = frozenset(
    {
        "HS256",
    }
)


__all__ = [
    "APPROVED_JWT_ALGORITHMS",
]
