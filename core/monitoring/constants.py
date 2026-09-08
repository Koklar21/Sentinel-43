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

"""Monitoring defaults for Sentinel-43."""

from typing import Final

DEFAULT_WATCHTOWER_PORT: Final[int] = 9200
DEFAULT_SENSITIVITY: Final[int] = 5
DEFAULT_ENVIRONMENT: Final[str] = "production"

__all__ = [
    "DEFAULT_ENVIRONMENT",
    "DEFAULT_SENSITIVITY",
    "DEFAULT_WATCHTOWER_PORT",
]
