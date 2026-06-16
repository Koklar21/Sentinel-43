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
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
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
Sentinel-43 Authentication Module.
Unified authentication interface.

All exports are eager and required.

Fenrir is an active security hunting component. Its auth layer
(FenrirAuthConfig, FenrirAuthManager, etc.) is a hard dependency —
if .fenrir_auth cannot be imported, this package raises ImportError
at load time. Fenrir must not fail silently.
"""

from __future__ import annotations

import logging

from .constants import (
    ALLOWED_ALGORITHMS,
    AUTH_HEADER,
    BEARER_PREFIX,
    BEARER_SCHEME,
    DEFAULT_ALGORITHM,
    is_allowed_algorithm,
)
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ExpiredTokenError,
    InvalidSignatureError,
    InvalidTokenError,
    MFARequiredError,
    PermissionDeniedError,
    ReplayAttackError,
    SentinelSecurityError,
)
from .globals import configure_auth, get_auth_manager, is_auth_configured
from .manager import AuthManager
from .models import AuthContext, AuthResult

_logger = logging.getLogger("sentinel43.security.auth")


# =============================================================================
# Stable public API — always available
# =============================================================================

__all__ = [
    # Manager
    "AuthManager",
    # Models
    "AuthContext",
    "AuthResult",
    # Globals
    "configure_auth",
    "get_auth_manager",
    "is_auth_configured",
    # Exceptions
    "SentinelSecurityError",
    "AuthenticationError",
    "AuthorizationError",
    "ExpiredTokenError",
    "InvalidSignatureError",
    "InvalidTokenError",
    "MFARequiredError",
    "PermissionDeniedError",
    "ReplayAttackError",
    # Constants
    "AUTH_HEADER",
    "BEARER_SCHEME",
    "BEARER_PREFIX",
    "DEFAULT_ALGORITHM",
    "ALLOWED_ALGORITHMS",
    "is_allowed_algorithm",
    # Fenrir — active security hunting auth (hard dependency)
    "FenrirAuthConfig",
    "FenrirAuthManager",
    "configure_fenrir_auth",
    "get_fenrir_auth_manager",
    "is_fenrir_auth_configured",
]


# =============================================================================
# Fenrir auth — EAGER hard import
#
# Fenrir is an active security hunting component, not a passive observer.
# Its auth integration is NOT optional: if fenrir_auth cannot be imported,
# Sentinel-43 cannot perform active security hunting and must not start
# silently in a degraded state.
#
# Fail loud at package import time so the problem surfaces immediately
# rather than at the first hunt cycle.
#
# If you are running a deployment that intentionally excludes Fenrir
# (e.g. a stripped-down audit-only instance), create a stub fenrir_auth
# module that exports the same names rather than relying on silent fallback.
# =============================================================================

try:
    from .fenrir_auth import (
        FenrirAuthConfig,
        FenrirAuthManager,
        configure_fenrir_auth,
        get_fenrir_auth_manager,
        is_fenrir_auth_configured,
    )
except ImportError as _fenrir_exc:
    raise ImportError(
        "sentinel43.security.auth: Fenrir auth module failed to import. "
        "Fenrir is an active security hunting component — its auth layer is "
        "required for S43 to function. "
        f"Underlying error: {_fenrir_exc}. "
        "Ensure core/security/fenrir_auth.py and all its dependencies "
        "(pyjwt, aiohttp, etc.) are installed in this environment."
    ) from _fenrir_exc


def __dir__() -> list[str]:
    return sorted(__all__)
