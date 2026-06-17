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
Sentinel-43 S34 Authentication Package.

Unified authentication interface for S34.

This package exposes:
    - constants
    - exceptions
    - auth models
    - AuthManager
    - token extraction helper
    - runtime auth globals
    - Fenrir auth integration

Fenrir is an active security hunting component. Its auth layer
(FenrirAuthConfig, FenrirAuthManager, etc.) is a hard dependency.

If .fenrir_auth cannot be imported, this package raises ImportError at
load time. Fenrir must not fail silently, because silent auth failure is how
software turns into a haunted vending machine.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

# =============================================================================
# Constants
# =============================================================================

from .constants import (
    ALLOWED_ALGORITHMS,
    AUTH_HEADER,
    BEARER_PREFIX,
    BEARER_SCHEME,
    DEFAULT_ALGORITHM,
    is_allowed_algorithm,
)

# =============================================================================
# Exceptions
# =============================================================================

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

# =============================================================================
# Models / manager
# =============================================================================

from .manager import AuthManager
from .models import AuthContext, AuthResult

# =============================================================================
# New S34 support files
# =============================================================================

from .extract_token import (
    AUTHORIZATION_HEADER,
    BEARER_SCHEME as EXTRACT_BEARER_SCHEME,
    extract_token,
)

from .globals import (
    AuthGlobalsSnapshot,
    auth_globals_ready,
    clear_auth_globals,
    clear_auth_manager,
    clear_jwt_service,
    clear_policy_engine,
    clear_token_verifier,
    clear_user_resolver,
    get_auth_globals_snapshot,
    get_auth_manager,
    get_jwt_service,
    get_policy_engine,
    get_token_verifier,
    get_user_resolver,
    set_auth_manager,
    set_jwt_service,
    set_policy_engine,
    set_token_verifier,
    set_user_resolver,
)


_logger = logging.getLogger("sentinel43.security.auth")


# =============================================================================
# Backward-compatible auth global helpers
# =============================================================================

def configure_auth(manager: AuthManager) -> None:
    """
    Register the active AuthManager.

    Backward-compatible wrapper around globals.set_auth_manager().
    """
    set_auth_manager(manager)


def is_auth_configured() -> bool:
    """
    Return True when the S34 auth layer has a useful runtime auth component.

    This remains compatible with older code that only checked for AuthManager,
    while also allowing the newer token verifier / JWT service globals.
    """
    return get_auth_manager() is not None or auth_globals_ready()


# =============================================================================
# Fenrir auth — EAGER hard import
#
# Fenrir is an active security hunting component, not a passive observer.
# Its auth integration is NOT optional: if fenrir_auth cannot be imported,
# Sentinel-43 cannot perform active security hunting and must not start
# silently in a degraded state.
#
# If you are running a deployment that intentionally excludes Fenrir
# (for example, a stripped-down audit-only instance), create a stub
# fenrir_auth module that exports the same names instead of relying on
# silent fallback.
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
        "Fenrir is an active security hunting component, so its auth layer is "
        "required for S43 to function. "
        f"Underlying error: {_fenrir_exc}. "
        "Ensure core/s34_auth/fenrir_auth.py and all required dependencies "
        "are installed in this environment."
    ) from _fenrir_exc


# =============================================================================
# Stable public API
# =============================================================================

__all__ = [
    # Manager
    "AuthManager",

    # Models
    "AuthContext",
    "AuthResult",

    # Token extraction
    "AUTHORIZATION_HEADER",
    "EXTRACT_BEARER_SCHEME",
    "extract_token",

    # Globals / runtime registry
    "AuthGlobalsSnapshot",
    "set_auth_manager",
    "get_auth_manager",
    "clear_auth_manager",
    "set_token_verifier",
    "get_token_verifier",
    "clear_token_verifier",
    "set_jwt_service",
    "get_jwt_service",
    "clear_jwt_service",
    "set_user_resolver",
    "get_user_resolver",
    "clear_user_resolver",
    "set_policy_engine",
    "get_policy_engine",
    "clear_policy_engine",
    "clear_auth_globals",
    "get_auth_globals_snapshot",
    "auth_globals_ready",

    # Backward-compatible globals
    "configure_auth",
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

    # Fenrir active security hunting auth
    "FenrirAuthConfig",
    "FenrirAuthManager",
    "configure_fenrir_auth",
    "get_fenrir_auth_manager",
    "is_fenrir_auth_configured",
]


def __dir__() -> list[str]:
    return sorted(__all__)
