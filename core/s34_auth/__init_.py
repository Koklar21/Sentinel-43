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
# 1. GNU Affero General Public License (AGPL v3.0)
# for open-source use, modification, and distribution.
#
# 2. Commercial License
# for proprietary, enterprise, government, or other commercial use
# not permitted under the AGPL v3.0.
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
"""

from __future__ import annotations

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

# Fenrir auth integration
try:
    from .fenrir_auth import (
        FenrirAuthConfig,
        FenrirAuthManager,
        configure_fenrir_auth,
        get_fenrir_auth_manager,
        is_fenrir_auth_configured,
    )
except ImportError:
    FenrirAuthConfig = None
    FenrirAuthManager = None
    configure_fenrir_auth = None
    get_fenrir_auth_manager = None
    is_fenrir_auth_configured = None


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

    # Fenrir
    "FenrirAuthConfig",
    "FenrirAuthManager",
    "configure_fenrir_auth",
    "get_fenrir_auth_manager",
    "is_fenrir_auth_configured",

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
]
