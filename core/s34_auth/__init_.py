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

Eager exports (always available):
  AuthManager, AuthContext, AuthResult, all exceptions and constants.

Lazy exports (loaded on first access):
  FenrirAuthConfig, FenrirAuthManager, configure_fenrir_auth,
  get_fenrir_auth_manager, is_fenrir_auth_configured.

  These require .fenrir_auth to be importable (i.e. the fenrir sub-package
  and its dependencies must be installed). If the import fails, accessing any
  of these names raises AttributeError with an ImportWarning — not TypeError
  from a None value, and not a silent null in the caller's namespace.
"""

from __future__ import annotations

import importlib
import logging
import warnings
from typing import Any

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
]


# =============================================================================
# Lazy exports — optional Fenrir auth integration
#
# Why __getattr__ instead of try/except + None:
#
#   The original code set FenrirAuthConfig = None on ImportError, then listed
#   it in __all__. This caused two problems:
#
#     1. `from core.security.auth import *` exported None values into the
#        caller's namespace. Calling configure_fenrir_auth(...) then raised
#        TypeError: 'NoneType' is not callable — a confusing error with no
#        indication that Fenrir auth is unavailable.
#
#     2. The failure was completely silent (no warning, no log). A developer
#        expecting Fenrir auth to work would not discover the import failure
#        until the first auth call failed at runtime.
#
#   The __getattr__ pattern raises AttributeError (which Python converts to
#   "cannot import name X from core.security.auth") with an ImportWarning
#   that names the exact module and error. Callers get a clear failure at
#   import time rather than a silent null that explodes later.
# =============================================================================

_FENRIR_LAZY_NAMES: frozenset[str] = frozenset({
    "FenrirAuthConfig",
    "FenrirAuthManager",
    "configure_fenrir_auth",
    "get_fenrir_auth_manager",
    "is_fenrir_auth_configured",
})

_LAZY_EXPORTS: set[str] = set(_FENRIR_LAZY_NAMES)


def __getattr__(name: str) -> Any:
    if name in _FENRIR_LAZY_NAMES:
        try:
            mod = importlib.import_module(".fenrir_auth", __name__)
        except ImportError as exc:
            _logger.debug(
                "sentinel43.security.auth: Fenrir auth unavailable: %s", exc
            )
            warnings.warn(
                f"sentinel43.security.auth: optional Fenrir auth export {name!r} "
                f"is unavailable (.fenrir_auth could not be imported: {exc}). "
                "Ensure the Fenrir sub-package and its dependencies are installed.",
                ImportWarning,
                stacklevel=2,
            )
            raise AttributeError(
                f"module {__name__!r} has no attribute {name!r}"
            ) from None

        # Cache all available Fenrir names in one go
        found: list[str] = []
        for attr_name in _FENRIR_LAZY_NAMES:
            val = getattr(mod, attr_name, None)
            if val is not None:
                globals()[attr_name] = val
                found.append(attr_name)

        if name in globals():
            return globals()[name]

        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r} "
            f"(fenrir_auth loaded but {name!r} not found; "
            f"available: {found})"
        )

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted([*__all__, *_LAZY_EXPORTS])
