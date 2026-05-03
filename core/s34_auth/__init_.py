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
