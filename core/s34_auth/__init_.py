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
