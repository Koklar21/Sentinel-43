
"""
Sentinel-43 Authentication Module
Unified authentication interface
"""

from .manager import AuthManager
from .models import AuthContext, AuthResult
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    InvalidTokenError,
)

__all__ = [
    "AuthManager",
    "AuthContext",
    "AuthResult",
    "AuthenticationError",
    "AuthorizationError",
    "InvalidTokenError",
]