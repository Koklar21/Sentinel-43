from typing import Optional

from .manager import AuthManager
from .exceptions import AuthenticationError


_auth_manager: Optional[AuthManager] = None


def configure_auth(manager: AuthManager):
    global _auth_manager
    _auth_manager = manager


def get_auth_manager() -> AuthManager:
    if _auth_manager is None:
        raise AuthenticationError("AuthManager not configured")

    return _auth_manager