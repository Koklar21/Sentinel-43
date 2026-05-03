from __future__ import annotations

import threading

from .manager import AuthManager


_lock = threading.Lock()
_auth_manager: AuthManager | None = None


def configure_auth(manager: AuthManager) -> None:
    """
    Configure the global AuthManager instance.

    This function may only be called once during application startup.
    """

    if not isinstance(manager, AuthManager):
        raise TypeError(
            f"manager must be AuthManager, got {type(manager).__name__}"
        )

    global _auth_manager

    with _lock:
        if _auth_manager is not None:
            raise RuntimeError(
                "AuthManager is already configured"
            )

        _auth_manager = manager


def get_auth_manager() -> AuthManager:
    """
    Return the configured global AuthManager instance.
    """

    manager = _auth_manager

    if manager is None:
        raise RuntimeError(
            "AuthManager has not been configured"
        )

    return manager


def is_auth_configured() -> bool:
    """
    Return True if the global AuthManager is configured.
    """

    return _auth_manager is not None


def _reset_auth_for_tests() -> None:
    """
    Reset global auth state.

    Intended for test environments only.
    """

    global _auth_manager

    with _lock:
        _auth_manager = None
