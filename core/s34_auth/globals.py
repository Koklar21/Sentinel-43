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
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
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
Sentinel-43 S34 authentication globals.

File:
    core/s34_auth/globals.py

Purpose:
    Hold small process-local runtime references for the S34 auth layer.

Design rules:
    - Import-safe.
    - Dependency-light.
    - No FastAPI imports.
    - No JWT imports.
    - No environment reads.
    - No object construction at import time.
    - Thread-safe enough for local/private beta runtime wiring.

This module exists so API startup code can register auth-related runtime
objects without creating circular imports. Yes, a global registry is not
architecture poetry. It is a small, contained bridge, not a lifestyle.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(slots=True)
class AuthGlobalsSnapshot:
    """
    Read-only style snapshot of currently registered auth globals.
    """

    auth_manager_set: bool
    token_verifier_set: bool
    jwt_service_set: bool
    user_resolver_set: bool
    policy_engine_set: bool


_lock = threading.RLock()

_auth_manager: Optional[Any] = None
_token_verifier: Optional[Any] = None
_jwt_service: Optional[Any] = None
_user_resolver: Optional[Any] = None
_policy_engine: Optional[Any] = None


def set_auth_manager(manager: Any) -> None:
    """
    Register the active auth manager.
    """
    global _auth_manager
    with _lock:
        _auth_manager = manager


def get_auth_manager() -> Optional[Any]:
    """
    Return the active auth manager, if one has been registered.
    """
    with _lock:
        return _auth_manager


def clear_auth_manager() -> None:
    """
    Clear the registered auth manager.
    """
    global _auth_manager
    with _lock:
        _auth_manager = None


def set_token_verifier(verifier: Any) -> None:
    """
    Register the active token verifier.

    A verifier is expected to expose a callable verification surface, such as:
        verifier.verify(token)
    or be directly callable:
        verifier(token)
    """
    global _token_verifier
    with _lock:
        _token_verifier = verifier


def get_token_verifier() -> Optional[Any]:
    """
    Return the active token verifier, if one has been registered.
    """
    with _lock:
        return _token_verifier


def clear_token_verifier() -> None:
    """
    Clear the registered token verifier.
    """
    global _token_verifier
    with _lock:
        _token_verifier = None


def set_jwt_service(service: Any) -> None:
    """
    Register the active JWT service.
    """
    global _jwt_service
    with _lock:
        _jwt_service = service


def get_jwt_service() -> Optional[Any]:
    """
    Return the active JWT service, if one has been registered.
    """
    with _lock:
        return _jwt_service


def clear_jwt_service() -> None:
    """
    Clear the registered JWT service.
    """
    global _jwt_service
    with _lock:
        _jwt_service = None


def set_user_resolver(resolver: Any) -> None:
    """
    Register the active user resolver.

    A resolver is usually responsible for mapping validated token claims to a
    user/principal object.
    """
    global _user_resolver
    with _lock:
        _user_resolver = resolver


def get_user_resolver() -> Optional[Any]:
    """
    Return the active user resolver, if one has been registered.
    """
    with _lock:
        return _user_resolver


def clear_user_resolver() -> None:
    """
    Clear the registered user resolver.
    """
    global _user_resolver
    with _lock:
        _user_resolver = None


def set_policy_engine(engine: Any) -> None:
    """
    Register the active policy/permission engine.
    """
    global _policy_engine
    with _lock:
        _policy_engine = engine


def get_policy_engine() -> Optional[Any]:
    """
    Return the active policy/permission engine, if one has been registered.
    """
    with _lock:
        return _policy_engine


def clear_policy_engine() -> None:
    """
    Clear the registered policy/permission engine.
    """
    global _policy_engine
    with _lock:
        _policy_engine = None


def clear_auth_globals() -> None:
    """
    Clear all registered S34 auth globals.

    Useful for tests, reload flows, and clean shutdown.
    """
    global _auth_manager
    global _token_verifier
    global _jwt_service
    global _user_resolver
    global _policy_engine

    with _lock:
        _auth_manager = None
        _token_verifier = None
        _jwt_service = None
        _user_resolver = None
        _policy_engine = None


def get_auth_globals_snapshot() -> AuthGlobalsSnapshot:
    """
    Return a compact snapshot showing which globals are currently set.
    """
    with _lock:
        return AuthGlobalsSnapshot(
            auth_manager_set=_auth_manager is not None,
            token_verifier_set=_token_verifier is not None,
            jwt_service_set=_jwt_service is not None,
            user_resolver_set=_user_resolver is not None,
            policy_engine_set=_policy_engine is not None,
        )


def auth_globals_ready() -> bool:
    """
    Return True when the minimum useful auth globals are registered.

    For S34, token verification is the minimum critical piece.
    """
    with _lock:
        return _token_verifier is not None or _jwt_service is not None


__all__ = [
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
]


# =============================================================================
# Minimal self-tests
# =============================================================================

def _run_self_tests() -> None:  # pragma: no cover
    import unittest

    class AuthGlobalsTests(unittest.TestCase):
        def tearDown(self) -> None:
            clear_auth_globals()

        def test_defaults_empty(self) -> None:
            snapshot = get_auth_globals_snapshot()
            self.assertFalse(snapshot.auth_manager_set)
            self.assertFalse(snapshot.token_verifier_set)
            self.assertFalse(snapshot.jwt_service_set)
            self.assertFalse(snapshot.user_resolver_set)
            self.assertFalse(snapshot.policy_engine_set)
            self.assertFalse(auth_globals_ready())

        def test_token_verifier_ready(self) -> None:
            verifier = object()
            set_token_verifier(verifier)

            self.assertIs(get_token_verifier(), verifier)
            self.assertTrue(auth_globals_ready())

            snapshot = get_auth_globals_snapshot()
            self.assertTrue(snapshot.token_verifier_set)

        def test_clear_all(self) -> None:
            set_auth_manager(object())
            set_token_verifier(object())
            set_jwt_service(object())
            set_user_resolver(object())
            set_policy_engine(object())

            clear_auth_globals()

            snapshot = get_auth_globals_snapshot()
            self.assertFalse(snapshot.auth_manager_set)
            self.assertFalse(snapshot.token_verifier_set)
            self.assertFalse(snapshot.jwt_service_set)
            self.assertFalse(snapshot.user_resolver_set)
            self.assertFalse(snapshot.policy_engine_set)

    unittest.main(argv=["globals.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
'''

path = Path("/mnt/data/globals.py")
path.write_text(content, encoding="utf-8")
print(f"created {path}")
print(path.stat().st_size)
