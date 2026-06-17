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
    core/security/auth/globals.py

Purpose:
    Hold small process-local runtime references for the S34 auth layer.

Design rules:
    - Import-safe.
    - Dependency-light.
    - No FastAPI imports.
    - No JWT imports.
    - No environment reads.
    - No object construction at import time.
    - Thread-safe for local/private beta runtime wiring.

This module exists so API startup code can register auth-related runtime
objects without creating circular imports. A global registry is not
architecture poetry — it is a small, contained bridge.

Changes from previous version:
  - Fix: AuthGlobalsSnapshot is now frozen=True. The docstring described it
    as "read-only style" but the dataclass was mutable. Callers could do
    snapshot.auth_manager_set = False without affecting the actual globals,
    which was confusing rather than dangerous. Now correctly immutable.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Optional


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


# Fix: frozen=True makes the snapshot genuinely read-only. The previous
# mutable dataclass contradicted the "read-only style" description.
@dataclass(frozen=True, slots=True)
class AuthGlobalsSnapshot:
    """
    Immutable snapshot of which auth globals are currently registered.
    Returned by get_auth_globals_snapshot(); does not affect live state.
    """

    auth_manager_set:   bool
    token_verifier_set: bool
    jwt_service_set:    bool
    user_resolver_set:  bool
    policy_engine_set:  bool


# =============================================================================
# Module-level globals and lock
# =============================================================================

_lock = threading.RLock()

_auth_manager:   Optional[Any] = None
_token_verifier: Optional[Any] = None
_jwt_service:    Optional[Any] = None
_user_resolver:  Optional[Any] = None
_policy_engine:  Optional[Any] = None


# =============================================================================
# auth_manager
# =============================================================================

def set_auth_manager(manager: Any) -> None:
    """Register the active auth manager."""
    global _auth_manager
    with _lock:
        _auth_manager = manager


def get_auth_manager() -> Optional[Any]:
    """Return the active auth manager, if one has been registered."""
    with _lock:
        return _auth_manager


def clear_auth_manager() -> None:
    """Clear the registered auth manager."""
    global _auth_manager
    with _lock:
        _auth_manager = None


# =============================================================================
# token_verifier
# =============================================================================

def set_token_verifier(verifier: Any) -> None:
    """
    Register the active token verifier.

    Expected interface:
        verifier.verify(token) -> AuthResult
    or callable:
        verifier(token) -> AuthResult
    """
    global _token_verifier
    with _lock:
        _token_verifier = verifier


def get_token_verifier() -> Optional[Any]:
    """Return the active token verifier, if one has been registered."""
    with _lock:
        return _token_verifier


def clear_token_verifier() -> None:
    """Clear the registered token verifier."""
    global _token_verifier
    with _lock:
        _token_verifier = None


# =============================================================================
# jwt_service
# =============================================================================

def set_jwt_service(service: Any) -> None:
    """Register the active JWT service."""
    global _jwt_service
    with _lock:
        _jwt_service = service


def get_jwt_service() -> Optional[Any]:
    """Return the active JWT service, if one has been registered."""
    with _lock:
        return _jwt_service


def clear_jwt_service() -> None:
    """Clear the registered JWT service."""
    global _jwt_service
    with _lock:
        _jwt_service = None


# =============================================================================
# user_resolver
# =============================================================================

def set_user_resolver(resolver: Any) -> None:
    """
    Register the active user resolver.

    A resolver maps validated token claims to a user/principal object.
    """
    global _user_resolver
    with _lock:
        _user_resolver = resolver


def get_user_resolver() -> Optional[Any]:
    """Return the active user resolver, if one has been registered."""
    with _lock:
        return _user_resolver


def clear_user_resolver() -> None:
    """Clear the registered user resolver."""
    global _user_resolver
    with _lock:
        _user_resolver = None


# =============================================================================
# policy_engine
# =============================================================================

def set_policy_engine(engine: Any) -> None:
    """Register the active policy/permission engine."""
    global _policy_engine
    with _lock:
        _policy_engine = engine


def get_policy_engine() -> Optional[Any]:
    """Return the active policy/permission engine, if one has been registered."""
    with _lock:
        return _policy_engine


def clear_policy_engine() -> None:
    """Clear the registered policy/permission engine."""
    global _policy_engine
    with _lock:
        _policy_engine = None


# =============================================================================
# Bulk operations
# =============================================================================

def clear_auth_globals() -> None:
    """
    Clear all registered S34 auth globals atomically.
    Useful for tests, reload flows, and clean shutdown.
    """
    global _auth_manager, _token_verifier, _jwt_service
    global _user_resolver, _policy_engine

    with _lock:
        _auth_manager   = None
        _token_verifier = None
        _jwt_service    = None
        _user_resolver  = None
        _policy_engine  = None


def get_auth_globals_snapshot() -> AuthGlobalsSnapshot:
    """
    Return an immutable snapshot showing which globals are currently set.
    The snapshot does not update — call again for a fresh reading.
    """
    with _lock:
        return AuthGlobalsSnapshot(
            auth_manager_set=   _auth_manager   is not None,
            token_verifier_set= _token_verifier is not None,
            jwt_service_set=    _jwt_service    is not None,
            user_resolver_set=  _user_resolver  is not None,
            policy_engine_set=  _policy_engine  is not None,
        )


def auth_globals_ready() -> bool:
    """
    Return True when the minimum viable auth globals are registered.
    For S34, token verification is the minimum critical piece — either
    the token verifier or the JWT service must be set.
    """
    with _lock:
        return _token_verifier is not None or _jwt_service is not None


# =============================================================================
# Minimal self-tests
# =============================================================================

def _run_self_tests() -> None:  # pragma: no cover
    import unittest

    class AuthGlobalsTests(unittest.TestCase):
        def tearDown(self) -> None:
            clear_auth_globals()

        def test_defaults_empty(self) -> None:
            snap = get_auth_globals_snapshot()
            self.assertFalse(snap.auth_manager_set)
            self.assertFalse(snap.token_verifier_set)
            self.assertFalse(snap.jwt_service_set)
            self.assertFalse(snap.user_resolver_set)
            self.assertFalse(snap.policy_engine_set)
            self.assertFalse(auth_globals_ready())

        def test_token_verifier_ready(self) -> None:
            verifier = object()
            set_token_verifier(verifier)
            self.assertIs(get_token_verifier(), verifier)
            self.assertTrue(auth_globals_ready())
            self.assertTrue(get_auth_globals_snapshot().token_verifier_set)

        def test_jwt_service_ready(self) -> None:
            set_jwt_service(object())
            self.assertTrue(auth_globals_ready())

        def test_snapshot_is_frozen(self) -> None:
            snap = get_auth_globals_snapshot()
            with self.assertRaises(Exception):
                snap.auth_manager_set = True  # type: ignore[misc]

        def test_clear_all(self) -> None:
            set_auth_manager(object())
            set_token_verifier(object())
            set_jwt_service(object())
            set_user_resolver(object())
            set_policy_engine(object())
            clear_auth_globals()
            snap = get_auth_globals_snapshot()
            self.assertFalse(snap.auth_manager_set)
            self.assertFalse(snap.token_verifier_set)
            self.assertFalse(snap.jwt_service_set)
            self.assertFalse(snap.user_resolver_set)
            self.assertFalse(snap.policy_engine_set)
            self.assertFalse(auth_globals_ready())

        def test_individual_clear(self) -> None:
            set_auth_manager(object())
            set_token_verifier(object())
            clear_auth_manager()
            self.assertIsNone(get_auth_manager())
            self.assertIsNotNone(get_token_verifier())

        def test_concurrent_set_get(self) -> None:
            import threading
            results = []
            obj = object()
            set_token_verifier(obj)

            def reader():
                results.append(get_token_verifier() is obj)

            threads = [threading.Thread(target=reader) for _ in range(20)]
            for t in threads: t.start()
            for t in threads: t.join()
            self.assertTrue(all(results))

    unittest.main(argv=["globals.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
