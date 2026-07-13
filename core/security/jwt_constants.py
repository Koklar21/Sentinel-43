"""
File: core/security/jwt_constants.py

Single source of truth for the JWT signing-algorithm allowlist.

This module intentionally has zero dependencies on core.bootstrap,
core.api.main, or any router, so it can be imported from any of them
without risking a circular or partially-initialized import. Only HS256
is permitted today; core/bootstrap.py, core/api/main.py,
core/api/deps/deps.py, and core/api/routers/auth.py must all import
APPROVED_JWT_ALGORITHMS from here rather than hardcoding their own copies.
"""

from __future__ import annotations

from typing import Final

APPROVED_JWT_ALGORITHMS: Final[frozenset[str]] = frozenset({"HS256"})
