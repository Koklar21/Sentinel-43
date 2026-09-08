# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 exception hierarchy."""

from __future__ import annotations


class SentinelError(Exception):
    """Base exception for Sentinel-43 application errors."""


class ConfigurationError(SentinelError):
    """Raised when Sentinel-43 configuration is invalid."""


class AuthenticationError(SentinelError):
    """Raised when authentication fails."""


class AuthorizationError(SentinelError):
    """Raised when an authenticated identity lacks required permission."""


class RuntimeStateError(SentinelError):
    """Raised when an operation is invalid for the current runtime state."""


class DatabaseError(SentinelError):
    """Raised for Sentinel-43 database-layer failures."""


class AuditIntegrityError(SentinelError):
    """Raised when audit-record integrity validation fails."""


__all__ = [
    "SentinelError",
    "ConfigurationError",
    "AuthenticationError",
    "AuthorizationError",
    "RuntimeStateError",
    "DatabaseError",
    "AuditIntegrityError",
]
