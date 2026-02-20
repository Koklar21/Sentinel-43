# =============================================================================
# Sentinel-43 Exception Definitions
# =============================================================================

from __future__ import annotations


class SentinelError(Exception):
    """
    Base Sentinel exception.
    All Sentinel-specific exceptions inherit from this.
    """


# --------------------------------------------------
# Configuration Errors
# --------------------------------------------------

class ConfigurationError(SentinelError):
    pass


# --------------------------------------------------
# Authentication Errors
# --------------------------------------------------

class AuthenticationError(SentinelError):
    pass


class AuthorizationError(SentinelError):
    pass


# --------------------------------------------------
# Runtime Errors
# --------------------------------------------------

class RuntimeStateError(SentinelError):
    pass


# --------------------------------------------------
# Database Errors
# --------------------------------------------------

class DatabaseError(SentinelError):
    pass


# --------------------------------------------------
# Audit Integrity Errors
# --------------------------------------------------

class AuditIntegrityError(SentinelError):
    pass


__all__ = [
    "SentinelError",
    "ConfigurationError",
    "AuthenticationError",
    "AuthorizationError",
    "RuntimeStateError",
    "DatabaseError",
    "AuditIntegrityError",
]