from __future__ import annotations


class SentinelSecurityError(Exception):
    """
    Base exception for all Sentinel-43 security-related failures.
    """

    __slots__ = ("message", "code")

    default_code = "SECURITY_ERROR"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
    ) -> None:
        super().__init__(message)

        self.message = message
        self.code = code or self.default_code


class AuthenticationError(SentinelSecurityError):
    """
    Raised when authentication fails.
    """

    default_code = "AUTHENTICATION_FAILED"


class AuthorizationError(SentinelSecurityError):
    """
    Raised when authorization fails.
    """

    default_code = "AUTHORIZATION_FAILED"


class InvalidTokenError(AuthenticationError):
    """
    Raised when a token is malformed or invalid.
    """

    default_code = "INVALID_TOKEN"


class ExpiredTokenError(AuthenticationError):
    """
    Raised when a token has expired.
    """

    default_code = "TOKEN_EXPIRED"


class ReplayAttackError(AuthenticationError):
    """
    Raised when replayed credentials or requests are detected.
    """

    default_code = "REPLAY_ATTACK_DETECTED"


class InvalidSignatureError(AuthenticationError):
    """
    Raised when cryptographic verification fails.
    """

    default_code = "INVALID_SIGNATURE"


class MFARequiredError(AuthenticationError):
    """
    Raised when MFA completion is required before authentication succeeds.
    """

    default_code = "MFA_REQUIRED"


class PermissionDeniedError(AuthorizationError):
    """
    Raised when an authenticated subject lacks required permissions.
    """

    default_code = "PERMISSION_DENIED"
