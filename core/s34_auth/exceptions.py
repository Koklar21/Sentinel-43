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
