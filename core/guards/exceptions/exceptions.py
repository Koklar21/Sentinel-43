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

"""Canonical Sentinel-43 exception types.

Exceptions are intentionally side-effect free. Raising or constructing an
exception must never perform logging, network I/O, monitoring, or mutation.

Reporting belongs at the boundary that catches the exception.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any


class SentinelError(Exception):
    """Base exception for Sentinel-43 domain/runtime failures."""

    code = "S43_ERROR"

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        normalized = str(
            message
            or ""
        ).strip()

        if not normalized:
            raise ValueError(
                "SentinelError message must not be empty"
            )

        self.message = normalized
        self.details = MappingProxyType(
            dict(
                details
                or {}
            )
        )

        super().__init__(
            self.message
        )

    def __str__(
        self,
    ) -> str:
        return (
            f"{self.code}: "
            f"{self.message}"
        )

    def safe_dict(
        self,
    ) -> dict[str, Any]:
        """Return a serialization-safe representation."""
        return {
            "type": self.__class__.__name__,
            "code": self.code,
            "message": self.message,
        }


class ConfigurationError(SentinelError):
    code = "CONFIGURATION_ERROR"


class AuthenticationError(SentinelError):
    code = "AUTHENTICATION_ERROR"


class AuthorizationError(SentinelError):
    code = "AUTHORIZATION_ERROR"


class PolicyError(SentinelError):
    code = "POLICY_ERROR"


class DetectionError(SentinelError):
    code = "DETECTION_ERROR"


class MonitoringError(SentinelError):
    code = "MONITORING_ERROR"


class AuditError(SentinelError):
    code = "AUDIT_ERROR"


class DependencyError(SentinelError):
    code = "DEPENDENCY_ERROR"


class ExpectationError(SentinelError):
    code = "EXPECTATION_ERROR"


class ExpectationFailed(ExpectationError):
    code = "EXPECTATION_FAILED"


class ConfigExpectationFailed(ConfigurationError, ExpectationFailed):
    code = "CONFIG_EXPECTATION_FAILED"


class AuthExpectationFailed(AuthenticationError, ExpectationFailed):
    code = "AUTH_EXPECTATION_FAILED"


class PolicyExpectationFailed(PolicyError, ExpectationFailed):
    code = "POLICY_EXPECTATION_FAILED"


class DetectionExpectationFailed(DetectionError, ExpectationFailed):
    code = "DETECTION_EXPECTATION_FAILED"


class MonitoringExpectationFailed(MonitoringError, ExpectationFailed):
    code = "MONITORING_EXPECTATION_FAILED"


class WatchtowerExpectationFailed(MonitoringExpectationFailed):
    code = "WATCHTOWER_EXPECTATION_FAILED"


__all__ = [
    "AuditError",
    "AuthenticationError",
    "AuthorizationError",
    "AuthExpectationFailed",
    "ConfigExpectationFailed",
    "ConfigurationError",
    "DependencyError",
    "DetectionError",
    "DetectionExpectationFailed",
    "ExpectationError",
    "ExpectationFailed",
    "MonitoringError",
    "MonitoringExpectationFailed",
    "PolicyError",
    "PolicyExpectationFailed",
    "SentinelError",
    "WatchtowerExpectationFailed",
]
