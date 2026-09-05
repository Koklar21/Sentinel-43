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
# 1. GNU Affero General Public License (AGPL v3.0)
# for open-source use, modification, and distribution.
#
# 2. Commercial License
# for proprietary, enterprise, government, or other commercial use
# not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
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

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ...monitoring.watchtower_client import watchtower_request


EXCEPTIONS_MODULE_ID = os.getenv("S43_EXCEPTIONS_MODULE_ID", "sentinel43-exceptions")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _report_exception_to_watchtower(
    *,
    code: str,
    message: str,
    error_type: str,
    details: dict[str, Any] | None = None,
) -> None:
    # DEFECT_INVENTORY.md D-16: this used to build the request without the
    # internal service token, so it 401'd against Watchtower on every raised
    # SentinelError and the bare `except Exception: pass` swallowed that
    # silently.
    payload = {
        "event": {
            "kind": "runtime",
            "source": EXCEPTIONS_MODULE_ID,
            "status": "failed",
            "error_code": code,
            "error_type": error_type,
            "message": message,
            "details": details or {},
            "timestamp": utc_now(),
        }
    }
    watchtower_request("POST", "/watchtower/analyze", payload)


@dataclass(slots=True)
class SentinelError(Exception):
    code: str
    message: str
    details: dict[str, Any] | None = None
    report: bool = True

    def __post_init__(self) -> None:
        super().__init__(self.message)

        if self.report:
            _report_exception_to_watchtower(
                code=self.code,
                message=self.message,
                error_type=self.__class__.__name__,
                details=self.details,
            )

    def __str__(self) -> str:
        if self.details:
            return f"{self.code}: {self.message} | details={self.details}"
        return f"{self.code}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.__class__.__name__,
            "code": self.code,
            "message": self.message,
            "details": self.details or {},
            "timestamp": utc_now(),
        }


# ============================================================
# Expectations
# ============================================================

class ExpectationFailed(SentinelError):
    """Raised when a required invariant or expectation is not met."""


class ConfigExpectationFailed(ExpectationFailed):
    """Raised when configuration expectations are invalid or incomplete."""


class AuthExpectationFailed(ExpectationFailed):
    """Raised when authentication expectations fail."""


class PolicyExpectationFailed(ExpectationFailed):
    """Raised when policy validation expectations fail."""


class DetectionExpectationFailed(ExpectationFailed):
    """Raised when detection pipeline expectations fail."""


class MonitoringExpectationFailed(ExpectationFailed):
    """Raised when monitoring subsystem expectations fail."""


class WatchtowerExpectationFailed(MonitoringExpectationFailed):
    """Raised when Watchtower runtime expectations fail."""


class WatchtowerConfigExpectationFailed(MonitoringExpectationFailed):
    """Raised when Watchtower configuration expectations fail."""


class WatchtowerStateExpectationFailed(MonitoringExpectationFailed):
    """Raised when Watchtower state transition expectations fail."""


class WatchtowerInputExpectationFailed(MonitoringExpectationFailed):
    """Raised when Watchtower event input expectations fail."""


class WatchtowerRuleExpectationFailed(MonitoringExpectationFailed):
    """Raised when Watchtower rule or threshold expectations fail."""
