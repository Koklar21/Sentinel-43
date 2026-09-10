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

"""Monitoring-specific exception exports."""

from __future__ import annotations


class MonitoringError(Exception):
    """Base exception for the Sentinel-43 monitoring subsystem."""

    code = "MONITORING_ERROR"


class MonitoringConfigError(MonitoringError):
    code = "MONITORING_CONFIG_ERROR"


class EventNormalizationError(MonitoringError):
    code = "EVENT_NORMALIZATION_ERROR"


class RuleRegistrationError(MonitoringError):
    code = "RULE_REGISTRATION_ERROR"


class WatchtowerStateError(MonitoringError):
    code = "WATCHTOWER_STATE_ERROR"


__all__ = [
    "EventNormalizationError",
    "MonitoringConfigError",
    "MonitoringError",
    "RuleRegistrationError",
    "WatchtowerStateError",
]
