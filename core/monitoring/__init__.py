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
Sentinel-43 Monitoring Package

Safe public exports for the monitoring layer.

Core Watchtower exports are loaded eagerly.
Legacy/optional exports are loaded lazily through __getattr__ so failed imports
do not create fake None objects in the package namespace.
"""

from __future__ import annotations

import warnings
from typing import Any


from .watchtower import (
    VERSION,
    ThresholdProfile,
    thresholds_for,
    WatchtowerState,
    TowerSlot,
    TowerType,
    AlertSeverity,
    CoordinatorDecision,
    ScanResult,
    TowerConfig,
    WatchtowerConfig,
    WatchtowerSegment,
    WatchtowerNode,
    AnalyzeRequest,
    ModuleRegisterRequest,
    ModuleHeartbeatRequest,
    DependencyReportRequest,
    build_node,
    create_watchtower_router,
    create_api_app,
)

from .event_types import (
    BaseEvent,
    RequestEvent,
    ExpectationEvent,
    ConfigEvent,
    LogEvent,
    RuntimeEvent,
    DependencyEvent,
    ResourceEvent,
    SecurityEvent,
    normalize_event,
)

from .exceptions import (
    MonitoringError,
    MonitoringConfigError,
    EventNormalizationError,
    RuleRegistrationError,
    WatchtowerStateError,
)


__all__ = [
    "VERSION",
    "ThresholdProfile",
    "thresholds_for",
    "WatchtowerState",
    "TowerSlot",
    "TowerType",
    "AlertSeverity",
    "CoordinatorDecision",
    "ScanResult",
    "TowerConfig",
    "WatchtowerConfig",
    "WatchtowerSegment",
    "WatchtowerNode",
    "AnalyzeRequest",
    "ModuleRegisterRequest",
    "ModuleHeartbeatRequest",
    "DependencyReportRequest",
    "build_node",
    "create_watchtower_router",
    "create_api_app",
    "BaseEvent",
    "RequestEvent",
    "ExpectationEvent",
    "ConfigEvent",
    "LogEvent",
    "RuntimeEvent",
    "DependencyEvent",
    "ResourceEvent",
    "SecurityEvent",
    "normalize_event",
    "MonitoringError",
    "MonitoringConfigError",
    "EventNormalizationError",
    "RuleRegistrationError",
    "WatchtowerStateError",
]


_LEGACY_EXPORTS = {
    "RuleRegistry",
    "registry",
    "MonitoringManager",
}


def __getattr__(name: str) -> Any:
    if name in {"RuleRegistry", "registry"}:
        try:
            from .rules import RuleRegistry, registry
        except ImportError as exc:
            warnings.warn(
                f"sentinel43.monitoring: optional legacy export from '.rules' is unavailable: {exc}",
                ImportWarning,
                stacklevel=2,
            )
            raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

        globals()["RuleRegistry"] = RuleRegistry
        globals()["registry"] = registry
        return globals()[name]

    if name == "MonitoringManager":
        try:
            from .manager import MonitoringManager
        except ImportError as exc:
            warnings.warn(
                f"sentinel43.monitoring: optional legacy export '.manager.MonitoringManager' is unavailable: {exc}",
                ImportWarning,
                stacklevel=2,
            )
            raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

        globals()["MonitoringManager"] = MonitoringManager
        return MonitoringManager

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted([*__all__, *_LEGACY_EXPORTS])
