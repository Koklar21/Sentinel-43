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
