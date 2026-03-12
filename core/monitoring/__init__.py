"""
Sentinel-43 Monitoring Package

Central import surface for Watchtower monitoring behavior.

This package exposes:
- Watchtower node and config types
- tower state/type enums
- event normalization helpers
- rule registry access
"""

from .watchtower import (
    WatchtowerState,
    TowerSlot,
    TowerType,
    TowerConfig,
    WatchtowerConfig,
    WatchtowerSegment,
    WatchtowerNode,
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

from .rules import (
    ThresholdProfile,
    thresholds_for,
    RuleRegistry,
    registry,
)

__all__ = [
    # watchtower core
    "WatchtowerState",
    "TowerSlot",
    "TowerType",
    "TowerConfig",
    "WatchtowerConfig",
    "WatchtowerSegment",
    "WatchtowerNode",
    "create_api_app",

    # event layer
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

    # rules layer
    "ThresholdProfile",
    "thresholds_for",
    "RuleRegistry",
    "registry",
]