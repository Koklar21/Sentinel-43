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

Core Watchtower and event-type exports are loaded eagerly.
Optional/heavyweight exports (rules registry, MonitoringManager, window
store, remote gateway wiring) are loaded lazily through __getattr__ so
failed imports from optional packages (e.g. sentinel_43_ai) do not create
fake None objects in the package namespace or break the whole monitoring
package for callers that don't need those features.
"""

from __future__ import annotations

import importlib
import warnings
from typing import Any


# =============================================================================
# Core Watchtower exports — eager, fail loudly if broken
# =============================================================================

try:
    from .watchtower import (
        VERSION,
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
except ImportError as exc:
    raise ImportError(
        "sentinel43.monitoring: failed to load core Watchtower exports "
        f"from .watchtower: {exc}"
    ) from exc


# =============================================================================
# ThresholdProfile / thresholds_for -- fallback resolution
#
# These were previously imported unconditionally from .watchtower, but per
# the rules-engine review they are actually defined there -- if watchtower.py
# doesn't independently re-export them that import takes down the whole
# package with no fault isolation.
#
# Also fixed: the original loop used `del _exc` after the loop body, which
# raises NameError if the first candidate succeeds (no exception is ever
# caught, so _exc is never assigned). Resolved by scoping the loop inside a
# helper function so no temporaries leak into the module namespace at all.
# =============================================================================

def _resolve_threshold_imports() -> tuple[Any, Any]:
    errors: list[str] = []
    for module_name in (".watchtower", ".rules_engine", ".rules"):
        try:
            mod = importlib.import_module(module_name, __name__)
            return mod.ThresholdProfile, mod.thresholds_for
        except (ImportError, AttributeError) as exc:
            errors.append(f"{module_name}: {exc}")

    raise ImportError(
        "sentinel43.monitoring: could not locate ThresholdProfile/"
        "thresholds_for in .watchtower, .rules_engine, or .rules. Tried: "
        + "; ".join(errors)
    )


ThresholdProfile, thresholds_for = _resolve_threshold_imports()
del _resolve_threshold_imports


# =============================================================================
# Event type exports -- eager
# MobileEvent and to_event_context are new; they bridge BaseEvent subclasses
# into EventContext for SentinelWindowStore ingestion.
# =============================================================================

try:
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
        MobileEvent,
        normalize_event,
        to_event_context,
    )
except ImportError as exc:
    raise ImportError(
        "sentinel43.monitoring: failed to load event type exports "
        f"from .event_types: {exc}"
    ) from exc


# =============================================================================
# Exception exports -- eager
# =============================================================================

try:
    from .exceptions import (
        MonitoringError,
        MonitoringConfigError,
        EventNormalizationError,
        RuleRegistrationError,
        WatchtowerStateError,
    )
except ImportError as exc:
    raise ImportError(
        "sentinel43.monitoring: failed to load exception exports "
        f"from .exceptions: {exc}"
    ) from exc


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Watchtower core
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
    # Event types
    "BaseEvent",
    "RequestEvent",
    "ExpectationEvent",
    "ConfigEvent",
    "LogEvent",
    "RuntimeEvent",
    "DependencyEvent",
    "ResourceEvent",
    "SecurityEvent",
    "MobileEvent",           # mobile companion app event type
    "normalize_event",
    "to_event_context",      # BaseEvent → EventContext bridge for SentinelWindowStore
    # Exceptions
    "MonitoringError",
    "MonitoringConfigError",
    "EventNormalizationError",
    "RuleRegistrationError",
    "WatchtowerStateError",
]


# =============================================================================
# Lazy exports
#
# These are loaded on first access so that:
#   - optional packages (sentinel_43_ai) don't need to be installed for the
#     core monitoring package to import cleanly
#   - failed imports produce a clear AttributeError + ImportWarning rather
#     than a silent None in the namespace
#
# Candidates are tried in order; the first that succeeds wins. The resolved
# name is cached in globals() so subsequent accesses skip __getattr__.
# =============================================================================

# Rules engine
_RULES_MODULE_CANDIDATES = (".rules_engine", ".rules")

# MonitoringManager
_MANAGER_MODULE_CANDIDATES = (".monitoring_manager", ".manager")

# SentinelWindowStore / SentinelWindowConfig
# Tries the local package first (if the store module is bundled here),
# then falls back to the sentinel_43_ai detection subpackage.
_WINDOW_STORE_CANDIDATES = (
    ".window_store",
    "sentinel_43_ai.detection.window_store",
)

# Gateway wiring: set_monitoring_manager() wires a MonitoringManager into
# the Remote Gateway so security events (auth failures, rate-limit hits,
# role mismatches) route through the monitoring pipeline rather than being
# siloed in a separate raw httpx POST to Watchtower.
_GATEWAY_MODULE_CANDIDATES = (".remote_gateway",)

_LAZY_EXPORTS: set[str] = {
    # Rules
    "RuleRegistry",
    "registry",
    # Manager
    "MonitoringManager",
    # Window store
    "SentinelWindowStore",
    "SentinelWindowConfig",
    # Gateway wiring
    "set_monitoring_manager",
}


def __getattr__(name: str) -> Any:

    # ------------------------------------------------------------------ rules
    if name in {"RuleRegistry", "registry"}:
        errors: list[str] = []
        for module_name in _RULES_MODULE_CANDIDATES:
            try:
                mod = importlib.import_module(module_name, __name__)
                globals()["RuleRegistry"] = mod.RuleRegistry
                globals()["registry"] = mod.registry
                return globals()[name]
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")

        warnings.warn(
            f"sentinel43.monitoring: optional export {name!r} is unavailable: "
            + "; ".join(errors),
            ImportWarning,
            stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    # -------------------------------------------------------- MonitoringManager
    if name == "MonitoringManager":
        errors = []
        for module_name in _MANAGER_MODULE_CANDIDATES:
            try:
                mod = importlib.import_module(module_name, __name__)
                globals()["MonitoringManager"] = mod.MonitoringManager
                return globals()["MonitoringManager"]
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")

        warnings.warn(
            f"sentinel43.monitoring: optional export {name!r} is unavailable: "
            + "; ".join(errors),
            ImportWarning,
            stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    # ------------------------------------------------------- SentinelWindowStore
    if name in {"SentinelWindowStore", "SentinelWindowConfig"}:
        errors = []
        for module_name in _WINDOW_STORE_CANDIDATES:
            # Absolute imports (sentinel_43_ai.*) use None as the anchor.
            anchor = __name__ if module_name.startswith(".") else None
            try:
                mod = importlib.import_module(module_name, anchor)
                globals()["SentinelWindowStore"] = mod.SentinelWindowStore
                globals()["SentinelWindowConfig"] = mod.SentinelWindowConfig
                return globals()[name]
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")

        warnings.warn(
            f"sentinel43.monitoring: optional export {name!r} is unavailable "
            "(sentinel_43_ai may not be installed): " + "; ".join(errors),
            ImportWarning,
            stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    # ------------------------------------------------- set_monitoring_manager
    if name == "set_monitoring_manager":
        errors = []
        for module_name in _GATEWAY_MODULE_CANDIDATES:
            try:
                mod = importlib.import_module(module_name, __name__)
                globals()["set_monitoring_manager"] = mod.set_monitoring_manager
                return globals()["set_monitoring_manager"]
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")

        warnings.warn(
            f"sentinel43.monitoring: optional export {name!r} is unavailable: "
            + "; ".join(errors),
            ImportWarning,
            stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted([*__all__, *_LAZY_EXPORTS])
