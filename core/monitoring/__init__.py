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

Eager exports (always available on import):
  - Watchtower core: WatchtowerNode, WatchtowerConfig, ScanResult, etc.
  - ThresholdProfile / thresholds_for (resolved via fallback chain)
  - Event types: BaseEvent, MobileEvent, to_event_context, normalize_event, etc.
  - Exceptions: MonitoringError, EventNormalizationError, etc.

Lazy exports (loaded on first access, optional dependencies gracefully absent):
  - RuleRegistry, registry            (.rules_engine / .rules)
  - MonitoringManager                 (.monitoring_manager / .manager)
  - SentinelWindowStore,              (.window_store /
    SentinelWindowConfig               sentinel_43_ai.detection.window_store)
  - set_monitoring_manager            (.remote_gateway)
  - SpartaCore, IntegrityConfig,      (.sparta_core)
    create_node_router
  - SentinelFirewall, FirewallConfig  (..middleware.sentinel_firewall)
  - JormungandrNode, JormungandrConfig,  (..audit.jormungandr)
    build_jormungandr

Lazy exports degrade to ImportWarning + AttributeError when their source
module or an optional dependency (sentinel_43_ai, starlette, cryptography)
is unavailable, rather than crashing the entire monitoring package.
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
# ThresholdProfile / thresholds_for — fallback resolution
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
# Event type exports — eager
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
# Exception exports — eager
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
# Public API — eager names
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
    "MobileEvent",
    "normalize_event",
    "to_event_context",
    # Exceptions
    "MonitoringError",
    "MonitoringConfigError",
    "EventNormalizationError",
    "RuleRegistrationError",
    "WatchtowerStateError",
]


# =============================================================================
# Lazy export registry
# =============================================================================

_RULES_MODULE_CANDIDATES    = (".rules_engine", ".rules")
_MANAGER_MODULE_CANDIDATES  = (".monitoring_manager", ".manager")
_WINDOW_STORE_CANDIDATES    = (".window_store", "sentinel_43_ai.detection.window_store")
_GATEWAY_MODULE_CANDIDATES  = (".remote_gateway",)
_SPARTA_MODULE_CANDIDATES   = (".sparta_core",)
_FIREWALL_MODULE_CANDIDATES = ("..middleware.sentinel_firewall",)
_JORM_MODULE_CANDIDATES     = ("..audit.jormungandr",)

_LAZY_EXPORTS: set[str] = {
    # Rules engine
    "RuleRegistry",
    "registry",
    # Monitoring orchestration
    "MonitoringManager",
    # Threat-detection window store (requires sentinel_43_ai)
    "SentinelWindowStore",
    "SentinelWindowConfig",
    # Remote gateway wiring
    "set_monitoring_manager",
    # File integrity watchdog  (core/monitoring/sparta_core.py)
    "SpartaCore",
    "IntegrityConfig",
    "create_node_router",
    # Application-layer firewall  (core/middleware/sentinel_firewall.py)
    "SentinelFirewall",
    "FirewallConfig",
    # Cryptographic audit node  (core/audit/jormungandr.py)
    "JormungandrNode",
    "JormungandrConfig",
    "build_jormungandr",
}


def __getattr__(name: str) -> Any:  # noqa: C901

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
            ImportWarning, stacklevel=2,
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
            ImportWarning, stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    # ----------------------------------------------- SentinelWindowStore / Config
    if name in {"SentinelWindowStore", "SentinelWindowConfig"}:
        errors = []
        for module_name in _WINDOW_STORE_CANDIDATES:
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
            ImportWarning, stacklevel=2,
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
            ImportWarning, stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    # ----------------------------- SpartaCore / IntegrityConfig / create_node_router
    if name in {"SpartaCore", "IntegrityConfig", "create_node_router"}:
        errors = []
        for module_name in _SPARTA_MODULE_CANDIDATES:
            try:
                mod = importlib.import_module(module_name, __name__)
                globals()["SpartaCore"] = mod.SpartaCore
                globals()["IntegrityConfig"] = mod.IntegrityConfig
                globals()["create_node_router"] = mod.create_node_router
                return globals()[name]
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")
        warnings.warn(
            f"sentinel43.monitoring: optional export {name!r} is unavailable: "
            + "; ".join(errors),
            ImportWarning, stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    # ----------------------------------------- SentinelFirewall / FirewallConfig
    if name in {"SentinelFirewall", "FirewallConfig"}:
        errors = []
        for module_name in _FIREWALL_MODULE_CANDIDATES:
            anchor = __name__ if module_name.startswith(".") else None
            try:
                mod = importlib.import_module(module_name, anchor)
                globals()["SentinelFirewall"] = mod.SentinelFirewall
                globals()["FirewallConfig"] = mod.FirewallConfig
                return globals()[name]
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")
        warnings.warn(
            f"sentinel43.monitoring: optional export {name!r} is unavailable "
            "(ensure core/middleware/sentinel_firewall.py is present): "
            + "; ".join(errors),
            ImportWarning, stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    # ----------------------------- JormungandrNode / JormungandrConfig / build_jormungandr
    if name in {"JormungandrNode", "JormungandrConfig", "build_jormungandr"}:
        errors = []
        for module_name in _JORM_MODULE_CANDIDATES:
            # "..audit.jormungandr" is relative: anchor = core.monitoring so
            # importlib resolves ".." up to "core", then into "core.audit".
            anchor = __name__ if module_name.startswith(".") else None
            try:
                mod = importlib.import_module(module_name, anchor)
                globals()["JormungandrNode"]   = mod.JormungandrNode
                globals()["JormungandrConfig"] = mod.JormungandrConfig
                globals()["build_jormungandr"] = mod.build_jormungandr
                return globals()[name]
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")
        warnings.warn(
            f"sentinel43.monitoring: optional export {name!r} is unavailable "
            "(ensure core/audit/jormungandr.py is present and "
            "the cryptography package is installed): " + "; ".join(errors),
            ImportWarning, stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted([*__all__, *_LAZY_EXPORTS])
