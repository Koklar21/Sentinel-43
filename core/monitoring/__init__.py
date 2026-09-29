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

Stable public exports for the monitoring layer.

Design goals:
  - Keep Watchtower/event/exception exports eager so real core breakage fails fast.
  - Keep optional subsystems lazy so missing beta modules do not crash import.
  - Provide direct MonitoringManager handoff helpers:
      set_monitoring_manager()
      get_monitoring_manager()
  - Export SpartaCore lazily from core.monitoring.sparta_core.
  - Export SentinelFirewall lazily from core.middleware.sentinel_firewall.

This file intentionally does not import API routers directly. The monitoring
package should not depend on core.api. Circular imports are how Python projects
learn pain as a second language.
"""

from __future__ import annotations

import importlib
import warnings
from typing import Any, Optional


# =============================================================================
# MonitoringManager handoff
# =============================================================================

_monitoring_manager: Optional[Any] = None


def set_monitoring_manager(manager: Any | None) -> None:
    """
    Register the active MonitoringManager for modules that need late wiring.

    This is intentionally small and direct. Remote gateway code can import this
    without creating a dependency from core.monitoring back into core.api.
    """
    global _monitoring_manager
    _monitoring_manager = manager


def get_monitoring_manager() -> Optional[Any]:
    """
    Return the active MonitoringManager, if one has been registered.
    """
    return _monitoring_manager


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
        "core.monitoring: failed to load Watchtower exports from "
        f"core.monitoring.watchtower: {exc}"
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
        "core.monitoring: could not locate ThresholdProfile/thresholds_for. "
        "Tried .watchtower, .rules_engine, .rules. Errors: "
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
        "core.monitoring: failed to load event type exports from "
        f"core.monitoring.event_types: {exc}"
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
        "core.monitoring: failed to load exception exports from "
        f"core.monitoring.exceptions: {exc}"
    ) from exc


# =============================================================================
# Lazy export registry
# =============================================================================

_RULES_MODULE_CANDIDATES: tuple[str, ...] = (
    ".rules_engine",
    ".rules",
)

_MANAGER_MODULE_CANDIDATES: tuple[str, ...] = (
    ".monitoring_manager",
    ".manager",
)

_WINDOW_STORE_CANDIDATES: tuple[str, ...] = (
    ".window_store",
    "core.detection.sentinel_window_store",
)

_SPARTA_MODULE_CANDIDATES: tuple[str, ...] = (
    ".sparta_core",
)

_FIREWALL_MODULE_CANDIDATES: tuple[str, ...] = (
    "core.middleware.sentinel_firewall",
)

_JORM_MODULE_CANDIDATES: tuple[str, ...] = (
    "core.monitoring.jormungandr",
    "core.audit.jormungandr",
)


_LAZY_EXPORTS: set[str] = {
    # Rules engine
    "RuleRegistry",
    "registry",

    # Monitoring orchestration
    "MonitoringManager",

    # Threat-detection window store
    "SentinelWindowStore",
    "SentinelWindowConfig",

    # File integrity watchdog
    "IntegrityConfig",
    "IntegrityEvent",
    "NodeAuthRequest",
    "NodeHeartbeatRequest",
    "NodeRegisterRequest",
    "SpartaCore",
    "SpartaState",
    "build_sparta_core",
    "create_node_router",
    "setup_signal_handlers",

    # Application-layer firewall
    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",

    # Cryptographic audit node
    "JormungandrNode",
    "JormungandrConfig",
}


def _warn_missing(name: str, errors: list[str], hint: str = "") -> None:
    suffix = f" {hint}" if hint else ""
    warnings.warn(
        f"core.monitoring: optional export {name!r} is unavailable.{suffix} "
        + "Errors: "
        + "; ".join(errors),
        ImportWarning,
        stacklevel=3,
    )


def _import_first(
    *,
    export_name: str,
    candidates: tuple[str, ...],
    relative_anchor: str | None = __name__,
) -> Any:
    """
    Import the first module candidate that contains export_name.

    Relative candidates beginning with '.' use relative_anchor.
    Absolute candidates use no package anchor.
    """
    errors: list[str] = []

    for module_name in candidates:
        anchor = relative_anchor if module_name.startswith(".") else None

        try:
            mod = importlib.import_module(module_name, anchor)
            return getattr(mod, export_name)
        except (ImportError, AttributeError) as exc:
            errors.append(f"{module_name}: {exc}")

    _warn_missing(export_name, errors)
    raise AttributeError(f"module {__name__!r} has no attribute {export_name!r}") from None


def _load_rules_export(name: str) -> Any:
    errors: list[str] = []

    for module_name in _RULES_MODULE_CANDIDATES:
        try:
            mod = importlib.import_module(module_name, __name__)
            globals()["RuleRegistry"] = mod.RuleRegistry
            globals()["registry"] = mod.registry
            return globals()[name]
        except (ImportError, AttributeError) as exc:
            errors.append(f"{module_name}: {exc}")

    _warn_missing(name, errors)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def _load_manager_export(name: str) -> Any:
    value = _import_first(
        export_name=name,
        candidates=_MANAGER_MODULE_CANDIDATES,
        relative_anchor=__name__,
    )
    globals()[name] = value
    return value


def _load_window_store_export(name: str) -> Any:
    errors: list[str] = []

    for module_name in _WINDOW_STORE_CANDIDATES:
        anchor = __name__ if module_name.startswith(".") else None

        try:
            mod = importlib.import_module(module_name, anchor)
            globals()["SentinelWindowStore"] = mod.SentinelWindowStore
            globals()["SentinelWindowConfig"] = mod.SentinelWindowConfig
            return globals()[name]
        except (ImportError, AttributeError) as exc:
            errors.append(f"{module_name}: {exc}")

    _warn_missing(
        name,
        errors,
        hint="Provide core/monitoring/window_store.py or core/detection/sentinel_window_store.py.",
    )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def _load_sparta_export(name: str) -> Any:
    errors: list[str] = []

    for module_name in _SPARTA_MODULE_CANDIDATES:
        try:
            mod = importlib.import_module(module_name, __name__)

            exports = {
                "IntegrityConfig": mod.IntegrityConfig,
                "IntegrityEvent": mod.IntegrityEvent,
                "NodeAuthRequest": mod.NodeAuthRequest,
                "NodeHeartbeatRequest": mod.NodeHeartbeatRequest,
                "NodeRegisterRequest": mod.NodeRegisterRequest,
                "NodeUnlockRequest": mod.NodeUnlockRequest,
                "SpartaCore": mod.SpartaCore,
                "SpartaState": mod.SpartaState,
                "build_sparta_core": mod.build_sparta_core,
                "create_node_router": mod.create_node_router,
                "setup_signal_handlers": mod.setup_signal_handlers,
            }

            globals().update(exports)
            return globals()[name]

        except (ImportError, AttributeError) as exc:
            errors.append(f"{module_name}: {exc}")

    _warn_missing(
        name,
        errors,
        hint="Ensure core/monitoring/sparta_core.py exists and compiles.",
    )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def _load_firewall_export(name: str) -> Any:
    errors: list[str] = []

    for module_name in _FIREWALL_MODULE_CANDIDATES:
        try:
            mod = importlib.import_module(module_name)

            exports = {
                "BlockReason": mod.BlockReason,
                "FirewallConfig": mod.FirewallConfig,
                "SentinelFirewall": mod.SentinelFirewall,
            }

            globals().update(exports)
            return globals()[name]

        except (ImportError, AttributeError) as exc:
            errors.append(f"{module_name}: {exc}")

    _warn_missing(
        name,
        errors,
        hint="Ensure core/middleware/sentinel_firewall.py and core/middleware/__init__.py exist.",
    )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def _load_jormungandr_export(name: str) -> Any:
    errors: list[str] = []

    for module_name in _JORM_MODULE_CANDIDATES:
        try:
            mod = importlib.import_module(module_name)

            # No build_jormungandr factory: jormungandr.py is deliberately
            # env-free ("no environment reads") and JormungandrNode requires
            # an injected root_key, so the composition root constructs it
            # directly. The symmetric factory this loader used to demand was
            # never implemented, and requiring it here made the two real
            # exports below unresolvable.
            exports = {
                "JormungandrNode": mod.JormungandrNode,
                "JormungandrConfig": mod.JormungandrConfig,
            }

            globals().update(exports)
            return globals()[name]

        except (ImportError, AttributeError) as exc:
            errors.append(f"{module_name}: {exc}")

    _warn_missing(
        name,
        errors,
        hint="Ensure core/monitoring/jormungandr.py exists and the 'cryptography' package is installed.",
    )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def __getattr__(name: str) -> Any:
    """
    Lazy optional exports.

    Required monitoring primitives are imported eagerly above. Optional beta
    subsystems load here only when requested.
    """
    if name in {"RuleRegistry", "registry"}:
        return _load_rules_export(name)

    if name in {"MonitoringManager", "WatchtowerNodeScanner"}:
        return _load_manager_export(name)

    if name in {"SentinelWindowStore", "SentinelWindowConfig"}:
        return _load_window_store_export(name)

    if name in {
        "IntegrityConfig",
        "IntegrityEvent",
        "NodeAuthRequest",
        "NodeHeartbeatRequest",
        "NodeRegisterRequest",
        "NodeUnlockRequest",
        "SpartaCore",
        "SpartaState",
        "build_sparta_core",
        "create_node_router",
        "setup_signal_handlers",
    }:
        return _load_sparta_export(name)

    if name in {"BlockReason", "FirewallConfig", "SentinelFirewall"}:
        return _load_firewall_export(name)

    if name in {"JormungandrNode", "JormungandrConfig"}:
        return _load_jormungandr_export(name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted([*__all__, *_LAZY_EXPORTS])


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

    # MonitoringManager handoff
    "set_monitoring_manager",
    "get_monitoring_manager",

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

    # Optional/lazy exports
    "RuleRegistry",
    "registry",
    "MonitoringManager",
    "SentinelWindowStore",
    "SentinelWindowConfig",

    "IntegrityConfig",
    "IntegrityEvent",
    "NodeAuthRequest",
    "NodeHeartbeatRequest",
    "NodeRegisterRequest",
    "NodeUnlockRequest",
    "SpartaCore",
    "SpartaState",
    "build_sparta_core",
    "create_node_router",
    "setup_signal_handlers",

    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",

    "JormungandrNode",
    "JormungandrConfig",
]
