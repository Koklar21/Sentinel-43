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

import importlib
import warnings
from typing import Any


# Fix #3: wrap the core eager import so a broken/renamed name in
# .watchtower fails with a clear, package-scoped error message instead of
# a bare ImportError pointing at an internal module path.
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
        f"sentinel43.monitoring: failed to load core Watchtower exports "
        f"from .watchtower: {exc}"
    ) from exc


# Fix #1: ThresholdProfile / thresholds_for were previously imported
# unconditionally from .watchtower alongside the names above. Per the
# rules-engine review, these are actually defined in the rules module, not
# watchtower -- if watchtower.py doesn't independently define/re-export
# them, that import raises ImportError with NO fault isolation (unlike the
# lazy legacy exports below), taking down the entire package.
#
# Resolve them with a fallback chain across the plausible locations so the
# package stays importable regardless of which module turns out to be
# canonical, and so we don't end up silently using two non-identical
# ThresholdProfile enum types depending on import order.
_threshold_import_errors: list[str] = []

for _module_name in (".watchtower", ".rules_engine", ".rules"):
    try:
        _mod = importlib.import_module(_module_name, __name__)
        ThresholdProfile = _mod.ThresholdProfile
        thresholds_for = _mod.thresholds_for
        break
    except (ImportError, AttributeError) as _exc:
        _threshold_import_errors.append(f"{_module_name}: {_exc}")
else:
    raise ImportError(
        "sentinel43.monitoring: could not locate ThresholdProfile/"
        "thresholds_for in .watchtower, .rules_engine, or .rules. Tried: "
        + "; ".join(_threshold_import_errors)
    )

del _threshold_import_errors, _module_name, _mod, _exc


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

# Fix #2: previously hardcoded to .rules / .manager. Try multiple plausible
# module names so a filename mismatch degrades to the existing
# ImportWarning + AttributeError behavior instead of a permanently silent
# "module has no attribute" with no diagnostic of *why*.
_RULES_MODULE_CANDIDATES = (".rules_engine", ".rules")
_MANAGER_MODULE_CANDIDATES = (".monitoring_manager", ".manager")


def __getattr__(name: str) -> Any:
    if name in {"RuleRegistry", "registry"}:
        errors: list[str] = []
        for module_name in _RULES_MODULE_CANDIDATES:
            try:
                mod = importlib.import_module(module_name, __name__)
                rule_registry_cls = mod.RuleRegistry
                registry_obj = mod.registry
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")
                continue

            globals()["RuleRegistry"] = rule_registry_cls
            globals()["registry"] = registry_obj
            return globals()[name]

        warnings.warn(
            "sentinel43.monitoring: optional legacy export "
            f"{name!r} is unavailable: " + "; ".join(errors),
            ImportWarning,
            stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    if name == "MonitoringManager":
        errors = []
        for module_name in _MANAGER_MODULE_CANDIDATES:
            try:
                mod = importlib.import_module(module_name, __name__)
                manager_cls = mod.MonitoringManager
            except (ImportError, AttributeError) as exc:
                errors.append(f"{module_name}: {exc}")
                continue

            globals()["MonitoringManager"] = manager_cls
            return manager_cls

        warnings.warn(
            "sentinel43.monitoring: optional legacy export "
            f"{name!r} is unavailable: " + "; ".join(errors),
            ImportWarning,
            stacklevel=2,
        )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted([*__all__, *_LEGACY_EXPORTS])
