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
#
# See LICENSE.md and COMMERCIAL_LICENSE.md at the repository root.
# =============================================================================

"""Sentinel-43 API dependency wiring — public surface.

This package is a thin re-export shim. Implementation lives in:
    - core.api.deps.config : environment + engine/store factory configuration
    - core.api.deps.deps   : dependency providers, auth dependencies, protocols

Routers import from ``core.api.deps`` directly, e.g.:
    from core.api.deps import get_engine, get_store, require_operator
"""

from __future__ import annotations

from .config import (
    DEFAULT_ENGINE_FACTORY,
    DEFAULT_STORE_FACTORY,
    ApiConfig,
    ConfigError,
    load_config,
)
from .deps import (
    DependencyResolutionError,
    DevEngine,
    DevStore,
    EngineProtocol,
    StoreProtocol,
    clear_factory_caches,
    deps_status,
    dev_engine_factory,
    dev_store_factory,
    get_engine,
    get_runtime_authority,
    get_store,
    register_dependencies_with_watchtower,
    require_admin,
    require_operator,
)

__all__ = [
    "ApiConfig",
    "ConfigError",
    "DEFAULT_ENGINE_FACTORY",
    "DEFAULT_STORE_FACTORY",
    "DependencyResolutionError",
    "DevEngine",
    "DevStore",
    "EngineProtocol",
    "StoreProtocol",
    "clear_factory_caches",
    "deps_status",
    "dev_engine_factory",
    "dev_store_factory",
    "get_engine",
    "get_runtime_authority",
    "get_store",
    "load_config",
    "register_dependencies_with_watchtower",
    "require_admin",
    "require_operator",
]
