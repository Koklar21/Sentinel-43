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
Sentinel-43 API Middleware Package

This package exposes FastAPI/Starlette middleware components used by the
Sentinel-43 API layer.

Physical layout
---------------
    core/api/middleware/__init__.py
    core/api/middleware/sentinel_firewall_middleware.py
    core/api/middleware/request_context.py

Primary exports
---------------
SentinelFirewall
    Application-layer ASGI firewall middleware.

FirewallConfig
    Configuration object for SentinelFirewall.

BlockReason
    Firewall block reason enum/string constants.

create_request_context_middleware
    Request context middleware factory. Adds/echoes X-Request-ID and attaches
    request.state.request_id.

Typical usage in core/api/main.py
---------------------------------
    from core.api.middleware import (
        FirewallConfig,
        SentinelFirewall,
        create_request_context_middleware,
    )

    app.add_middleware(create_request_context_middleware())

    app.add_middleware(
        SentinelFirewall,
        config=FirewallConfig(),
        monitoring_manager=monitoring_manager,
    )

Compatibility note
------------------
The firewall module was intentionally named:

    sentinel_firewall_middleware.py

instead of:

    sentinel_firewall.py

so Pylance does not get clever and start chewing the furniture. The exported
public names stay clean:

    SentinelFirewall
    FirewallConfig
    BlockReason
"""

from __future__ import annotations

try:
    from .sentinel_firewall_middleware import (
        BlockReason,
        FirewallConfig,
        SentinelFirewall,
    )
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "core.api.middleware: failed to import SentinelFirewall from "
        "core.api.middleware.sentinel_firewall_middleware. Ensure the file "
        "exists and defines BlockReason, FirewallConfig, and SentinelFirewall."
    ) from exc


try:
    from .request_context import (
        X_REQUEST_ID,
        create_request_context_middleware,
    )
except ImportError:
    # Request context middleware is useful but should not prevent firewall import
    # during early beta wiring.
    X_REQUEST_ID = "X-Request-ID"  # type: ignore[assignment]
    create_request_context_middleware = None  # type: ignore[assignment]


__all__ = [
    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",
    "X_REQUEST_ID",
    "create_request_context_middleware",
]
