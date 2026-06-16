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
Sentinel-43 Application-Layer Middleware Package

This package exposes the FastAPI/Starlette middleware components that sit
in front of every route in the S43 API layer.

Exports
-------
SentinelFirewall
    Application-layer firewall middleware. Enforces IP allowlist/blocklist,
    per-IP rate limiting, request size limits, and path blocking. Routes
    blocked-request events to MonitoringManager for Watchtower alerting and
    SentinelWindowStore threat scoring.

FirewallConfig
    Immutable frozen-dataclass configuration for SentinelFirewall.
    Build from environment variables via FirewallConfig.from_env()
    (reads S43_FIREWALL_* vars) or construct directly.

BlockReason
    String constants for firewall block reason codes used in monitoring
    events and HTTP error responses:
        ip_blocked, ip_not_in_allowlist, rate_limited,
        payload_too_large, path_blocked.

Typical usage in core/api/main.py
----------------------------------
    from core.middleware import SentinelFirewall, FirewallConfig

    app.add_middleware(
        SentinelFirewall,
        config=FirewallConfig.from_env(),
        monitoring_manager=_monitoring_manager,   # optional
    )

Note on other security components
----------------------------------
SpartaCore (file-integrity watchdog) and JormungandrNode (cryptographic
audit node) live in their own packages and are exported from
core.monitoring, not here:

    from core.monitoring import SpartaCore, IntegrityConfig, create_node_router
    from core.monitoring import JormungandrNode, JormungandrConfig, build_jormungandr

Keeping middleware separate from monitoring avoids duplicate module loads
(which would cause isinstance checks to fail across import paths) and
matches the physical file layout:

    core/middleware/sentinel_firewall.py   ← this package
    core/monitoring/sparta_core.py         ← core.monitoring
    core/audit/jormungandr.py              ← core.monitoring (lazy export)
"""

from __future__ import annotations

from .sentinel_firewall import BlockReason, FirewallConfig, SentinelFirewall

__all__ = [
    "SentinelFirewall",
    "FirewallConfig",
    "BlockReason",
]
