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
# =============================================================================

"""Sentinel-43 middleware compatibility exports.

There is one SentinelFirewall implementation:
core.api.middleware.sentinel_firewall_middleware.

The core.middleware namespace is retained for compatibility with existing
imports and re-exports that exact implementation. No fallback implementation,
monkey-patching, or duplicate configuration parser exists here.
"""

from .sentinel_firewall import (
    BlockReason,
    FirewallConfig,
    SentinelFirewall,
    TrafficClass,
)

__all__ = [
    "SentinelFirewall",
    "FirewallConfig",
    "BlockReason",
    "TrafficClass",
]
