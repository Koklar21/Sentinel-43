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

"""Canonical compatibility exports for SentinelFirewall.

The implementation and FirewallConfig.from_env() live in
core.api.middleware.sentinel_firewall_middleware.

This module exists only to preserve the long-standing
core.middleware.sentinel_firewall import path. It contains no second
configuration parser and no alternate firewall behavior.
"""

from core.api.middleware.sentinel_firewall_middleware import (
    BlockReason,
    FirewallConfig,
    SentinelFirewall,
    TrafficClass,
)

__all__ = [
    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",
    "TrafficClass",
]
