# =============================================================================
# Sentinel-43  —  core/middleware/__init__.py
#
# Copyright (c) 2026 Justin Armstrong. All Rights Reserved.
# [license header as before]
# =============================================================================

"""
Sentinel-43 Middleware Package

Firewall was relocated to core/api/middleware/sentinel_firewall_middleware.py.
This package re-exports from the new location so existing imports of the form

    from core.middleware import SentinelFirewall, FirewallConfig

continue to work without changes to call sites.

If the file is later moved again, update the import below.
"""

from __future__ import annotations

try:
    # New location after Pylance-driven relocation
    from core.api.middleware.sentinel_firewall_middleware import (
        BlockReason,
        FirewallConfig,
        SentinelFirewall,
    )
except ImportError:
    try:
        # Original location (if repo hasn't relocated yet)
        from .sentinel_firewall import (  # type: ignore[no-redef]
            BlockReason,
            FirewallConfig,
            SentinelFirewall,
        )
    except ImportError:
        raise ImportError(
            "SentinelFirewall not found at "
            "core.api.middleware.sentinel_firewall_middleware "
            "or core.middleware.sentinel_firewall. "
            "Check that sentinel_firewall_middleware.py exists and is importable."
        )

__all__ = [
    "SentinelFirewall",
    "FirewallConfig",
    "BlockReason",
]
