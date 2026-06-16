# =============================================================================
# Sentinel-43  —  core/api/middleware/__init__.py
#
# Copyright (c) 2026 Justin Armstrong. All Rights Reserved.
# [license header as before]
# =============================================================================

"""
Sentinel-43 API Middleware Package

Firewall was relocated here from core/middleware/ to resolve
Pylance import resolution conflicts.

Exports:
  SentinelFirewall  — Application-layer FastAPI/Starlette firewall middleware.
  FirewallConfig    — Immutable config for SentinelFirewall; use from_env().
  BlockReason       — String constants for block reason codes.

Usage in core/api/main.py:

    from core.api.middleware import SentinelFirewall, FirewallConfig
    app.add_middleware(SentinelFirewall, config=FirewallConfig.from_env(),
                       monitoring_manager=_monitoring_manager)
"""

from __future__ import annotations

from .sentinel_firewall_middleware import BlockReason, FirewallConfig, SentinelFirewall

__all__ = [
    "SentinelFirewall",
    "FirewallConfig",
    "BlockReason",
]
