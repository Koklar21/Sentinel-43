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
# =============================================================================
#
# core/tests/test_firewall_trusted_proxy_config.py
#
# core/middleware/sentinel_firewall.py's from_env() compatibility shim built
# a "trusted_proxies" kwarg for FirewallConfig, but the real dataclass field
# (core/api/middleware/sentinel_firewall_middleware.py) is
# trusted_proxy_cidrs. _constructor_accepts() only forwards kwargs whose name
# matches an actual constructor parameter, so the mismatched key was silently
# dropped and trusted_proxy_cidrs was permanently (). Since
# respect_x_forwarded_for defaults to True, that meant X-Forwarded-For was
# trusted unconditionally from any caller — a real IP-spoofing gap in the
# firewall's IP allow/block logic, rate-limiter key, and audit client_ip,
# independent of Kubernetes. See docs/security/trusted_proxy_handling.md.
#
# This file proves S43_TRUSTED_PROXIES actually reaches
# FirewallConfig.trusted_proxy_cidrs now, and that the safe-by-default
# behavior (trust nobody when unset) is unchanged.
# =============================================================================

from __future__ import annotations

import pytest

# Importing this module (rather than the FirewallConfig re-exported straight
# from sentinel_firewall_middleware) triggers the from_env() compatibility
# shim's module-level attach logic — the same path core.api.main takes.
from core.middleware.sentinel_firewall import FirewallConfig


def test_trusted_proxies_env_unset_trusts_nobody(monkeypatch):
    monkeypatch.delenv("S43_TRUSTED_PROXIES", raising=False)

    config = FirewallConfig.from_env()

    assert config.trusted_proxy_cidrs == ()


def test_trusted_proxies_env_reaches_config(monkeypatch):
    monkeypatch.setenv("S43_TRUSTED_PROXIES", "10.0.0.0/8,192.168.1.1")

    config = FirewallConfig.from_env()

    assert config.trusted_proxy_cidrs == ("10.0.0.0/8", "192.168.1.1")


__all__: list[str] = []
