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
# This file proves S43_TRUSTED_PROXIES reaches the single canonical
# FirewallConfig.trusted_proxy_cidrs field and that the safe-by-default
# behavior (trust nobody when unset) remains unchanged. The old compatibility
# parser that once used a mismatched "trusted_proxies" kwarg has been removed;
# both firewall import paths now expose the same implementation.
# =============================================================================

from __future__ import annotations

import pytest

# This compatibility import is intentionally the same class object exported
# by core.api.middleware.sentinel_firewall_middleware and used by main.py.
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
