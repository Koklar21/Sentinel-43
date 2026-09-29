# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Firewall import-path identity contract."""

def test_firewall_compatibility_paths_are_the_same_implementation():
    from core.api.middleware.sentinel_firewall_middleware import (
        BlockReason as ImplementationBlockReason,
        FirewallConfig as ImplementationFirewallConfig,
        SentinelFirewall as ImplementationSentinelFirewall,
        TrafficClass as ImplementationTrafficClass,
    )
    from core.middleware import (
        BlockReason,
        FirewallConfig,
        SentinelFirewall,
        TrafficClass,
    )

    assert SentinelFirewall is ImplementationSentinelFirewall
    assert FirewallConfig is ImplementationFirewallConfig
    assert BlockReason is ImplementationBlockReason
    assert TrafficClass is ImplementationTrafficClass


def test_compatibility_wrapper_contains_no_second_env_parser():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    source = (root / "core" / "middleware" / "sentinel_firewall.py").read_text(
        encoding="utf-8"
    )

    assert "def firewall_config_from_env" not in source
    assert "def _env_bool" not in source
    assert "except ImportError" not in source
