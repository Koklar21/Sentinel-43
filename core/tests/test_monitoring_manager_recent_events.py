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
#
# core/tests/test_monitoring_manager_recent_events.py
#
# Post-merge baseline remediation, Section C.
#
# Proves MonitoringManager.recent_events() -- the method GET
# /operator/findings reads from -- is a real passthrough to the same
# WatchtowerNode/WatchtowerNodeScanner combination the embedded monitoring
# stack actually uses (core.api.main._start_monitoring_manager), not a
# fake or a second store. Uses the real classes end to end, the same way
# the live baseline verification pass proved SpartaCore's finding reaches
# and changes WatchtowerNode's own state.
# =============================================================================

from __future__ import annotations

import os

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")

from core.monitoring.manager import MonitoringManager, WatchtowerNodeScanner  # noqa: E402
from core.monitoring.watchtower import WatchtowerConfig, WatchtowerNode  # noqa: E402


def _build_manager() -> MonitoringManager:
    config = WatchtowerConfig.default_sentinel_octagon("test-recent-events-node")
    node = WatchtowerNode(config)
    manager = MonitoringManager(WatchtowerNodeScanner(node))
    manager.start()
    return manager


def test_recent_events_requires_the_manager_to_be_started():
    config = WatchtowerConfig.default_sentinel_octagon("test-unstarted-node")
    node = WatchtowerNode(config)
    manager = MonitoringManager(WatchtowerNodeScanner(node))

    import pytest

    with pytest.raises(RuntimeError):
        manager.recent_events(10)


def test_recent_events_is_empty_before_any_analysis():
    manager = _build_manager()
    snapshot = manager.recent_events(10)
    assert snapshot["count"] == 0
    assert snapshot["events"] == []


def test_fenrir_shaped_finding_appears_in_recent_events():
    manager = _build_manager()

    manager.analyze_event(
        {
            "kind": "security",
            "source": "fenrir",
            "source_identity": "service:fenrir",
            "severity": "HIGH",
            "threat_kind": "credential_stuffing",
            "confidence": 0.9,
        }
    )

    snapshot = manager.recent_events(10)
    kinds = [e.get("kind") for e in snapshot["events"]]
    assert "security" in kinds

    finding = next(e for e in snapshot["events"] if e.get("kind") == "security")
    assert finding["source"] == "fenrir"
    assert finding["severity"] == "HIGH"
    assert finding["threat_kind"] == "credential_stuffing"


def test_sparta_integrity_compromise_appears_in_recent_events_and_alerts():
    manager = _build_manager()

    manager.analyze_event(
        {
            "kind": "log",
            "integrity_status": "compromised",
            "source": "SpartaCore",
            "source_identity": "service:sparta-node",
        }
    )

    snapshot = manager.recent_events(10)

    log_events = [e for e in snapshot["events"] if e.get("kind") == "log"]
    assert log_events
    assert log_events[0]["integrity_status"] == "compromised"

    alert_events = [e for e in snapshot["events"] if e.get("kind") == "watchtower_alerts"]
    assert alert_events, "a CRITICAL integrity compromise must produce a real alert entry"
    assert alert_events[0]["alerts"][0]["severity"] == "CRITICAL"
    assert alert_events[0]["alerts"][0]["tower_type"] == "LOGGING_AUDIT"


def test_recent_events_is_bounded_by_the_requested_limit():
    manager = _build_manager()

    for i in range(5):
        manager.analyze_event({"kind": "log", "integrity_status": "ok", "source": f"probe-{i}"})

    snapshot = manager.recent_events(2)
    assert snapshot["limit"] == 2
    assert len(snapshot["events"]) == 2
