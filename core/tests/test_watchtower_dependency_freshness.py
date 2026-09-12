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
# core/tests/test_watchtower_dependency_freshness.py
#
# Post-merge baseline remediation, Section A.
#
# Live baseline verification found that /watchtower/health stayed healthy
# indefinitely while /watchtower/ready silently and permanently flipped to
# not_ready after roughly S43_DEPENDENCY_STALE_SECONDS (60s default) of
# perfectly ordinary operation. Root cause: core.api.main's lifespan reports
# the API as a Watchtower "dependency" exactly once, at startup
# (report_dependency_to_watchtower), while the periodic heartbeat loop only
# ever refreshed the *module* heartbeat, never the *dependency* report -- so
# the one-time report always aged out.
#
# This file pins the fix directly on _async_heartbeat_loop: on every
# successful cycle (the same cycle that already refreshes the module
# heartbeat), it must also re-report the "sentinel-43-api" dependency, using
# the same identity/details shape as the original startup call. It must NOT
# do so when the heartbeat itself failed (never fabricate health), and must
# not touch the optional/required status of any subsystem's declaration.
# =============================================================================

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-watchtower-freshness-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.main as main_module  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _drive_one_heartbeat_cycle(monkeypatch, *, heartbeat_sent: bool) -> tuple[list[dict], list[tuple]]:
    """Run _async_heartbeat_loop for exactly one cycle and capture calls."""
    stop_event = asyncio.Event()
    main_module.runtime.stop_heartbeat_event = stop_event

    # Make the wait_for(..., timeout=...) branch fire immediately instead of
    # sleeping the real 15s default.
    monkeypatch.setattr(main_module, "WATCHTOWER_HEARTBEAT_SECONDS", 0.01)

    dependency_calls: list[tuple] = []

    async def fake_send_api_heartbeat(status: str = "online"):
        # Stop after this single cycle so the loop returns rather than
        # sleeping again.
        stop_event.set()
        return {"heartbeat_sent": heartbeat_sent}

    async def fake_report_dependency_to_watchtower(name, status, details=None):
        dependency_calls.append((name, status, details))
        return {"error": None}

    broadcast_calls: list[dict] = []

    async def fake_broadcast(event_type, payload, channel=None):
        broadcast_calls.append(
            {"event_type": event_type, "payload": payload, "channel": channel}
        )

    monkeypatch.setattr(main_module, "send_api_heartbeat", fake_send_api_heartbeat)
    monkeypatch.setattr(
        main_module,
        "report_dependency_to_watchtower",
        fake_report_dependency_to_watchtower,
    )
    monkeypatch.setattr(main_module, "_broadcast_dashboard_event", fake_broadcast)

    _run(asyncio.wait_for(main_module._async_heartbeat_loop(), timeout=5.0))

    return broadcast_calls, dependency_calls


def test_healthy_cycle_refreshes_the_dependency_report(monkeypatch):
    _, dependency_calls = _drive_one_heartbeat_cycle(monkeypatch, heartbeat_sent=True)

    assert len(dependency_calls) == 1
    name, status, details = dependency_calls[0]
    assert name == "sentinel-43-api"
    assert status == "online"
    # Same identity/details shape as the original one-time startup report --
    # no new fields invented, no fabricated health.
    assert details == {"version": main_module.APP_VERSION, "environment": main_module.SENTINEL_ENV}


def test_failed_heartbeat_does_not_fabricate_a_dependency_report(monkeypatch):
    _, dependency_calls = _drive_one_heartbeat_cycle(monkeypatch, heartbeat_sent=False)

    assert dependency_calls == []


def test_dependency_refresh_runs_on_every_successful_cycle_not_only_the_first(monkeypatch):
    stop_event = asyncio.Event()
    main_module.runtime.stop_heartbeat_event = stop_event
    monkeypatch.setattr(main_module, "WATCHTOWER_HEARTBEAT_SECONDS", 0.01)

    calls = {"heartbeats": 0}
    dependency_calls: list[tuple] = []

    async def fake_send_api_heartbeat(status: str = "online"):
        calls["heartbeats"] += 1
        if calls["heartbeats"] >= 3:
            stop_event.set()
        return {"heartbeat_sent": True}

    async def fake_report_dependency_to_watchtower(name, status, details=None):
        dependency_calls.append((name, status, details))
        return {"error": None}

    async def fake_broadcast(event_type, payload, channel=None):
        return None

    monkeypatch.setattr(main_module, "send_api_heartbeat", fake_send_api_heartbeat)
    monkeypatch.setattr(
        main_module,
        "report_dependency_to_watchtower",
        fake_report_dependency_to_watchtower,
    )
    monkeypatch.setattr(main_module, "_broadcast_dashboard_event", fake_broadcast)

    _run(asyncio.wait_for(main_module._async_heartbeat_loop(), timeout=5.0))

    # Three successful heartbeat cycles -> three dependency refreshes. This
    # is the behavior that keeps /watchtower/ready truthful indefinitely
    # rather than only for the first ~60 seconds after startup.
    assert calls["heartbeats"] == 3
    assert len(dependency_calls) == 3
