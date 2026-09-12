# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_nervous_system.py
#
# Contract coverage for core-to-subsystem signal routing.
#
# The gaps this closes, found by tracing the live runtime:
#   - Fenrir findings reached Watchtower and the dashboard but NEVER
#     MonitoringManager. Every other producer (firewall, Sparta, remote
#     gateway, governance) already did.
#   - /internal/events/broadcast was pure distribution: fan out to dashboards
#     and forget. No analysis, no correlation identity.
#   - The envelope had no causation, so a derived finding could not be linked
#     back to the signal that produced it.
#   - Nothing prevented an analyzer's own derived output from being fed back
#     into that analyzer.
# =============================================================================

from __future__ import annotations

import pytest

from core.monitoring.event_types import (
    derive_envelope,
    is_derived,
    normalize_event,
    would_loop,
)


# --------------------------------------------------------------------------- #
# causation
# --------------------------------------------------------------------------- #

def test_derived_event_gets_its_own_identity():
    """A derived finding IS a new event, so it gets a new event_id."""
    parent = {"event_id": "A", "correlation_id": "corr-1", "source": "Fenrir"}
    child = derive_envelope(parent, source="Watchtower")

    assert child["event_id"]
    assert child["event_id"] != "A"


def test_derived_event_preserves_causal_linkage():
    parent = {"event_id": "A", "correlation_id": "corr-1", "source": "Fenrir"}
    child = derive_envelope(parent, source="Watchtower")

    assert child["parent_event_id"] == "A"
    assert child["correlation_id"] == "corr-1"


def test_derivation_falls_back_to_parent_id_for_correlation():
    """An originating event with no correlation still yields a usable trace."""
    child = derive_envelope({"event_id": "A"}, source="Watchtower")
    assert child["correlation_id"] == "A"


def test_causation_survives_normalization():
    event = normalize_event(
        {"kind": "security", "event_id": "B", "parent_event_id": "A"}
    ).event
    assert event.to_dict()["parent_event_id"] == "A"


def test_originating_event_has_no_parent():
    assert not is_derived({"event_id": "A"})
    assert is_derived({"event_id": "B", "parent_event_id": "A"})


# --------------------------------------------------------------------------- #
# loop prevention
# --------------------------------------------------------------------------- #

def test_analyzer_own_derived_output_would_loop():
    """Watchtower finding -> monitoring -> Watchtower -> ... is unbounded."""
    derived = {
        "event_id": "D",
        "parent_event_id": "A",
        "source": "Watchtower",
    }
    assert would_loop(derived, analyzer_source="Watchtower")


def test_originating_event_does_not_trip_the_loop_guard():
    """A fresh signal must not be mistaken for a cycle."""
    assert not would_loop(
        {"event_id": "A", "source": "Watchtower"},
        analyzer_source="Watchtower",
    )


def test_derived_output_from_another_producer_is_not_a_loop():
    """Only the analyzer's OWN output closes the cycle."""
    derived = {
        "event_id": "D",
        "parent_event_id": "A",
        "source": "FenrirHunter",
    }
    assert not would_loop(derived, analyzer_source="Watchtower")


@pytest.mark.parametrize("source", ["watchtower", "WATCHTOWER", " Watchtower "])
def test_loop_guard_is_not_defeated_by_casing_or_padding(source):
    derived = {"event_id": "D", "parent_event_id": "A", "source": source}
    assert would_loop(derived, analyzer_source="Watchtower")


def test_loop_guard_is_stateless_not_a_hop_counter():
    """An explicit origin contract cannot be defeated by resetting a count.

    Asserted behaviourally: the guard is a pure function of the event, so
    repeated calls give the same answer and no accumulated state can be
    exhausted or reset to slip a cycle through.
    """
    derived = {"event_id": "D", "parent_event_id": "A", "source": "Watchtower"}
    fresh = {"event_id": "A", "source": "Watchtower"}

    for _ in range(50):
        assert would_loop(derived, analyzer_source="Watchtower") is True
        assert would_loop(fresh, analyzer_source="Watchtower") is False

    # The event is not mutated by the check, so nothing is consumed.
    assert derived == {
        "event_id": "D", "parent_event_id": "A", "source": "Watchtower"
    }


# --------------------------------------------------------------------------- #
# producer -> monitoring wiring
# --------------------------------------------------------------------------- #

def test_monitoring_notify_helper_exists_and_is_best_effort():
    """Monitoring is observational: it must not fail an accepted ingest, but
    the failure must be counted rather than silently swallowed."""
    import inspect

    import core.api.main as main

    source = inspect.getsource(main._notify_monitoring)
    assert "events_rejected" in source, "a monitoring failure must be counted"
    assert "logger.warning" in source, "a monitoring failure must be visible"


def test_ingress_rejects_a_circular_event_path():
    import inspect

    import core.api.main as main

    source = inspect.getsource(main._reject_analysis_loop)
    assert "would_loop" in source
    assert "409" in source


def test_exactly_one_fenrir_route_publishes_to_monitoring():
    """A Fenrir finding must be analyzed exactly once.

    FenrirHunter.process_finding posts every finding to BOTH
    /watchtower/events and /internal/events/broadcast concurrently, and a
    raw finding carries no event_id of its own -- so if both routes called
    _notify_monitoring, each would mint a different event_id and
    MonitoringManager would analyze the same finding twice under two
    identities, doubling alert counts and corrupting frequency/temporal
    scoring. Exactly one route -- the one that also owns the
    reliability/idempotency pipeline and the real Watchtower delivery --
    may call it; the other must stay distribution-only.

    Both routes still guard against a circular Watchtower-derived event
    (_reject_analysis_loop) regardless of which one analyzes.
    """
    import inspect

    import core.api.main as main

    sources = {
        handler.__name__: inspect.getsource(handler)
        for handler in (main.watchtower_ingest_event, main.internal_broadcast_event)
    }

    notifying = [name for name, src in sources.items() if "_notify_monitoring" in src]
    assert notifying == ["watchtower_ingest_event"], (
        "exactly one Fenrir ingress route may call _notify_monitoring; "
        f"got {notifying}"
    )

    for name, src in sources.items():
        assert "_reject_analysis_loop" in src, name


def test_monitoring_event_carries_full_provenance():
    """A consumer must be able to tell where a signal came from."""
    import inspect

    import core.api.main as main

    source = inspect.getsource(main._notify_monitoring)
    for field in (
        "event_id",
        "correlation_id",
        "parent_event_id",
        "source_identity",
        "schema_version",
    ):
        assert field in source, field


# --------------------------------------------------------------------------- #
# governance boundary (unchanged by this pass)
# --------------------------------------------------------------------------- #

def test_signal_routing_introduces_no_executor():
    """Nerves carry signals. They do not act on them."""
    import inspect
    import re

    import core.api.main as main

    for handler in (main._notify_monitoring, main._reject_analysis_loop):
        source = inspect.getsource(handler)
        assert not re.search(
            r"(^|[^a-z_])(execute|enforce|remediate|approve)\(", source
        ), handler.__name__
