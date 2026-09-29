# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_monitoring_event_pipeline.py
#
# Contract coverage for the monitoring/security event pipeline:
#
#     Sparta / SentinelFirewall / remote gateway
#         -> MonitoringManager.analyze_event()
#         -> core.monitoring.event_types.normalize_event()
#         -> scanner
#
#     FenrirHunter -> POST /internal/events/broadcast (fenrir.* namespace)
#
# Added after the subsystem reconstruction pass, which found this whole path
# had no tests at all -- and that 8 of the 9 typed event kinds had been
# raising at construction time, so every non-"security" event was silently
# discarded by the callers' best-effort exception handling.
# =============================================================================

from __future__ import annotations

import asyncio
import inspect

import pytest

from core.monitoring.event_types import _EVENT_TYPE_MAP, normalize_event
from core.monitoring.manager import MonitoringManager
from core.monitoring.rules import sparta_core_rule
from core.monitoring.sparta_core import (
    IntegrityConfig,
    IntegrityEvent,
    SpartaCore,
    SpartaState,
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

class _RecordingScanner:
    """Minimal EventScanner that records what actually reached it."""

    def __init__(self) -> None:
        self.seen: list[dict] = []

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def get_status(self) -> dict:
        return {"scanner": "recording"}

    def scan_event(self, event: dict) -> list[dict]:
        self.seen.append(event)
        return []


def _sparta(monitoring_manager=None) -> SpartaCore:
    return SpartaCore(
        IntegrityConfig(
            watched_files={},
            node_signature="test-node",
            node_api_token="spn-" + "k" * 40,
            token_secret="sps-" + "m" * 40,
        ),
        monitoring_manager=monitoring_manager,
    )


# --------------------------------------------------------------------------- #
# 1. typed events must actually construct
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("kind", sorted(_EVENT_TYPE_MAP))
def test_every_typed_event_kind_normalizes(kind):
    """@dataclass(slots=True) rebuilds the class, so the __class__ cell that
    zero-arg super() closes over pointed at the discarded original and every
    subclass __post_init__ raised TypeError. normalize_event() surfaced that
    as ValueError("invalid <kind> event"), disabling 8 of 9 event kinds."""
    result = normalize_event({"kind": kind})
    assert result.event.kind == kind


def test_base_event_kind_normalizes():
    assert normalize_event({"kind": "base"}).event.kind == "base"


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "request", "status_code": 999},
        {"kind": "request", "latency_ms": -1},
        {"kind": "runtime", "error_rate_percent": 150},
        {"kind": "log", "integrity_status": "   "},
        {"kind": "base", "id": "   "},
    ],
)
def test_subclass_validators_still_reject_bad_values(payload):
    """Chaining to BaseEvent explicitly must not skip any validation."""
    with pytest.raises(ValueError):
        normalize_event(payload)


def test_unknown_event_kind_is_rejected_not_coerced():
    with pytest.raises(ValueError, match="unknown event kind"):
        normalize_event({"kind": "definitely-not-a-real-kind"})


# --------------------------------------------------------------------------- #
# 2. Sparta -> MonitoringManager provenance
# --------------------------------------------------------------------------- #

def test_sparta_integrity_event_reaches_monitoring_with_provenance():
    """A raw IntegrityEvent.to_dict() carries no "kind", so it normalized to a
    bare BaseEvent and every Sparta field was dropped. Integrity findings are
    emitted as a typed "log" event instead."""
    scanner = _RecordingScanner()
    manager = MonitoringManager(scanner)
    manager.start()

    core = _sparta(monitoring_manager=manager)
    core._emit(
        IntegrityEvent(
            event_type="TamperDetected",
            file_path="/watched/file",
            state_at_event=SpartaState.COMPROMISED,
            source="probe",
            details={"expected_hash": "a" * 64},
        )
    )
    core.close()

    assert len(scanner.seen) == 1, "Sparta event never reached MonitoringManager"
    assert scanner.seen[0]["kind"] == "log"
    assert scanner.seen[0]["integrity_status"] == "compromised"


def test_sparta_clean_event_reports_ok_integrity_status():
    scanner = _RecordingScanner()
    manager = MonitoringManager(scanner)
    manager.start()

    core = _sparta(monitoring_manager=manager)
    core._emit(
        IntegrityEvent(
            event_type="RecoveryAcknowledged",
            file_path="",
            state_at_event=SpartaState.OPERATIONAL,
            source="NodeAPI",
        )
    )
    core.close()

    assert scanner.seen[0]["integrity_status"] == "ok"


def test_monitoring_failure_never_breaks_the_integrity_path():
    """Sparta is observational: a monitoring fault must not change its state
    or propagate to the caller."""

    class _Exploding:
        def analyze_event(self, event, **kwargs):
            raise RuntimeError("monitoring is down")

    core = _sparta(monitoring_manager=_Exploding())
    result = core.check_integrity()
    core._emit(
        IntegrityEvent(
            event_type="TamperDetected",
            file_path="/x",
            state_at_event=SpartaState.COMPROMISED,
        )
    )
    assert result.ok
    core.close()


# --------------------------------------------------------------------------- #
# 3. SpartaCore.get_status() is the sparta_core_rule contract
# --------------------------------------------------------------------------- #

def test_get_status_satisfies_sparta_core_rule_contract():
    """core.monitoring.rules.sparta_core_rule reads these keys off the Sparta
    status payload; tracked_auth_clients had been lost."""
    core = _sparta()
    status = core.get_status()
    core.close()

    required = {
        "state",
        "tamper_count",
        "blocked_clients",
        "tracked_auth_clients",
        "watched_file_count",
        "total_checks",
    }
    assert not required - set(status), f"missing: {required - set(status)}"


def test_sparta_core_rule_evaluates_a_real_status_payload():
    core = _sparta()
    core.check_integrity()
    result = sparta_core_rule(core.get_status())
    core.close()

    assert result.name == "sparta_core"
    assert result.details["tracked_auth_clients"] == 0


def test_tracked_auth_clients_counts_failed_authenticators():
    core = _sparta()
    core._record_auth_failure("198.51.100.7", "missing_or_invalid_bearer")
    status = core.get_status()
    core.close()

    assert status["tracked_auth_clients"] == 1


# --------------------------------------------------------------------------- #
# 4. FenrirHunter must emit into the namespace the API enforces
# --------------------------------------------------------------------------- #

def test_fenrir_broadcast_uses_the_enforced_fenrir_namespace(monkeypatch):
    """/internal/events/broadcast 403s any event_type outside "fenrir.*".
    FenrirHunter sent "fenrir_finding" (underscore), so every broadcast was
    rejected and counted as broadcast_failures."""
    from core.detection.fenrir_hunter import FenrirConfig, FenrirHunter

    monkeypatch.setenv("S43_FENRIR_BROADCAST_URL", "http://api.invalid/internal/events/broadcast")
    monkeypatch.setenv("S43_FENRIR_WATCHTOWER_URL", "")
    monkeypatch.setenv("S43_FENRIR_HOST", "127.0.0.1")

    hunter = FenrirHunter(FenrirConfig.from_env())

    captured: list[dict] = []

    async def _capture(*, url, payload, success_metric, failure_metric, label):
        captured.append(payload)

    monkeypatch.setattr(hunter, "_post_json", _capture)
    asyncio.run(hunter.process_finding({"severity": "HIGH", "score": 91}))

    assert captured, "FenrirHunter did not attempt a broadcast"
    event_type = captured[0]["event_type"]
    assert event_type.startswith("fenrir."), (
        f"event_type {event_type!r} would be rejected with 403 by "
        "/internal/events/broadcast"
    )


def test_internal_broadcast_guard_still_requires_the_fenrir_prefix():
    """The other half of the contract above, asserted at the API."""
    import core.api.main as main

    source = inspect.getsource(main.internal_broadcast_event)
    assert 'startswith("fenrir.")' in source
    assert "403" in source
