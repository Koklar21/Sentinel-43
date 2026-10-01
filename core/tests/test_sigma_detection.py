# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Focused Phase-1 Sigma-compatible detection coverage."""

from __future__ import annotations

import hashlib
from pathlib import Path

from core.detection.fenrir_hunter import FenrirConfig, FenrirHunter
from core.detection.sentinel_threat_detector import (
    EventContext,
    SentinelThreatDetector,
)
from core.detection.sentinel_threat_types import (
    ThreatKind,
    ThreatSeverity,
)
from core.detection.sigma_detector import SigmaDetector
from core.monitoring.manager import MonitoringManager


RULE_ID = "11111111-2222-4333-8444-555555555555"

SUPPORTED_RULE = f"""
title: S43 Blocked Firewall Event
id: {RULE_ID}
status: test
logsource:
  product: sentinel43
  category: security
detection:
  selection:
    EventType: firewall_block
    Status: blocked
  condition: selection
level: high
tags:
  - attack.credential-access
""".strip()

UNSUPPORTED_RULE = """
title: Unsupported Regex Example
id: aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
status: test
logsource:
  product: sentinel43
  category: security
detection:
  selection:
    EventType|re: '^firewall_.*$'
  condition: selection
level: medium
""".strip()

INVALID_RULE = """
title: [this is not valid yaml
logsource:
  category: security
""".strip()


def _write_rule(root: Path, name: str, text: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text(text, encoding="utf-8")
    return path


def _event(*, event_type: str = "firewall_block", status: str = "blocked") -> dict:
    return {
        "product": "sentinel43",
        "category": "security",
        "kind": "security",
        "service": "sentinel-firewall",
        "source": "sentinel-firewall",
        "source_identity": "anonymous",
        "source_ip": "203.0.113.8",
        "principal_id": "",
        "event_type": event_type,
        "status": status,
        "success": False,
    }


def test_supported_rule_loads_and_matches(tmp_path: Path) -> None:
    path = _write_rule(tmp_path, "supported.yml", SUPPORTED_RULE)
    detector = SigmaDetector.from_path(tmp_path)

    assert detector.rule_count == 1
    assert detector.issues == ()

    matches = detector.match(_event())
    assert len(matches) == 1

    match = matches[0]
    assert match.rule_id == RULE_ID
    assert match.title == "S43 Blocked Firewall Event"
    assert match.level == "high"
    assert match.source == path.name
    assert match.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_supported_rule_does_not_match_unrelated_event(tmp_path: Path) -> None:
    _write_rule(tmp_path, "supported.yml", SUPPORTED_RULE)
    detector = SigmaDetector.from_path(tmp_path)

    assert detector.match(
        _event(event_type="request_allowed", status="allowed")
    ) == ()


def test_invalid_rule_is_rejected_without_disabling_valid_rules(
    tmp_path: Path,
) -> None:
    _write_rule(tmp_path, "valid.yml", SUPPORTED_RULE)
    _write_rule(tmp_path, "invalid.yml", INVALID_RULE)

    detector = SigmaDetector.from_path(tmp_path)

    assert detector.rule_count == 1
    assert any(issue.kind == "invalid" for issue in detector.issues)
    assert len(detector.match(_event())) == 1


def test_unsupported_sigma_construct_is_reported_not_approximated(
    tmp_path: Path,
) -> None:
    _write_rule(tmp_path, "unsupported.yml", UNSUPPORTED_RULE)

    detector = SigmaDetector.from_path(tmp_path)

    assert detector.rule_count == 0
    assert detector.issues
    assert detector.issues[0].kind == "unsupported"
    assert "unsupported Sigma value type" in detector.issues[0].message


def test_sigma_provenance_survives_into_canonical_assessment(
    tmp_path: Path,
) -> None:
    path = _write_rule(tmp_path, "supported.yml", SUPPORTED_RULE)
    sigma = SigmaDetector.from_path(tmp_path)
    detector = SentinelThreatDetector(sigma_detector=sigma)

    assessment = detector.ingest(
        EventContext(
            source_identity="anonymous",
            source_ip="203.0.113.8",
            event_type="firewall_block",
            success=False,
            metadata={
                "event_id": "evt-001",
                "trusted_producer": "firewall",
                "sigma_event": _event(),
            },
        )
    )

    assert assessment.threat_kind is ThreatKind.GENERIC_INTRUSION
    assert assessment.severity is ThreatSeverity.HIGH
    assert assessment.score >= 65.0

    matches = assessment.indicators["sigma_matches"]
    assert len(matches) == 1
    assert matches[0]["rule_id"] == RULE_ID
    assert matches[0]["event_id"] == "evt-001"
    assert matches[0]["detector"] == "sigma"
    assert matches[0]["detector_version"] == "s43-sigma-1"
    assert matches[0]["rule_source"] == path.name
    assert matches[0]["rule_source_sha256"] == hashlib.sha256(
        path.read_bytes()
    ).hexdigest()

    # Sigma is an analyzer, not a counterfeit independent sensor.
    assert assessment.indicators["evidence_sources"] == ["firewall"]


def test_overlapping_sigma_rules_use_score_floor_not_additive_stacking(
    tmp_path: Path,
) -> None:
    _write_rule(tmp_path, "one.yml", SUPPORTED_RULE)
    _write_rule(
        tmp_path,
        "two.yml",
        SUPPORTED_RULE.replace(
            RULE_ID,
            "99999999-8888-4777-8666-555555555555",
        ).replace("S43 Blocked Firewall Event", "Same Evidence Second Rule"),
    )

    detector = SentinelThreatDetector(
        sigma_detector=SigmaDetector.from_path(tmp_path)
    )
    assessment = detector.ingest(
        EventContext(
            source_identity="anonymous",
            source_ip="203.0.113.8",
            event_type="firewall_block",
            success=False,
            metadata={
                "event_id": "evt-002",
                "trusted_producer": "firewall",
                "sigma_event": _event(),
            },
        )
    )

    assert assessment.indicators["sigma_match_count"] == 2
    assert assessment.indicators["sigma_score_floor"] == 65.0
    assert assessment.score == 65.0


def test_sigma_runtime_failure_does_not_break_base_detector() -> None:
    class BrokenSigma:
        def match(self, event):
            raise RuntimeError("matcher failed")

        def status(self):
            return {"active": True, "rules_loaded": 1}

    detector = SentinelThreatDetector(sigma_detector=BrokenSigma())

    assessment = detector.ingest(
        EventContext(
            source_identity="anonymous",
            source_ip="203.0.113.8",
            event_type="ordinary_event",
            metadata={
                "event_id": "evt-003",
                "trusted_producer": "firewall",
                "sigma_event": _event(),
            },
        )
    )

    assert assessment.window_size == 1
    assert "sigma_matches" not in assessment.indicators
    assert detector.sigma_status()["detector_failures"] == 1


def test_sigma_match_count_is_bounded_per_event(tmp_path: Path) -> None:
    for index in range(4):
        rule_id = f"00000000-0000-4000-8000-{index:012d}"
        _write_rule(
            tmp_path,
            f"rule-{index}.yml",
            SUPPORTED_RULE.replace(RULE_ID, rule_id),
        )

    detector = SigmaDetector.from_path(
        tmp_path,
        max_matches_per_event=2,
    )

    assert len(detector.match(_event())) == 2
    status = detector.status()
    assert status["stats"]["match_truncations"] == 1


def test_monitoring_projection_is_bounded_and_drops_arbitrary_raw_fields() -> None:
    class Scanner:
        def start(self): ...
        def stop(self): ...
        def get_status(self): return {}
        def scan_event(self, event): return []

    class Recorder:
        def __init__(self) -> None:
            self.contexts = []

        def ingest(self, context) -> None:
            self.contexts.append(context)

    recorder = Recorder()
    manager = MonitoringManager(Scanner())
    manager.start()
    manager.attach_threat_ingestor(
        recorder,
        producers={"firewall": "sentinel-firewall"},
    )

    manager.analyze_event(
        {
            "kind": "security",
            "source": "sentinel-firewall",
            "source_identity": "anonymous",
            "event_type": "firewall_block",
            "status": "blocked",
            "password": "must-never-enter-sigma",
            "authorization": "Bearer also-no",
        },
        source_ip="203.0.113.8",
        trusted_producer="firewall",
    )

    sigma_event = recorder.contexts[0].metadata["sigma_event"]
    assert sigma_event["event_type"] == "firewall_block"
    assert sigma_event["status"] == "blocked"
    assert "password" not in sigma_event
    assert "authorization" not in sigma_event


def test_fenrir_survives_unavailable_sigma_rule_source(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("S43_SIGMA_ENABLED", "true")
    monkeypatch.setenv(
        "S43_SIGMA_RULES_PATH",
        str(tmp_path / "does-not-exist"),
    )

    hunter = FenrirHunter(FenrirConfig.from_env())
    snapshot = hunter.snapshot()

    assert snapshot["sigma_detection"]["enabled"] is True
    assert snapshot["sigma_detection"]["coverage"] == "degraded"
    assert snapshot["sigma_detection"]["active"] is False

    assessment = hunter.detector.ingest(
        EventContext(
            source_identity="anonymous",
            source_ip="203.0.113.8",
            event_type="ordinary_event",
            metadata={"event_id": "evt-004", "trusted_producer": "firewall"},
        )
    )
    assert assessment.window_size == 1
