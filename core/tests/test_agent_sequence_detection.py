# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial

from core.detection.agent_sequence_detector import match_agent_sequences
from core.detection.sentinel_threat_detector import EventContext, SentinelThreatDetector


def test_agent_sequence_requires_ordered_steps():
    assert not match_agent_sequences(
        ["agent_external_transfer", "agent_secret_access"]
    )


def test_agent_secret_then_transfer_is_critical_sequence():
    matches = match_agent_sequences(
        ["agent_secret_access", "agent_external_transfer"]
    )
    assert len(matches) == 1
    assert matches[0].sequence_id == "agent_secret_to_external_transfer"
    assert matches[0].level == "critical"


def test_agent_sequence_uses_existing_subject_window():
    detector = SentinelThreatDetector()
    first = detector.ingest(
        EventContext(
            source_identity="service:agent-runtime",
            source_ip="192.0.2.20",
            event_type="agent_secret_access",
            metadata={"event_id": "agent-1", "trusted_producer": "agent_runtime"},
        )
    )
    assert "agent_sequence_match" not in first.supporting_tags

    second = detector.ingest(
        EventContext(
            source_identity="service:agent-runtime",
            source_ip="192.0.2.20",
            event_type="agent_external_transfer",
            metadata={"event_id": "agent-2", "trusted_producer": "agent_runtime"},
        )
    )
    assert "agent_sequence_match" in second.supporting_tags
    assert second.score >= 85.0
    assert second.indicators["agent_sequence_match_count"] == 1


def test_agent_sequence_does_not_cross_subjects():
    detector = SentinelThreatDetector()
    detector.ingest(
        EventContext(
            source_identity="service:agent-runtime",
            source_ip="192.0.2.20",
            event_type="agent_secret_access",
            metadata={"event_id": "agent-a"},
        )
    )
    assessment = detector.ingest(
        EventContext(
            source_identity="service:agent-runtime",
            source_ip="192.0.2.21",
            event_type="agent_external_transfer",
            metadata={"event_id": "agent-b"},
        )
    )
    assert "agent_sequence_match" not in assessment.supporting_tags
