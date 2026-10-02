# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Focused Phase 3 integration contract: ingress -> manager -> detector."""

from core.api.routers import agent_runtime
from core.api.routers.agent_runtime import AgentActivityEvent
from core.detection.sentinel_threat_detector import SentinelThreatDetector
from core.monitoring.manager import MonitoringManager


class _Scanner:
    def start(self): ...
    def stop(self): ...
    def get_status(self): return {"scanner": "phase3-test"}
    def scan_event(self, event): return []


class _RecordingDetector:
    def __init__(self):
        self.inner = SentinelThreatDetector()
        self.assessments = []

    def ingest(self, event):
        assessment = self.inner.ingest(event)
        self.assessments.append(assessment)
        return assessment


def _send(activity, event_id, manager, *, agent_id="agent-7"):
    agent_runtime.ingest_agent_activity(
        AgentActivityEvent(
            event_id=event_id,
            activity=activity,
            subject_ip="192.0.2.30",
            agent_id=agent_id,
        ),
        authorization="Bearer phase3-token",
    )


def test_agent_ingress_reaches_sequence_detector_end_to_end(monkeypatch):
    manager = MonitoringManager(_Scanner())
    detector = _RecordingDetector()
    manager.attach_threat_ingestor(
        detector,
        producers={"agent_runtime": "sentinel-agent-runtime"},
    )
    manager.start()

    monkeypatch.setenv("S43_AGENT_RUNTIME_ENABLED", "true")
    monkeypatch.setenv("S43_AGENT_RUNTIME_INGEST_TOKEN", "phase3-token")
    monkeypatch.setattr(agent_runtime, "get_monitoring_manager", lambda: manager)

    _send("agent_secret_access", "agent-e2e-1", manager)
    _send("agent_external_transfer", "agent-e2e-2", manager)

    assert len(detector.assessments) == 2
    first, second = detector.assessments
    assert "agent_sequence_match" not in first.supporting_tags
    assert "agent_sequence_match" in second.supporting_tags
    assert second.score >= 85.0
    matches = second.indicators["agent_sequence_matches"]
    assert matches[0]["sequence_id"] == "agent_secret_to_external_transfer"
    assert second.indicators["evidence_sources"] == ["agent_runtime"]


def test_replayed_agent_event_cannot_advance_sequence(monkeypatch):
    manager = MonitoringManager(_Scanner())
    detector = _RecordingDetector()
    manager.attach_threat_ingestor(
        detector,
        producers={"agent_runtime": "sentinel-agent-runtime"},
    )
    manager.start()

    monkeypatch.setenv("S43_AGENT_RUNTIME_ENABLED", "true")
    monkeypatch.setenv("S43_AGENT_RUNTIME_INGEST_TOKEN", "phase3-token")
    monkeypatch.setattr(agent_runtime, "get_monitoring_manager", lambda: manager)

    _send("agent_secret_access", "agent-replay-1", manager)
    _send("agent_secret_access", "agent-replay-1", manager)
    assert len(detector.assessments) == 1
    status = manager.get_status()["manager"]["threat_ingestion"]
    assert status["skipped_replay"] == 1
