# =============================================================================
# Sentinel-43 -- detection-to-Heart ingestion and corroboration regressions
#
# Permanent coverage for the behaviour that was first verified with temporary
# probes (PR #292): trusted-producer ingestion into the ONE detector Fenrir
# evaluates, retry/replay/rate-limit semantics, and Heart corroboration that
# counts INDEPENDENT trusted producers -- never repeated events, unchanged
# rescans, renamed labels or a single producer.
#
# Self-contained: real detector / manager / Fenrir / Heart / audit / core store
# in disposable temp storage. No network, no skips.
# =============================================================================
from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("SENTINEL_ENV", "test")

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from core.api.middleware.sentinel_firewall_middleware import (  # noqa: E402
    FirewallConfig,
    SentinelFirewall,
)
from core.audit import AuditConfig, AuditStore  # noqa: E402
from core.detection.fenrir_hunter import FenrirHunter  # noqa: E402
from core.detection.sentinel_threat_detector import (  # noqa: E402
    DetectorConfig,
    EventContext,
    SentinelThreatDetector,
)
from core.detection.sentinel_threat_types import (  # noqa: E402
    ThreatAssessment,
    ThreatKind,
    ThreatSeverity,
    ThreatSourceKind,
)
from core.detection.sigma_detector import SigmaDetector  # noqa: E402
from core.governance import (  # noqa: E402
    HeartConfig,
    build_heart_from_settings,
    build_runtime_authority_from_settings,
)
from core.monitoring import manager as manager_module  # noqa: E402
from core.monitoring.event_types import normalize_event  # noqa: E402
from core.monitoring.manager import MonitoringManager  # noqa: E402
from core.sentinel43_core_db import (  # noqa: E402
    ActionStatus,
    CoreStoreConfig,
    SentinelCoreStore,
)

LABEL = "sentinel-firewall"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class _Scanner:
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def get_status(self) -> dict:
        return {}

    def scan_event(self, event: dict) -> list:
        return []


class _RecordingIngestor:
    def __init__(self, delay: float = 0.0, fail_first: bool = False) -> None:
        self.contexts: list[EventContext] = []
        self._delay = delay
        self._fail_first = fail_first
        self._calls = 0
        self._lock = threading.Lock()

    def ingest(self, context: EventContext) -> None:
        with self._lock:
            self._calls += 1
            first = self._calls == 1
        if self._delay:
            time.sleep(self._delay)
        if self._fail_first and first:
            raise RuntimeError("transient detector failure")
        with self._lock:
            self.contexts.append(context)


def _manager(ingestor, producers=None) -> MonitoringManager:
    manager = MonitoringManager(_Scanner())
    manager.start()
    manager.attach_threat_ingestor(
        ingestor, producers={"firewall": LABEL} if producers is None else producers
    )
    return manager


def _event(**overrides) -> dict:
    event = {
        "kind": "security",
        "source": LABEL,
        "source_identity": "anonymous",
        "status": "blocked",
        "event_type": "firewall_block",
    }
    event.update(overrides)
    return event


def _counts(manager: MonitoringManager) -> dict:
    return manager.get_status()["manager"]["threat_ingestion"]


def _stores(
    tmp_path: Path,
    mode: str = "HUMAN_GATED",
    staged: list | None = None,
    max_pending: int = 500,
):
    audit = AuditStore(
        AuditConfig(sqlite_path=tmp_path / "audit.sqlite3", signing_key="k" * 48)
    )
    audit.initialize()
    core = SentinelCoreStore(CoreStoreConfig(db_path=tmp_path / "heart.sqlite3"))
    core.initialize()

    class Settings:
        default_mode = mode
        velocity_window_seconds = 60
        velocity_limit = 100_000
        dedupe_ttl_seconds = 300
        corroboration_window_seconds = 300
        corroboration_min_signals_for_high = 2
        max_pending_actions = max_pending

    class Sink:
        def stage(self, record: dict) -> None:
            if staged is not None:
                staged.append(record)

    class GovernanceSettings:
        default_mode = "HUMAN_GATED"

    authority = build_runtime_authority_from_settings(
        GovernanceSettings(), audit_store=audit
    )
    heart = build_heart_from_settings(
        Settings(),
        audit_store=audit,
        core_store=core,
        authority=authority,
        action_sink=Sink(),
    )
    # Match the production composition root: Heart is subordinate to the
    # already-built Sentinel43RuntimeAuthority before authority ingress is used.
    authority.attach_heart(heart)
    return audit, core, heart


def _assessment(seq: int, sources, ip: str = "203.0.113.9") -> ThreatAssessment:
    indicators: dict = {}
    if seq is not None:
        indicators["evidence_seq"] = seq
    if sources is not None:
        indicators["evidence_sources"] = list(sources)
    return ThreatAssessment(
        identity="anonymous",
        source_ip=ip,
        threat_kind=list(ThreatKind)[0],
        severity=ThreatSeverity.HIGH,
        source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
        score=80.0,
        indicators=indicators,
        supporting_tags=["t"],
        window_size=5,
    )


# ---------------------------------------------------------------------------
# Original AI/pattern detection + escalation preservation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("event_type", "expected_kind", "expected_classification"),
    [
        (
            "virus_detected",
            ThreatKind.MALWARE_DELIVERY,
            "AI_AUTOMATION_MALWARE_LIKELY",
        ),
        (
            "spyware_detected",
            ThreatKind.SPYWARE_ACTIVITY,
            "AI_AUTOMATION_SPYWARE_LIKELY",
        ),
    ],
)
def test_ai_malware_and_spyware_patterns_remain_explicit(
    event_type,
    expected_kind,
    expected_classification,
):
    detector = SentinelThreatDetector(
        DetectorConfig(automation_event_rate=2)
    )

    detector.ingest(
        EventContext(
            source_identity="service",
            source_ip="203.0.113.44",
            event_type=event_type,
            metadata={
                "event_id": "ai-pattern-1",
                "trusted_producer": "agent_runtime",
            },
        )
    )
    assessment = detector.ingest(
        EventContext(
            source_identity="service",
            source_ip="203.0.113.44",
            event_type=event_type,
            metadata={
                "event_id": "ai-pattern-2",
                "trusted_producer": "agent_runtime",
            },
        )
    )

    assert assessment.threat_kind is expected_kind
    assert assessment.source_kind is ThreatSourceKind.AI_AUTOMATION_LIKELY
    profile = assessment.indicators["ai_pattern_profile"]
    assert profile["classification"] == expected_classification
    assert profile["automation_likely"] is True
    assert profile["deterministic"] is True
    assert f"type:{event_type}" in profile["deterministic_signals"]
    assert (
        f"ai_pattern:{expected_classification.casefold()}"
        in assessment.supporting_tags
    )


def test_deterministic_agent_sequence_marks_ai_automation_without_rate_burst():
    detector = SentinelThreatDetector()

    for index, event_type in enumerate(
        (
            "agent_policy_probe",
            "agent_privileged_action",
        ),
        start=1,
    ):
        assessment = detector.ingest(
            EventContext(
                source_identity="service",
                source_ip="203.0.113.45",
                event_type=event_type,
                metadata={
                    "event_id": f"agent-pattern-{index}",
                    "trusted_producer": "agent_runtime",
                    "producer_correlation_id": "agent-session-1",
                },
            )
        )

    assert assessment.window_size == 2
    assert assessment.source_kind is ThreatSourceKind.AI_AUTOMATION_LIKELY
    assert assessment.indicators["agent_sequence_match_count"] >= 1
    profile = assessment.indicators["ai_pattern_profile"]
    assert profile["automation_likely"] is True
    assert profile["deterministic"] is True
    assert any(
        item.startswith("agent_sequence:")
        for item in profile["deterministic_signals"]
    )


def test_owner_ai_escalation_provenance_reaches_authoritative_audit(tmp_path):
    audit, _core, heart = _stores(tmp_path)
    authority = heart._authority

    assessment = ThreatAssessment(
        identity="service",
        source_ip="203.0.113.46",
        threat_kind=ThreatKind.MALWARE_DELIVERY,
        severity=ThreatSeverity.HIGH,
        source_kind=ThreatSourceKind.AI_AUTOMATION_LIKELY,
        score=80.0,
        indicators={
            "evidence_seq": 1,
            "evidence_sources": ["firewall"],
            "ai_pattern_profile": {
                "classification": "AI_AUTOMATION_MALWARE_LIKELY",
                "automation_likely": True,
                "threat_kind": ThreatKind.MALWARE_DELIVERY.value,
                "deterministic": True,
                "deterministic_signals": ["type:virus_detected"],
            },
            # Upstream input is not allowed to impersonate owner provenance.
            "ai_escalation": {"system_id": "forged"},
        },
        supporting_tags=[
            "automation_likely",
            "type:virus_detected",
            "ai_pattern:ai_automation_malware_likely",
        ],
        window_size=2,
    )

    decision = authority.observe_threat(assessment)
    assert decision.reason == "AWAITING_CORROBORATION"

    records = audit.get_records(component="heart", limit=50)
    record = records[-1]
    provenance = record["indicators"]["ai_escalation"]

    assert provenance["system_id"] == "SENTINEL-43-AI-ESCALATION-01"
    assert provenance["threat_kind"] == ThreatKind.MALWARE_DELIVERY.value
    assert provenance["source_kind"] == ThreatSourceKind.AI_AUTOMATION_LIKELY.value
    assert provenance["automation_likely"] is True
    assert provenance["pattern_classification"] == "AI_AUTOMATION_MALWARE_LIKELY"
    assert provenance["pattern_deterministic"] is True
    assert provenance["deterministic_signals"] == ["type:virus_detected"]
    assert len(provenance["assessment_fingerprint"]) == 64


# ---------------------------------------------------------------------------
# Manager: identity, replay, concurrency, retry, rate limit
# ---------------------------------------------------------------------------
def test_normalized_id_aliases_are_one_event():
    ingestor = _RecordingIngestor()
    manager = _manager(ingestor)
    event_id = str(uuid.uuid4())

    manager.analyze_event(_event(id=event_id), source_ip="198.51.100.2", trusted_producer="firewall")
    manager.analyze_event(_event(event_id=event_id), source_ip="198.51.100.2", trusted_producer="firewall")
    normalized = normalize_event(_event(id=event_id)).event
    manager.analyze_event(normalized, source_ip="198.51.100.2", trusted_producer="firewall")

    counts = _counts(manager)
    assert counts["ingested"] == 1
    assert counts["skipped_replay"] == 2
    assert len(ingestor.contexts) == 1
    assert ingestor.contexts[0].metadata["event_id"] == event_id


def test_concurrent_duplicates_ingest_exactly_once():
    ingestor = _RecordingIngestor(delay=0.15)
    manager = _manager(ingestor)
    event_id = str(uuid.uuid4())
    threads = [
        threading.Thread(
            target=lambda: manager.analyze_event(
                _event(id=event_id), source_ip="192.0.2.5", trusted_producer="firewall"
            )
        )
        for _ in range(12)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    counts = _counts(manager)
    assert len(ingestor.contexts) == 1
    assert counts["ingested"] == 1
    assert counts["skipped_replay"] == 11
    assert not manager._ingest_inflight_ids


def test_failed_ingest_is_retryable_then_real_replay_is_suppressed():
    ingestor = _RecordingIngestor(fail_first=True)
    manager = _manager(ingestor)
    event_id = str(uuid.uuid4())

    manager.analyze_event(_event(id=event_id), source_ip="192.0.2.6", trusted_producer="firewall")
    after_failure = dict(_counts(manager))
    assert after_failure["failed"] == 1 and after_failure["ingested"] == 0
    assert not manager._ingest_inflight_ids, "failed attempt must release its reservation"

    manager.analyze_event(_event(id=event_id), source_ip="192.0.2.6", trusted_producer="firewall")
    assert _counts(manager)["ingested"] == 1

    manager.analyze_event(_event(id=event_id), source_ip="192.0.2.6", trusted_producer="firewall")
    assert _counts(manager)["skipped_replay"] == 1
    assert len(ingestor.contexts) == 1


def test_rate_limited_event_keeps_replay_eligibility(monkeypatch):
    monkeypatch.setattr(manager_module, "_INGEST_RATE_LIMIT", 2)
    ingestor = _RecordingIngestor()
    manager = _manager(ingestor)
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for event_id in ids:
        manager.analyze_event(_event(id=event_id), source_ip="192.0.2.7", trusted_producer="firewall")

    counts = _counts(manager)
    assert counts["ingested"] == 2 and counts["skipped_rate_limited"] == 1

    manager._ingest_rate.clear()
    manager.analyze_event(_event(id=ids[2]), source_ip="192.0.2.7", trusted_producer="firewall")
    assert _counts(manager)["ingested"] == 3, "a rate-limited id must not be treated as replayed"


def test_trusted_producer_identity_is_required():
    ingestor = _RecordingIngestor()
    manager = _manager(ingestor)

    # Payload label alone, with no in-process provenance.
    manager.analyze_event(_event(), source_ip="198.51.100.1")
    # In-process provenance but a renamed (unconfigured) payload label.
    manager.analyze_event(_event(source="renamed-firewall"), source_ip="198.51.100.1", trusted_producer="firewall")
    # Unregistered producer kind.
    manager.analyze_event(_event(), source_ip="198.51.100.1", trusted_producer="unregistered")
    # Derived event (has a parent) and missing client IP.
    manager.analyze_event(_event(parent_event_id="p-1"), source_ip="198.51.100.1", trusted_producer="firewall")
    manager.analyze_event(_event(), trusted_producer="firewall")
    # Heart's own notification shape.
    manager.analyze_event(
        {"kind": "security", "source": "heart", "source_identity": "service:sentinel-api", "event_category": "x"},
        source_ip="10.0.0.1",
    )

    counts = _counts(manager)
    assert counts["ingested"] == 0
    assert counts["skipped_source"] == 6
    assert ingestor.contexts == []

    manager.analyze_event(_event(), source_ip="198.51.100.1", trusted_producer="firewall")
    assert _counts(manager)["ingested"] == 1
    assert ingestor.contexts[0].metadata["trusted_producer"] == "firewall"


# ---------------------------------------------------------------------------
# Real firewall middleware -> manager -> detector
# ---------------------------------------------------------------------------
def _drive_firewall(manager: MonitoringManager, source_label: str, requests: int) -> None:
    app = Starlette(routes=[Route("/", lambda request: PlainTextResponse("ok"))])
    firewall = SentinelFirewall(
        app,
        config=FirewallConfig(monitoring_source=source_label, monitoring_timeout_seconds=5.0),
        monitoring_manager=manager,
    )
    with TestClient(firewall, client=("203.0.113.9", 5555)) as client:
        for _ in range(requests):
            assert client.get("/.env").status_code >= 400
        deadline = time.time() + 10
        while time.time() < deadline:
            counts = _counts(manager)
            if counts["ingested"] + counts["skipped_source"] >= requests:
                break
            time.sleep(0.1)


@pytest.mark.parametrize("label", ["sentinel-firewall", "custom-firewall-source"])
def test_real_firewall_events_reach_the_shared_detector(label):
    detector = SentinelThreatDetector()
    manager = MonitoringManager(_Scanner())
    manager.start()
    manager.attach_threat_ingestor(detector, producers={"firewall": label})

    _drive_firewall(manager, label, requests=12)

    assert _counts(manager)["ingested"] == 12
    assessments = detector.assess_all()
    assert len(assessments) == 1
    assert assessments[0].source_ip == "203.0.113.9"
    assert list(assessments[0].indicators["evidence_sources"]) == ["firewall"]


def test_firewall_label_not_matching_configured_source_is_not_ingested():
    detector = SentinelThreatDetector()
    manager = MonitoringManager(_Scanner())
    manager.start()
    manager.attach_threat_ingestor(detector, producers={"firewall": "sentinel-firewall"})

    _drive_firewall(manager, "some-other-label", requests=5)

    counts = _counts(manager)
    assert counts["ingested"] == 0 and counts["skipped_source"] == 5
    assert detector.assess_all() == []


# ---------------------------------------------------------------------------
# Detector provenance
# ---------------------------------------------------------------------------
def test_detector_reports_sources_only_from_trusted_metadata():
    detector = SentinelThreatDetector()
    detector.ingest(
        EventContext(source_identity="anonymous", source_ip="203.0.113.1", event_type="firewall_block", success=False)
    )
    assessment = detector.assess_all()[0]
    assert list(assessment.indicators["evidence_sources"]) == []

    detector.ingest(
        EventContext(
            source_identity="anonymous",
            source_ip="203.0.113.1",
            event_type="firewall_block",
            success=False,
            metadata={"trusted_producer": "firewall", "event_id": "e-1"},
        )
    )
    assessment = detector.assess_all()[0]
    assert list(assessment.indicators["evidence_sources"]) == ["firewall"]
    seq = assessment.indicators["evidence_seq"]

    # The same explicit event id is a replay: no new evidence, sequence unchanged.
    detector.ingest(
        EventContext(
            source_identity="anonymous",
            source_ip="203.0.113.1",
            event_type="firewall_block",
            success=False,
            metadata={"trusted_producer": "firewall", "event_id": "e-1"},
        )
    )
    assert detector.assess_all()[0].indicators["evidence_seq"] == seq


# ---------------------------------------------------------------------------
# Heart corroboration: independent producers, not observations
# ---------------------------------------------------------------------------
def test_single_producer_can_never_satisfy_the_threshold(tmp_path):
    staged: list = []
    audit, core, heart = _stores(tmp_path, staged=staged)

    for seq in range(1, 40):  # arbitrarily many "new evidence" observations
        decision = heart.observe(_assessment(seq, ["firewall"]))
        assert decision.status == "OBSERVED"
        assert decision.reason == "AWAITING_CORROBORATION"

    assert staged == [] and heart.list_pending() == ()


def test_missing_or_unchanged_provenance_never_counts(tmp_path):
    staged: list = []
    _, _, heart = _stores(tmp_path, staged=staged)

    assert heart.observe(_assessment(None, ["firewall", "sparta"])).reason == "AWAITING_CORROBORATION"
    assert heart.observe(_assessment(5, None)).reason == "AWAITING_CORROBORATION"
    assert heart.observe(_assessment(5, [])).reason == "AWAITING_CORROBORATION"
    assert heart.observe(_assessment(1, ["firewall"])).reason == "AWAITING_CORROBORATION"
    # Same evidence sequence again, now claiming a second producer: unchanged
    # evidence must not be re-counted.
    assert heart.observe(_assessment(1, ["firewall", "sparta"])).reason == "AWAITING_CORROBORATION"
    assert staged == []


def test_distinct_producers_stage_for_human_review(tmp_path):
    staged: list = []
    audit, core, heart = _stores(tmp_path, staged=staged)

    assert heart.observe(_assessment(1, ["firewall"])).reason == "AWAITING_CORROBORATION"
    decision = heart.observe(_assessment(2, ["firewall", "sparta"]))

    assert decision.status == "STAGED" and decision.action_id
    assert len(staged) == 1 and staged[0]["action_type"] == "HEART_RECOMMENDATION"
    assert len(heart.list_pending()) == 1
    records = audit.get_records(component="heart", correlation_id=decision.action_id)
    assert [r["decision"] for r in records] == ["STAGED"]

    # Unchanged rescans of the now-corroborated evidence are duplicate-suppressed.
    assert heart.observe(_assessment(2, ["firewall", "sparta"])).reason == "DUPLICATE_SUPPRESSED"
    assert len(staged) == 1


def test_shadow_mode_observes_but_never_stages(tmp_path):
    staged: list = []
    _, core, heart = _stores(tmp_path, mode="SHADOW", staged=staged)

    heart.observe(_assessment(1, ["firewall"]))
    decision = heart.observe(_assessment(2, ["firewall", "sparta"]))

    assert decision.status == "OBSERVED" and decision.reason == "POLICY_OBSERVED"
    assert staged == [] and heart.list_pending() == ()


# ---------------------------------------------------------------------------
# Sigma provenance uses real producer corroboration
# ---------------------------------------------------------------------------
def test_sigma_match_does_not_counterfeit_an_independent_producer(tmp_path):
    rule_path = tmp_path / "sigma"
    rule_path.mkdir()
    (rule_path / "firewall.yml").write_text(
        """
title: S43 Firewall Block
id: 12345678-1234-4234-8234-123456789abc
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
""".strip(),
        encoding="utf-8",
    )

    sigma = SigmaDetector.from_path(rule_path)
    detector = SentinelThreatDetector(sigma_detector=sigma)
    staged: list = []
    _, _, heart = _stores(tmp_path, staged=staged)

    sigma_event = {
        "product": "sentinel43",
        "category": "security",
        "event_type": "firewall_block",
        "status": "blocked",
    }
    first = detector.ingest(
        EventContext(
            source_identity="anonymous",
            source_ip="203.0.113.9",
            event_type="firewall_block",
            success=False,
            metadata={
                "event_id": "sigma-firewall-1",
                "trusted_producer": "firewall",
                "sigma_event": sigma_event,
            },
        )
    )

    assert first.indicators["sigma_match_count"] == 1
    assert first.indicators["evidence_sources"] == ["firewall"]
    decision = heart.observe(first)
    assert decision.reason == "AWAITING_CORROBORATION"
    assert staged == []

    second = detector.ingest(
        EventContext(
            source_identity="anonymous",
            source_ip="203.0.113.9",
            event_type="integrity_signal",
            success=False,
            metadata={
                "event_id": "sparta-2",
                "trusted_producer": "sparta",
                "sigma_event": {
                    "product": "sentinel43",
                    "category": "log",
                    "event_type": "integrity_signal",
                },
            },
        )
    )

    assert second.indicators["evidence_sources"] == ["firewall", "sparta"]
    decision = heart.observe(second)
    assert decision.status == "STAGED"
    assert len(staged) == 1

# ---------------------------------------------------------------------------
# Fenrir hand-off and the full pipeline
# ---------------------------------------------------------------------------
def test_fenrir_does_not_resubmit_unchanged_evidence_and_retries_after_failure():
    class CountingHeart:
        def __init__(self) -> None:
            self.calls = 0
            self.fail = False

        def observe(self, assessment):
            self.calls += 1
            if self.fail:
                raise RuntimeError("heart down")

    async def scenario() -> tuple[int, int, int]:
        counting = CountingHeart()

        class CountingAuthority:
            threat_ingress_available = True

            def observe_threat(self, assessment):
                return counting.observe(assessment)

        fenrir = FenrirHunter(authority=CountingAuthority())

        def feed(n: int) -> None:
            for _ in range(n):
                fenrir.detector.ingest(
                    EventContext(
                        source_identity="anonymous",
                        source_ip="203.0.113.9",
                        event_type="firewall_block",
                        success=False,
                        metadata={"trusted_producer": "firewall", "event_id": str(uuid.uuid4())},
                    )
                )

        feed(60)
        for _ in range(3):
            await fenrir.observe_signals()
        unchanged_calls = counting.calls

        counting.fail = True
        feed(1)
        await fenrir.observe_signals()  # fails -> must not be recorded as observed
        failed_calls = counting.calls
        counting.fail = False
        await fenrir.observe_signals()  # same evidence again -> retried
        return unchanged_calls, failed_calls, counting.calls

    unchanged_calls, failed_calls, retried_calls = asyncio.run(scenario())
    assert unchanged_calls == 1
    assert failed_calls == 2
    assert retried_calls == 3


def test_full_pipeline_firewall_only_stays_pending_second_producer_stages(tmp_path):
    staged: list = []
    audit, core, heart = _stores(tmp_path, staged=staged)

    async def scenario() -> None:
        class HeartAuthority:
            threat_ingress_available = True

            def observe_threat(self, assessment):
                return heart.observe(assessment)

        fenrir = FenrirHunter(authority=HeartAuthority())
        manager = MonitoringManager(_Scanner())
        manager.start()
        manager.attach_threat_ingestor(fenrir.detector, producers={"firewall": LABEL, "sparta": "SpartaCore"})

        _drive_firewall(manager, LABEL, requests=60)
        for _ in range(3):
            await fenrir.observe_signals()
        assert staged == [] and heart.list_pending() == ()

        # More events from the same producer do not manufacture independence.
        _drive_firewall(manager, LABEL, requests=10)
        await fenrir.observe_signals()
        assert staged == [] and heart.list_pending() == ()

        # A genuinely distinct trusted producer kind (test-only registration).
        for _ in range(4):
            manager.analyze_event(
                {
                    "kind": "security",
                    "source": "SpartaCore",
                    "source_identity": "anonymous",
                    "status": "blocked",
                    "event_type": "firewall_block",
                },
                source_ip="203.0.113.9",
                trusted_producer="sparta",
            )
        await fenrir.observe_signals()

    asyncio.run(scenario())

    assert len(staged) == 1
    assert len(heart.list_pending()) == 1
    assert staged[0]["payload"]["source_ip"] == "203.0.113.9"





def test_anomaly_evidence_crosses_the_authority_boundary_without_severity_inflation():
    captured: list[ThreatAssessment] = []

    class RecordingAuthority:
        threat_ingress_available = True

        def observe_threat(self, assessment):
            captured.append(assessment)

    assessment = ThreatAssessment(
        identity="anonymous",
        source_ip="203.0.113.77",
        threat_kind=ThreatKind.UNKNOWN,
        severity=ThreatSeverity.LOW,
        source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
        score=10.0,
        indicators={
            "evidence_seq": 7,
            "evidence_sources": ["firewall"],
            "failure_ratio": 0.8,
        },
        supporting_tags=[],
        window_size=10,
    )
    anomaly = {
        "behavioral_shift": {
            "dimension": "failure_ratio",
            "value": 0.8,
            "zscore": float("inf"),
            "baseline_mean": 0.05,
            "baseline_std": 0.0,
        },
        "observations": 6,
        "evidence_seq": 7,
    }

    async def scenario():
        fenrir = FenrirHunter(authority=RecordingAuthority())
        fenrir._run_detection = lambda: (
            [assessment],
            {
                (
                    assessment.identity,
                    assessment.source_ip,
                    assessment.threat_kind.value,
                    assessment.source_kind.value,
                ): anomaly
            },
        )
        return await fenrir.observe_signals()

    findings = asyncio.run(scenario())

    assert len(captured) == 1
    observed = captured[0]
    assert observed.score == 10.0
    assert observed.severity is ThreatSeverity.LOW
    assert observed.indicators["fenrir_anomaly"] == anomaly
    assert "statistical_anomaly" in observed.supporting_tags
    assert "behavioral_anomaly" in observed.supporting_tags
    assert findings[0]["anomaly"] == anomaly

# ---------------------------------------------------------------------------
# Staging back-pressure (restored historical max_pending_or_gated)
# ---------------------------------------------------------------------------
def _stage_one(heart, seq: int, ip: str):
    return heart.observe(_assessment(seq, ["firewall", "sparta"], ip=ip))


def test_staging_stops_at_the_pending_ceiling(tmp_path):
    staged: list = []
    audit, core, heart = _stores(tmp_path, staged=staged, max_pending=3)

    for index in range(3):
        decision = _stage_one(heart, index + 1, f"203.0.113.{100 + index}")
        assert decision.status == "STAGED", decision

    refused = _stage_one(heart, 99, "203.0.113.200")
    assert refused.status == "OBSERVED"
    assert refused.reason == "BACKPRESSURE_LIMIT"
    assert refused.action_id is None

    # Nothing durable was created for the refused finding, and the ceiling
    # holds rather than drifting upward.
    assert len(heart.list_pending()) == 3
    assert len(staged) == 3
    assert core.count_actions(status=ActionStatus.PENDING) == 3


def test_backpressure_refusal_is_audited_with_the_counts(tmp_path):
    audit, core, heart = _stores(tmp_path, max_pending=1)
    _stage_one(heart, 1, "203.0.113.150")
    _stage_one(heart, 2, "203.0.113.151")

    records = audit.get_records(component="heart", limit=200)
    refusals = [r for r in records if r.get("reason_code") == "BACKPRESSURE_LIMIT"]
    assert len(refusals) == 1
    assert refusals[0]["decision"] == "OBSERVED"
    assert refusals[0]["pending_actions"] == 1
    assert refusals[0]["pending_limit"] == 1


def test_resolving_a_decision_restores_staging_capacity(tmp_path):
    audit, core, heart = _stores(tmp_path, max_pending=1)
    first = _stage_one(heart, 1, "203.0.113.160")
    assert first.status == "STAGED"
    assert _stage_one(heart, 2, "203.0.113.161").reason == "BACKPRESSURE_LIMIT"

    core.transition_status(
        first.action_id,
        expected=ActionStatus.PENDING,
        new_status=ActionStatus.VETOED,
        operator_id="heart-op",
        operator_reason="making room",
    )

    assert _stage_one(heart, 3, "203.0.113.162").status == "STAGED"


def test_shadow_mode_keeps_observing_regardless_of_queue_depth(tmp_path):
    staged: list = []
    audit, core, heart = _stores(tmp_path, mode="SHADOW", staged=staged, max_pending=1)

    for index in range(4):
        decision = _stage_one(heart, index + 1, f"203.0.113.{170 + index}")
        assert decision.status == "OBSERVED"
        assert decision.reason == "POLICY_OBSERVED", decision

    assert staged == [] and heart.list_pending() == ()


def test_the_ceiling_cannot_exceed_what_restart_recovery_can_enumerate():
    """Staging must never be able to create more pending rows than
    _rehydrate_heart_pending can read back, or a restart would block
    readiness with no way forward."""
    import core.api.main as main_module

    assert HeartConfig().max_pending_actions < main_module._HEART_RECOVERY_PAGE


def test_ceiling_holds_under_concurrent_staging(tmp_path):
    """N observations racing must not collectively overshoot the ceiling.

    Counting and staging are done under one lock; without that, each thread
    reads "under the limit" before any of them inserts.
    """
    import threading

    staged: list = []
    audit, core, heart = _stores(tmp_path, staged=staged, max_pending=5)

    barrier = threading.Barrier(20)
    results: list[str] = []
    lock = threading.Lock()

    def attempt(index: int) -> None:
        barrier.wait()
        decision = heart.observe(
            _assessment(index + 1, ["firewall", "sparta"], ip=f"198.51.100.{index + 1}")
        )
        with lock:
            results.append(decision.reason)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert core.count_actions(status=ActionStatus.PENDING) == 5, results
    assert len(staged) == 5
    assert results.count("STAGED_FOR_HUMAN_REVIEW") == 5
    assert results.count("BACKPRESSURE_LIMIT") == 15


def test_a_store_already_over_the_ceiling_refuses_to_stage(tmp_path):
    """A new limit does not repair pre-existing overflow: it stops growth,
    keeps observing, and must not silently resume staging."""
    import sqlite3
    import time as _time

    audit, core, heart = _stores(tmp_path, max_pending=3)

    now_ms = int(_time.time() * 1000)
    rows = [
        (
            f"HEART-PREEXIST{i:04d}", now_ms, "PENDING", "identity_source_ip",
            f"anonymous|10.0.0.{i}", "human_review", '["review"]', "HIGH", "k",
            "MIXED_OR_UNKNOWN", 1.0, "pre-existing backlog", "heart", None, None, None,
        )
        for i in range(9)
    ]
    connection = sqlite3.connect(tmp_path / "heart.sqlite3")
    try:
        connection.executemany(
            "INSERT INTO pending_actions (action_id,created_at_ms,status,target_type,"
            "target_value,primary_action,actions_json,severity,kind,source_kind,score,"
            "reason,system_id,execute_at_ms,operator_id,operator_reason) VALUES ("
            + ",".join("?" * 16)
            + ")",
            rows,
        )
        connection.commit()
    finally:
        connection.close()

    assert core.count_actions(status=ActionStatus.PENDING) == 9  # already 3x over

    refused = _stage_one(heart, 1, "203.0.113.210")
    assert refused.reason == "BACKPRESSURE_LIMIT"
    assert core.count_actions(status=ActionStatus.PENDING) == 9, "must not grow"

    # Draining below the ceiling is what restores staging -- nothing else.
    for index in range(7):
        core.transition_status(
            f"HEART-PREEXIST{index:04d}",
            expected=ActionStatus.PENDING,
            new_status=ActionStatus.VETOED,
            operator_id="heart-op",
            operator_reason="draining the backlog",
        )
    assert core.count_actions(status=ActionStatus.PENDING) == 2
    assert _stage_one(heart, 2, "203.0.113.211").status == "STAGED"


@pytest.mark.parametrize(
    "identity,source_ip",
    [
        ("anonymous|203.0.113.9", "198.51.100.1"),  # separator in identity
        ("some-user-name", "198.51.100.1"),         # not a server identity type
        ("anonymous", "not-an-address"),            # not an IP address
        ("anonymous", "198.51.100.1|x"),            # separator in address
    ],
)
def test_ingestion_refuses_a_malformed_subject(identity, source_ip):
    ingestor = _RecordingIngestor()
    manager = _manager(ingestor)
    manager.analyze_event(
        _event(source_identity=identity), source_ip=source_ip, trusted_producer="firewall"
    )
    counts = _counts(manager)
    assert counts["ingested"] == 0
    assert counts["skipped_invalid_subject"] == 1
    assert ingestor.contexts == []


# ---------------------------------------------------------------------------
# The account an account-scoped response acts on, from the request pipeline
# ---------------------------------------------------------------------------
def test_a_trusted_producer_can_report_the_authenticated_account():
    """An account-scoped response needs the account the request pipeline
    authenticated. It travels as in-process provenance from a REGISTERED
    producer -- registration is the trust boundary -- and reaches the
    assessment the orchestration authority decides on."""
    detector = SentinelThreatDetector()
    manager = _manager(detector, producers={"firewall": "sentinel-firewall"})

    for index in range(6):
        manager.analyze_event(
            _event(
                id=f"e-{index}",
                source="sentinel-firewall",
                source_identity="operator",
                source_principal="user-7f3a",
            ),
            source_ip="198.51.100.2",
            source_identity="operator",
            trusted_producer="firewall",
        )

    assert _counts(manager)["ingested"] == 6
    assessment = detector.assess_all()[0]
    assert list(assessment.indicators["subject_principals"]) == ["user-7f3a"]

    from core.governance.sentinel43_engine import principal_of_assessment

    assert principal_of_assessment(assessment) == "user-7f3a"


def test_evidence_from_two_accounts_names_neither():
    """Two accounts behind one (identity type, address) subject: the window
    names no account, so no account action can be approved for it."""
    detector = SentinelThreatDetector()
    manager = _manager(detector, producers={"firewall": "sentinel-firewall"})

    for index, principal in enumerate(("user-7f3a", "user-0b12")):
        manager.analyze_event(
            _event(
                id=f"m-{index}",
                source="sentinel-firewall",
                source_identity="operator",
                source_principal=principal,
            ),
            source_ip="198.51.100.3",
            source_identity="operator",
            trusted_producer="firewall",
        )

    from core.governance.sentinel43_engine import principal_of_assessment

    assessment = detector.assess_all()[0]
    assert list(assessment.indicators["subject_principals"]) == [
        "user-0b12",
        "user-7f3a",
    ]
    assert principal_of_assessment(assessment) == ""


def test_the_firewall_block_path_reports_no_account_today():
    """Recorded, deliberately: the only registered producer emits its event
    while REJECTING a request, which happens before anything authenticates
    it. So a real firewall block names no account, and account-scoped
    responses stay unapprovable until an authenticated-stage producer is
    authorized. Nothing invents one to close that gap."""
    detector = SentinelThreatDetector()
    manager = MonitoringManager(_Scanner())
    manager.start()
    manager.attach_threat_ingestor(detector, producers={"firewall": "sentinel-firewall"})

    _drive_firewall(manager, "sentinel-firewall", requests=6)

    assessment = detector.assess_all()[0]
    assert list(assessment.indicators["subject_principals"]) == []


def test_an_anonymous_request_carries_no_account():
    detector = SentinelThreatDetector()
    manager = MonitoringManager(_Scanner())
    manager.start()
    manager.attach_threat_ingestor(detector, producers={"firewall": "sentinel-firewall"})

    _drive_firewall(manager, "sentinel-firewall", requests=6)

    assessment = detector.assess_all()[0]
    assert list(assessment.indicators["subject_principals"]) == []


def test_an_account_is_never_taken_from_an_untrusted_payload():
    """The principal is in-process provenance. An event whose producer is not
    registered is not ingested at all, so a payload cannot name an account."""
    detector = SentinelThreatDetector()
    manager = _manager(detector, producers={"firewall": "sentinel-firewall"})
    # A payload that names an account, from a producer nothing registered.
    manager.analyze_event(
        _event(source="impostor-source", source_principal="admin-account"),
        source_ip="198.51.100.2",
        trusted_producer=None,
    )
    assert _counts(manager)["ingested"] == 0
    assert detector.assess_all() == []

    # ...and one from the trusted producer: the account comes from in-process
    # provenance, so the payload's claim is what is carried ONLY because the
    # firewall itself set it. A different producer label cannot reach here.
    manager.analyze_event(
        _event(source="sentinel-firewall"),
        source_ip="198.51.100.2",
        source_identity="anonymous",
        trusted_producer="firewall",
    )
    assert _counts(manager)["ingested"] == 1
    assert list(detector.assess_all()[0].indicators["subject_principals"]) == []


def test_a_reported_account_is_bounded_at_the_ingestion_boundary():
    """Each layer refuses a malformed account on its own. The manager clamps
    what it carries out of a payload, so an oversized or unprintable value
    never reaches the detector -- not only the authority's later check."""
    from core.governance.sentinel43_engine import MAX_PRINCIPAL_LENGTH

    ingestor = _RecordingIngestor()
    manager = _manager(ingestor, producers={"firewall": "sentinel-firewall"})

    manager.analyze_event(
        _event(
            id="clamp-1",
            source="sentinel-firewall",
            source_identity="operator",
            source_principal="u" * (MAX_PRINCIPAL_LENGTH + 500),
        ),
        source_ip="198.51.100.4",
        source_identity="operator",
        trusted_producer="firewall",
    )
    manager.analyze_event(
        _event(
            id="clamp-2",
            source="sentinel-firewall",
            source_identity="operator",
            source_principal="bad\nvalue",
        ),
        source_ip="198.51.100.5",
        source_identity="operator",
        trusted_producer="firewall",
    )

    assert _counts(manager)["ingested"] == 2
    carried = [c.metadata["principal_id"] for c in ingestor.contexts]
    assert len(carried[0]) == MAX_PRINCIPAL_LENGTH
    assert carried[1] == ""
