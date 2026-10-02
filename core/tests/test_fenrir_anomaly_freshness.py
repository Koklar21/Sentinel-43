# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Focused regression coverage for Fenrir statistical-evidence freshness.

The hunting loop polls detector assessments repeatedly. A poll is not new
security evidence. These tests pin the invariant that statistical baseline
learning and cumulative pressure advance only when the detector's monotonic
evidence_seq advances.
"""

from __future__ import annotations

import core.detection.fenrir_hunter as fenrir_hunter
from core.detection.fenrir_hunter import FenrirAnomalyLayer
from core.detection.sentinel_threat_types import (
    ThreatAssessment,
    ThreatKind,
    ThreatSeverity,
    ThreatSourceKind,
)


def _assessment(
    seq: int | None,
    *,
    score: float = 10.0,
    failure_ratio: float | None = None,
) -> ThreatAssessment:
    indicators = {}
    if seq is not None:
        indicators["evidence_seq"] = seq
    if failure_ratio is not None:
        indicators["failure_ratio"] = failure_ratio

    return ThreatAssessment(
        identity="anonymous",
        source_ip="203.0.113.10",
        threat_kind=ThreatKind.RATE_ANOMALY,
        severity=ThreatSeverity.LOW,
        source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
        score=score,
        indicators=indicators,
        supporting_tags=[],
        window_size=1,
    )


def _layer() -> FenrirAnomalyLayer:
    return FenrirAnomalyLayer(
        zscore_threshold=100.0,
        pressure_threshold=25.0,
        decay_rate=0.000001,
        min_observations=2,
        max_keys=100,
        stale_seconds=3600.0,
    )


def test_repeated_poll_of_same_evidence_does_not_raise_pressure() -> None:
    layer = _layer()

    assert layer.update(_assessment(1)) is None
    for _ in range(20):
        assert layer.update(_assessment(1)) is None

    # Only genuinely newer detector evidence may move pressure from 10 -> 20.
    assert layer.update(_assessment(2)) is None

    stats = layer.stats()
    assert stats["fresh_updates"] == 2
    assert stats["duplicate_updates_skipped"] == 20
    assert stats["pressure_fires"] == 0


def test_new_evidence_can_still_accumulate_pressure() -> None:
    layer = _layer()

    assert layer.update(_assessment(1)) is None
    assert layer.update(_assessment(2)) is None

    anomaly = layer.update(_assessment(3))
    assert anomaly is not None
    assert anomaly["cumulative_pressure"] >= 25.0
    assert anomaly["evidence_seq"] == 3

    stats = layer.stats()
    assert stats["fresh_updates"] == 3
    assert stats["pressure_fires"] == 1


def test_sequence_regression_is_not_relearned() -> None:
    layer = _layer()

    assert layer.update(_assessment(5)) is None
    assert layer.update(_assessment(4)) is None
    assert layer.update(_assessment(6)) is None

    stats = layer.stats()
    assert stats["fresh_updates"] == 2
    assert stats["sequence_regressions_skipped"] == 1
    assert stats["duplicate_updates_skipped"] == 0


def test_missing_evidence_sequence_is_not_treated_as_observation() -> None:
    layer = _layer()

    assert layer.update(_assessment(None)) is None

    stats = layer.stats()
    assert stats["updates"] == 1
    assert stats["fresh_updates"] == 0
    assert stats["missing_evidence_seq_skipped"] == 1
    assert stats["active_keys"] == 0

def _zscore_layer() -> FenrirAnomalyLayer:
    return FenrirAnomalyLayer(
        zscore_threshold=2.5,
        pressure_threshold=1_000_000.0,
        decay_rate=0.000001,
        min_observations=5,
        max_keys=100,
        stale_seconds=3600.0,
    )


def _prime_score_baseline(layer: FenrirAnomalyLayer) -> None:
    for seq, score in enumerate((50.0, 52.0, 48.0, 51.0, 49.0), start=1):
        assert layer.update(_assessment(seq, score=score)) is None


def test_downward_score_deviation_does_not_escalate() -> None:
    layer = _zscore_layer()
    _prime_score_baseline(layer)

    assert layer.update(_assessment(6, score=5.0)) is None
    assert layer.stats()["zscore_fires"] == 0


def test_upward_score_deviation_still_escalates() -> None:
    layer = _zscore_layer()
    _prime_score_baseline(layer)

    anomaly = layer.update(_assessment(6, score=90.0))
    assert anomaly is not None
    assert anomaly["zscore"] >= 2.5
    assert anomaly["evidence_seq"] == 6
    assert layer.stats()["zscore_fires"] == 1


def test_zscore_anomaly_does_not_poison_learned_baseline() -> None:
    layer = _zscore_layer()
    _prime_score_baseline(layer)

    anomaly = layer.update(_assessment(6, score=90.0))
    assert anomaly is not None

    # If the anomalous 90 were learned, it would drag mean/std toward the
    # outlier and weaken the next independent high observation.
    second = layer.update(_assessment(7, score=88.0))
    assert second is not None
    assert second["zscore"] >= 2.5


def test_pressure_fire_does_not_ratchet_pressure_with_flagged_observation() -> None:
    layer = _layer()

    assert layer.update(_assessment(1)) is None
    assert layer.update(_assessment(2)) is None
    first = layer.update(_assessment(3))
    assert first is not None

    # The fired observation is evidence, not training data. A later low score
    # is evaluated from the last accepted normal pressure rather than a
    # ratcheted pressure that included the prior anomaly.
    later = layer.update(_assessment(4, score=1.0))
    assert later is None


def test_stable_baseline_detects_first_upward_departure() -> None:
    layer = _zscore_layer()

    for seq in range(1, 7):
        assert layer.update(_assessment(seq, score=10.0)) is None

    anomaly = layer.update(_assessment(7, score=20.0))
    assert anomaly is not None
    assert anomaly["zscore"] == float("inf")
    assert anomaly["baseline_mean"] == 10.0
    assert anomaly["baseline_std"] == 0.0


def test_stable_baseline_does_not_treat_downward_departure_as_threat() -> None:
    layer = _zscore_layer()

    for seq in range(1, 7):
        assert layer.update(_assessment(seq, score=10.0)) is None

    assert layer.update(_assessment(7, score=5.0)) is None


def test_failure_ratio_shift_detected_without_score_shift() -> None:
    layer = _zscore_layer()

    for seq in range(1, 7):
        assert layer.update(
            _assessment(seq, score=10.0, failure_ratio=0.05)
        ) is None

    anomaly = layer.update(
        _assessment(7, score=10.0, failure_ratio=0.80)
    )
    assert anomaly is not None
    shift = anomaly["behavioral_shift"]
    assert shift["dimension"] == "failure_ratio"
    assert shift["value"] == 0.8
    assert shift["zscore"] == float("inf")
    assert layer.stats()["behavioral_fires"] == 1
    assert layer.stats()["zscore_fires"] == 0


def test_failure_ratio_anomaly_does_not_poison_behavior_baseline() -> None:
    layer = _zscore_layer()

    for seq in range(1, 7):
        assert layer.update(
            _assessment(seq, score=10.0, failure_ratio=0.05)
        ) is None

    first = layer.update(
        _assessment(7, score=10.0, failure_ratio=0.80)
    )
    second = layer.update(
        _assessment(8, score=10.0, failure_ratio=0.75)
    )
    assert first is not None
    assert second is not None
    assert second["behavioral_shift"]["zscore"] == float("inf")


def test_missing_failure_ratio_preserves_score_only_behavior() -> None:
    layer = _zscore_layer()
    _prime_score_baseline(layer)

    assert layer.update(_assessment(6, score=50.0)) is None
    assert layer.stats()["behavioral_fires"] == 0



def test_stale_behavior_dimension_resets_while_score_subject_stays_active(
    monkeypatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr(
        fenrir_hunter.time,
        "monotonic",
        lambda: now[0],
    )
    layer = FenrirAnomalyLayer(
        zscore_threshold=2.5,
        pressure_threshold=1_000_000.0,
        decay_rate=0.000001,
        min_observations=5,
        max_keys=100,
        stale_seconds=60.0,
    )

    for seq in range(1, 7):
        assert layer.update(
            _assessment(seq, score=10.0, failure_ratio=0.05)
        ) is None
        now[0] += 1.0

    # Keep the subject itself fresh with score-only evidence while the
    # optional behavioral dimension is absent for longer than stale_seconds.
    for seq in range(7, 10):
        now[0] += 25.0
        assert layer.update(
            _assessment(seq, score=10.0)
        ) is None

    # A returning dimension starts a new behavioral baseline instead of being
    # compared against behavior that has been absent beyond the stale window.
    assert layer.update(
        _assessment(10, score=10.0, failure_ratio=0.80)
    ) is None

    stats = layer.stats()
    assert stats["active_keys"] == 1
    assert stats["behavioral_baselines_reset"] == 1
    assert stats["behavioral_fires"] == 0


def test_fresh_behavior_dimension_still_detects_shift(monkeypatch) -> None:
    now = [2000.0]
    monkeypatch.setattr(
        fenrir_hunter.time,
        "monotonic",
        lambda: now[0],
    )
    layer = FenrirAnomalyLayer(
        zscore_threshold=2.5,
        pressure_threshold=1_000_000.0,
        decay_rate=0.000001,
        min_observations=5,
        max_keys=100,
        stale_seconds=60.0,
    )

    for seq in range(1, 7):
        assert layer.update(
            _assessment(seq, score=10.0, failure_ratio=0.05)
        ) is None
        now[0] += 1.0

    now[0] += 10.0
    anomaly = layer.update(
        _assessment(7, score=10.0, failure_ratio=0.80)
    )
    assert anomaly is not None
    assert anomaly["behavioral_shift"]["dimension"] == "failure_ratio"
    assert layer.stats()["behavioral_baselines_reset"] == 0
