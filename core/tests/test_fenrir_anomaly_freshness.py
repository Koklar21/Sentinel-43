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
) -> ThreatAssessment:
    indicators = {}
    if seq is not None:
        indicators["evidence_seq"] = seq

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
