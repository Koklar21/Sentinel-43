# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
# 1. GNU Affero General Public License (AGPL v3.0)
#    for open-source use, modification, and distribution.
#
# 2. Commercial License
#    for proprietary, enterprise, government, or other commercial use
#    not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

"""
Sentinel-43 — FenrirHunter

Active threat hunting node. Owns both a SentinelThreatDetector (threshold-
based scoring) and a FenrirAnomalyLayer (Welford statistical baseline tracking).

Every scan:
  1. detector.assess_all()    — threshold-based scoring of all tracked windows
  2. anomaly_layer.update()   — z-score + cumulative pressure check on every
                                assessment regardless of severity

Two reporting paths:
  Path A — Threshold:  severity >= min_report_severity → report
  Path B — Anomaly:    statistical anomaly regardless of severity → report
                       catches slow/low-and-slow attacks that never cross
                       fixed score thresholds

All findings forward to Watchtower and dashboard broadcast concurrently.
Fenrir hunts. It does not bite.

Non-responsibilities:
  - No blocking of traffic
  - No approval/veto decisions
  - No firewall changes
  - No secret handling

Anomaly layer extracted and adapted from Aegis42 OnlineAnomalyDetector:
  - sklearn/IsolationForest removed (not in S43 stack)
  - Cumulative pressure gains exponential time-decay (was unbounded)
  - Per-identity LRU eviction and stale-key pruning added
  - Thread-safe for run_in_executor context

State machine:
  DEGRADED = below error threshold — readiness 200 (limping but hunting)
  ERROR    = at/above threshold    — readiness 503 (hard stop)

Import path note:
  Adjust the two detector imports marked ADJUST IMPORT PATH to match your
  actual package layout. Hard imports — Fenrir refuses to start if either
  is missing.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import signal as _signal
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Tuple

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector, web

# ---------------------------------------------------------------------------
# ADJUST IMPORT PATH if your package layout differs from sentinel_43_ai/detection/
# Hard imports — Fenrir refuses to start if either is not importable.
# ---------------------------------------------------------------------------
from sentinel_43_ai.detection.sentinel_threat_detector import (
    DetectorConfig,
    SentinelThreatDetector,
)
from sentinel_43_ai.detection.sentinel_threat_types import (
    ThreatAssessment,
    ThreatSeverity,
)
# ---------------------------------------------------------------------------

logger = logging.getLogger("sentinel43.fenrir")


# =============================================================================
# Severity ordering
# =============================================================================

_SEVERITY_RANK: dict[ThreatSeverity, int] = {
    ThreatSeverity.LOW:      0,
    ThreatSeverity.MEDIUM:   1,
    ThreatSeverity.HIGH:     2,
    ThreatSeverity.CRITICAL: 3,
}

_SEVERITY_FROM_STR: dict[str, ThreatSeverity] = {
    "LOW":      ThreatSeverity.LOW,
    "MEDIUM":   ThreatSeverity.MEDIUM,
    "HIGH":     ThreatSeverity.HIGH,
    "CRITICAL": ThreatSeverity.CRITICAL,
}


# =============================================================================
# Anomaly layer — Welford streaming baseline
# =============================================================================

@dataclass
class _WelfordStream:
    """
    Online mean/variance tracker using Welford's algorithm.
    Single-value streaming. Caller must hold the enclosing RLock.
    """

    count: int   = 0
    mean:  float = 0.0
    _m2:   float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta      = value - self.mean
        self.mean += delta / self.count
        delta2     = value - self.mean
        self._m2  += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self._m2 / (self.count - 1)

    @property
    def std(self) -> float:
        v = self.variance
        return math.sqrt(v) if v > 0 else 0.0

    def zscore(self, value: float) -> float:
        s = self.std
        if s == 0.0 or self.count < 2:
            return 0.0
        return abs((value - self.mean) / s)


@dataclass
class _IdentityBaseline:
    """
    Score history for one (identity, ip) pair.

    Pure data container. All update logic lives in FenrirAnomalyLayer.update()
    so that z-score and pressure checks are calculated against the EXISTING
    baseline before the new score contaminates it.
    """

    stream:    _WelfordStream = field(default_factory=_WelfordStream)
    pressure:  float          = 0.0
    last_seen: float          = field(default_factory=time.time)


class FenrirAnomalyLayer:
    """
    Per-identity statistical baseline tracking using Welford's algorithm.

    Thread-safe. Called from the dedicated detection executor after
    assess_all() returns, inside the same _run_detection() call.

    Two signals:
      1. Z-score: single score deviates from identity's historical baseline.
         Catches sudden spikes for previously quiet identities.
      2. Cumulative pressure: decayed running total exceeds threshold.
         Catches sustained low-score activity across many scan cycles.
    """

    def __init__(
        self,
        *,
        zscore_threshold:   float = 3.5,
        pressure_threshold: float = 150.0,
        decay_rate:         float = 0.002,
        min_observations:   int   = 5,
        max_keys:           int   = 10_000,
        stale_seconds:      float = 3_600.0,
    ) -> None:
        self.zscore_threshold   = zscore_threshold
        self.pressure_threshold = pressure_threshold
        self.decay_rate         = decay_rate
        self.min_observations   = min_observations
        self.max_keys           = max_keys
        self.stale_seconds      = stale_seconds

        self._baselines: OrderedDict[Tuple[str, str], _IdentityBaseline] = OrderedDict()
        self._lock = threading.RLock()

        self._stats: dict[str, int] = {
            "updates":        0,
            "zscore_fires":   0,
            "pressure_fires": 0,
            "keys_evicted":   0,
            "keys_pruned":    0,
        }

    def update(self, assessment: ThreatAssessment) -> Optional[dict[str, Any]]:
        """
        Update the baseline for this identity/IP and check for anomalies.

        Critical ordering: z-score and pressure are calculated against the
        EXISTING baseline BEFORE the new score is incorporated. Updating
        first would let a suspicious score blend into its own mean, reducing
        its anomaly signal. "Let the criminal vote on whether crime happened."
        """
        key   = (assessment.identity, assessment.source_ip)
        now   = time.time()
        score = assessment.score

        with self._lock:
            self._stats["updates"] += 1

            if key not in self._baselines and len(self._baselines) >= self.max_keys:
                self._baselines.popitem(last=False)
                self._stats["keys_evicted"] += 1

            baseline = self._baselines.get(key)
            if baseline is None:
                baseline = _IdentityBaseline()
                self._baselines[key] = baseline
            else:
                self._baselines.move_to_end(key)

            # --- Step 1: read existing state BEFORE touching the baseline ---
            previous_count = baseline.stream.count
            prev_mean      = baseline.stream.mean
            prev_std       = baseline.stream.std

            # z-score against existing history (not yet contaminated)
            z = baseline.stream.zscore(score)

            # Decay pressure and project what it will be after adding this score
            elapsed            = max(0.0, now - baseline.last_seen)
            decayed_pressure   = baseline.pressure * math.exp(-self.decay_rate * elapsed)
            projected_pressure = decayed_pressure + score

            # --- Step 2: commit the update ---
            baseline.stream.update(score)
            baseline.pressure  = projected_pressure
            baseline.last_seen = now

            # --- Step 3: evaluate signals using pre-update state ---
            # Use previous_count so we require min_observations PRIOR to this
            # score — the observation we're currently judging doesn't count
            # toward its own baseline qualification.
            if previous_count < self.min_observations:
                return None

            anomaly: dict[str, Any] = {}

            if z >= self.zscore_threshold:
                self._stats["zscore_fires"] += 1
                anomaly["zscore"]           = round(z, 3)
                anomaly["zscore_threshold"] = self.zscore_threshold
                anomaly["baseline_mean"]    = round(prev_mean, 3)
                anomaly["baseline_std"]     = round(prev_std, 3)

            if projected_pressure >= self.pressure_threshold:
                self._stats["pressure_fires"] += 1
                anomaly["cumulative_pressure"] = round(projected_pressure, 3)
                anomaly["pressure_threshold"]  = self.pressure_threshold

            if not anomaly:
                return None

            anomaly["observations"] = previous_count
            return anomaly

    def prune(self) -> int:
        """Remove identities silent for stale_seconds. Returns count pruned."""
        now    = time.time()
        cutoff = now - self.stale_seconds
        with self._lock:
            stale = [k for k, b in self._baselines.items() if b.last_seen < cutoff]
            for k in stale:
                del self._baselines[k]
            self._stats["keys_pruned"] += len(stale)
            return len(stale)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "active_keys":        len(self._baselines),
                "zscore_threshold":   self.zscore_threshold,
                "pressure_threshold": self.pressure_threshold,
                "decay_rate":         self.decay_rate,
                "min_observations":   self.min_observations,
            }


# =============================================================================
# State
# =============================================================================

class FenrirState(str, Enum):
    INITIALIZING = "INITIALIZING"
    HUNTING      = "HUNTING"
    TRACKING     = "TRACKING"
    DEGRADED     = "DEGRADED"
    DORMANT      = "DORMANT"
    ERROR        = "ERROR"


# =============================================================================
# Config
# =============================================================================

def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class FenrirConfig:
    node_id: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_NODE_ID", "fenrir-hunter-01")
    )
    embedded_mode: bool = field(
        default_factory=lambda: _env_bool("S43_FENRIR_EMBEDDED", True)
    )
    host: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_HOST", "0.0.0.0")
    )
    health_port: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_HEALTH_PORT", "9201"))
    )
    scan_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_SCAN_INTERVAL", "2.0"))
    )
    max_consecutive_errors: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_MAX_ERRORS", "3"))
    )
    min_report_severity: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_MIN_SEVERITY", "HIGH").upper()
    )
    watchtower_url: str = field(
        default_factory=lambda: os.getenv(
            "S43_FENRIR_WATCHTOWER_URL", "http://s43-api:8000/watchtower/events"
        )
    )
    api_broadcast_url: str = field(
        default_factory=lambda: os.getenv(
            "S43_FENRIR_BROADCAST_URL", "http://s43-api:8000/internal/events/broadcast"
        )
    )
    report_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_REPORT_TIMEOUT", "5.0"))
    )
    api_token: Optional[str] = field(
        default_factory=lambda: os.getenv("S43_FENRIR_API_TOKEN")
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_LOG_LEVEL", "INFO")
    )
    detector_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_WINDOW_SECONDS", "60.0"))
    )
    detector_max_keys: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_MAX_KEYS", "0"))
    )
    detector_pool_workers: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_POOL_WORKERS", "2"))
    )
    anomaly_zscore_threshold: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_ANOMALY_ZSCORE", "3.5"))
    )
    anomaly_pressure_threshold: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_ANOMALY_PRESSURE", "150.0"))
    )
    anomaly_decay_rate: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_ANOMALY_DECAY", "0.002"))
    )
    anomaly_min_observations: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_ANOMALY_MIN_OBS", "5"))
    )
    anomaly_max_keys: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_ANOMALY_MAX_KEYS", "10000"))
    )
    anomaly_stale_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_ANOMALY_STALE", "3600.0"))
    )
    anomaly_prune_interval: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_PRUNE_INTERVAL", "300"))
    )


# =============================================================================
# Hunter
# =============================================================================

class FenrirHunter:
    """
    Fenrir hunter node for Sentinel-43.

    Path A — Threshold (SentinelThreatDetector):
      Assessments at or above min_report_severity become findings.

    Path B — Statistical anomaly (FenrirAnomalyLayer):
      Assessments below threshold but flagged by Welford z-score or
      cumulative pressure become anomaly escalation findings.

    All findings report to Watchtower and dashboard broadcast concurrently.
    Reporting failures are logged and counted but never crash the hunt loop.

    Fenrir hunts. It does not bite.
    """

    def __init__(self, config: Optional[FenrirConfig] = None) -> None:
        self.config = config or FenrirConfig()

        logging.basicConfig(
            level=self.config.log_level.upper(),
            format="%(asctime)s - FenrirHunter - %(levelname)s - %(message)s",
        )

        self.state              = FenrirState.INITIALIZING
        self.started_at         = datetime.now(timezone.utc)
        self.last_scan_at:        Optional[str]           = None
        self.last_finding:        Optional[dict[str, Any]] = None
        self.consecutive_errors = 0
        self._scan_count        = 0

        self.shutdown_event = asyncio.Event()
        self.runner:    Optional[web.AppRunner]      = None
        self.main_task: Optional[asyncio.Task[None]] = None
        self._session:  Optional[ClientSession]      = None
        self._started   = False
        self._lock      = asyncio.Lock()

        self._executor = ThreadPoolExecutor(
            max_workers=self.config.detector_pool_workers,
            thread_name_prefix="fenrir_detector",
        )

        self.detector = SentinelThreatDetector(
            cfg=DetectorConfig(
                window_seconds=self.config.detector_window_seconds,
                max_keys_hint=self.config.detector_max_keys,
            )
        )

        self.anomaly_layer = FenrirAnomalyLayer(
            zscore_threshold=self.config.anomaly_zscore_threshold,
            pressure_threshold=self.config.anomaly_pressure_threshold,
            decay_rate=self.config.anomaly_decay_rate,
            min_observations=self.config.anomaly_min_observations,
            max_keys=self.config.anomaly_max_keys,
            stale_seconds=self.config.anomaly_stale_seconds,
        )

        resolved = _SEVERITY_FROM_STR.get(self.config.min_report_severity)
        if resolved is None:
            raise ValueError(
                f"S43_FENRIR_MIN_SEVERITY must be one of "
                f"{sorted(_SEVERITY_FROM_STR)}, "
                f"got {self.config.min_report_severity!r}"
            )
        self._min_severity_rank: int = _SEVERITY_RANK[resolved]

        self.metrics: dict[str, Any] = {
            "scans":                0,
            "assessments_total":    0,
            "findings_low":         0,
            "findings_medium":      0,
            "findings_high":        0,
            "findings_critical":    0,
            "findings_reported":    0,
            "anomaly_escalations":  0,
            "watchtower_ok":        0,
            "watchtower_failures":  0,
            "broadcast_ok":         0,
            "broadcast_failures":   0,
            "errors":               0,
            "state_transitions":    0,
        }

        logger.info(
            "FenrirHunter initialized: node_id=%s embedded=%s "
            "min_severity=%s anomaly_zscore=%.1f anomaly_pressure=%.0f",
            self.config.node_id,
            self.config.embedded_mode,
            self.config.min_report_severity,
            self.config.anomaly_zscore_threshold,
            self.config.anomaly_pressure_threshold,
        )

    # -------------------------------------------------------------------------
    # State
    # -------------------------------------------------------------------------

    def transition(self, new_state: FenrirState) -> None:
        if self.state == new_state:
            return
        old = self.state
        self.state = new_state
        self.metrics["state_transitions"] += 1
        logger.info("Fenrir state: %s -> %s", old.value, new_state.value)

    # -------------------------------------------------------------------------
    # Health / readiness
    # -------------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        return {
            "node_id":            self.config.node_id,
            "node_type":          "fenrir_hunter",
            "state":              self.state.value,
            "status":             (
                "error"
                if self.state == FenrirState.ERROR
                else "degraded"
                if self.state == FenrirState.DEGRADED
                else "ok"
            ),
            "embedded_mode":      self.config.embedded_mode,
            "started":            self._started,
            "started_at":         self.started_at.isoformat(),
            "uptime_seconds":     round((now - self.started_at).total_seconds(), 3),
            "last_scan_at":       self.last_scan_at,
            "last_finding":       self.last_finding,
            "consecutive_errors": self.consecutive_errors,
            "metrics":            dict(self.metrics),
            "anomaly_layer":      self.anomaly_layer.stats(),
            "config": {
                "scan_interval_seconds":      self.config.scan_interval_seconds,
                "min_report_severity":        self.config.min_report_severity,
                "detector_window_seconds":    self.config.detector_window_seconds,
                "anomaly_zscore_threshold":   self.config.anomaly_zscore_threshold,
                "anomaly_pressure_threshold": self.config.anomaly_pressure_threshold,
                "anomaly_decay_rate":         self.config.anomaly_decay_rate,
            },
            "capabilities": [
                "threat_detection",
                "statistical_anomaly_detection",
                "anomaly_tracking",
                "watchtower_reporting",
                "dashboard_broadcast",
            ],
        }

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response(self.snapshot())

    async def readiness(self, request: web.Request) -> web.Response:
        ready = self.state in {
            FenrirState.HUNTING,
            FenrirState.TRACKING,
            FenrirState.DEGRADED,
        }
        return web.json_response(
            {
                "ready":   ready,
                "state":   self.state.value,
                "node_id": self.config.node_id,
                "status":  (
                    "error"    if self.state == FenrirState.ERROR
                    else "degraded" if self.state == FenrirState.DEGRADED
                    else "ok"
                ),
            },
            status=200 if ready else 503,
        )

    # -------------------------------------------------------------------------
    # Detection
    # -------------------------------------------------------------------------

    def _assessment_to_finding(
        self,
        assessment: ThreatAssessment,
        *,
        detection_method: str,
        anomaly: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        finding: dict[str, Any] = {
            "source":           "fenrir",
            "node_id":          self.config.node_id,
            "type":             "threat_finding",
            "detection_method": detection_method,
            "severity":         assessment.severity.value,
            "threat_kind":      assessment.threat_kind.value,
            "source_kind":      assessment.source_kind.value,
            "score":            assessment.score,
            "identity":         assessment.identity,
            "source_ip":        assessment.source_ip,
            "window_size":      assessment.window_size,
            "tags":             list(assessment.supporting_tags),
            "indicators":       dict(assessment.indicators),
            "generated_at":     datetime.fromtimestamp(
                assessment.generated_at, tz=timezone.utc
            ).isoformat(),
            "reported_at":      datetime.now(timezone.utc).isoformat(),
        }
        if anomaly:
            finding["anomaly"] = anomaly
        return finding

    def _run_detection(
        self,
    ) -> tuple[list[ThreatAssessment], dict[tuple, dict[str, Any]]]:
        """
        Synchronous — runs in the dedicated thread pool.
        Both detector and anomaly layer run in one executor call.
        """
        assessments = self.detector.assess_all()
        anomaly_map: dict[tuple, dict[str, Any]] = {}
        for a in assessments:
            result = self.anomaly_layer.update(a)
            if result is not None:
                # Include threat_kind and source_kind in the key so multiple
                # assessments for the same identity/IP don't overwrite each other.
                anomaly_map[
                    (a.identity, a.source_ip, a.threat_kind.value, a.source_kind.value)
                ] = result
        return assessments, anomaly_map

    async def observe_signals(self) -> list[dict[str, Any]]:
        """
        Run both detection paths. Returns unified finding dicts.

        Path A: severity >= min_report_severity → threshold finding
        Path B: anomaly fired on low/medium score → anomaly escalation
        """
        loop = asyncio.get_running_loop()
        assessments, anomaly_map = await loop.run_in_executor(
            self._executor, self._run_detection
        )

        self.metrics["assessments_total"] += len(assessments)
        findings: list[dict[str, Any]] = []

        for a in assessments:
            rank    = _SEVERITY_RANK.get(a.severity, 0)
            anomaly = anomaly_map.get(
                (a.identity, a.source_ip, a.threat_kind.value, a.source_kind.value)
            )

            if a.severity == ThreatSeverity.LOW:
                self.metrics["findings_low"] += 1
            elif a.severity == ThreatSeverity.MEDIUM:
                self.metrics["findings_medium"] += 1
            elif a.severity == ThreatSeverity.HIGH:
                self.metrics["findings_high"] += 1
            elif a.severity == ThreatSeverity.CRITICAL:
                self.metrics["findings_critical"] += 1

            if rank >= self._min_severity_rank:
                findings.append(
                    self._assessment_to_finding(
                        a, detection_method="threshold", anomaly=anomaly
                    )
                )
            elif anomaly:
                self.metrics["anomaly_escalations"] += 1
                findings.append(
                    self._assessment_to_finding(
                        a, detection_method="statistical_anomaly", anomaly=anomaly
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Reporting
    # -------------------------------------------------------------------------

    async def process_finding(self, finding: dict[str, Any]) -> None:
        self.transition(FenrirState.TRACKING)
        self.metrics["findings_reported"] += 1
        self.last_finding = finding

        logger.warning(
            "Fenrir finding: method=%s severity=%s kind=%s "
            "identity=%s ip=%s score=%.2f%s",
            finding.get("detection_method", "?"),
            finding.get("severity", "?"),
            finding.get("threat_kind", "?"),
            finding.get("identity", "?"),
            finding.get("source_ip", "?"),
            finding.get("score", 0.0),
            f" [z={finding['anomaly'].get('zscore', '?')}]"
            if finding.get("anomaly") else "",
        )

        await asyncio.gather(
            self._report_to_watchtower(finding),
            self._broadcast_to_dashboard(finding),
            return_exceptions=True,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"
        return headers

    async def _report_to_watchtower(self, finding: dict[str, Any]) -> None:
        if not self._session or self._session.closed:
            self.metrics["watchtower_failures"] += 1
            return
        try:
            async with self._session.post(
                self.config.watchtower_url,
                json=finding,
                headers=self._headers(),
                timeout=ClientTimeout(total=self.config.report_timeout_seconds),
            ) as resp:
                if 200 <= resp.status < 300:
                    self.metrics["watchtower_ok"] += 1
                else:
                    self.metrics["watchtower_failures"] += 1
                    logger.warning("Watchtower rejected finding: status=%s", resp.status)
        except asyncio.TimeoutError:
            self.metrics["watchtower_failures"] += 1
            logger.warning("Watchtower timed out after %.1fs", self.config.report_timeout_seconds)
        except aiohttp.ClientError as exc:
            self.metrics["watchtower_failures"] += 1
            logger.warning("Watchtower report failed: %s", exc)
        except Exception as exc:
            self.metrics["watchtower_failures"] += 1
            logger.exception("Watchtower unexpected error: %s", exc)

    async def _broadcast_to_dashboard(self, finding: dict[str, Any]) -> None:
        if not self._session or self._session.closed:
            self.metrics["broadcast_failures"] += 1
            return
        payload = {"event_type": "fenrir_finding", "channel": "security", "data": finding}
        try:
            async with self._session.post(
                self.config.api_broadcast_url,
                json=payload,
                headers=self._headers(),
                timeout=ClientTimeout(total=self.config.report_timeout_seconds),
            ) as resp:
                if 200 <= resp.status < 300:
                    self.metrics["broadcast_ok"] += 1
                else:
                    self.metrics["broadcast_failures"] += 1
                    logger.warning("Dashboard broadcast rejected: status=%s", resp.status)
        except asyncio.TimeoutError:
            self.metrics["broadcast_failures"] += 1
            logger.warning("Dashboard broadcast timed out after %.1fs", self.config.report_timeout_seconds)
        except aiohttp.ClientError as exc:
            self.metrics["broadcast_failures"] += 1
            logger.warning("Dashboard broadcast failed: %s", exc)
        except Exception as exc:
            self.metrics["broadcast_failures"] += 1
            logger.exception("Dashboard broadcast unexpected error: %s", exc)

    # -------------------------------------------------------------------------
    # Hunt loop
    # -------------------------------------------------------------------------

    async def hunting_loop(self) -> None:
        self.transition(FenrirState.HUNTING)
        logger.info(
            "Fenrir hunt loop started: interval=%.1fs min_severity=%s "
            "anomaly_zscore=%.1f anomaly_pressure=%.0f",
            self.config.scan_interval_seconds,
            self.config.min_report_severity,
            self.config.anomaly_zscore_threshold,
            self.config.anomaly_pressure_threshold,
        )

        while not self.shutdown_event.is_set():
            try:
                self._scan_count      += 1
                self.metrics["scans"] += 1
                self.last_scan_at      = datetime.now(timezone.utc).isoformat()

                # Periodic stale-key pruning
                if self._scan_count % self.config.anomaly_prune_interval == 0:
                    loop   = asyncio.get_running_loop()
                    pruned = await loop.run_in_executor(
                        self._executor, self.anomaly_layer.prune
                    )
                    if pruned:
                        logger.debug("Anomaly layer pruned %d stale keys.", pruned)

                findings = await self.observe_signals()

                for finding in findings:
                    await self.process_finding(finding)

                if not findings and self.state == FenrirState.TRACKING:
                    self.transition(FenrirState.HUNTING)

                self.consecutive_errors = 0

                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(),
                        timeout=self.config.scan_interval_seconds,
                    )
                except asyncio.TimeoutError:
                    pass

            except asyncio.CancelledError:
                logger.info("Fenrir hunt loop cancelled.")
                raise

            except Exception as exc:
                self.metrics["errors"]  += 1
                self.consecutive_errors += 1
                logger.exception("Fenrir hunt loop error: %s", exc)

                # DEGRADED = limping (readiness 200), ERROR = hard stop (readiness 503)
                if self.consecutive_errors >= self.config.max_consecutive_errors:
                    self.transition(FenrirState.ERROR)
                else:
                    self.transition(FenrirState.DEGRADED)

                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(),
                        timeout=min(5.0, self.config.scan_interval_seconds),
                    )
                except asyncio.TimeoutError:
                    pass

                if not self.shutdown_event.is_set():
                    self.transition(FenrirState.HUNTING)

        self.transition(FenrirState.DORMANT)
        logger.info("Fenrir hunt loop stopped.")

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def _start_session(self) -> None:
        if self._session and not self._session.closed:
            return
        self._session = ClientSession(connector=TCPConnector(limit=10))
        logger.debug("Fenrir HTTP session created.")

    async def start_health_server(self) -> None:
        app = web.Application()
        app.router.add_get("/health", self.health)
        app.router.add_get("/ready",  self.readiness)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.config.host, self.config.health_port)
        await site.start()
        logger.info(
            "Fenrir health server listening on %s:%s",
            self.config.host, self.config.health_port,
        )

    async def start(self) -> None:
        """Start Fenrir. Idempotent."""
        async with self._lock:
            if self._started:
                return
            self.shutdown_event.clear()
            self.transition(FenrirState.INITIALIZING)
            await self._start_session()
            if not self.config.embedded_mode:
                await self.start_health_server()
            self.main_task = asyncio.create_task(
                self.hunting_loop(), name="sentinel43-fenrir-hunter"
            )
            self._started = True
            logger.info("Fenrir started.")

    async def shutdown(self, reason: str = "shutdown") -> None:
        """Graceful shutdown. Idempotent."""
        async with self._lock:
            if not self._started and self.state == FenrirState.DORMANT:
                return
            logger.warning("Fenrir shutdown: %s", reason)
            self.shutdown_event.set()
            if self.main_task and self.main_task is not asyncio.current_task():
                self.main_task.cancel()
                try:
                    await self.main_task
                except asyncio.CancelledError:
                    pass
                self.main_task = None
            if self.runner:
                await self.runner.cleanup()
                self.runner = None
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None
            # wait=False avoids blocking the event loop if a detector scan
            # is in-flight at shutdown time. Threads complete naturally once
            # the task that submitted them finishes.
            self._executor.shutdown(wait=False)
            self.transition(FenrirState.DORMANT)
            self._started = False
            logger.info("Fenrir shutdown complete.")

    async def stop(self, reason: str = "stop requested") -> None:
        """Alias for shutdown(). Called by FastAPI lifespan teardown."""
        await self.shutdown(reason)

    async def run(self) -> None:
        """Standalone entry point. Sets embedded_mode=False."""
        self.config.embedded_mode = False
        loop = asyncio.get_running_loop()
        for sig in (_signal.SIGINT, _signal.SIGTERM):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self.shutdown(s.name)),
                )
            except NotImplementedError:
                pass
        await self.start()
        try:
            await self.shutdown_event.wait()
        finally:
            await self.shutdown("run-finally")


# =============================================================================
# Entry point
# =============================================================================

async def main() -> None:
    hunter = FenrirHunter()
    await hunter.run()


if __name__ == "__main__":
    asyncio.run(main())
