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

"""Sentinel-43 Fenrir observational threat-hunting node.

Fenrir observes, scores, correlates, and reports findings.

It does NOT:
    - block traffic
    - change firewall state
    - approve or veto actions
    - execute remediation
    - mutate governance state

Detection combines fixed-threshold assessments with per-identity statistical
anomaly tracking.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import signal
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Final

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector, web

from core.detection.sentinel_threat_detector import (
    DetectorConfig,
    SentinelThreatDetector,
)
from core.detection.sigma_detector import SigmaDetector
from core.detection.sentinel_threat_types import (
    ThreatAssessment,
    ThreatSeverity,
)


logger = logging.getLogger("sentinel43.fenrir")


# =============================================================================
# Constants
# =============================================================================

_SEVERITY_RANK: Final[dict[ThreatSeverity, int]] = {
    ThreatSeverity.LOW: 0,
    ThreatSeverity.MEDIUM: 1,
    ThreatSeverity.HIGH: 2,
    ThreatSeverity.CRITICAL: 3,
}

_SEVERITY_FROM_STR: Final[dict[str, ThreatSeverity]] = {
    "LOW": ThreatSeverity.LOW,
    "MEDIUM": ThreatSeverity.MEDIUM,
    "HIGH": ThreatSeverity.HIGH,
    "CRITICAL": ThreatSeverity.CRITICAL,
}

_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)

_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)


# =============================================================================
# Environment helpers
# =============================================================================

def _environment() -> str:
    raw = (
        os.getenv("SENTINEL_ENV")
        or os.getenv("S43_ENV")
        or "production"
    ).strip().lower()

    aliases = {
        "dev": "development",
        "local": "development",
        "prod": "production",
        "stage": "staging",
    }

    return aliases.get(raw, raw)


def _is_local() -> bool:
    return _environment() in _LOCAL_ENVIRONMENTS


def _env_bool(
    name: str,
    default: bool,
) -> bool:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    normalized = raw.strip().lower()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    if not _is_local():
        raise RuntimeError(
            f"{name} must be boolean; got {raw!r}"
        )

    logger.warning(
        "Invalid %s=%r; using default %s",
        name,
        raw,
        default,
    )
    return default


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    try:
        value = int(raw.strip())
    except ValueError as exc:
        if not _is_local():
            raise RuntimeError(
                f"{name} must be an integer"
            ) from exc

        logger.warning(
            "Invalid %s=%r; using default %s",
            name,
            raw,
            default,
        )
        return default

    if not minimum <= value <= maximum:
        raise RuntimeError(
            f"{name} must be between {minimum} and {maximum}"
        )

    return value


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    try:
        value = float(raw.strip())
    except ValueError as exc:
        if not _is_local():
            raise RuntimeError(
                f"{name} must be numeric"
            ) from exc

        logger.warning(
            "Invalid %s=%r; using default %s",
            name,
            raw,
            default,
        )
        return default

    if not minimum <= value <= maximum:
        raise RuntimeError(
            f"{name} must be between {minimum} and {maximum}"
        )

    return value


# =============================================================================
# Statistical anomaly layer
# =============================================================================

@dataclass(slots=True)
class _WelfordStream:
    count: int = 0
    mean: float = 0.0
    _m2: float = 0.0

    def update(
        self,
        value: float,
    ) -> None:
        self.count += 1

        delta = (
            value
            - self.mean
        )

        self.mean += (
            delta
            / self.count
        )

        delta2 = (
            value
            - self.mean
        )

        self._m2 += (
            delta
            * delta2
        )

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0

        return self._m2 / (
            self.count - 1
        )

    @property
    def std(self) -> float:
        variance = self.variance

        return (
            math.sqrt(variance)
            if variance > 0.0
            else 0.0
        )

    def zscore(
        self,
        value: float,
    ) -> float:
        """Return the upper-tail z-score for a threat score.

        Fenrir is looking for suspicious increases above an established
        baseline. A large downward deviation may be statistically unusual,
        but it is not evidence of increased threat and must not escalate.
        """
        standard_deviation = self.std

        if self.count < 2:
            return 0.0

        if standard_deviation == 0.0:
            # A perfectly stable mature baseline still has information.
            # Treat an upward departure as maximally unusual rather than
            # silently declaring it non-anomalous because division by zero
            # is unavailable.
            return (
                math.inf
                if value > self.mean
                else 0.0
            )

        return max(
            0.0,
            (
                value
                - self.mean
            )
            / standard_deviation,
        )


@dataclass(slots=True)
class _IdentityBaseline:
    stream: _WelfordStream = field(
        default_factory=_WelfordStream
    )
    pressure: float = 0.0
    last_evidence_seq: int = 0
    last_seen_monotonic: float = field(
        default_factory=time.monotonic
    )


class FenrirAnomalyLayer:
    """Bounded per-identity statistical anomaly tracker."""

    def __init__(
        self,
        *,
        zscore_threshold: float = 3.5,
        pressure_threshold: float = 150.0,
        decay_rate: float = 0.002,
        min_observations: int = 5,
        max_keys: int = 10_000,
        stale_seconds: float = 3_600.0,
    ) -> None:
        if zscore_threshold <= 0:
            raise ValueError(
                "zscore_threshold must be > 0"
            )

        if pressure_threshold <= 0:
            raise ValueError(
                "pressure_threshold must be > 0"
            )

        if decay_rate <= 0:
            raise ValueError(
                "decay_rate must be > 0"
            )

        if min_observations < 2:
            raise ValueError(
                "min_observations must be >= 2"
            )

        if max_keys < 1:
            raise ValueError(
                "max_keys must be >= 1"
            )

        if stale_seconds <= 0:
            raise ValueError(
                "stale_seconds must be > 0"
            )

        self.zscore_threshold = zscore_threshold
        self.pressure_threshold = pressure_threshold
        self.decay_rate = decay_rate
        self.min_observations = min_observations
        self.max_keys = max_keys
        self.stale_seconds = stale_seconds

        self._baselines: OrderedDict[
            tuple[str, str],
            _IdentityBaseline,
        ] = OrderedDict()

        self._lock = threading.RLock()

        self._stats: dict[str, int] = {
            "updates": 0,
            "fresh_updates": 0,
            "duplicate_updates_skipped": 0,
            "sequence_regressions_skipped": 0,
            "missing_evidence_seq_skipped": 0,
            "zscore_fires": 0,
            "pressure_fires": 0,
            "keys_evicted": 0,
            "keys_pruned": 0,
        }

    def update(
        self,
        assessment: ThreatAssessment,
    ) -> dict[str, Any] | None:
        key = (
            str(assessment.identity),
            str(assessment.source_ip),
        )

        raw_evidence_seq = assessment.indicators.get(
            "evidence_seq"
        )
        evidence_seq = (
            raw_evidence_seq
            if isinstance(raw_evidence_seq, int)
            and not isinstance(raw_evidence_seq, bool)
            and raw_evidence_seq > 0
            else None
        )

        now = time.monotonic()
        score = float(
            assessment.score
        )

        with self._lock:
            self._stats[
                "updates"
            ] += 1

            # Fenrir's statistical layer is allowed to learn only from fresh
            # detector evidence. assess_all() is polled repeatedly even when
            # nothing new arrived; treating each poll as a new observation
            # would inflate cumulative pressure and contaminate the baseline.
            if evidence_seq is None:
                self._stats[
                    "missing_evidence_seq_skipped"
                ] += 1
                return None

            existing = self._baselines.get(
                key
            )
            if existing is not None:
                if evidence_seq < existing.last_evidence_seq:
                    self._stats[
                        "sequence_regressions_skipped"
                    ] += 1
                    return None

                if evidence_seq == existing.last_evidence_seq:
                    self._stats[
                        "duplicate_updates_skipped"
                    ] += 1
                    return None

            if (
                key not in self._baselines
                and len(self._baselines)
                >= self.max_keys
            ):
                self._baselines.popitem(
                    last=False
                )

                self._stats[
                    "keys_evicted"
                ] += 1

            baseline = self._baselines.get(
                key
            )

            if baseline is None:
                baseline = _IdentityBaseline()
                self._baselines[
                    key
                ] = baseline
            else:
                self._baselines.move_to_end(
                    key
                )

            self._stats[
                "fresh_updates"
            ] += 1

            previous_count = (
                baseline.stream.count
            )

            previous_mean = (
                baseline.stream.mean
            )

            previous_std = (
                baseline.stream.std
            )

            zscore = baseline.stream.zscore(
                score
            )

            elapsed = max(
                0.0,
                now
                - baseline.last_seen_monotonic,
            )

            decayed_pressure = (
                baseline.pressure
                * math.exp(
                    -self.decay_rate
                    * elapsed
                )
            )

            projected_pressure = (
                decayed_pressure
                + score
            )

            baseline.last_evidence_seq = evidence_seq
            baseline.last_seen_monotonic = (
                now
            )

            if (
                previous_count
                < self.min_observations
            ):
                baseline.stream.update(
                    score
                )
                baseline.pressure = (
                    projected_pressure
                )
                return None

            anomaly: dict[str, Any] = {}

            if zscore >= self.zscore_threshold:
                self._stats[
                    "zscore_fires"
                ] += 1

                anomaly.update(
                    {
                        "zscore": round(
                            zscore,
                            3,
                        ),
                        "zscore_threshold": self.zscore_threshold,
                        "baseline_mean": round(
                            previous_mean,
                            3,
                        ),
                        "baseline_std": round(
                            previous_std,
                            3,
                        ),
                    }
                )

            if (
                projected_pressure
                >= self.pressure_threshold
            ):
                self._stats[
                    "pressure_fires"
                ] += 1

                anomaly.update(
                    {
                        "cumulative_pressure": round(
                            projected_pressure,
                            3,
                        ),
                        "pressure_threshold": self.pressure_threshold,
                    }
                )

            if not anomaly:
                # Learn only normal observations once the baseline is mature.
                # An observation that already crossed an anomaly threshold
                # must not drag the baseline toward itself or inflate future
                # cumulative pressure.
                baseline.stream.update(
                    score
                )
                baseline.pressure = (
                    projected_pressure
                )
                return None

            anomaly[
                "observations"
            ] = previous_count
            anomaly[
                "evidence_seq"
            ] = evidence_seq

            return anomaly

    def prune(
        self,
    ) -> int:
        now = time.monotonic()
        cutoff = (
            now
            - self.stale_seconds
        )

        with self._lock:
            stale_keys = [
                key
                for key, baseline
                in self._baselines.items()
                if baseline.last_seen_monotonic
                < cutoff
            ]

            for key in stale_keys:
                del self._baselines[
                    key
                ]

            self._stats[
                "keys_pruned"
            ] += len(
                stale_keys
            )

            return len(
                stale_keys
            )

    def stats(
        self,
    ) -> dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "active_keys": len(
                    self._baselines
                ),
                "zscore_threshold": self.zscore_threshold,
                "pressure_threshold": self.pressure_threshold,
                "decay_rate": self.decay_rate,
                "min_observations": self.min_observations,
            }


# =============================================================================
# State / configuration
# =============================================================================

class FenrirState(str, Enum):
    INITIALIZING = "INITIALIZING"
    HUNTING = "HUNTING"
    TRACKING = "TRACKING"
    DEGRADED = "DEGRADED"
    DORMANT = "DORMANT"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class FenrirConfig:
    node_id: str
    embedded_mode: bool
    health_host: str
    health_port: int
    scan_interval_seconds: float
    max_consecutive_errors: int
    min_report_severity: str
    report_timeout_seconds: float
    api_token: str | None
    detector_window_seconds: float
    detector_max_keys: int
    detector_pool_workers: int
    sigma_enabled: bool
    sigma_rules_path: str
    sigma_max_rules: int
    sigma_max_matches_per_event: int
    anomaly_zscore_threshold: float
    anomaly_pressure_threshold: float
    anomaly_decay_rate: float
    anomaly_min_observations: int
    anomaly_max_keys: int
    anomaly_stale_seconds: float
    anomaly_prune_interval: int
    watchtower_url: str | None
    api_broadcast_url: str | None

    @classmethod
    def from_env(
        cls,
    ) -> "FenrirConfig":
        node_id = os.getenv(
            "S43_FENRIR_NODE_ID",
            "fenrir-hunter-01",
        ).strip()

        if not node_id:
            raise RuntimeError(
                "S43_FENRIR_NODE_ID must not be empty"
            )

        embedded_mode = _env_bool(
            "S43_FENRIR_EMBEDDED",
            True,
        )

        health_host = os.getenv(
            "S43_FENRIR_HOST",
            "127.0.0.1",
        ).strip()

        if not health_host:
            raise RuntimeError(
                "S43_FENRIR_HOST must not be empty"
            )

        if (
            health_host
            in {
                "0.0.0.0",
                "::",
                "*",
            }
            and not _is_local()
            and not _env_bool(
                "S43_FENRIR_ALLOW_REMOTE_HEALTH",
                False,
            )
        ):
            raise RuntimeError(
                "Fenrir health server may not bind all interfaces "
                "outside local/test without explicit opt-in"
            )

        severity = os.getenv(
            "S43_FENRIR_MIN_SEVERITY",
            "HIGH",
        ).strip().upper()

        if severity not in _SEVERITY_FROM_STR:
            raise RuntimeError(
                f"S43_FENRIR_MIN_SEVERITY must be one of "
                f"{sorted(_SEVERITY_FROM_STR)}"
            )

        watchtower_url = os.getenv(
            "S43_FENRIR_WATCHTOWER_URL",
            "",
        ).strip() or None

        api_broadcast_url = os.getenv(
            "S43_FENRIR_BROADCAST_URL",
            "",
        ).strip() or None

        return cls(
            node_id=node_id,
            embedded_mode=embedded_mode,
            health_host=health_host,
            health_port=_env_int(
                "S43_FENRIR_HEALTH_PORT",
                9201,
                minimum=1,
                maximum=65535,
            ),
            scan_interval_seconds=_env_float(
                "S43_FENRIR_SCAN_INTERVAL",
                2.0,
                minimum=0.1,
                maximum=3600.0,
            ),
            max_consecutive_errors=_env_int(
                "S43_FENRIR_MAX_ERRORS",
                3,
                minimum=1,
                maximum=100,
            ),
            min_report_severity=severity,
            report_timeout_seconds=_env_float(
                "S43_FENRIR_REPORT_TIMEOUT",
                5.0,
                minimum=0.1,
                maximum=60.0,
            ),
            api_token=os.getenv(
                "S43_FENRIR_API_TOKEN"
            ),
            detector_window_seconds=_env_float(
                "S43_FENRIR_WINDOW_SECONDS",
                60.0,
                minimum=1.0,
                maximum=86_400.0,
            ),
            detector_max_keys=_env_int(
                "S43_FENRIR_MAX_KEYS",
                10_000,
                minimum=1,
                maximum=1_000_000,
            ),
            detector_pool_workers=_env_int(
                "S43_FENRIR_POOL_WORKERS",
                2,
                minimum=1,
                maximum=32,
            ),
            sigma_enabled=_env_bool(
                "S43_SIGMA_ENABLED",
                False,
            ),
            sigma_rules_path=(
                os.getenv(
                    "S43_SIGMA_RULES_PATH",
                    "/app/rules/sigma",
                ).strip()
                or "/app/rules/sigma"
            ),
            sigma_max_rules=_env_int(
                "S43_SIGMA_MAX_RULES",
                256,
                minimum=1,
                maximum=10_000,
            ),
            sigma_max_matches_per_event=_env_int(
                "S43_SIGMA_MAX_MATCHES_PER_EVENT",
                8,
                minimum=1,
                maximum=128,
            ),
            anomaly_zscore_threshold=_env_float(
                "S43_FENRIR_ANOMALY_ZSCORE",
                3.5,
                minimum=0.1,
                maximum=100.0,
            ),
            anomaly_pressure_threshold=_env_float(
                "S43_FENRIR_ANOMALY_PRESSURE",
                150.0,
                minimum=1.0,
                maximum=1_000_000.0,
            ),
            anomaly_decay_rate=_env_float(
                "S43_FENRIR_ANOMALY_DECAY",
                0.002,
                minimum=0.000001,
                maximum=1.0,
            ),
            anomaly_min_observations=_env_int(
                "S43_FENRIR_ANOMALY_MIN_OBS",
                5,
                minimum=2,
                maximum=10_000,
            ),
            anomaly_max_keys=_env_int(
                "S43_FENRIR_ANOMALY_MAX_KEYS",
                10_000,
                minimum=1,
                maximum=1_000_000,
            ),
            anomaly_stale_seconds=_env_float(
                "S43_FENRIR_ANOMALY_STALE",
                3600.0,
                minimum=1.0,
                maximum=30 * 24 * 3600.0,
            ),
            anomaly_prune_interval=_env_int(
                "S43_FENRIR_PRUNE_INTERVAL",
                300,
                minimum=1,
                maximum=1_000_000,
            ),
            watchtower_url=watchtower_url,
            api_broadcast_url=api_broadcast_url,
        )


# =============================================================================
# Hunter
# =============================================================================

class FenrirHunter:
    """Observational Fenrir hunter node."""

    def __init__(
        self,
        config: FenrirConfig | None = None,
        *,
        authority: Any | None = None,
    ) -> None:
        self.config = (
            config
            or FenrirConfig.from_env()
        )

        self.state = FenrirState.INITIALIZING
        self.started_at = datetime.now(
            timezone.utc
        )
        self._start_monotonic = (
            time.monotonic()
        )

        self.last_scan_at: str | None = None
        self.last_finding: dict[str, Any] | None = None

        self.consecutive_errors = 0
        self._scan_count = 0

        self.shutdown_event = asyncio.Event()
        self.runner: web.AppRunner | None = None
        self.main_task: asyncio.Task[None] | None = None
        self._session: ClientSession | None = None
        self._executor: ThreadPoolExecutor | None = None

        self._started = False
        self._lifecycle_lock = asyncio.Lock()

        # Embedded Sentinel-43 binds the top-level runtime authority here.
        # Fenrir never receives Heart directly. Without authority Fenrir may
        # remain observational, but no human-governed staging can occur.
        self.authority: Any | None = authority
        self._heart_unavailable_logged = False
        # (identity, ip, kind) -> evidence_seq last handed to Sentinel-43
        # successfully. Bounded; unchanged evidence is not re-submitted.
        self._heart_observed_seq: OrderedDict[
            tuple[str, str, str], int
        ] = OrderedDict()

        self._sigma_load_error: str | None = None
        sigma_detector: SigmaDetector | None = None
        if self.config.sigma_enabled:
            try:
                sigma_detector = SigmaDetector.from_path(
                    Path(self.config.sigma_rules_path),
                    max_rules=self.config.sigma_max_rules,
                    max_matches_per_event=(
                        self.config.sigma_max_matches_per_event
                    ),
                )
            except Exception as exc:
                # Sigma is an optional evidence producer. A bad rule source
                # degrades Sigma coverage but must not stop Fenrir or S43.
                self._sigma_load_error = (
                    f"{type(exc).__name__}: {exc}"
                )[:512]
                logger.warning(
                    "Sigma detector unavailable; continuing without Sigma",
                    exc_info=True,
                )

        self.detector = SentinelThreatDetector(
            cfg=DetectorConfig(
                window_seconds=self.config.detector_window_seconds,
                max_keys_hint=self.config.detector_max_keys,
            ),
            sigma_detector=sigma_detector,
        )

        self.anomaly_layer = FenrirAnomalyLayer(
            zscore_threshold=self.config.anomaly_zscore_threshold,
            pressure_threshold=self.config.anomaly_pressure_threshold,
            decay_rate=self.config.anomaly_decay_rate,
            min_observations=self.config.anomaly_min_observations,
            max_keys=self.config.anomaly_max_keys,
            stale_seconds=self.config.anomaly_stale_seconds,
        )

        severity = _SEVERITY_FROM_STR[
            self.config.min_report_severity
        ]

        self._min_severity_rank = (
            _SEVERITY_RANK[
                severity
            ]
        )

        self.metrics: dict[str, int] = {
            "scans": 0,
            "assessments_total": 0,
            "findings_low": 0,
            "findings_medium": 0,
            "findings_high": 0,
            "findings_critical": 0,
            "findings_reported": 0,
            "anomaly_escalations": 0,
            "watchtower_ok": 0,
            "watchtower_failures": 0,
            "broadcast_ok": 0,
            "broadcast_failures": 0,
            "errors": 0,
            "state_transitions": 0,
            "heart_unavailable": 0,
            "heart_observe_failed": 0,
        }

    # ------------------------------------------------------------------
    # Lifecycle internals
    # ------------------------------------------------------------------

    def _ensure_executor(
        self,
    ) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self.config.detector_pool_workers,
                thread_name_prefix="fenrir-detector",
            )

        return self._executor

    async def _ensure_http_session(
        self,
    ) -> None:
        if (
            self._session is not None
            and not self._session.closed
        ):
            return

        self._session = ClientSession(
            connector=TCPConnector(
                limit=10
            ),
            timeout=ClientTimeout(
                total=self.config.report_timeout_seconds
            ),
        )

    # ------------------------------------------------------------------
    # State / health
    # ------------------------------------------------------------------

    def transition(
        self,
        new_state: FenrirState,
    ) -> None:
        if self.state is new_state:
            return

        old_state = self.state
        self.state = new_state

        self.metrics[
            "state_transitions"
        ] += 1

        logger.info(
            "Fenrir state: %s -> %s",
            old_state.value,
            new_state.value,
        )

    def snapshot(
        self,
    ) -> dict[str, Any]:
        sigma = self.detector.sigma_status()
        sigma["enabled"] = self.config.sigma_enabled
        if self._sigma_load_error:
            sigma["coverage"] = "degraded"
            sigma["load_error"] = self._sigma_load_error
        elif self.config.sigma_enabled and not sigma.get("active"):
            sigma["coverage"] = "inactive"
        elif self.config.sigma_enabled:
            sigma["coverage"] = "active"
        else:
            sigma["coverage"] = "disabled"

        capabilities = [
            "threat_detection",
            "statistical_anomaly_detection",
            "watchtower_reporting",
            "dashboard_broadcast",
        ]
        if self.config.sigma_enabled:
            capabilities.append("sigma_deterministic_detection")

        return {
            "node_id": self.config.node_id,
            "node_type": "fenrir_hunter",
            "state": self.state.value,
            "status": (
                "error"
                if self.state is FenrirState.ERROR
                else "degraded"
                if self.state is FenrirState.DEGRADED
                else "ok"
            ),
            "started": self._started,
            "uptime_seconds": round(
                max(
                    0.0,
                    time.monotonic()
                    - self._start_monotonic,
                ),
                3,
            ),
            "last_scan_at": self.last_scan_at,
            "consecutive_errors": self.consecutive_errors,
            "metrics": dict(
                self.metrics
            ),
            "sigma_detection": sigma,
            "anomaly_layer": self.anomaly_layer.stats(),
            "capabilities": capabilities,
        }

    async def health(
        self,
        request: web.Request,
    ) -> web.Response:
        return web.json_response(
            {
                "status": (
                    "error"
                    if self.state
                    is FenrirState.ERROR
                    else "ok"
                ),
                "node": "fenrir",
            }
        )

    async def readiness(
        self,
        request: web.Request,
    ) -> web.Response:
        ready = self.state in {
            FenrirState.HUNTING,
            FenrirState.TRACKING,
            FenrirState.DEGRADED,
        }

        return web.json_response(
            {
                "ready": ready,
                "state": self.state.value,
            },
            status=(
                200
                if ready
                else 503
            ),
        )

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _assessment_to_finding(
        self,
        assessment: ThreatAssessment,
        *,
        detection_method: str,
        anomaly: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        finding: dict[str, Any] = {
            "source": "fenrir",
            "node_id": self.config.node_id,
            "type": "threat_finding",
            "detection_method": detection_method,
            "severity": assessment.severity.value,
            "threat_kind": assessment.threat_kind.value,
            "source_kind": assessment.source_kind.value,
            "score": float(
                assessment.score
            ),
            "identity": str(
                assessment.identity
            ),
            "source_ip": str(
                assessment.source_ip
            ),
            "window_size": int(
                assessment.window_size
            ),
            "tags": list(
                assessment.supporting_tags
            ),
            "indicators": dict(
                assessment.indicators
            ),
            "generated_at": datetime.fromtimestamp(
                assessment.generated_at,
                tz=timezone.utc,
            ).isoformat(),
            "reported_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

        if anomaly is not None:
            finding[
                "anomaly"
            ] = anomaly

        return finding

    def _run_detection(
        self,
    ) -> tuple[
        list[ThreatAssessment],
        dict[
            tuple[str, str, str, str],
            dict[str, Any],
        ],
    ]:
        assessments = list(
            self.detector.assess_all()
        )

        anomaly_map: dict[
            tuple[str, str, str, str],
            dict[str, Any],
        ] = {}

        for assessment in assessments:
            anomaly = self.anomaly_layer.update(
                assessment
            )

            if anomaly is None:
                continue

            anomaly_map[
                (
                    str(assessment.identity),
                    str(assessment.source_ip),
                    assessment.threat_kind.value,
                    assessment.source_kind.value,
                )
            ] = anomaly

        return (
            assessments,
            anomaly_map,
        )

    async def _observe_with_heart(
        self,
        assessment: ThreatAssessment,
    ) -> None:
        """Hand-off to Sentinel-43 authority, which owns the Heart.

        Fenrir's own detection and reporting continue unconditionally
        either way (called from observe_signals() after the finding is
        already built) -- raw evidence is never lost because the Heart is
        unavailable, and this method never raises to its caller. But
        unavailability itself must not be silent: an unresolved recommendation
        that was never even attempted is different from a genuinely
        corroboration-pending one, and an operator watching Fenrir's own
        metrics/logs must be able to tell the two apart. Failure here is
        never reinterpreted as "no threat" -- the finding was still real and
        still reported through Fenrir's normal path; only Heart-governed
        staging of it did not happen.
        """
        authority = self.authority

        if (
            authority is None
            or not bool(getattr(authority, "threat_ingress_available", False))
        ):
            self.metrics["heart_unavailable"] += 1
            if not self._heart_unavailable_logged:
                self._heart_unavailable_logged = True
                logger.warning(
                    "Sentinel-43 authority is not wired in -- Fenrir findings "
                    "are reported as usual but are not entering "
                    "human-governed staging. "
                    "(Logged once; see the heart_unavailable metric for "
                    "the ongoing count.)"
                )
            return

        seq_key = (
            str(assessment.identity),
            str(assessment.source_ip),
            assessment.threat_kind.value,
        )
        raw_seq = assessment.indicators.get("evidence_seq")
        seq = (
            raw_seq
            if isinstance(raw_seq, int) and not isinstance(raw_seq, bool)
            else None
        )
        if seq is not None and self._heart_observed_seq.get(seq_key, 0) >= seq:
            return

        try:
            await asyncio.get_running_loop().run_in_executor(
                self._ensure_executor(),
                authority.observe_threat,
                assessment,
            )
        except Exception:
            self.metrics["heart_observe_failed"] += 1
            logger.warning(
                "Heart observation failed for a Fenrir finding",
                exc_info=True,
            )
        else:
            self._heart_unavailable_logged = False
            if seq is not None:
                self._heart_observed_seq[seq_key] = seq
                self._heart_observed_seq.move_to_end(seq_key)
                while len(self._heart_observed_seq) > 10_000:
                    self._heart_observed_seq.popitem(last=False)

    async def observe_signals(
        self,
    ) -> list[dict[str, Any]]:
        loop = asyncio.get_running_loop()

        assessments, anomaly_map = (
            await loop.run_in_executor(
                self._ensure_executor(),
                self._run_detection,
            )
        )

        self.metrics[
            "assessments_total"
        ] += len(
            assessments
        )

        findings: list[
            dict[str, Any]
        ] = []

        for assessment in assessments:
            rank = _SEVERITY_RANK.get(
                assessment.severity,
                0,
            )

            anomaly = anomaly_map.get(
                (
                    str(assessment.identity),
                    str(assessment.source_ip),
                    assessment.threat_kind.value,
                    assessment.source_kind.value,
                )
            )

            metric_key = {
                ThreatSeverity.LOW: "findings_low",
                ThreatSeverity.MEDIUM: "findings_medium",
                ThreatSeverity.HIGH: "findings_high",
                ThreatSeverity.CRITICAL: "findings_critical",
            }.get(
                assessment.severity
            )

            if metric_key:
                self.metrics[
                    metric_key
                ] += 1

            if rank >= self._min_severity_rank:
                await self._observe_with_heart(assessment)

                findings.append(
                    self._assessment_to_finding(
                        assessment,
                        detection_method="threshold",
                        anomaly=anomaly,
                    )
                )

            elif anomaly is not None:
                self.metrics[
                    "anomaly_escalations"
                ] += 1

                await self._observe_with_heart(assessment)

                findings.append(
                    self._assessment_to_finding(
                        assessment,
                        detection_method="statistical_anomaly",
                        anomaly=anomaly,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def _headers(
        self,
    ) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json"
        }

        if self.config.api_token:
            headers[
                "Authorization"
            ] = (
                f"Bearer "
                f"{self.config.api_token}"
            )

        return headers

    async def _post_json(
        self,
        *,
        url: str,
        payload: dict[str, Any],
        success_metric: str,
        failure_metric: str,
        label: str,
    ) -> None:
        if (
            self._session is None
            or self._session.closed
        ):
            self.metrics[
                failure_metric
            ] += 1
            return

        try:
            async with self._session.post(
                url,
                json=payload,
                headers=self._headers(),
            ) as response:
                if 200 <= response.status < 300:
                    self.metrics[
                        success_metric
                    ] += 1
                    return

                self.metrics[
                    failure_metric
                ] += 1

                logger.warning(
                    "%s rejected Fenrir report: status=%s",
                    label,
                    response.status,
                )

        except asyncio.TimeoutError:
            self.metrics[
                failure_metric
            ] += 1

            logger.warning(
                "%s Fenrir report timed out",
                label,
            )

        except aiohttp.ClientError as exc:
            self.metrics[
                failure_metric
            ] += 1

            logger.warning(
                "%s Fenrir report failed: %s",
                label,
                exc,
            )

    async def process_finding(
        self,
        finding: dict[str, Any],
    ) -> None:
        self.transition(
            FenrirState.TRACKING
        )

        self.metrics[
            "findings_reported"
        ] += 1

        self.last_finding = finding

        tasks: list[
            asyncio.Future[Any] | asyncio.Task[Any] | Any
        ] = []

        if self.config.watchtower_url:
            tasks.append(
                self._post_json(
                    url=self.config.watchtower_url,
                    payload=finding,
                    success_metric="watchtower_ok",
                    failure_metric="watchtower_failures",
                    label="Watchtower",
                )
            )

        if self.config.api_broadcast_url:
            tasks.append(
                self._post_json(
                    url=self.config.api_broadcast_url,
                    payload={
                        # Must be "fenrir.*": /internal/events/broadcast
                        # restricts the Fenrir service token to its own
                        # namespace and 403s anything else. The former
                        # "fenrir_finding" (underscore) was rejected on
                        # every call and counted as broadcast_failures.
                        "event_type": "fenrir.finding",
                        "channel": "security",
                        "data": finding,
                    },
                    success_metric="broadcast_ok",
                    failure_metric="broadcast_failures",
                    label="Dashboard",
                )
            )

        if tasks:
            await asyncio.gather(
                *tasks,
                return_exceptions=True,
            )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def hunting_loop(
        self,
    ) -> None:
        self.transition(
            FenrirState.HUNTING
        )

        while not self.shutdown_event.is_set():
            try:
                self._scan_count += 1
                self.metrics[
                    "scans"
                ] += 1

                self.last_scan_at = (
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                )

                if (
                    self._scan_count
                    % self.config.anomaly_prune_interval
                    == 0
                ):
                    loop = asyncio.get_running_loop()

                    await loop.run_in_executor(
                        self._ensure_executor(),
                        self.anomaly_layer.prune,
                    )

                findings = (
                    await self.observe_signals()
                )

                for finding in findings:
                    await self.process_finding(
                        finding
                    )

                if (
                    not findings
                    and self.state
                    is FenrirState.TRACKING
                ):
                    self.transition(
                        FenrirState.HUNTING
                    )

                self.consecutive_errors = 0

                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(),
                        timeout=self.config.scan_interval_seconds,
                    )
                except asyncio.TimeoutError:
                    pass

            except asyncio.CancelledError:
                raise

            except Exception:
                self.metrics[
                    "errors"
                ] += 1

                self.consecutive_errors += 1

                logger.exception(
                    "Fenrir hunt loop error"
                )

                if (
                    self.consecutive_errors
                    >= self.config.max_consecutive_errors
                ):
                    self.transition(
                        FenrirState.ERROR
                    )
                else:
                    self.transition(
                        FenrirState.DEGRADED
                    )

                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(),
                        timeout=min(
                            5.0,
                            self.config.scan_interval_seconds,
                        ),
                    )
                except asyncio.TimeoutError:
                    pass

                if (
                    not self.shutdown_event.is_set()
                    and self.state
                    is not FenrirState.ERROR
                ):
                    self.transition(
                        FenrirState.HUNTING
                    )

        self.transition(
            FenrirState.DORMANT
        )

    # ------------------------------------------------------------------
    # Startup / shutdown
    # ------------------------------------------------------------------

    async def start_health_server(
        self,
    ) -> None:
        if self.config.embedded_mode:
            return

        app = web.Application()

        app.router.add_get(
            "/health",
            self.health,
        )

        app.router.add_get(
            "/ready",
            self.readiness,
        )

        self.runner = web.AppRunner(
            app
        )

        await self.runner.setup()

        site = web.TCPSite(
            self.runner,
            self.config.health_host,
            self.config.health_port,
        )

        await site.start()

    async def start(
        self,
    ) -> None:
        async with self._lifecycle_lock:
            if self._started:
                return

            self.shutdown_event.clear()
            self.transition(
                FenrirState.INITIALIZING
            )

            self._ensure_executor()

            if (
                self.config.watchtower_url
                or self.config.api_broadcast_url
            ):
                await self._ensure_http_session()

            await self.start_health_server()

            self.main_task = (
                asyncio.create_task(
                    self.hunting_loop(),
                    name="sentinel43-fenrir-hunter",
                )
            )

            self._started = True

    async def shutdown(
        self,
        reason: str = "shutdown",
    ) -> None:
        async with self._lifecycle_lock:
            if not self._started:
                return

            logger.info(
                "Fenrir shutdown requested: %s",
                reason,
            )

            self.shutdown_event.set()

            task = self.main_task
            self.main_task = None

            if (
                task is not None
                and task
                is not asyncio.current_task()
            ):
                task.cancel()

                try:
                    await task
                except asyncio.CancelledError:
                    pass

            if self.runner is not None:
                await self.runner.cleanup()
                self.runner = None

            if (
                self._session is not None
                and not self._session.closed
            ):
                await self._session.close()

            self._session = None

            if self._executor is not None:
                self._executor.shutdown(
                    wait=False,
                    cancel_futures=True,
                )
                self._executor = None

            self.transition(
                FenrirState.DORMANT
            )

            self._started = False

    async def stop(
        self,
        reason: str = "stop requested",
    ) -> None:
        await self.shutdown(
            reason
        )

    async def run(
        self,
    ) -> None:
        if self.config.embedded_mode:
            raise RuntimeError(
                "Standalone run requires embedded_mode=False"
            )

        loop = asyncio.get_running_loop()

        for sig in (
            signal.SIGINT,
            signal.SIGTERM,
        ):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(
                        self.shutdown(
                            s.name
                        )
                    ),
                )
            except NotImplementedError:
                pass

        await self.start()

        try:
            await self.shutdown_event.wait()
        finally:
            await self.shutdown(
                "run-finally"
            )


async def main() -> None:
    config = FenrirConfig.from_env()

    if config.embedded_mode:
        config = FenrirConfig(
            **{
                **{
                    field_name: getattr(
                        config,
                        field_name,
                    )
                    for field_name
                    in config.__dataclass_fields__
                },
                "embedded_mode": False,
            }
        )

    hunter = FenrirHunter(
        config
    )

    await hunter.run()


if __name__ == "__main__":
    asyncio.run(
        main()
    )


__all__ = [
    "FenrirAnomalyLayer",
    "FenrirConfig",
    "FenrirHunter",
    "FenrirState",
    "main",
]
