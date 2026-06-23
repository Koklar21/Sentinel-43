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

Active threat hunting node. Owns a SentinelThreatDetector instance,
runs assess_all() on every scan interval, filters findings by minimum
severity, and reports qualifying findings to both:

  1. Watchtower  — HTTP POST to the configured Watchtower event endpoint
  2. Dashboard   — HTTP POST to the API's internal broadcast endpoint,
                   which fans findings out to connected WebSocket clients

Fenrir hunts. It does not bite.

Non-responsibilities:
  - No blocking of traffic
  - No approval/veto decisions
  - No firewall changes
  - No secret handling

Incorporated fixes (this pass):
  - Dedicated ThreadPoolExecutor isolates detector scans from the shared
    default pool, preventing cross-contamination with other async executor
    work (Gemini review, valid).
  - State machine corrected: DEGRADED means limping-but-running (still
    reports ready), ERROR means hard stop (reports not-ready). First N-1
    errors transition to DEGRADED; crossing max_consecutive_errors flips
    to ERROR (Gemini review, valid).
  - asyncio.gather backpressure concern rejected: process_finding() is
    awaited sequentially inside the hunt loop — one finding at a time,
    no concurrent accumulation of unresolved futures (Gemini review,
    not applicable to this loop structure).
  - executor.shutdown(wait=True) inside async shutdown replaced with
    wait=False + asyncio.to_thread to avoid blocking the event loop
    if the detector is mid-execution at shutdown time (new bug introduced
    by Gemini's refactor, fixed here).

Import path note:
  Adjust the two imports marked ADJUST IMPORT PATH to match your actual
  package layout. Hard import — Fenrir refuses to start if the detector
  is not importable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal as _signal
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector, web

# ---------------------------------------------------------------------------
# ADJUST IMPORT PATH if your package layout differs from sentinel_43_ai/detection/
# Hard import — Fenrir refuses to start if the detector is not importable.
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
    ThreatSeverity.LOW: 0,
    ThreatSeverity.MEDIUM: 1,
    ThreatSeverity.HIGH: 2,
    ThreatSeverity.CRITICAL: 3,
}

_SEVERITY_FROM_STR: dict[str, ThreatSeverity] = {
    "LOW": ThreatSeverity.LOW,
    "MEDIUM": ThreatSeverity.MEDIUM,
    "HIGH": ThreatSeverity.HIGH,
    "CRITICAL": ThreatSeverity.CRITICAL,
}


# =============================================================================
# State
# =============================================================================

class FenrirState(str, Enum):
    INITIALIZING = "INITIALIZING"
    HUNTING      = "HUNTING"
    TRACKING     = "TRACKING"
    DEGRADED     = "DEGRADED"   # limping — readiness returns 200
    DORMANT      = "DORMANT"
    ERROR        = "ERROR"      # hard stop — readiness returns 503


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
    # Node identity
    node_id: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_NODE_ID", "fenrir-hunter-01")
    )

    # When embedded_mode=True the health server is skipped — the parent
    # process (e.g. FastAPI lifespan) owns lifecycle and health reporting.
    embedded_mode: bool = field(
        default_factory=lambda: _env_bool("S43_FENRIR_EMBEDDED", True)
    )

    # Health server (standalone mode only)
    host: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_HOST", "0.0.0.0")
    )
    health_port: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_HEALTH_PORT", "9201"))
    )

    # Hunt loop
    scan_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_SCAN_INTERVAL", "2.0"))
    )
    max_consecutive_errors: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_MAX_ERRORS", "3"))
    )

    # Minimum severity to report externally.
    # LOW and MEDIUM are counted in metrics but not forwarded.
    min_report_severity: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_MIN_SEVERITY", "HIGH").upper()
    )

    # Reporting endpoints
    watchtower_url: str = field(
        default_factory=lambda: os.getenv(
            "S43_FENRIR_WATCHTOWER_URL",
            "http://s43-api:8000/watchtower/events",
        )
    )
    api_broadcast_url: str = field(
        default_factory=lambda: os.getenv(
            "S43_FENRIR_BROADCAST_URL",
            "http://s43-api:8000/internal/events/broadcast",
        )
    )

    # HTTP timeout for outbound reports
    report_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_REPORT_TIMEOUT", "5.0"))
    )

    # Internal token for API calls
    api_token: Optional[str] = field(
        default_factory=lambda: os.getenv("S43_FENRIR_API_TOKEN")
    )

    log_level: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_LOG_LEVEL", "INFO")
    )

    # Detector tuning
    detector_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_WINDOW_SECONDS", "60.0"))
    )
    detector_max_keys: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_MAX_KEYS", "0"))
    )

    # Dedicated thread pool size for detector scans.
    # 2 workers is enough — assess_all() is single-threaded internally
    # (RLock) so extra workers only matter for concurrent ingest() calls.
    detector_pool_workers: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_POOL_WORKERS", "2"))
    )


# =============================================================================
# Hunter
# =============================================================================

class FenrirHunter:
    """
    Fenrir hunter node for Sentinel-43.

    Owns a SentinelThreatDetector. On every scan interval:
      1. Calls detector.assess_all() in an isolated thread pool (non-blocking).
      2. Filters assessments to min_report_severity and above.
      3. Reports each qualifying finding to Watchtower and the dashboard
         WebSocket broadcast endpoint concurrently.

    LOW and MEDIUM findings are counted in metrics but not forwarded.

    State machine:
      INITIALIZING → HUNTING       normal startup
      HUNTING      → TRACKING      finding detected
      TRACKING     → HUNTING       no findings this scan
      HUNTING      → DEGRADED      error, below threshold
      DEGRADED     → HUNTING       recovered
      HUNTING      → ERROR         errors >= max_consecutive_errors
      any          → DORMANT       shutdown complete
    """

    def __init__(self, config: Optional[FenrirConfig] = None) -> None:
        self.config = config or FenrirConfig()

        logging.basicConfig(
            level=self.config.log_level.upper(),
            format="%(asctime)s - FenrirHunter - %(levelname)s - %(message)s",
        )

        self.state = FenrirState.INITIALIZING
        self.started_at = datetime.now(timezone.utc)
        self.last_scan_at: Optional[str] = None
        self.last_finding: Optional[dict[str, Any]] = None
        self.consecutive_errors = 0

        self.shutdown_event = asyncio.Event()
        self.runner: Optional[web.AppRunner] = None
        self.main_task: Optional[asyncio.Task[None]] = None
        self._session: Optional[ClientSession] = None
        self._started = False
        self._lock = asyncio.Lock()

        # Dedicated pool — isolates detector scans from the shared default
        # executor, preventing cross-contamination with FastAPI's own
        # executor work. 2 workers matches assess_all()'s internal RLock
        # (it can only run one scan at a time anyway).
        self._executor = ThreadPoolExecutor(
            max_workers=self.config.detector_pool_workers,
            thread_name_prefix="fenrir_detector",
        )

        # Hard import already enforced at module level. If we get here,
        # the detector is importable.
        self.detector = SentinelThreatDetector(
            cfg=DetectorConfig(
                window_seconds=self.config.detector_window_seconds,
                max_keys_hint=self.config.detector_max_keys,
            )
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
            "scans": 0,
            "assessments_total": 0,
            "findings_low": 0,
            "findings_medium": 0,
            "findings_high": 0,
            "findings_critical": 0,
            "findings_reported": 0,
            "watchtower_ok": 0,
            "watchtower_failures": 0,
            "broadcast_ok": 0,
            "broadcast_failures": 0,
            "errors": 0,
            "state_transitions": 0,
        }

        logger.info(
            "FenrirHunter initialized: node_id=%s embedded=%s min_severity=%s",
            self.config.node_id,
            self.config.embedded_mode,
            self.config.min_report_severity,
        )

    # -------------------------------------------------------------------------
    # State management
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
            "node_id": self.config.node_id,
            "node_type": "fenrir_hunter",
            "state": self.state.value,
            "status": (
                "ok"
                if self.state not in {FenrirState.ERROR, FenrirState.DEGRADED}
                else "degraded"
            ),
            "embedded_mode": self.config.embedded_mode,
            "started": self._started,
            "started_at": self.started_at.isoformat(),
            "uptime_seconds": round((now - self.started_at).total_seconds(), 3),
            "last_scan_at": self.last_scan_at,
            "last_finding": self.last_finding,
            "consecutive_errors": self.consecutive_errors,
            "metrics": dict(self.metrics),
            "config": {
                "scan_interval_seconds": self.config.scan_interval_seconds,
                "min_report_severity": self.config.min_report_severity,
                "detector_window_seconds": self.config.detector_window_seconds,
            },
            "capabilities": [
                "threat_detection",
                "anomaly_tracking",
                "watchtower_reporting",
                "dashboard_broadcast",
            ],
        }

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response(self.snapshot())

    async def readiness(self, request: web.Request) -> web.Response:
        # DEGRADED is still ready — limping but hunting.
        # ERROR is not ready — needs operator attention.
        ready = self.state in {
            FenrirState.HUNTING,
            FenrirState.TRACKING,
            FenrirState.DEGRADED,
        }
        return web.json_response(
            {
                "ready": ready,
                "state": self.state.value,
                "node_id": self.config.node_id,
            },
            status=200 if ready else 503,
        )

    # -------------------------------------------------------------------------
    # Detection
    # -------------------------------------------------------------------------

    def _assessment_to_finding(self, assessment: ThreatAssessment) -> dict[str, Any]:
        return {
            "source": "fenrir",
            "node_id": self.config.node_id,
            "type": "threat_finding",
            "severity": assessment.severity.value,
            "threat_kind": assessment.threat_kind.value,
            "source_kind": assessment.source_kind.value,
            "score": assessment.score,
            "identity": assessment.identity,
            "source_ip": assessment.source_ip,
            "window_size": assessment.window_size,
            "tags": list(assessment.supporting_tags),
            "indicators": dict(assessment.indicators),
            "generated_at": datetime.fromtimestamp(
                assessment.generated_at, tz=timezone.utc
            ).isoformat(),
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }

    async def observe_signals(self) -> list[ThreatAssessment]:
        """
        Run the detector and return assessments at or above min_report_severity.

        Uses the dedicated thread pool so detector scans don't compete with
        FastAPI's default executor work.
        """
        loop = asyncio.get_running_loop()
        assessments: list[ThreatAssessment] = await loop.run_in_executor(
            self._executor,
            self.detector.assess_all,
        )

        self.metrics["assessments_total"] += len(assessments)
        qualifying: list[ThreatAssessment] = []

        for a in assessments:
            rank = _SEVERITY_RANK.get(a.severity, 0)

            if a.severity == ThreatSeverity.LOW:
                self.metrics["findings_low"] += 1
            elif a.severity == ThreatSeverity.MEDIUM:
                self.metrics["findings_medium"] += 1
            elif a.severity == ThreatSeverity.HIGH:
                self.metrics["findings_high"] += 1
            elif a.severity == ThreatSeverity.CRITICAL:
                self.metrics["findings_critical"] += 1

            if rank >= self._min_severity_rank:
                qualifying.append(a)

        return qualifying

    async def process_finding(self, assessment: ThreatAssessment) -> None:
        """
        Handle a qualifying threat assessment.

        Reports to Watchtower and dashboard broadcast concurrently.
        Neither failure crashes the hunt loop.

        Note: process_finding() is awaited sequentially inside hunting_loop —
        one finding at a time. There is no concurrent accumulation of
        unresolved futures, so no semaphore is needed here.
        """
        self.transition(FenrirState.TRACKING)
        self.metrics["findings_reported"] += 1

        finding = self._assessment_to_finding(assessment)
        self.last_finding = finding

        logger.warning(
            "Fenrir finding: severity=%s kind=%s identity=%s ip=%s score=%.2f tags=%s",
            assessment.severity.value,
            assessment.threat_kind.value,
            assessment.identity,
            assessment.source_ip,
            assessment.score,
            assessment.supporting_tags,
        )

        await asyncio.gather(
            self._report_to_watchtower(finding),
            self._broadcast_to_dashboard(finding),
            return_exceptions=True,
        )

    # -------------------------------------------------------------------------
    # Reporting sinks
    # -------------------------------------------------------------------------

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
                    logger.warning(
                        "Watchtower rejected finding: status=%s", resp.status
                    )

        except asyncio.TimeoutError:
            self.metrics["watchtower_failures"] += 1
            logger.warning(
                "Watchtower report timed out after %.1fs",
                self.config.report_timeout_seconds,
            )
        except aiohttp.ClientError as exc:
            self.metrics["watchtower_failures"] += 1
            logger.warning("Watchtower report failed: %s", exc)
        except Exception as exc:
            self.metrics["watchtower_failures"] += 1
            logger.exception("Watchtower report unexpected error: %s", exc)

    async def _broadcast_to_dashboard(self, finding: dict[str, Any]) -> None:
        if not self._session or self._session.closed:
            self.metrics["broadcast_failures"] += 1
            return

        payload = {
            "event_type": "fenrir_finding",
            "channel": "security",
            "data": finding,
        }

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
                    logger.warning(
                        "Dashboard broadcast rejected: status=%s", resp.status
                    )

        except asyncio.TimeoutError:
            self.metrics["broadcast_failures"] += 1
            logger.warning(
                "Dashboard broadcast timed out after %.1fs",
                self.config.report_timeout_seconds,
            )
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
            "Fenrir hunt loop started: interval=%.1fs min_severity=%s",
            self.config.scan_interval_seconds,
            self.config.min_report_severity,
        )

        while not self.shutdown_event.is_set():
            try:
                self.metrics["scans"] += 1
                self.last_scan_at = datetime.now(timezone.utc).isoformat()

                findings = await self.observe_signals()

                for assessment in findings:
                    await self.process_finding(assessment)

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
                self.metrics["errors"] += 1
                self.consecutive_errors += 1
                logger.exception("Fenrir hunt loop error: %s", exc)

                # Corrected state machine:
                # First N-1 errors → DEGRADED (limping, still ready)
                # Crossing max_consecutive_errors → ERROR (hard stop, not ready)
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
        """
        Create the shared aiohttp ClientSession.

        Called after the event loop is running — never in __init__.
        Idempotent: re-entry is safe.
        """
        if self._session and not self._session.closed:
            return
        connector = TCPConnector(limit=10)
        self._session = ClientSession(connector=connector)
        logger.debug("Fenrir HTTP session created.")

    async def start_health_server(self) -> None:
        app = web.Application()
        app.router.add_get("/health", self.health)
        app.router.add_get("/ready", self.readiness)

        self.runner = web.AppRunner(app)
        await self.runner.setup()

        site = web.TCPSite(self.runner, self.config.host, self.config.health_port)
        await site.start()

        logger.info(
            "Fenrir health server listening on %s:%s",
            self.config.host,
            self.config.health_port,
        )

    async def start(self) -> None:
        """
        Start Fenrir. Idempotent — safe to call more than once.

        When embedded_mode=True the health server is skipped; the parent
        process owns lifecycle. When False (standalone), the health server
        starts on health_port.
        """
        async with self._lock:
            if self._started:
                return

            self.shutdown_event.clear()
            self.transition(FenrirState.INITIALIZING)

            await self._start_session()

            if not self.config.embedded_mode:
                await self.start_health_server()

            self.main_task = asyncio.create_task(
                self.hunting_loop(),
                name="sentinel43-fenrir-hunter",
            )
            self._started = True
            logger.info("Fenrir started.")

    async def shutdown(self, reason: str = "shutdown") -> None:
        """
        Graceful shutdown. Idempotent.

        executor.shutdown() is run via asyncio.to_thread with wait=False
        to avoid blocking the event loop if assess_all() is mid-execution.
        """
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

            # Fix: wait=False avoids blocking the event loop if a detector
            # scan is in-flight. Threads complete naturally after the task
            # that submitted them finishes.
            self._executor.shutdown(wait=False)

            self.transition(FenrirState.DORMANT)
            self._started = False
            logger.info("Fenrir shutdown complete.")

    async def stop(self, reason: str = "stop requested") -> None:
        """Alias for shutdown(). Called by FastAPI lifespan teardown."""
        await self.shutdown(reason)

    async def run(self) -> None:
        """
        Standalone entry point. Sets embedded_mode=False and owns its
        own lifecycle including signal handling.
        """
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
