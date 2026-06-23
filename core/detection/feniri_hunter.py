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

  1. Watchtower  — via HTTP POST to the configured Watchtower event endpoint
  2. Dashboard   — via HTTP POST to the API's internal broadcast endpoint,
                   which fans findings out to connected WebSocket clients

Fenrir hunts. It does not bite.
Non-responsibilities:
  - No blocking of traffic
  - No approval/veto decisions
  - No firewall changes
  - No secret handling

Import path note:
  The SentinelThreatDetector import below uses the path from the docstring
  in sentinel_threat_types.py (sentinel_43_ai.detection.*). If your package
  layout differs, adjust ONLY the two import lines marked ADJUST IMPORT PATH.
  The import is intentionally hard — if it fails, Fenrir refuses to start
  rather than running silently without detection capability.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal as _signal
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
    DEGRADED     = "DEGRADED"
    DORMANT      = "DORMANT"
    ERROR        = "ERROR"


# =============================================================================
# Config
# =============================================================================

@dataclass(slots=True)
class FenrirConfig:
    # Node identity
    node_id: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_NODE_ID", "fenrir-hunter-01")
    )

    # Health server
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
    # LOW and MEDIUM are counted but not forwarded to Watchtower or the dashboard.
    min_report_severity: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_MIN_SEVERITY", "HIGH").upper()
    )

    # Reporting endpoints
    # Watchtower: receives a structured finding POST
    watchtower_url: str = field(
        default_factory=lambda: os.getenv(
            "S43_FENRIR_WATCHTOWER_URL", "http://s43-api:8000/watchtower/events"
        )
    )
    # API internal broadcast: fans finding out to WebSocket clients
    api_broadcast_url: str = field(
        default_factory=lambda: os.getenv(
            "S43_FENRIR_BROADCAST_URL", "http://s43-api:8000/internal/events/broadcast"
        )
    )

    # HTTP timeout for outbound reports
    report_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_REPORT_TIMEOUT", "5.0"))
    )

    # Internal token for API calls (e.g. broadcast endpoint)
    api_token: Optional[str] = field(
        default_factory=lambda: os.getenv("S43_FENRIR_API_TOKEN")
    )

    log_level: str = field(
        default_factory=lambda: os.getenv("S43_FENRIR_LOG_LEVEL", "INFO")
    )

    # Detector tuning — passed straight through to DetectorConfig
    detector_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("S43_FENRIR_WINDOW_SECONDS", "60.0"))
    )
    detector_max_keys: int = field(
        default_factory=lambda: int(os.getenv("S43_FENRIR_MAX_KEYS", "0"))
    )


# =============================================================================
# Hunter
# =============================================================================

class FenrirHunter:
    """
    Fenrir hunter node for Sentinel-43.

    Owns a SentinelThreatDetector. On every scan interval:
      1. Calls detector.assess_all() in a thread pool (non-blocking).
      2. Filters assessments to min_report_severity and above.
      3. Reports each qualifying finding to Watchtower and the dashboard
         WebSocket broadcast endpoint concurrently.

    LOW and MEDIUM findings are counted but not forwarded — they are
    observable via the health endpoint metrics.
    """

    def __init__(self, config: Optional[FenrirConfig] = None) -> None:
        self.config = config or FenrirConfig()
        self.state = FenrirState.INITIALIZING
        self.started_at = datetime.now(timezone.utc)
        self.last_scan_at: Optional[str] = None
        self.last_finding: Optional[dict[str, Any]] = None
        self.consecutive_errors = 0

        self.shutdown_event = asyncio.Event()
        self.runner: Optional[web.AppRunner] = None
        self.main_task: Optional[asyncio.Task[None]] = None
        self._session: Optional[ClientSession] = None

        # Build the detector. Hard fail if imports or config are broken.
        self.detector = SentinelThreatDetector(
            cfg=DetectorConfig(
                window_seconds=self.config.detector_window_seconds,
                max_keys_hint=self.config.detector_max_keys,
            )
        )

        # Resolve min severity rank once at init rather than on every scan.
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

        logging.basicConfig(
            level=self.config.log_level.upper(),
            format="%(asctime)s - FenrirHunter - %(levelname)s - %(message)s",
        )

        logger.info(
            "FenrirHunter initialized: node_id=%s min_severity=%s "
            "watchtower=%s broadcast=%s",
            self.config.node_id,
            self.config.min_report_severity,
            self.config.watchtower_url,
            self.config.api_broadcast_url,
        )

    # -------------------------------------------------------------------------
    # State management
    # -------------------------------------------------------------------------

    def transition(self, new_state: FenrirState) -> None:
        if self.state == new_state:
            return

        old_state = self.state
        self.state = new_state
        self.metrics["state_transitions"] += 1
        logger.info(
            "Fenrir state transition: %s -> %s",
            old_state.value,
            new_state.value,
        )

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
            "started_at": self.started_at.isoformat(),
            "uptime_seconds": round((now - self.started_at).total_seconds(), 3),
            "last_scan_at": self.last_scan_at,
            "last_finding": self.last_finding,
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
        """
        Convert a ThreatAssessment into a structured finding payload
        suitable for both Watchtower ingestion and dashboard broadcast.
        """
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

        The detector's assess_all() holds an RLock while scanning all windows.
        It runs in a thread pool executor to avoid blocking the event loop
        during scans with many tracked identities.

        Low and MEDIUM findings are counted in metrics but not returned —
        they are below the reporting threshold and do not trigger Watchtower
        or dashboard notifications.
        """
        loop = asyncio.get_running_loop()
        assessments: list[ThreatAssessment] = await loop.run_in_executor(
            None, self.detector.assess_all
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

        Transitions to TRACKING state and fires reports to Watchtower and
        the dashboard broadcast endpoint concurrently. Neither failure
        crashes the hunt loop — Fenrir keeps hunting even if reporting
        sinks are temporarily unreachable.
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

        # Fire both reports concurrently. Failures are logged and counted,
        # never re-raised — a dead reporting sink does not stop the hunt.
        await asyncio.gather(
            self._report_to_watchtower(finding),
            self._broadcast_to_dashboard(finding),
            return_exceptions=True,
        )

    # -------------------------------------------------------------------------
    # Reporting sinks
    # -------------------------------------------------------------------------

    async def _report_to_watchtower(self, finding: dict[str, Any]) -> None:
        """
        POST a finding to the Watchtower event ingestion endpoint.

        NOTE: /watchtower/events is a planned endpoint. If it does not yet
        exist in main.py, register it before enabling Watchtower reporting.
        """
        if not self._session:
            logger.debug("Watchtower report skipped: no HTTP session.")
            return

        headers = {"Content-Type": "application/json"}
        if self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"

        try:
            async with self._session.post(
                self.config.watchtower_url,
                data=json.dumps(finding),
                headers=headers,
                timeout=ClientTimeout(total=self.config.report_timeout_seconds),
            ) as resp:
                if 200 <= resp.status < 300:
                    self.metrics["watchtower_ok"] += 1
                    logger.debug(
                        "Watchtower report accepted: status=%s", resp.status
                    )
                else:
                    self.metrics["watchtower_failures"] += 1
                    body = await resp.text()
                    logger.warning(
                        "Watchtower report rejected: status=%s body=%s",
                        resp.status,
                        body[:200],
                    )

        except asyncio.TimeoutError:
            self.metrics["watchtower_failures"] += 1
            logger.warning("Watchtower report timed out after %.1fs", self.config.report_timeout_seconds)

        except aiohttp.ClientError as exc:
            self.metrics["watchtower_failures"] += 1
            logger.warning("Watchtower report failed: %s", exc)

        except Exception as exc:
            self.metrics["watchtower_failures"] += 1
            logger.exception("Watchtower report unexpected error: %s", exc)

    async def _broadcast_to_dashboard(self, finding: dict[str, Any]) -> None:
        """
        POST a finding to the API's internal broadcast endpoint, which
        fans it out to all connected WebSocket dashboard clients.

        NOTE: /internal/events/broadcast must be registered in core/api/main.py.
        This is a required follow-up before dashboard broadcast is live.
        """
        if not self._session:
            logger.debug("Dashboard broadcast skipped: no HTTP session.")
            return

        headers = {"Content-Type": "application/json"}
        if self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"

        payload = {
            "event_type": "fenrir_finding",
            "channel": "security",
            "data": finding,
        }

        try:
            async with self._session.post(
                self.config.api_broadcast_url,
                data=json.dumps(payload),
                headers=headers,
                timeout=ClientTimeout(total=self.config.report_timeout_seconds),
            ) as resp:
                if 200 <= resp.status < 300:
                    self.metrics["broadcast_ok"] += 1
                    logger.debug(
                        "Dashboard broadcast accepted: status=%s", resp.status
                    )
                else:
                    self.metrics["broadcast_failures"] += 1
                    body = await resp.text()
                    logger.warning(
                        "Dashboard broadcast rejected: status=%s body=%s",
                        resp.status,
                        body[:200],
                    )

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

                # Return to HUNTING if no findings came back this scan.
                if not findings and self.state == FenrirState.TRACKING:
                    self.transition(FenrirState.HUNTING)

                self.consecutive_errors = 0

                # Sleep for the scan interval, but wake immediately on shutdown.
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

                if self.consecutive_errors >= self.config.max_consecutive_errors:
                    self.transition(FenrirState.DEGRADED)
                else:
                    self.transition(FenrirState.ERROR)

                await asyncio.sleep(min(5.0, self.config.scan_interval_seconds))
                self.transition(FenrirState.HUNTING)

        self.transition(FenrirState.DORMANT)
        logger.info("Fenrir hunt loop stopped.")

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

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

    async def _start_session(self) -> None:
        """
        Create the shared aiohttp ClientSession for outbound reports.

        Must be called after the event loop is running (not in __init__).
        Connection limit is deliberately low — Fenrir is a hunter, not a
        throughput engine.
        """
        connector = TCPConnector(limit=10)
        self._session = ClientSession(connector=connector)
        logger.debug("Fenrir HTTP session created.")

    async def shutdown(self, reason: str = "shutdown") -> None:
        logger.warning("Fenrir shutdown requested: %s", reason)

        self.shutdown_event.set()

        if self.main_task:
            self.main_task.cancel()
            try:
                await self.main_task
            except asyncio.CancelledError:
                pass

        if self.runner:
            await self.runner.cleanup()

        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("Fenrir HTTP session closed.")

        self.transition(FenrirState.DORMANT)
        logger.info("Fenrir shutdown complete.")

    async def run(self) -> None:
        self.transition(FenrirState.INITIALIZING)

        loop = asyncio.get_running_loop()

        for sig in (_signal.SIGINT, _signal.SIGTERM):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self.shutdown(s.name)),
                )
            except NotImplementedError:
                # Windows does not support add_signal_handler on the event loop.
                pass

        await self._start_session()
        await self.start_health_server()

        self.main_task = asyncio.create_task(self.hunting_loop())

        try:
            await self.main_task
        finally:
            if not self.shutdown_event.is_set():
                await self.shutdown("run-finally")


# =============================================================================
# Entry point
# =============================================================================

async def main() -> None:
    hunter = FenrirHunter()
    await hunter.run()


if __name__ == "__main__":
    asyncio.run(main())
