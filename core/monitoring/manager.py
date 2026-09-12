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

"""Sentinel-43 monitoring orchestration.

The manager coordinates typed event normalization, scanning, optional rolling
window population, and optional threat scoring.

It intentionally does not:
    - read environment variables
    - construct Watchtower clients/nodes
    - register itself over the network
    - emit telemetry directly
    - spawn background workers
    - expose raw tracebacks
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .event_types import (
    BaseEvent,
    EventNormalizationResult,
    normalize_event,
    to_event_context,
)


@runtime_checkable
class EventScanner(Protocol):
    """Scanner interface used by MonitoringManager."""

    def start(self) -> None: ...

    def scan_event(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]: ...

    def get_status(self) -> dict[str, Any]: ...

    def stop(self) -> None: ...


class WatchtowerNodeScanner:
    """Canonical EventScanner binding for a WatchtowerNode.

    A WatchtowerNode is the embedded scanner for MonitoringManager, but its
    ``scan_event()`` returns a rich ``ScanResult`` (``.alerts`` plus the
    tower ``decision`` / ``accepted`` fields the s43-core Watchtower service
    needs). MonitoringManager only consumes the alert mappings, so this
    adapter projects the result down to ``list[dict]`` and forwards the
    lifecycle calls unchanged.
    """

    def __init__(self, node: Any) -> None:
        self._node = node

    def start(self) -> None:
        self._node.start()

    def stop(self) -> None:
        self._node.stop()

    def get_status(self) -> dict[str, Any]:
        return self._node.get_status()

    def scan_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        return list(self._node.scan_event(event).alerts)

    def recent_event_snapshot(self, limit: int) -> dict[str, Any]:
        """Canonical bounded recent-event view, unchanged from the node.

        WatchtowerNode already maintains this (a bounded deque, sized by
        its own config) for every event it scans -- Fenrir findings, Sparta
        integrity events, and everything else routed through
        MonitoringManager.analyze_event(). This is a passthrough, not a
        second store.
        """
        return self._node.recent_event_snapshot(limit)


@runtime_checkable
class WindowStore(Protocol):
    """Minimal rolling-window store interface."""

    def add_event(
        self,
        event: Any,
    ) -> None: ...

    def build_window(
        self,
        source_identity: str,
        source_ip: str,
    ) -> Any: ...


@runtime_checkable
class ThreatDetector(Protocol):
    """Minimal threat-detector interface."""

    def score(
        self,
        window: Any,
    ) -> Any: ...


@runtime_checkable
class MonitoringTelemetrySink(Protocol):
    """Optional best-effort observer for manager lifecycle/results."""

    def emit(
        self,
        event: dict[str, Any],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class MonitoringResult:
    alerts: tuple[dict[str, Any], ...]
    alert_count: int
    threat_score: float | None
    dropped_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.alert_count != len(
            self.alerts
        ):
            raise ValueError(
                "alert_count must equal len(alerts)"
            )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "alerts": [
                dict(
                    alert
                )
                for alert in self.alerts
            ],
            "alert_count": self.alert_count,
            "threat_score": self.threat_score,
            "dropped_fields": list(
                self.dropped_fields
            ),
        }


class MonitoringManager:
    """Coordinate scanning and optional temporal threat analysis."""

    def __init__(
        self,
        scanner: EventScanner,
        *,
        window_store: WindowStore | None = None,
        threat_detector: ThreatDetector | None = None,
        telemetry_sink: MonitoringTelemetrySink | None = None,
    ) -> None:
        if (
            threat_detector is not None
            and window_store is None
        ):
            raise ValueError(
                "threat_detector requires window_store"
            )

        self._scanner = scanner
        self._window_store = window_store
        self._threat_detector = threat_detector
        self._telemetry_sink = telemetry_sink

        self._lock = threading.Lock()
        self._started = False
        self._scan_count = 0
        self._alert_count = 0
        self._failure_count = 0

    def _emit(
        self,
        event: dict[str, Any],
    ) -> None:
        sink = self._telemetry_sink

        if sink is None:
            return

        try:
            sink.emit(
                event
            )
        except Exception:
            # Monitoring telemetry must not mutate scan outcome.
            return

    def start(
        self,
    ) -> None:
        with self._lock:
            if self._started:
                return

        try:
            self._scanner.start()
        except Exception:
            with self._lock:
                self._failure_count += 1

            self._emit(
                {
                    "kind": "monitoring",
                    "status": "start_failed",
                }
            )
            raise

        with self._lock:
            self._started = True

        self._emit(
            {
                "kind": "monitoring",
                "status": "started",
                "window_store_enabled": self._window_store
                is not None,
                "threat_detector_enabled": self._threat_detector
                is not None,
            }
        )

    def _normalize(
        self,
        event: dict[str, Any] | BaseEvent,
    ) -> EventNormalizationResult:
        if isinstance(
            event,
            BaseEvent,
        ):
            return EventNormalizationResult(
                event=event
            )

        return normalize_event(
            event
        )

    def _build_window(
        self,
        *,
        event: BaseEvent,
        source_ip: str | None,
        source_identity: str | None,
    ) -> Any | None:
        store = self._window_store

        if store is None:
            return None

        context = to_event_context(
            event,
            source_ip=source_ip,
            source_identity=source_identity,
        )

        store.add_event(
            context
        )

        return store.build_window(
            context.source_identity,
            context.source_ip,
        )

    def _score_window(
        self,
        window: Any | None,
    ) -> float | None:
        detector = self._threat_detector

        if (
            detector is None
            or window is None
        ):
            return None

        result = detector.score(
            window
        )

        if hasattr(
            result,
            "score",
        ):
            value = getattr(
                result,
                "score",
            )
        else:
            value = result

        return float(
            value
        )

    def analyze_event(
        self,
        event: dict[str, Any] | BaseEvent,
        *,
        source_ip: str | None = None,
        source_identity: str | None = None,
    ) -> MonitoringResult:
        with self._lock:
            started = self._started

        if not started:
            raise RuntimeError(
                "MonitoringManager is not started"
            )

        normalized_result = self._normalize(
            event
        )

        normalized = normalized_result.event

        try:
            window = self._build_window(
                event=normalized,
                source_ip=source_ip,
                source_identity=source_identity,
            )

            threat_score = self._score_window(
                window
            )

            alerts_raw = self._scanner.scan_event(
                normalized.to_dict()
            )

            alerts = tuple(
                dict(
                    alert
                )
                for alert in alerts_raw
            )

        except Exception:
            with self._lock:
                self._failure_count += 1

            self._emit(
                {
                    "kind": "monitoring",
                    "status": "analysis_failed",
                    "event_kind": normalized.kind,
                }
            )
            raise

        with self._lock:
            self._scan_count += 1
            self._alert_count += len(
                alerts
            )

        result = MonitoringResult(
            alerts=alerts,
            alert_count=len(
                alerts
            ),
            threat_score=threat_score,
            dropped_fields=normalized_result.dropped_fields,
        )

        if alerts:
            self._emit(
                {
                    "kind": "monitoring",
                    "status": "alerts_generated",
                    "event_kind": normalized.kind,
                    "alert_count": result.alert_count,
                    "threat_score": result.threat_score,
                }
            )

        return result

    def get_status(
        self,
    ) -> dict[str, Any]:
        with self._lock:
            manager_status = {
                "started": self._started,
                "scan_count": self._scan_count,
                "alert_count": self._alert_count,
                "failure_count": self._failure_count,
                "window_store_enabled": self._window_store
                is not None,
                "threat_detector_enabled": self._threat_detector
                is not None,
            }

        return {
            "manager": manager_status,
            "scanner": self._scanner.get_status(),
        }

    def recent_events(self, limit: int) -> dict[str, Any]:
        """Bounded, canonical, already-recorded recent events.

        Delegates to the scanner's own recent-event view when it has one
        (WatchtowerNodeScanner does). Raises if the wired scanner does not
        support this rather than inventing a second, parallel history.
        """
        provider = getattr(self._scanner, "recent_event_snapshot", None)
        if not callable(provider):
            raise RuntimeError(
                "The wired event scanner does not expose recent events"
            )

        with self._lock:
            started = self._started

        if not started:
            raise RuntimeError("MonitoringManager is not started")

        return provider(limit)

    def stop(
        self,
    ) -> None:
        with self._lock:
            if not self._started:
                return

        try:
            self._scanner.stop()
        except Exception:
            with self._lock:
                self._failure_count += 1

            self._emit(
                {
                    "kind": "monitoring",
                    "status": "stop_failed",
                }
            )
            raise

        with self._lock:
            self._started = False

        self._emit(
            {
                "kind": "monitoring",
                "status": "stopped",
            }
        )


__all__ = [
    "EventScanner",
    "MonitoringManager",
    "MonitoringResult",
    "MonitoringTelemetrySink",
    "ThreatDetector",
    "WatchtowerNodeScanner",
    "WindowStore",
]
