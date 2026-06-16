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
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

from __future__ import annotations

import json
import logging
import os
import threading
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from .event_types import BaseEvent, MobileEvent, normalize_event, to_event_context
from .watchtower import WatchtowerConfig, WatchtowerNode


logger = logging.getLogger("SentinelMonitoringManager")

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
MANAGER_MODULE_ID = os.getenv("S43_MONITORING_MANAGER_ID", "sentinel43-monitoring-manager")
MANAGER_VERSION = os.getenv("S43_MANAGER_VERSION", os.getenv("SENTINEL_VERSION", "0.1.0"))


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "[monitoring_manager] invalid value %r for %s, falling back to %s",
            raw, name, default,
        )
        return default


WATCHTOWER_TIMEOUT = _float_env("S43_WATCHTOWER_TIMEOUT", 2.0)
REGISTRATION_RETRY_SECONDS = _float_env("S43_REGISTRATION_RETRY_SECONDS", 30.0)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{WATCHTOWER_URL}{path}"
    data = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        try:
            data = json.dumps(payload).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return {
                "error": "watchtower_payload_serialization_error",
                "detail": str(exc),
            }

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            if not body:
                return {"status_code": response.status}

            parsed = json.loads(body)
            if isinstance(parsed, dict):
                parsed.setdefault("status_code", response.status)
                return parsed

            return {"status_code": response.status, "body": parsed}

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)

        return {
            "error": "watchtower_http_error",
            "status_code": exc.code,
            "detail": detail,
        }

    except Exception as exc:
        return {
            "error": "watchtower_unreachable",
            "detail": str(exc),
        }


class MonitoringManager:
    """
    High-level orchestration layer for Sentinel monitoring.
    Keeps the rest of the system from depending on Watchtower internals.
    Reports manager lifecycle, scan failures, and degraded states to the primary Watchtower.

    Window store / threat detector integration
    ------------------------------------------
    If a SentinelWindowStore and threat_detector are supplied, analyze_event()
    will:
      1. Convert the normalized event to an EventContext via to_event_context()
      2. Add it to the window store's rolling buffer for (identity, ip)
      3. Build a SequenceWindow snapshot for the threat detector
      4. Score the window and include the result in the returned dict

    source_ip is required for window store population and must be supplied by
    the gateway / request handler -- it is never read from the event payload
    itself, to avoid trusting client-supplied IPs. For MobileEvent, source_ip
    is already on the event (set at the gateway before construction) so the
    kwarg may be omitted, but supplying it explicitly is also fine.
    """

    def __init__(
        self,
        config: WatchtowerConfig,
        *,
        window_store: Optional[Any] = None,
        threat_detector: Optional[Any] = None,
    ) -> None:
        """
        Parameters
        ----------
        config:
            WatchtowerConfig for the embedded WatchtowerNode.
        window_store:
            Optional SentinelWindowStore instance. When supplied, every
            successfully normalized event is added to the rolling window
            buffer so that temporal threat patterns accumulate over time.
            Type: SentinelWindowStore (from sentinel_43_ai or local package).
        threat_detector:
            Optional threat detector with a .score(window: SequenceWindow)
            method. Requires window_store to be set -- if window_store is
            None this parameter is ignored.
            Type: whatever the sentinel_43_ai detector exposes.
        """
        self.node = WatchtowerNode(config)

        # Window store + threat detector are optional; the manager degrades
        # gracefully to pure Watchtower-only monitoring if they're absent.
        self._window_store = window_store
        self._threat_detector = threat_detector

        if threat_detector is not None and window_store is None:
            logger.warning(
                "MonitoringManager: threat_detector supplied without a "
                "window_store -- threat scoring will be skipped. Pass a "
                "SentinelWindowStore instance to enable it."
            )

        self._registered = False
        self._last_error: dict[str, Any] | None = None
        self._scan_count = 0
        self._alert_count = 0
        self._failure_count = 0
        self._next_registration_attempt = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Watchtower registration / telemetry helpers
    # ------------------------------------------------------------------

    def _register_if_needed(self) -> None:
        with self._lock:
            if self._registered:
                return

            now = time.monotonic()
            if now < self._next_registration_attempt:
                return

        capabilities = [
            "watchtower_orchestration",
            "event_normalization",
            "event_analysis",
            "alert_counting",
            "scan_failure_reporting",
            "manager_status_reporting",
        ]

        if self._window_store is not None:
            capabilities.append("rolling_window_store")
        if self._threat_detector is not None:
            capabilities.append("threat_scoring")

        payload = {
            "module_id": MANAGER_MODULE_ID,
            "module_type": "monitoring-manager",
            "version": MANAGER_VERSION,
            "endpoint": None,
            "capabilities": capabilities,
            "metadata": {
                "timestamp": utc_now(),
                "window_store_enabled": self._window_store is not None,
                "threat_detector_enabled": self._threat_detector is not None,
            },
        }

        result = _watchtower_request("POST", "/watchtower/modules/register", payload)
        registered = "error" not in result

        with self._lock:
            self._registered = registered
            self._last_error = None if registered else result
            if not registered:
                self._next_registration_attempt = time.monotonic() + REGISTRATION_RETRY_SECONDS

    def _report_dependency(
        self,
        status: str,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        try:
            self._register_if_needed()

            with self._lock:
                snapshot = {
                    "scan_count": self._scan_count,
                    "alert_count": self._alert_count,
                    "failure_count": self._failure_count,
                }

            payload = {
                "name": MANAGER_MODULE_ID,
                "status": status,
                "version": MANAGER_VERSION,
                "details": {
                    "event": event,
                    **snapshot,
                    "timestamp": utc_now(),
                    **(details or {}),
                },
            }

            result = _watchtower_request("POST", "/watchtower/dependencies/report", payload)

            with self._lock:
                self._last_error = result if "error" in result else None

        except Exception as exc:
            with self._lock:
                self._last_error = {
                    "error": "telemetry_reporting_failed",
                    "detail": str(exc),
                }

    def _report_event(
        self,
        kind: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        try:
            self._register_if_needed()

            with self._lock:
                snapshot = {
                    "scan_count": self._scan_count,
                    "alert_count": self._alert_count,
                    "failure_count": self._failure_count,
                }

            payload = {
                "event": {
                    "kind": kind,
                    "source": MANAGER_MODULE_ID,
                    "status": status,
                    "details": {
                        **snapshot,
                        "timestamp": utc_now(),
                        **(details or {}),
                    },
                }
            }

            result = _watchtower_request("POST", "/watchtower/analyze", payload)

            with self._lock:
                self._last_error = result if "error" in result else None

        except Exception as exc:
            with self._lock:
                self._last_error = {
                    "error": "telemetry_reporting_failed",
                    "detail": str(exc),
                }

    # ------------------------------------------------------------------
    # Window store helpers
    # ------------------------------------------------------------------

    def _populate_window(
        self,
        normalized: BaseEvent,
        source_ip: Optional[str],
    ) -> Optional[Any]:
        """
        Add the normalized event to the rolling window store and return the
        resulting SequenceWindow for threat scoring. Returns None if the
        window store is not configured, source_ip is unavailable, or
        population fails for any reason.

        This is best-effort -- any exception is logged and suppressed so
        that window store errors never fail or slow down the scan path.
        """
        if self._window_store is None:
            return None

        # For MobileEvent, source_ip is already on the event (set at the
        # gateway before construction). For all other event types the caller
        # must supply it explicitly.
        effective_ip: Optional[str] = (
            getattr(normalized, "source_ip", None) or source_ip
        )

        if not effective_ip:
            logger.debug(
                "Window store skipped for event id=%s kind=%s: "
                "source_ip not available. Supply it via analyze_event(source_ip=...)",
                normalized.id, normalized.kind,
            )
            return None

        try:
            ctx = to_event_context(normalized, source_ip=effective_ip)
            self._window_store.add_event(ctx)
            return self._window_store.build_window(ctx.source_identity, effective_ip)

        except Exception as exc:
            logger.warning(
                "Window store population failed for event id=%s kind=%s: %s",
                normalized.id, normalized.kind, exc,
            )
            return None

    def _score_window(self, window: Optional[Any]) -> Optional[float]:
        """
        Run the threat detector over the SequenceWindow and return a score.
        Returns None if no detector is configured or scoring fails.
        Best-effort -- never raises.
        """
        if self._threat_detector is None or window is None:
            return None

        try:
            return float(self._threat_detector.score(window))
        except Exception as exc:
            logger.warning("Threat detector scoring failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._register_if_needed()

        try:
            self.node.start()
        except Exception as exc:
            with self._lock:
                self._failure_count += 1

            self._report_dependency(
                status="failed",
                event="monitoring_manager_start_failed",
                details={
                    "error": str(exc),
                    "exception_type": type(exc).__name__,
                    "traceback": traceback.format_exc(limit=10),
                },
            )

            raise

        self._report_dependency(
            status="online",
            event="monitoring_manager_started",
            details={
                "node_status": self.node.get_status(),
                "window_store_enabled": self._window_store is not None,
                "threat_detector_enabled": self._threat_detector is not None,
            },
        )

    def analyze_event(
        self,
        event: Union[Dict[str, Any], BaseEvent],
        *,
        source_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Normalize, scan, and optionally score an event.

        Parameters
        ----------
        event:
            A raw event dict or a typed BaseEvent subclass.
        source_ip:
            The client IP address, extracted from the request by the gateway
            layer (e.g. X-Forwarded-For header). Required for window store
            population for non-MobileEvent types. For MobileEvent, the IP is
            already on the event and this kwarg may be omitted.

        Returns
        -------
        {
            "alerts":       list of alert dicts from the Watchtower scan,
            "alert_count":  int,
            "threat_score": float | None,  -- None if window store / detector
                                              not configured or unavailable
        }
        """
        self._register_if_needed()

        try:
            # Normalize to a typed BaseEvent first so both the window store
            # (which needs the object) and the Watchtower scan (which needs
            # the dict) can share the same normalization pass.
            if isinstance(event, BaseEvent):
                normalized = event
            else:
                normalized = normalize_event(event)

            scan_payload = normalized.to_dict()

            # Window population + threat scoring are best-effort and must
            # not affect the outcome of the Watchtower scan below.
            window = self._populate_window(normalized, source_ip)
            threat_score = self._score_window(window)

            alerts = self.node.scan_event(scan_payload)

        except Exception as exc:
            with self._lock:
                self._failure_count += 1

            self._report_dependency(
                status="failed",
                event="monitoring_analysis_failed",
                details={
                    "error": str(exc),
                    "exception_type": type(exc).__name__,
                    "traceback": traceback.format_exc(limit=10),
                },
            )

            raise

        with self._lock:
            self._scan_count += 1
            self._alert_count += len(alerts)

        if alerts:
            self._report_event(
                kind="runtime",
                status="degraded",
                details={
                    "event": "monitoring_alerts_generated",
                    "alert_count": len(alerts),
                    "alerts": alerts,
                    "threat_score": threat_score,
                },
            )

        return {
            "alerts": alerts,
            "alert_count": len(alerts),
            "threat_score": threat_score,
        }

    def get_status(self) -> Dict[str, Any]:
        status = self.node.get_status()

        with self._lock:
            registered = self._registered
            scan_count = self._scan_count
            alert_count = self._alert_count
            failure_count = self._failure_count
            last_error = self._last_error

        return {
            "manager": {
                "module_id": MANAGER_MODULE_ID,
                "version": MANAGER_VERSION,
                "registered_with_watchtower": registered,
                "scan_count": scan_count,
                "alert_count": alert_count,
                "failure_count": failure_count,
                "last_error": last_error,
                "timestamp": utc_now(),
                "window_store_enabled": self._window_store is not None,
                "threat_detector_enabled": self._threat_detector is not None,
            },
            "watchtower_node": status,
        }

    def stop(self) -> None:
        with self._lock:
            final_scan_count = self._scan_count
            final_alert_count = self._alert_count
            final_failure_count = self._failure_count

        node_stop_error: str | None = None
        try:
            self.node.stop()
        except Exception as exc:
            node_stop_error = str(exc)
            with self._lock:
                self._failure_count += 1
                final_failure_count = self._failure_count

        self._report_dependency(
            status="offline",
            event="monitoring_manager_stopped",
            details={
                "final_scan_count": final_scan_count,
                "final_alert_count": final_alert_count,
                "final_failure_count": final_failure_count,
                **({"node_stop_error": node_stop_error} if node_stop_error else {}),
            },
        )

        if node_stop_error is not None:
            raise RuntimeError(f"Failed to stop WatchtowerNode: {node_stop_error}")
