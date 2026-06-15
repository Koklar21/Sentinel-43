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
import os
import threading
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Union

from .event_types import BaseEvent, normalize_event
from .watchtower import WatchtowerConfig, WatchtowerNode


WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
MANAGER_MODULE_ID = os.getenv("S43_MONITORING_MANAGER_ID", "sentinel43-monitoring-manager")

# Fix #6: prefer the S43_* naming convention used by every other constant in
# this module, but fall back to the legacy SENTINEL_VERSION name for
# backwards compatibility with existing deployments.
MANAGER_VERSION = os.getenv("S43_MANAGER_VERSION", os.getenv("SENTINEL_VERSION", "0.1.0"))


def _float_env(name: str, default: float) -> float:
    """
    Fix #5: previously WATCHTOWER_TIMEOUT = float(os.getenv(...)) was an
    unguarded cast performed at import time. An invalid value for the env
    var would raise ValueError and crash the entire module on import.

    This helper falls back to the provided default (and logs a warning to
    stderr) if the env var is missing or not a valid float.
    """
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        return float(raw)
    except ValueError:
        print(
            f"[monitoring_manager] WARNING: invalid value {raw!r} for {name}, "
            f"falling back to default {default}",
        )
        return default


WATCHTOWER_TIMEOUT = _float_env("S43_WATCHTOWER_TIMEOUT", 2.0)

# Fix #3: when registration with Watchtower fails, don't retry it on every
# single analyze_event() call -- that turns every monitored event into a
# blocking network round trip while Watchtower is down. Instead, back off
# for this many seconds between registration attempts.
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
        # Fix #1 (part 1): json.dumps() used to be called outside of any
        # try/except. A non-serializable value anywhere in `payload`
        # (e.g. a datetime object nested inside node status/alerts) raised
        # an uncaught TypeError here that propagated all the way up into
        # start() / analyze_event(), where it was caught by their broad
        # `except Exception` blocks and misreported as a start/scan
        # failure -- discarding real results in the process.
        #
        # Serialization failures are now contained to this function and
        # reported the same way as any other Watchtower-unreachable error.
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
    """

    def __init__(self, config: WatchtowerConfig):
        self.node = WatchtowerNode(config)
        self._registered = False
        self._last_error: dict[str, Any] | None = None
        self._scan_count = 0
        self._alert_count = 0
        self._failure_count = 0

        # Fix #3: tracks when we're allowed to retry registration again
        # after a failure, to avoid hammering Watchtower (and blocking the
        # scan hot path) on every single call while it's unreachable.
        self._next_registration_attempt = 0.0

        # Fix #4: counters and registration/error state are mutated from
        # analyze_event(), start(), stop(), and the various _report_*
        # helpers, any of which may be invoked concurrently (e.g. from
        # multiple FastAPI request handlers sharing one MonitoringManager
        # instance). Guard all mutations/reads of shared state with a lock.
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
                # Still within backoff window from a previous failed
                # registration attempt -- skip the network call entirely.
                return

        payload = {
            "module_id": MANAGER_MODULE_ID,
            "module_type": "monitoring-manager",
            "version": MANAGER_VERSION,
            "endpoint": None,
            "capabilities": [
                "watchtower_orchestration",
                "event_normalization",
                "event_analysis",
                "alert_counting",
                "scan_failure_reporting",
                "manager_status_reporting",
            ],
            "metadata": {
                "timestamp": utc_now(),
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
        # Fix #1 (part 2): _report_* helpers are best-effort telemetry.
        # They must never raise into start()/analyze_event(), or a
        # telemetry hiccup (network blip, serialization issue, etc.) gets
        # misreported as a failure of the actual operation being performed.
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
        # Fix #1 (part 2): see _report_dependency -- this must never raise.
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

        # Reporting success is best-effort telemetry and must not affect
        # the outcome of start() itself -- node.start() already succeeded
        # by this point regardless of whether this report goes through.
        self._report_dependency(
            status="online",
            event="monitoring_manager_started",
            details={
                "node_status": self.node.get_status(),
            },
        )

    def analyze_event(self, event: Union[Dict[str, Any], BaseEvent]) -> Dict[str, Any]:
        self._register_if_needed()

        try:
            if isinstance(event, BaseEvent):
                payload = event.to_dict()
            else:
                payload = normalize_event(event).to_dict()

            alerts = self.node.scan_event(payload)
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

        # Reporting alerts to Watchtower is best-effort telemetry and must
        # not prevent the caller from receiving the (already-successful)
        # scan results.
        if alerts:
            self._report_event(
                kind="runtime",
                status="degraded",
                details={
                    "event": "monitoring_alerts_generated",
                    "alert_count": len(alerts),
                    "alerts": alerts,
                },
            )

        return {
            "alerts": alerts,
            "alert_count": len(alerts),
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
            },
            "watchtower_node": status,
        }

    def stop(self) -> None:
        with self._lock:
            final_scan_count = self._scan_count
            final_alert_count = self._alert_count
            final_failure_count = self._failure_count

        # Fix #2: previously stop() only sent a "going offline" telemetry
        # report and never actually stopped the underlying WatchtowerNode,
        # leaving it running after the manager reported itself offline.
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
