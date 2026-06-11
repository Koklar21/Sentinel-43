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
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Union

from .event_types import BaseEvent, normalize_event
from .watchtower import WatchtowerConfig, WatchtowerNode


WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
MANAGER_MODULE_ID = os.getenv("S43_MONITORING_MANAGER_ID", "sentinel43-monitoring-manager")
MANAGER_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")


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
        data = json.dumps(payload).encode("utf-8")

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

    def _register_if_needed(self) -> None:
        if self._registered:
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
        self._registered = "error" not in result
        self._last_error = result if "error" in result else None

    def _report_dependency(
        self,
        status: str,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._register_if_needed()

        payload = {
            "name": MANAGER_MODULE_ID,
            "status": status,
            "version": MANAGER_VERSION,
            "details": {
                "event": event,
                "scan_count": self._scan_count,
                "alert_count": self._alert_count,
                "failure_count": self._failure_count,
                "timestamp": utc_now(),
                **(details or {}),
            },
        }

        result = _watchtower_request("POST", "/watchtower/dependencies/report", payload)
        self._last_error = result if "error" in result else None

    def _report_event(
        self,
        kind: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._register_if_needed()

        payload = {
            "event": {
                "kind": kind,
                "source": MANAGER_MODULE_ID,
                "status": status,
                "details": {
                    "scan_count": self._scan_count,
                    "alert_count": self._alert_count,
                    "failure_count": self._failure_count,
                    "timestamp": utc_now(),
                    **(details or {}),
                },
            }
        }

        result = _watchtower_request("POST", "/watchtower/analyze", payload)
        self._last_error = result if "error" in result else None

    def start(self) -> None:
        self._register_if_needed()

        try:
            self.node.start()

            self._report_dependency(
                status="online",
                event="monitoring_manager_started",
                details={
                    "node_status": self.node.get_status(),
                },
            )

        except Exception as exc:
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

    def analyze_event(self, event: Union[Dict[str, Any], BaseEvent]) -> Dict[str, Any]:
        self._register_if_needed()

        try:
            if isinstance(event, BaseEvent):
                payload = event.to_dict()
            else:
                payload = normalize_event(event).to_dict()

            alerts = self.node.scan_event(payload)

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
                    },
                )

            return {
                "alerts": alerts,
                "alert_count": len(alerts),
            }

        except Exception as exc:
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

    def get_status(self) -> Dict[str, Any]:
        status = self.node.get_status()

        return {
            "manager": {
                "module_id": MANAGER_MODULE_ID,
                "version": MANAGER_VERSION,
                "registered_with_watchtower": self._registered,
                "scan_count": self._scan_count,
                "alert_count": self._alert_count,
                "failure_count": self._failure_count,
                "last_error": self._last_error,
                "timestamp": utc_now(),
            },
            "watchtower_node": status,
        }

    def stop(self) -> None:
        self._report_dependency(
            status="offline",
            event="monitoring_manager_stopped",
            details={
                "final_scan_count": self._scan_count,
                "final_alert_count": self._alert_count,
                "final_failure_count": self._failure_count,
            },
        )
