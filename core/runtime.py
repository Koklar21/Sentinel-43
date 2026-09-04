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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from core.logging_init import get_logger


RUNTIME_MODULE_ID = os.getenv("S43_RUNTIME_MODULE_ID", "sentinel-43-runtime")
RUNTIME_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
RUNTIME_HEARTBEAT_SECONDS = int(os.getenv("S43_RUNTIME_HEARTBEAT_SECONDS", "15"))


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

            return {
                "status_code": response.status,
                "body": parsed,
            }

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


@dataclass
class RuntimeWorker:
    name: str
    target: Callable[[], None]
    daemon: bool = True
    thread: threading.Thread | None = None
    started_ts: float | None = None
    stopped_ts: float | None = None
    last_error: str | None = None

    def is_alive(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def to_status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "alive": self.is_alive(),
            "started_ts": self.started_ts,
            "stopped_ts": self.stopped_ts,
            "last_error": self.last_error,
        }


@dataclass
class SentinelRuntime:
    mode: str = "normal"
    dry_run: bool = False

    _stop_event: threading.Event = field(init=False)
    _workers: dict[str, RuntimeWorker] = field(init=False, default_factory=dict)
    _logger: Any = field(init=False)
    _lock: threading.RLock = field(init=False)
    _started_ts: float = field(init=False)
    _last_heartbeat_ts: float | None = field(init=False, default=None)
    _last_watchtower_error: dict[str, Any] | None = field(init=False, default=None)
    _runtime_state: str = field(init=False, default="INITIALIZING")

    def __post_init__(self) -> None:
        self._stop_event = threading.Event()
        self._workers = {}
        self._logger = get_logger(self.__class__.__name__)
        self._lock = threading.RLock()
        self._started_ts = time.time()

    def uptime_seconds(self) -> float:
        return round(time.time() - self._started_ts, 3)

    def _report_watchtower_result(self, result: dict[str, Any]) -> None:
        with self._lock:
            if "error" in result:
                self._last_watchtower_error = result
            else:
                self._last_watchtower_error = None

    def register_with_watchtower(self) -> dict[str, Any]:
        payload = {
            "module_id": RUNTIME_MODULE_ID,
            "module_type": "runtime-manager",
            "version": RUNTIME_VERSION,
            "endpoint": None,
            "capabilities": [
                "runtime_lifecycle",
                "worker_management",
                "worker_failure_reporting",
                "runtime_heartbeat",
                "core_orchestration",
            ],
            "metadata": {
                "mode": self.mode,
                "dry_run": self.dry_run,
                "timestamp": utc_now(),
            },
        }

        result = _watchtower_request("POST", "/watchtower/modules/register", payload)
        self._report_watchtower_result(result)
        return result

    def send_heartbeat(self, status: str = "online", message: str = "Runtime heartbeat online") -> dict[str, Any]:
        payload = {
            "module_id": RUNTIME_MODULE_ID,
            "status": status,
            "metrics": {
                "mode": self.mode,
                "dry_run": self.dry_run,
                "runtime_state": self._runtime_state,
                "uptime_seconds": self.uptime_seconds(),
                "worker_count": len(self._workers),
                "workers": [worker.to_status() for worker in self._workers.values()],
                "timestamp": utc_now(),
            },
            "message": message,
        }

        result = _watchtower_request("POST", "/watchtower/modules/heartbeat", payload)

        with self._lock:
            if "error" not in result:
                self._last_heartbeat_ts = time.time()

        self._report_watchtower_result(result)
        return result

    def report_dependency(
        self,
        name: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "name": name,
            "status": status,
            "version": RUNTIME_VERSION,
            "details": {
                "runtime_module_id": RUNTIME_MODULE_ID,
                "mode": self.mode,
                "dry_run": self.dry_run,
                "runtime_state": self._runtime_state,
                "uptime_seconds": self.uptime_seconds(),
                "timestamp": utc_now(),
                **(details or {}),
            },
        }

        result = _watchtower_request("POST", "/watchtower/dependencies/report", payload)
        self._report_watchtower_result(result)
        return result

    def report_runtime_event(
        self,
        kind: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "event": {
                "kind": kind,
                "source": RUNTIME_MODULE_ID,
                "status": status,
                "runtime_state": self._runtime_state,
                "mode": self.mode,
                "dry_run": self.dry_run,
                "uptime_seconds": self.uptime_seconds(),
                "details": details or {},
                "timestamp": utc_now(),
            }
        }

        result = _watchtower_request("POST", "/watchtower/analyze", payload)
        self._report_watchtower_result(result)
        return result

    def add_worker(self, name: str, target: Callable[[], None], daemon: bool = True) -> None:
        with self._lock:
            if name in self._workers:
                raise ValueError(f"Worker already registered: {name}")

            self._workers[name] = RuntimeWorker(
                name=name,
                target=target,
                daemon=daemon,
            )

    def _run_worker(self, worker: RuntimeWorker) -> None:
        worker.started_ts = time.time()

        try:
            self._logger.info("Worker online: %s", worker.name)
            self.report_dependency(
                name=f"worker:{worker.name}",
                status="online",
                details={"event": "worker_started"},
            )

            worker.target()

            worker.stopped_ts = time.time()
            self.report_dependency(
                name=f"worker:{worker.name}",
                status="offline",
                details={"event": "worker_stopped_cleanly"},
            )

        except Exception as exc:
            worker.last_error = str(exc)
            worker.stopped_ts = time.time()

            self._logger.exception("Worker failed: %s", worker.name)

            self.report_dependency(
                name=f"worker:{worker.name}",
                status="failed",
                details={
                    "event": "worker_failed",
                    "error": str(exc),
                    "traceback": traceback.format_exc(limit=10),
                },
            )

            self.send_heartbeat(
                status="degraded",
                message=f"Runtime worker failed: {worker.name}",
            )

            self.report_runtime_event(
                kind="runtime",
                status="failed",
                details={
                    "worker": worker.name,
                    "error": str(exc),
                },
            )

    def _main_loop(self) -> None:
        self._logger.info("Main loop online.")

        while not self._stop_event.is_set():
            time.sleep(1.0)

        self._logger.info("Main loop offline.")

    def _watchtower_heartbeat_loop(self) -> None:
        self._logger.info("Watchtower heartbeat loop online.")

        while not self._stop_event.wait(RUNTIME_HEARTBEAT_SECONDS):
            result = self.send_heartbeat(
                status="online",
                message="Sentinel-43 runtime heartbeat online",
            )

            if "error" in result:
                self._logger.warning("Runtime Watchtower heartbeat failed: %s", result)

        self._logger.info("Watchtower heartbeat loop offline.")

    def start(self) -> None:
        with self._lock:
            if self._runtime_state == "ACTIVE":
                self._logger.warning("Runtime already active.")
                return

            self._runtime_state = "STARTING"

        self._logger.info(
            "Starting Sentinel-43 runtime (mode=%s dry_run=%s)",
            self.mode,
            self.dry_run,
        )

        self.register_with_watchtower()
        self.report_dependency(
            name=RUNTIME_MODULE_ID,
            status="online",
            details={"event": "runtime_starting"},
        )

        self.add_worker("sentinel-main-loop", self._main_loop)
        self.add_worker("watchtower-heartbeat-loop", self._watchtower_heartbeat_loop)

        with self._lock:
            for worker in self._workers.values():
                if worker.thread is not None:
                    continue

                worker.thread = threading.Thread(
                    target=self._run_worker,
                    args=(worker,),
                    name=worker.name,
                    daemon=worker.daemon,
                )
                worker.thread.start()

            self._runtime_state = "ACTIVE"

        self.send_heartbeat(
            status="online",
            message="Sentinel-43 runtime active",
        )

    def stop(self) -> None:
        if self._stop_event.is_set():
            return

        with self._lock:
            self._runtime_state = "STOPPING"

        self._logger.info("Stopping Sentinel-43 runtime...")

        self.report_dependency(
            name=RUNTIME_MODULE_ID,
            status="degraded",
            details={"event": "runtime_stopping"},
        )

        self.send_heartbeat(
            status="degraded",
            message="Sentinel-43 runtime stopping",
        )

        self._stop_event.set()

        with self._lock:
            workers = list(self._workers.values())

        for worker in workers:
            if worker.thread and worker.thread.is_alive():
                worker.thread.join(timeout=5)

        with self._lock:
            self._runtime_state = "STOPPED"

        self.report_dependency(
            name=RUNTIME_MODULE_ID,
            status="offline",
            details={"event": "runtime_stopped"},
        )

        self.send_heartbeat(
            status="offline",
            message="Sentinel-43 runtime stopped",
        )

        self._logger.info("Sentinel-43 runtime stopped.")

    def block_forever(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(0.25)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "module_id": RUNTIME_MODULE_ID,
                "version": RUNTIME_VERSION,
                "mode": self.mode,
                "dry_run": self.dry_run,
                "state": self._runtime_state,
                "uptime_seconds": self.uptime_seconds(),
                "worker_count": len(self._workers),
                "workers": [worker.to_status() for worker in self._workers.values()],
                "last_heartbeat_ts": self._last_heartbeat_ts,
                "last_watchtower_error": self._last_watchtower_error,
                "watchtower_url": WATCHTOWER_URL,
                "timestamp": utc_now(),
            }
