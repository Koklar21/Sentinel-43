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

"""Sentinel-43 runtime lifecycle state.

This module owns process-local runtime state and bounded worker bookkeeping.

It intentionally performs:
    - no environment reads
    - no Watchtower/network calls
    - no implicit logging configuration
    - no traceback serialization
    - no automatic heartbeat thread creation
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol


logger = logging.getLogger(__name__)


class RuntimeState(StrEnum):
    INITIALIZING = "INITIALIZING"
    STARTING = "STARTING"
    ACTIVE = "ACTIVE"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    DEGRADED = "DEGRADED"


class WorkerState(StrEnum):
    REGISTERED = "REGISTERED"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class RuntimeEventSink(Protocol):
    def emit(
        self,
        event: Mapping[str, Any],
    ) -> None:
        ...


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    module_id: str = "sentinel43-runtime"
    version: str = "unknown"
    mode: str = "normal"
    dry_run: bool = False
    max_workers: int = 32
    worker_join_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        module_id = str(
            self.module_id
        ).strip()

        version = str(
            self.version
        ).strip()

        mode = str(
            self.mode
        ).strip()

        if not module_id:
            raise ValueError(
                "module_id must not be empty"
            )

        if not version:
            raise ValueError(
                "version must not be empty"
            )

        if not mode:
            raise ValueError(
                "mode must not be empty"
            )

        if not 1 <= self.max_workers <= 256:
            raise ValueError(
                "max_workers must be between 1 and 256"
            )

        if not 0.1 <= self.worker_join_timeout_seconds <= 60.0:
            raise ValueError(
                "worker_join_timeout_seconds must be between 0.1 and 60"
            )

        object.__setattr__(
            self,
            "module_id",
            module_id,
        )

        object.__setattr__(
            self,
            "version",
            version,
        )

        object.__setattr__(
            self,
            "mode",
            mode,
        )


@dataclass(slots=True)
class RuntimeWorker:
    name: str
    target: Callable[[], None]
    daemon: bool = False
    state: WorkerState = WorkerState.REGISTERED
    thread: threading.Thread | None = None
    started_monotonic: float | None = None
    stopped_monotonic: float | None = None
    error_type: str | None = None

    def __post_init__(self) -> None:
        self.name = str(
            self.name
        ).strip()

        if not self.name:
            raise ValueError(
                "worker name must not be empty"
            )

        if not callable(
            self.target
        ):
            raise TypeError(
                "worker target must be callable"
            )

    def is_alive(
        self,
    ) -> bool:
        return bool(
            self.thread
            and self.thread.is_alive()
        )

    def status(
        self,
    ) -> Mapping[str, Any]:
        return MappingProxyType(
            {
                "name": self.name,
                "state": self.state.value,
                "alive": self.is_alive(),
                "started_monotonic": self.started_monotonic,
                "stopped_monotonic": self.stopped_monotonic,
                "error_type": self.error_type,
            }
        )


class SentinelRuntime:
    """Bounded, process-local runtime lifecycle coordinator."""

    def __init__(
        self,
        config: RuntimeConfig,
        *,
        event_sink: RuntimeEventSink | None = None,
    ) -> None:
        self._config = config
        self._event_sink = event_sink

        self._pid = os.getpid()
        self._process_id = uuid.uuid4().hex
        self._started_monotonic = time.monotonic()

        self._state = RuntimeState.INITIALIZING
        self._workers: dict[
            str,
            RuntimeWorker,
        ] = {}

        self._lock = threading.RLock()
        self._stop_event = threading.Event()

    def _refresh_process_identity_if_forked(
        self,
    ) -> None:
        current_pid = os.getpid()

        if current_pid == self._pid:
            return

        with self._lock:
            if current_pid == self._pid:
                return

            self._pid = current_pid
            self._process_id = uuid.uuid4().hex
            self._started_monotonic = time.monotonic()
            self._state = RuntimeState.INITIALIZING
            self._workers.clear()
            self._stop_event = threading.Event()

    def _emit(
        self,
        event_type: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        sink = self._event_sink

        if sink is None:
            return

        event = {
            "kind": "runtime",
            "event_type": event_type,
            "module_id": self._config.module_id,
            "process_id": self._process_id,
            "pid": self._pid,
            "state": self._state.value,
            "details": dict(
                details
                or {}
            ),
        }

        try:
            sink.emit(
                event
            )
        except Exception:
            logger.debug(
                "runtime event sink failed",
                exc_info=True,
            )

    def uptime_seconds(
        self,
    ) -> float:
        self._refresh_process_identity_if_forked()

        return round(
            time.monotonic()
            - self._started_monotonic,
            3,
        )

    def add_worker(
        self,
        name: str,
        target: Callable[[], None],
        *,
        daemon: bool = False,
    ) -> None:
        self._refresh_process_identity_if_forked()

        worker = RuntimeWorker(
            name=name,
            target=target,
            daemon=daemon,
        )

        with self._lock:
            if self._state not in {
                RuntimeState.INITIALIZING,
                RuntimeState.STOPPED,
            }:
                raise RuntimeError(
                    "workers may only be registered before runtime start"
                )

            if worker.name in self._workers:
                raise ValueError(
                    f"worker already registered: {worker.name}"
                )

            if len(
                self._workers
            ) >= self._config.max_workers:
                raise RuntimeError(
                    "runtime worker capacity reached"
                )

            self._workers[
                worker.name
            ] = worker

    def _run_worker(
        self,
        worker: RuntimeWorker,
    ) -> None:
        worker.started_monotonic = (
            time.monotonic()
        )
        worker.state = WorkerState.RUNNING

        self._emit(
            "worker_started",
            details={
                "worker": worker.name,
            },
        )

        try:
            worker.target()

        except Exception as exc:
            worker.error_type = (
                type(
                    exc
                ).__name__
            )
            worker.state = WorkerState.FAILED
            worker.stopped_monotonic = (
                time.monotonic()
            )

            with self._lock:
                if self._state is RuntimeState.ACTIVE:
                    self._state = RuntimeState.DEGRADED

            logger.exception(
                "runtime worker failed: %s",
                worker.name,
            )

            self._emit(
                "worker_failed",
                details={
                    "worker": worker.name,
                    "error_type": worker.error_type,
                },
            )

            return

        worker.state = WorkerState.STOPPED
        worker.stopped_monotonic = (
            time.monotonic()
        )

        self._emit(
            "worker_stopped",
            details={
                "worker": worker.name,
            },
        )

    def start(
        self,
    ) -> None:
        self._refresh_process_identity_if_forked()

        with self._lock:
            if self._state in {
                RuntimeState.STARTING,
                RuntimeState.ACTIVE,
            }:
                return

            if self._state is RuntimeState.STOPPING:
                raise RuntimeError(
                    "runtime cannot start while stopping"
                )

            self._stop_event.clear()
            self._state = RuntimeState.STARTING

            workers = tuple(
                self._workers.values()
            )

        self._emit(
            "runtime_starting"
        )

        for worker in workers:
            if worker.thread is not None:
                raise RuntimeError(
                    f"worker {worker.name!r} already has a thread"
                )

            thread = threading.Thread(
                target=self._run_worker,
                args=(
                    worker,
                ),
                name=worker.name,
                daemon=worker.daemon,
            )

            worker.thread = thread
            thread.start()

        with self._lock:
            if any(
                worker.state is WorkerState.FAILED
                for worker in workers
            ):
                self._state = RuntimeState.DEGRADED
            else:
                self._state = RuntimeState.ACTIVE

        self._emit(
            "runtime_started"
        )

    def stop(
        self,
    ) -> None:
        self._refresh_process_identity_if_forked()

        with self._lock:
            if self._state is RuntimeState.STOPPED:
                return

            self._state = RuntimeState.STOPPING
            self._stop_event.set()

            workers = tuple(
                self._workers.values()
            )

        self._emit(
            "runtime_stopping"
        )

        for worker in workers:
            thread = worker.thread

            if (
                thread is None
                or not thread.is_alive()
            ):
                continue

            thread.join(
                timeout=(
                    self._config.worker_join_timeout_seconds
                )
            )

        with self._lock:
            still_alive = tuple(
                worker.name
                for worker in workers
                if worker.is_alive()
            )

            self._state = (
                RuntimeState.DEGRADED
                if still_alive
                else RuntimeState.STOPPED
            )

        self._emit(
            "runtime_stopped"
            if not still_alive
            else "runtime_stop_incomplete",
            details={
                "alive_workers": still_alive,
            },
        )

    def stop_requested(
        self,
    ) -> bool:
        return self._stop_event.is_set()

    def wait_for_stop(
        self,
        timeout: float | None = None,
    ) -> bool:
        return self._stop_event.wait(
            timeout
        )

    def status(
        self,
    ) -> Mapping[str, Any]:
        self._refresh_process_identity_if_forked()

        with self._lock:
            workers = tuple(
                dict(
                    worker.status()
                )
                for worker
                in self._workers.values()
            )

            return MappingProxyType(
                {
                    "module_id": self._config.module_id,
                    "version": self._config.version,
                    "mode": self._config.mode,
                    "dry_run": self._config.dry_run,
                    "state": self._state.value,
                    "pid": self._pid,
                    "process_id": self._process_id,
                    "uptime_seconds": self.uptime_seconds(),
                    "worker_count": len(
                        self._workers
                    ),
                    "workers": workers,
                }
            )


__all__ = [
    "RuntimeConfig",
    "RuntimeEventSink",
    "RuntimeState",
    "RuntimeWorker",
    "SentinelRuntime",
    "WorkerState",
]
