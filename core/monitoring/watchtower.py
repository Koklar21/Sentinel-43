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

"""SpartaCore file-integrity watchdog.

SpartaCore is an observational integrity component.

Responsibilities:
    - hash configured files
    - compare against expected SHA-256 digests
    - track bounded integrity events
    - expose current integrity state
    - run an explicit async watchdog loop
    - optionally emit coarse events through an injected sink

Non-responsibilities:
    - no FastAPI routes
    - no bearer-token auth
    - no client blocking/rate limiting
    - no session-token issuance
    - no environment reads
    - no signal registration
    - no background executors
    - no autonomous enforcement outside its own reported state
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


class SpartaState(StrEnum):
    INITIALIZING = "INITIALIZING"
    OPERATIONAL = "OPERATIONAL"
    DEGRADED = "DEGRADED"
    COMPROMISED = "COMPROMISED"
    SHUTDOWN = "SHUTDOWN"


@runtime_checkable
class IntegrityEventSink(Protocol):
    def emit(
        self,
        event: dict[str, Any],
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class IntegrityConfig:
    watched_files: Mapping[str, str]
    check_interval_seconds: float = 30.0
    max_event_log_entries: int = 1000

    def __post_init__(self) -> None:
        normalized: dict[str, str] = {}

        for path, digest in dict(
            self.watched_files
        ).items():
            clean_path = str(
                path
            ).strip()

            clean_digest = str(
                digest
            ).strip().lower()

            if not clean_path:
                raise ValueError(
                    "watched file path must not be empty"
                )

            if len(
                clean_digest
            ) != 64:
                raise ValueError(
                    f"expected SHA-256 digest for {clean_path!r} must be 64 hex characters"
                )

            try:
                int(
                    clean_digest,
                    16,
                )
            except ValueError as exc:
                raise ValueError(
                    f"expected digest for {clean_path!r} is not valid hexadecimal"
                ) from exc

            normalized[
                clean_path
            ] = clean_digest

        if not normalized:
            raise ValueError(
                "watched_files must not be empty"
            )

        if not 0.1 <= self.check_interval_seconds <= 86_400.0:
            raise ValueError(
                "check_interval_seconds must be between 0.1 and 86400"
            )

        if not 1 <= self.max_event_log_entries <= 100_000:
            raise ValueError(
                "max_event_log_entries must be between 1 and 100000"
            )

        object.__setattr__(
            self,
            "watched_files",
            MappingProxyType(
                normalized
            ),
        )


@dataclass(frozen=True, slots=True)
class IntegrityEvent:
    event_type: str
    file_path: str
    state_at_event: SpartaState
    details: Mapping[str, Any] = field(
        default_factory=dict
    )
    timestamp: str = field(
        default_factory=utc_now
    )

    def __post_init__(self) -> None:
        event_type = str(
            self.event_type
        ).strip()

        if not event_type:
            raise ValueError(
                "event_type must not be empty"
            )

        object.__setattr__(
            self,
            "event_type",
            event_type,
        )

        object.__setattr__(
            self,
            "file_path",
            str(
                self.file_path
            ).strip(),
        )

        object.__setattr__(
            self,
            "details",
            MappingProxyType(
                dict(
                    self.details
                )
            ),
        )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "file_path": self.file_path,
            "state_at_event": self.state_at_event.value,
            "details": dict(
                self.details
            ),
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class IntegrityCheckResult:
    ok: bool
    checked_files: int
    failed_files: tuple[str, ...]
    state: SpartaState


class SpartaCore:
    """Thread-safe file-integrity watchdog."""

    def __init__(
        self,
        config: IntegrityConfig,
        *,
        event_sink: IntegrityEventSink | None = None,
    ) -> None:
        self._config = config
        self._event_sink = event_sink

        self._state = SpartaState.INITIALIZING
        self._lock = threading.RLock()
        self._check_lock = threading.Lock()

        self._event_log: deque[
            IntegrityEvent
        ] = deque(
            maxlen=config.max_event_log_entries
        )

        self._tamper_count = 0
        self._total_checks = 0
        self._stop_requested = threading.Event()

    def _emit(
        self,
        event: IntegrityEvent,
    ) -> None:
        with self._lock:
            self._event_log.append(
                event
            )

        sink = self._event_sink

        if sink is None:
            return

        try:
            sink.emit(
                event.to_dict()
            )
        except Exception:
            return

    @staticmethod
    def _calculate_sha256(
        file_path: str,
    ) -> str | None:
        try:
            digest = hashlib.sha256()

            with open(
                file_path,
                "rb",
            ) as handle:
                for chunk in iter(
                    lambda: handle.read(
                        65_536
                    ),
                    b"",
                ):
                    digest.update(
                        chunk
                    )

            return digest.hexdigest()

        except OSError:
            return None

    def _set_state(
        self,
        state: SpartaState,
    ) -> None:
        with self._lock:
            self._state = state

    def check_integrity(
        self,
    ) -> IntegrityCheckResult:
        # Serialize full integrity scans. File I/O remains outside _lock so
        # status/event readers are not blocked, but two scans may not race
        # each other and apply stale state transitions out of order.
        with self._check_lock:
            with self._lock:
                self._total_checks += 1
                state_before = self._state

            failed_files: list[str] = []

            for (
                file_path,
                expected_hash,
            ) in self._config.watched_files.items():
                actual_hash = self._calculate_sha256(
                    file_path
                )

                if actual_hash is None:
                    failed_files.append(
                        file_path
                    )

                    self._emit(
                        IntegrityEvent(
                            event_type="FileUnavailable",
                            file_path=file_path,
                            state_at_event=state_before,
                            details={
                                "reason": "unreadable_or_missing"
                            },
                        )
                    )
                    continue

                if not secrets.compare_digest(
                    actual_hash,
                    expected_hash,
                ):
                    failed_files.append(
                        file_path
                    )

                    self._emit(
                        IntegrityEvent(
                            event_type="TamperDetected",
                            file_path=file_path,
                            state_at_event=state_before,
                            details={
                                "reason": "sha256_mismatch"
                            },
                        )
                    )

            if failed_files:
                with self._lock:
                    self._tamper_count += len(
                        failed_files
                    )
                    self._state = SpartaState.COMPROMISED

                self._emit(
                    IntegrityEvent(
                        event_type="IntegrityCompromised",
                        file_path="",
                        state_at_event=SpartaState.COMPROMISED,
                        details={
                            "failed_file_count": len(
                                failed_files
                            )
                        },
                    )
                )

                state = SpartaState.COMPROMISED

            else:
                with self._lock:
                    if self._state in {
                        SpartaState.INITIALIZING,
                        SpartaState.DEGRADED,
                    }:
                        self._state = SpartaState.OPERATIONAL

                    state = self._state

            return IntegrityCheckResult(
                ok=not failed_files,
                checked_files=len(
                    self._config.watched_files
                ),
                failed_files=tuple(
                    failed_files
                ),
                state=state,
            )

    def acknowledge_recovery(
        self,
        *,
        operator: str,
        reason: str,
    ) -> bool:
        """Allow a human/operator path to clear COMPROMISED after a clean check.

        This method changes only SpartaCore's reported state. It does not alter
        firewall, auth, routing, or any other subsystem.
        """
        normalized_operator = str(
            operator
        ).strip()

        normalized_reason = str(
            reason
        ).strip()

        if not normalized_operator:
            raise ValueError(
                "operator must not be empty"
            )

        if not normalized_reason:
            raise ValueError(
                "reason must not be empty"
            )

        result = self.check_integrity()

        if not result.ok:
            return False

        with self._lock:
            if self._state is not SpartaState.COMPROMISED:
                return False

            self._state = SpartaState.OPERATIONAL

        self._emit(
            IntegrityEvent(
                event_type="RecoveryAcknowledged",
                file_path="",
                state_at_event=SpartaState.OPERATIONAL,
                details={
                    "operator": normalized_operator,
                    "reason": normalized_reason,
                },
            )
        )

        return True

    async def run(
        self,
    ) -> None:
        with self._lock:
            if self._state is SpartaState.INITIALIZING:
                self._state = SpartaState.DEGRADED

        interval = self._config.check_interval_seconds

        while not self._stop_requested.is_set():
            await asyncio.to_thread(
                self.check_integrity
            )

            deadline = (
                time.monotonic()
                + interval
            )

            while (
                not self._stop_requested.is_set()
                and time.monotonic()
                < deadline
            ):
                await asyncio.sleep(
                    min(
                        1.0,
                        max(
                            0.0,
                            deadline
                            - time.monotonic(),
                        ),
                    )
                )

        self._set_state(
            SpartaState.SHUTDOWN
        )

    def stop(
        self,
    ) -> None:
        self._stop_requested.set()

    def get_status(
        self,
    ) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self._state.value,
                "watched_file_count": len(
                    self._config.watched_files
                ),
                "total_checks": self._total_checks,
                "tamper_count": self._tamper_count,
                "event_log_entries": len(
                    self._event_log
                ),
            }

    def get_public_health(
        self,
    ) -> dict[str, str]:
        with self._lock:
            operational = (
                self._state
                is SpartaState.OPERATIONAL
            )

        return {
            "status": (
                "ok"
                if operational
                else "degraded"
            )
        }

    def get_event_log(
        self,
        *,
        limit: int = 50,
    ) -> tuple[
        dict[str, Any],
        ...
    ]:
        bounded_limit = max(
            1,
            min(
                int(
                    limit
                ),
                500,
            ),
        )

        with self._lock:
            return tuple(
                event.to_dict()
                for event in list(
                    self._event_log
                )[
                    -bounded_limit:
                ]
            )


__all__ = [
    "IntegrityCheckResult",
    "IntegrityConfig",
    "IntegrityEvent",
    "IntegrityEventSink",
    "SpartaCore",
    "SpartaState",
]
