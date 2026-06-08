"""
dashboard/state/audit_state.py

Audit state management for Sentinel-43 Dashboard.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any


DEFAULT_STALE_THRESHOLD = timedelta(minutes=5)
DEFAULT_MAX_RECORDS = 1000


@dataclass(slots=True)
class AuditState:
    """
    Stores dashboard audit data.

    REST snapshot behavior:
    - update() replaces the current record list.

    WebSocket incremental behavior:
    - append_record() adds a new audit record without wiping history.

    Error behavior:
    - Previous records are preserved as last-known-good data.
    - The error timestamp records when freshness became uncertain.
    """

    max_records: int = DEFAULT_MAX_RECORDS
    stale_threshold: timedelta = DEFAULT_STALE_THRESHOLD

    _records: list[dict[str, Any]] = field(
        default_factory=list,
        init=False,
        repr=False,
    )
    _last_updated: datetime | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _last_error_at: datetime | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _error: str | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _lock: RLock = field(
        default_factory=RLock,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.max_records, int):
            raise TypeError("max_records must be an integer")

        if self.max_records <= 0:
            raise ValueError("max_records must be greater than 0")

        if not isinstance(self.stale_threshold, timedelta):
            raise TypeError("stale_threshold must be a timedelta")

        if self.stale_threshold <= timedelta(seconds=0):
            raise ValueError("stale_threshold must be greater than 0")

    @property
    def records(self) -> list[dict[str, Any]]:
        """
        Return a defensive copy of the stored audit records.
        """
        with self._lock:
            return copy.deepcopy(self._records)

    @property
    def last_updated(self) -> datetime | None:
        """
        Return the last successful update timestamp.
        """
        with self._lock:
            return self._last_updated

    @property
    def last_error_at(self) -> datetime | None:
        """
        Return the timestamp of the most recent retrieval error.
        """
        with self._lock:
            return self._last_error_at

    @property
    def error(self) -> str | None:
        """
        Return the current retrieval error, if present.
        """
        with self._lock:
            return self._error

    @property
    def total_records(self) -> int:
        """
        Return the current record count.
        """
        with self._lock:
            return len(self._records)

    def update(
        self,
        records: list[dict[str, Any]],
    ) -> None:
        """
        Replace records from a complete REST snapshot.

        Do not use this method for a single WebSocket audit event.
        Use append_record() for incremental updates.
        """
        sanitized = self._validate_records(records)

        with self._lock:
            self._records = sanitized[: self.max_records]
            self._last_updated = datetime.now(timezone.utc)
            self._last_error_at = None
            self._error = None

    def append_record(
        self,
        record: dict[str, Any],
        *,
        newest_first: bool = True,
    ) -> None:
        """
        Store a single incremental audit record.

        Intended for WebSocket events or other streaming updates.
        """
        sanitized = self._validate_record(
            record,
            field_name="record",
        )

        with self._lock:
            if newest_first:
                self._records.insert(0, sanitized)

                if len(self._records) > self.max_records:
                    del self._records[self.max_records :]
            else:
                self._records.append(sanitized)

                if len(self._records) > self.max_records:
                    del self._records[: -self.max_records]

            self._last_updated = datetime.now(timezone.utc)
            self._last_error_at = None
            self._error = None

    def set_error(
        self,
        message: str,
        *,
        preserve_records: bool = True,
    ) -> None:
        """
        Record a retrieval error.

        By default, last-known-good records remain available while the
        serialized state marks them as potentially stale.
        """
        if not isinstance(message, str):
            raise TypeError("error message must be a string")

        cleaned = message.strip()

        if not cleaned:
            raise ValueError("error message must not be empty")

        now = datetime.now(timezone.utc)

        with self._lock:
            if not preserve_records:
                self._records = []

            self._error = cleaned
            self._last_error_at = now

    def is_stale(
        self,
        *,
        now: datetime | None = None,
        threshold: timedelta | None = None,
    ) -> bool:
        """
        Return True when the stored records are too old to trust.
        """
        current_time = now or datetime.now(timezone.utc)
        effective_threshold = threshold or self.stale_threshold

        if current_time.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        if effective_threshold <= timedelta(seconds=0):
            raise ValueError("threshold must be greater than 0")

        with self._lock:
            if self._last_updated is None:
                return True

            return current_time - self._last_updated > effective_threshold

    def clear(self, *, reason: str) -> None:
        """
        Reset state explicitly.

        The caller must provide a reason so a silent reset cannot happen
        accidentally during dashboard wiring.
        """
        if not isinstance(reason, str):
            raise TypeError("clear reason must be a string")

        if not reason.strip():
            raise ValueError("clear reason must not be empty")

        with self._lock:
            self._records = []
            self._last_updated = None
            self._last_error_at = None
            self._error = None

    def to_dict(self) -> dict[str, Any]:
        """
        Return a serialization-safe point-in-time snapshot.
        """
        with self._lock:
            records = copy.deepcopy(self._records)
            last_updated = self._last_updated
            last_error_at = self._last_error_at
            error = self._error

        return {
            "total_records": len(records),
            "last_updated": (
                last_updated.isoformat()
                if last_updated is not None
                else None
            ),
            "last_error_at": (
                last_error_at.isoformat()
                if last_error_at is not None
                else None
            ),
            "error": error,
            "is_stale": self.is_stale(),
            "records": records,
        }

    @staticmethod
    def _validate_records(
        records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not isinstance(records, list):
            raise TypeError(
                f"records must be a list, got {type(records).__name__}"
            )

        return [
            AuditState._validate_record(
                record,
                field_name=f"records[{index}]",
            )
            for index, record in enumerate(records)
        ]

    @staticmethod
    def _validate_record(
        record: dict[str, Any],
        *,
        field_name: str,
    ) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise TypeError(
                f"{field_name} must be a dictionary, "
                f"got {type(record).__name__}"
            )

        return copy.deepcopy(record)
