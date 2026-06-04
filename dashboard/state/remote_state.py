"""
dashboard/state/remote_state.py

Remote Gateway state management for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True)
class RemoteState:
    """
    Stores Remote Gateway status and event records.
    """

    status: str = "UNKNOWN"
    connection_status: str = "UNKNOWN"
    records: list[dict[str, Any]] = field(default_factory=list)

    last_submitted_event: dict[str, Any] | None = None
    last_updated: datetime | None = None
    error: str | None = None

    def update(
        self,
        *,
        status: str | None = None,
        connection_status: str | None = None,
        records: list[dict[str, Any]] | None = None,
    ) -> None:
        """
        Update Remote Gateway state.
        """

        if status is not None:
            self.status = status

        if connection_status is not None:
            self.connection_status = connection_status

        if records is not None:
            self.records = records

        self.last_updated = datetime.now(UTC)
        self.error = None

    def record_submission(
        self,
        payload: dict[str, Any],
    ) -> None:
        """
        Store last submitted remote event payload.
        """

        self.last_submitted_event = payload
        self.last_updated = datetime.now(UTC)

    def set_error(
        self,
        message: str,
    ) -> None:
        """
        Record Remote Gateway error state.
        """

        self.error = message
        self.last_updated = datetime.now(UTC)

    def clear(self) -> None:
        """
        Reset Remote Gateway state.
        """

        self.status = "UNKNOWN"
        self.connection_status = "UNKNOWN"
        self.records.clear()
        self.last_submitted_event = None
        self.last_updated = None
        self.error = None

    @property
    def total_records(self) -> int:
        """
        Return total remote records.
        """

        return len(self.records)

    @property
    def is_connected(self) -> bool:
        """
        Return whether Remote Gateway appears connected.
        """

        return self.connection_status.upper() in {
            "CONNECTED",
            "ONLINE",
            "ACTIVE",
        }


remote_state = RemoteState()
