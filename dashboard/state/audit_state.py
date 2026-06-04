"""
dashboard/state/audit_state.py

Audit state management for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class AuditState:
    """
    Stores dashboard audit data.
    """

    records: list[dict[str, Any]] = field(default_factory=list)
    last_updated: datetime | None = None
    error: str | None = None

    @property
    def total_records(self) -> int:
        """
        Return total audit records.
        """
        return len(self.records)

    def update(
        self,
        records: list[dict[str, Any]],
    ) -> None:
        """
        Update audit records.
        """

        self.records = records
        self.last_updated = datetime.utcnow()
        self.error = None

    def set_error(
        self,
        message: str,
    ) -> None:
        """
        Record an audit retrieval error.
        """

        self.error = message

    def clear(self) -> None:
        """
        Reset state.
        """

        self.records.clear()
        self.last_updated = None
        self.error = None


audit_state = AuditState()
