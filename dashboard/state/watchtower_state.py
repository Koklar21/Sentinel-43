"""
dashboard/state/watchtower_state.py

Watchtower state management for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True)
class WatchtowerState:
    """
    Stores Watchtower dashboard status.
    """

    overall_status: str = "UNKNOWN"
    tower_count: int = 0
    degraded_towers: int = 0
    active_alerts: int = 0

    towers: list[dict[str, Any]] = field(default_factory=list)

    last_updated: datetime | None = None
    error: str | None = None

    def update(
        self,
        *,
        overall_status: str | None = None,
        tower_count: int | None = None,
        degraded_towers: int | None = None,
        active_alerts: int | None = None,
        towers: list[dict[str, Any]] | None = None,
    ) -> None:
        """
        Update Watchtower state.
        """

        if overall_status is not None:
            self.overall_status = overall_status

        if tower_count is not None:
            self.tower_count = tower_count

        if degraded_towers is not None:
            self.degraded_towers = degraded_towers

        if active_alerts is not None:
            self.active_alerts = active_alerts

        if towers is not None:
            self.towers = towers

        self.last_updated = datetime.now(UTC)
        self.error = None

    def set_error(self, message: str) -> None:
        """
        Record Watchtower error state.
        """

        self.error = message
        self.last_updated = datetime.now(UTC)

    def clear(self) -> None:
        """
        Reset Watchtower state.
        """

        self.overall_status = "UNKNOWN"
        self.tower_count = 0
        self.degraded_towers = 0
        self.active_alerts = 0
        self.towers.clear()
        self.last_updated = None
        self.error = None

    @property
    def is_healthy(self) -> bool:
        """
        Return whether Watchtower appears healthy.
        """

        return (
            self.overall_status.upper() in {"ACTIVE", "ONLINE", "HEALTHY"}
            and self.degraded_towers == 0
            and self.active_alerts == 0
        )


watchtower_state = WatchtowerState()
