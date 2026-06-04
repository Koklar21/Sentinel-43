"""
dashboard/state/health_state.py

Health monitoring state for Sentinel-43 Dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(slots=True)
class HealthState:
    """
    Stores system health information.
    """

    api_status: str = "UNKNOWN"
    ready_status: str = "UNKNOWN"

    database_status: str = "UNKNOWN"
    redis_status: str = "UNKNOWN"

    dependencies: dict[str, Any] = field(default_factory=dict)

    last_updated: datetime | None = None
    error: str | None = None

    def update(
        self,
        *,
        api_status: str | None = None,
        ready_status: str | None = None,
        database_status: str | None = None,
        redis_status: str | None = None,
        dependencies: dict[str, Any] | None = None,
    ) -> None:
        """
        Update health state.
        """

        if api_status is not None:
            self.api_status = api_status

        if ready_status is not None:
            self.ready_status = ready_status

        if database_status is not None:
            self.database_status = database_status

        if redis_status is not None:
            self.redis_status = redis_status

        if dependencies is not None:
            self.dependencies = dependencies

        self.last_updated = datetime.now(UTC)
        self.error = None

    def set_error(
        self,
        message: str,
    ) -> None:
        """
        Record health-related error.
        """

        self.error = message
        self.last_updated = datetime.now(UTC)

    def clear(self) -> None:
        """
        Reset health state.
        """

        self.api_status = "UNKNOWN"
        self.ready_status = "UNKNOWN"

        self.database_status = "UNKNOWN"
        self.redis_status = "UNKNOWN"

        self.dependencies.clear()

        self.last_updated = None
        self.error = None

    @property
    def is_healthy(self) -> bool:
        """
        Determine if the system appears healthy.
        """

        unhealthy_states = {
            "FAILED",
            "OFFLINE",
            "ERROR",
            "CRITICAL",
            "DEGRADED",
        }

        statuses = {
            self.api_status.upper(),
            self.ready_status.upper(),
            self.database_status.upper(),
            self.redis_status.upper(),
        }

        return not bool(statuses & unhealthy_states)


health_state = HealthState()
