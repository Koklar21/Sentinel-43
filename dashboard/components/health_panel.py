"""
Sentinel-43 Dashboard Component
Health Panel
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any


VALID_STATUSES = frozenset({
    "ok",
    "degraded",
    "warning",
    "error",
    "failed",
    "offline",
    "unknown",
})

STALE_THRESHOLD = timedelta(minutes=5)
HISTORY_LIMIT = 25


@dataclass(frozen=True, slots=True)
class HealthCheck:
    name: str
    status: str
    message: str
    timestamp: datetime
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class HealthTransition:
    name: str
    previous_status: str | None
    new_status: str
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "timestamp": self.timestamp.isoformat(),
        }


class HealthPanel:
    """
    Dashboard health panel manager.

    Tracks:
    - API health
    - Watchtower health
    - Remote Gateway health
    - dependency status
    - readiness state
    """

    def __init__(
        self,
        *,
        stale_threshold: timedelta = STALE_THRESHOLD,
        history_limit: int = HISTORY_LIMIT,
    ) -> None:
        if stale_threshold <= timedelta(seconds=0):
            raise ValueError("stale_threshold must be greater than 0")

        if history_limit <= 0:
            raise ValueError("history_limit must be greater than 0")

        self._checks: dict[str, HealthCheck] = {}
        self._history: deque[HealthTransition] = deque(maxlen=history_limit)
        self._stale_threshold = stale_threshold
        self._cached_overall_status: str | None = None

    def update_check(
        self,
        *,
        name: str,
        status: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> HealthCheck:
        normalized_name = name.strip()
        normalized_status = status.lower().strip()
        normalized_message = message.strip()

        if not normalized_name:
            raise ValueError("name must not be empty")

        if not normalized_message:
            raise ValueError("message must not be empty")

        if normalized_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status!r}")

        previous = self._checks.get(normalized_name)
        now = datetime.now(timezone.utc)

        check = HealthCheck(
            name=normalized_name,
            status=normalized_status,
            message=normalized_message,
            timestamp=now,
            details=dict(details) if details else {},
        )

        self._checks[normalized_name] = check

        if previous is None or previous.status != normalized_status:
            self._history.appendleft(
                HealthTransition(
                    name=normalized_name,
                    previous_status=previous.status if previous else None,
                    new_status=normalized_status,
                    timestamp=now,
                )
            )

        self._cached_overall_status = None
        return check

    def get_check(self, name: str) -> HealthCheck | None:
        check = self._checks.get(name.strip())

        if check is None:
            return None

        return replace(check, details=dict(check.details))

    def get_checks(self) -> list[HealthCheck]:
        return [
            replace(check, details=dict(check.details))
            for check in self._checks.values()
        ]

    def get_history(self) -> list[HealthTransition]:
        return list(self._history)

    def overall_status(self) -> str:
        if self._cached_overall_status is not None:
            return self._cached_overall_status

        if not self._checks:
            self._cached_overall_status = "unknown"
            return self._cached_overall_status

        now = datetime.now(timezone.utc)
        statuses: set[str] = set()

        for check in self._checks.values():
            age = now - check.timestamp

            if age > self._stale_threshold:
                statuses.add("unknown")
            else:
                statuses.add(check.status)

        if statuses.intersection({"failed", "error", "offline"}):
            self._cached_overall_status = "error"
        elif statuses.intersection({"degraded", "warning", "unknown"}):
            self._cached_overall_status = "warning"
        else:
            self._cached_overall_status = "ok"

        return self._cached_overall_status

    def clear(self, *, reason: str) -> None:
        if not reason or not reason.strip():
            raise ValueError("clear reason must not be empty")

        self._checks.clear()
        self._history.appendleft(
            HealthTransition(
                name="__health_panel__",
                previous_status=None,
                new_status="unknown",
                timestamp=datetime.now(timezone.utc),
            )
        )
        self._cached_overall_status = None

    def count(self) -> int:
        return len(self._checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status(),
            "check_count": len(self._checks),
            "checks": [
                check.to_dict()
                for check in self._checks.values()
            ],
            "history": [
                transition.to_dict()
                for transition in self._history
            ],
        }
