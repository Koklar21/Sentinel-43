"""
Sentinel-43 Dashboard Component
Health Panel
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class HealthCheck:
    name: str
    status: str
    message: str
    timestamp: str
    details: dict[str, Any] = field(default_factory=dict)


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

    def __init__(self) -> None:
        self._checks: dict[str, HealthCheck] = {}

    def update_check(
        self,
        *,
        name: str,
        status: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> HealthCheck:
        check = HealthCheck(
            name=name,
            status=status,
            message=message,
            timestamp=datetime.now(timezone.utc).isoformat(),
            details=details or {},
        )

        self._checks[name] = check
        return check

    def get_check(self, name: str) -> HealthCheck | None:
        return self._checks.get(name)

    def get_checks(self) -> list[HealthCheck]:
        return list(self._checks.values())

    def overall_status(self) -> str:
        if not self._checks:
            return "unknown"

        statuses = {check.status.lower() for check in self._checks.values()}

        if "failed" in statuses or "error" in statuses or "offline" in statuses:
            return "error"

        if "degraded" in statuses or "warning" in statuses or "unknown" in statuses:
            return "warning"

        return "ok"

    def clear(self) -> None:
        self._checks.clear()

    def count(self) -> int:
        return len(self._checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status(),
            "check_count": len(self._checks),
            "checks": [
                {
                    "name": check.name,
                    "status": check.status,
                    "message": check.message,
                    "timestamp": check.timestamp,
                    "details": check.details,
                }
                for check in self._checks.values()
            ],
        }


health_panel = HealthPanel()
