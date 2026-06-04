"""
Sentinel-43 Dashboard Component
Audit Table
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class AuditEntry:
    audit_id: str
    timestamp: str
    actor: str
    action: str
    target: str
    result: str
    correlation_id: str
    metadata: dict[str, Any] = field(default_factory=dict)


class AuditTable:
    """
    Dashboard audit table manager.

    Tracks:
    - Remote Gateway audit events
    - Watchtower events
    - operator actions
    - system state changes
    """

    def __init__(self, max_entries: int = 1000) -> None:
        self.max_entries = max_entries
        self._entries: list[AuditEntry] = []

    def add_entry(
        self,
        *,
        audit_id: str,
        actor: str,
        action: str,
        target: str,
        result: str,
        correlation_id: str,
        metadata: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            audit_id=audit_id,
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            target=target,
            result=result,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )

        self._entries.insert(0, entry)

        if len(self._entries) > self.max_entries:
            self._entries = self._entries[: self.max_entries]

        return entry

    def get_entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def find_by_correlation_id(self, correlation_id: str) -> list[AuditEntry]:
        return [
            entry
            for entry in self._entries
            if entry.correlation_id == correlation_id
        ]

    def clear(self) -> None:
        self._entries.clear()

    def count(self) -> int:
        return len(self._entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_count": len(self._entries),
            "entries": [
                {
                    "audit_id": entry.audit_id,
                    "timestamp": entry.timestamp,
                    "actor": entry.actor,
                    "action": entry.action,
                    "target": entry.target,
                    "result": entry.result,
                    "correlation_id": entry.correlation_id,
                    "metadata": entry.metadata,
                }
                for entry in self._entries
            ],
        }


audit_table = AuditTable()
