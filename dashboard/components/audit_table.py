"""
Sentinel-43 Dashboard Component
Audit Table
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Deque


VALID_RESULTS = frozenset({"success", "failure", "denied", "error"})


@dataclass(frozen=True, slots=True)
class AuditEntry:
    audit_id: str
    timestamp: datetime
    actor: str
    action: str
    target: str
    result: str
    correlation_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "result": self.result,
            "correlation_id": self.correlation_id,
            "metadata": dict(self.metadata),
        }


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
        if max_entries <= 0:
            raise ValueError("max_entries must be greater than 0")

        self.max_entries = max_entries
        self._entries: Deque[AuditEntry] = deque(maxlen=max_entries)
        self._audit_ids: set[str] = set()
        self._by_correlation: dict[str, list[AuditEntry]] = {}

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
    ) -> AuditEntry:
        result = result.lower().strip()

        if result not in VALID_RESULTS:
            raise ValueError(f"Invalid result: {result!r}")

        if audit_id in self._audit_ids:
            raise ValueError(f"Duplicate audit_id: {audit_id!r}")

        for field_name, value in (
            ("audit_id", audit_id),
            ("actor", actor),
            ("action", action),
            ("target", target),
            ("correlation_id", correlation_id),
        ):
            if not value or not value.strip():
                raise ValueError(f"{field_name} must not be empty")

        if len(self._entries) == self.max_entries:
            oldest = self._entries[-1]
            self._audit_ids.discard(oldest.audit_id)

            bucket = self._by_correlation.get(oldest.correlation_id)
            if bucket is not None:
                self._by_correlation[oldest.correlation_id] = [
                    entry
                    for entry in bucket
                    if entry.audit_id != oldest.audit_id
                ]

                if not self._by_correlation[oldest.correlation_id]:
                    del self._by_correlation[oldest.correlation_id]

        entry = AuditEntry(
            audit_id=audit_id,
            timestamp=datetime.now(timezone.utc),
            actor=actor.strip(),
            action=action.strip(),
            target=target.strip(),
            result=result,
            correlation_id=correlation_id.strip(),
            metadata=dict(metadata) if metadata else {},
        )

        self._entries.appendleft(entry)
        self._audit_ids.add(entry.audit_id)
        self._by_correlation.setdefault(entry.correlation_id, []).insert(0, entry)

        return entry

    def get_entries(self) -> list[AuditEntry]:
        return [
            replace(entry, metadata=dict(entry.metadata))
            for entry in self._entries
        ]

    def find_by_correlation_id(self, correlation_id: str) -> list[AuditEntry]:
        key = correlation_id.strip()

        return [
            replace(entry, metadata=dict(entry.metadata))
            for entry in self._by_correlation.get(key, [])
        ]

    def clear(self, *, reason: str) -> None:
        if not reason or not reason.strip():
            raise ValueError("clear reason must not be empty")

        self._entries.clear()
        self._audit_ids.clear()
        self._by_correlation.clear()

    def count(self) -> int:
        return len(self._entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_count": len(self._entries),
            "entries": [
                entry.to_dict()
                for entry in self._entries
            ],
        }
