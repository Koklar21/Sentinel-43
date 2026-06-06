# =============================================================================
# Sentinel-43 Audit Module
# File: audit/audit.py
#
# Purpose:
#   Provides structured audit event creation, validation, and local persistence.
#
# Design:
#   - Simple JSONL audit log support
#   - Stable event schema
#   - Optional metadata
#   - UTC timestamps
#   - Safe append-only behavior
# =============================================================================

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


AuditMetadata = Dict[str, Any]


@dataclass(frozen=True)
class AuditEvent:
    """
    Represents a single Sentinel-43 audit event.
    """

    event_id: str
    timestamp: str
    actor: str
    action: str
    target: str
    status: str
    message: str
    metadata: AuditMetadata = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)


class AuditLogger:
    """
    Append-only JSONL audit logger.

    Each line in the audit file is one JSON object.
    Because apparently civilization still needs logs to prove
    the machine did the thing it said it did.
    """

    def __init__(self, log_path: str | Path = "audit/audit.log") -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def create_event(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        status: str = "success",
        message: str = "",
        metadata: Optional[AuditMetadata] = None,
    ) -> AuditEvent:
        """
        Create a structured audit event.
        """

        return AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            target=target,
            status=status,
            message=message,
            metadata=metadata or {},
        )

    def write_event(self, event: AuditEvent) -> AuditEvent:
        """
        Write an audit event to disk.
        """

        with self.log_path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(event.to_json() + "\n")

        return event

    def log(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        status: str = "success",
        message: str = "",
        metadata: Optional[AuditMetadata] = None,
    ) -> AuditEvent:
        """
        Create and write an audit event in one call.
        """

        event = self.create_event(
            actor=actor,
            action=action,
            target=target,
            status=status,
            message=message,
            metadata=metadata,
        )

        return self.write_event(event)

    def read_events(self, limit: int = 100) -> list[Dict[str, Any]]:
        """
        Read recent audit events from the audit log.
        """

        if not self.log_path.exists():
            return []

        with self.log_path.open("r", encoding="utf-8") as audit_file:
            lines = audit_file.readlines()

        recent_lines = lines[-limit:]

        events: list[Dict[str, Any]] = []

        for line in recent_lines:
            line = line.strip()
            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append(
                    {
                        "event_id": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "actor": "audit-system",
                        "action": "read_corrupt_event",
                        "target": str(self.log_path),
                        "status": "warning",
                        "message": "Corrupt audit log line detected.",
                        "metadata": {"raw_line": line},
                    }
                )

        return events


default_audit_logger = AuditLogger()


def audit_event(
    *,
    actor: str,
    action: str,
    target: str,
    status: str = "success",
    message: str = "",
    metadata: Optional[AuditMetadata] = None,
) -> AuditEvent:
    """
    Convenience function for writing audit events without manually creating
    an AuditLogger instance.
    """

    return default_audit_logger.log(
        actor=actor,
        action=action,
        target=target,
        status=status,
        message=message,
        metadata=metadata,
    )
