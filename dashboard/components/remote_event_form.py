"""
Sentinel-43 Dashboard Component
Remote Event Form
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RemoteEventFormData:
    operator_id: str
    operator_role: str
    target_id: str
    event_type: str
    reason: str
    correlation_id: str
    dry_run: bool = True
    payload: dict[str, Any] = field(default_factory=dict)


class RemoteEventForm:
    """
    Dashboard-side remote event form helper.

    This does NOT authorize the action.
    The backend Remote Gateway owns authorization, validation, and audit logging.
    """

    required_fields = {
        "operator_id",
        "operator_role",
        "target_id",
        "event_type",
        "reason",
        "correlation_id",
    }

    def validate(self, data: RemoteEventFormData) -> list[str]:
        errors: list[str] = []

        if not data.operator_id.strip():
            errors.append("operator_id is required")

        if data.operator_role not in {"owner", "admin", "auditor"}:
            errors.append("operator_role must be owner, admin, or auditor")

        if not data.target_id.strip():
            errors.append("target_id is required")

        if data.event_type not in {
            "force_health_check",
            "force_sync",
            "rotate_remote_token",
            "request_diagnostic_snapshot",
        }:
            errors.append("event_type is not allowed")

        if len(data.reason.strip()) < 10:
            errors.append("reason must be at least 10 characters")

        if len(data.correlation_id.strip()) < 8:
            errors.append("correlation_id must be at least 8 characters")

        if not isinstance(data.payload, dict):
            errors.append("payload must be a dictionary")

        return errors

    def to_payload(self, data: RemoteEventFormData) -> dict[str, Any]:
        errors = self.validate(data)

        if errors:
            return {
                "ok": False,
                "errors": errors,
                "payload": None,
            }

        return {
            "ok": True,
            "errors": [],
            "payload": {
                "operator_id": data.operator_id.strip(),
                "operator_role": data.operator_role.strip(),
                "target_id": data.target_id.strip(),
                "event_type": data.event_type.strip(),
                "reason": data.reason.strip(),
                "correlation_id": data.correlation_id.strip(),
                "dry_run": data.dry_run,
                "payload": data.payload,
            },
        }

    def empty(self) -> RemoteEventFormData:
        return RemoteEventFormData(
            operator_id="",
            operator_role="auditor",
            target_id="",
            event_type="request_diagnostic_snapshot",
            reason="",
            correlation_id="",
            dry_run=True,
            payload={},
        )


remote_event_form = RemoteEventForm()
