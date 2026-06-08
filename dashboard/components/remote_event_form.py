"""
Sentinel-43 Dashboard Component
Remote Event Form
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any


VALID_OPERATOR_ROLES = frozenset({"owner", "admin", "auditor"})

VALID_EVENT_TYPES = frozenset({
    "force_health_check",
    "force_sync",
    "rotate_remote_token",
    "request_diagnostic_snapshot",
})

REQUIRED_FIELDS = frozenset({
    "operator_id",
    "operator_role",
    "target_id",
    "event_type",
    "reason",
    "correlation_id",
})

CORRELATION_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")

MAX_PAYLOAD_BYTES = 4096
MIN_REASON_LENGTH = 20


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

    required_fields = REQUIRED_FIELDS

    def _require_string(
        self,
        value: Any,
        field_name: str,
        errors: list[str],
    ) -> str:
        if not isinstance(value, str):
            errors.append(f"{field_name} must be a string")
            return ""

        stripped = value.strip()

        if not stripped:
            errors.append(f"{field_name} is required")

        return stripped

    def _validate_and_clean(
        self,
        data: RemoteEventFormData,
    ) -> tuple[list[str], dict[str, Any] | None]:
        errors: list[str] = []

        operator_id = self._require_string(
            data.operator_id,
            "operator_id",
            errors,
        )
        operator_role = self._require_string(
            data.operator_role,
            "operator_role",
            errors,
        ).lower()
        target_id = self._require_string(
            data.target_id,
            "target_id",
            errors,
        )
        event_type = self._require_string(
            data.event_type,
            "event_type",
            errors,
        ).lower()
        reason = self._require_string(
            data.reason,
            "reason",
            errors,
        )
        correlation_id = self._require_string(
            data.correlation_id,
            "correlation_id",
            errors,
        )

        if operator_role and operator_role not in VALID_OPERATOR_ROLES:
            errors.append("operator_role must be owner, admin, or auditor")

        if event_type and event_type not in VALID_EVENT_TYPES:
            errors.append("event_type is not allowed")

        if reason and len(reason) < MIN_REASON_LENGTH:
            errors.append(
                f"reason must be at least {MIN_REASON_LENGTH} characters"
            )

        if correlation_id and not CORRELATION_ID_RE.fullmatch(correlation_id):
            errors.append(
                "correlation_id must be 8-64 alphanumeric, dash, or underscore characters"
            )

        if not isinstance(data.dry_run, bool):
            errors.append("dry_run must be a boolean")

        if not isinstance(data.payload, dict):
            errors.append("payload must be a dictionary")
            payload_copy: dict[str, Any] = {}
        else:
            payload_copy = copy.deepcopy(data.payload)

            try:
                payload_size = len(
                    json.dumps(
                        payload_copy,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ).encode("utf-8")
                )
            except (TypeError, ValueError):
                errors.append("payload must be JSON serializable")
                payload_size = 0

            if payload_size > MAX_PAYLOAD_BYTES:
                errors.append(
                    f"payload exceeds maximum allowed size of {MAX_PAYLOAD_BYTES} bytes"
                )

        if errors:
            return errors, None

        return errors, {
            "operator_id": operator_id,
            "operator_role": operator_role,
            "target_id": target_id,
            "event_type": event_type,
            "reason": reason,
            "correlation_id": correlation_id,
            "dry_run": data.dry_run,
            "payload": payload_copy,
        }

    def validate(self, data: RemoteEventFormData) -> list[str]:
        errors, _ = self._validate_and_clean(data)
        return errors

    def to_payload(self, data: RemoteEventFormData) -> dict[str, Any]:
        errors, payload = self._validate_and_clean(data)

        if errors:
            return {
                "ok": False,
                "errors": errors,
                "payload": None,
            }

        return {
            "ok": True,
            "errors": [],
            "payload": payload,
        }

    def empty(self) -> RemoteEventFormData:
        return RemoteEventFormData(
            operator_id="",
            operator_role="",
            target_id="",
            event_type="",
            reason="",
            correlation_id="",
            dry_run=True,
            payload={},
        )
