# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 local tamper-evident audit ledger.

This module provides:
    - a stable structured audit event schema
    - append-only JSONL persistence
    - per-record SHA-256 hash chaining
    - bounded metadata
    - explicit integrity verification
    - no filesystem mutation at import time

The hash chain is tamper-evident, not tamper-proof. Stronger guarantees require
an external append-only or signed audit sink.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final


AuditMetadata = dict[str, Any]

MAX_ACTOR_LEN: Final[int] = 256
MAX_ACTION_LEN: Final[int] = 256
MAX_TARGET_LEN: Final[int] = 512
MAX_STATUS_LEN: Final[int] = 64
MAX_MESSAGE_LEN: Final[int] = 4096
MAX_METADATA_KEYS: Final[int] = 128
MAX_METADATA_BYTES: Final[int] = 16_384
MAX_READ_LIMIT: Final[int] = 10_000

GENESIS_HASH: Final[str] = "0" * 64

_ALLOWED_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "success",
        "failure",
        "denied",
        "warning",
        "error",
        "pending",
    }
)


class AuditError(RuntimeError):
    """Base error for Sentinel-43 local audit operations."""


class AuditIntegrityError(AuditError):
    """Raised when the local audit chain is malformed or inconsistent."""


class AuditPersistenceError(AuditError):
    """Raised when an audit record cannot be durably appended."""


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _validate_text(
    name: str,
    value: str,
    *,
    minimum: int,
    maximum: int,
) -> str:
    cleaned = str(value).strip()

    if not minimum <= len(cleaned) <= maximum:
        raise ValueError(
            f"{name} length must be between {minimum} and {maximum}"
        )

    if any(ord(char) < 32 and char not in {"\t"} for char in cleaned):
        raise ValueError(
            f"{name} contains unsupported control characters"
        )

    return cleaned


def _validate_metadata(
    metadata: AuditMetadata | None,
) -> AuditMetadata:
    value = dict(metadata or {})

    if len(value) > MAX_METADATA_KEYS:
        raise ValueError(
            f"metadata may contain at most {MAX_METADATA_KEYS} keys"
        )

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "metadata must be JSON serializable"
        ) from exc

    if len(encoded) > MAX_METADATA_BYTES:
        raise ValueError(
            f"metadata exceeds {MAX_METADATA_BYTES} bytes"
        )

    return value


def _canonical_record_bytes(
    record: dict[str, Any],
) -> bytes:
    data = dict(record)
    data.pop("record_hash", None)

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _compute_record_hash(
    record: dict[str, Any],
) -> str:
    return hashlib.sha256(
        _canonical_record_bytes(record)
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Single Sentinel-43 audit record."""

    event_id: str
    timestamp: str
    actor: str
    action: str
    target: str
    status: str
    message: str
    metadata: AuditMetadata = field(
        default_factory=dict
    )
    previous_hash: str = GENESIS_HASH
    record_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )


@dataclass(frozen=True, slots=True)
class AuditVerificationResult:
    valid: bool
    records_checked: int
    last_hash: str
    error_line: int | None = None
    error: str | None = None


class AuditLogger:
    """Append-only local JSONL audit ledger with hash chaining."""

    def __init__(
        self,
        log_path: str | Path = "audit/audit.log",
    ) -> None:
        self.log_path = Path(log_path)
        self._lock = threading.RLock()

    def ensure_parent_directory(self) -> None:
        """Create the audit directory explicitly during application startup."""
        self.log_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def create_event(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        status: str = "success",
        message: str = "",
        metadata: AuditMetadata | None = None,
        previous_hash: str = GENESIS_HASH,
    ) -> AuditEvent:
        actor_clean = _validate_text(
            "actor",
            actor,
            minimum=1,
            maximum=MAX_ACTOR_LEN,
        )
        action_clean = _validate_text(
            "action",
            action,
            minimum=1,
            maximum=MAX_ACTION_LEN,
        )
        target_clean = _validate_text(
            "target",
            target,
            minimum=1,
            maximum=MAX_TARGET_LEN,
        )

        status_clean = str(status).strip().lower()
        if status_clean not in _ALLOWED_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(_ALLOWED_STATUSES)}"
            )

        message_clean = str(message).strip()
        if len(message_clean) > MAX_MESSAGE_LEN:
            raise ValueError(
                f"message may contain at most {MAX_MESSAGE_LEN} characters"
            )

        metadata_clean = _validate_metadata(
            metadata
        )

        if (
            len(previous_hash) != 64
            or any(
                char not in "0123456789abcdef"
                for char in previous_hash.lower()
            )
        ):
            raise ValueError(
                "previous_hash must be a 64-character hex digest"
            )

        draft = {
            "event_id": str(uuid.uuid4()),
            "timestamp": utc_now_iso(),
            "actor": actor_clean,
            "action": action_clean,
            "target": target_clean,
            "status": status_clean,
            "message": message_clean,
            "metadata": metadata_clean,
            "previous_hash": previous_hash.lower(),
        }

        record_hash = _compute_record_hash(
            draft
        )

        return AuditEvent(
            **draft,
            record_hash=record_hash,
        )

    def _last_hash_unlocked(self) -> str:
        if not self.log_path.exists():
            return GENESIS_HASH

        last_nonempty: str | None = None

        with self.log_path.open(
            "r",
            encoding="utf-8",
        ) as audit_file:
            for line in audit_file:
                if line.strip():
                    last_nonempty = line

        if last_nonempty is None:
            return GENESIS_HASH

        try:
            record = json.loads(
                last_nonempty
            )
        except json.JSONDecodeError as exc:
            raise AuditIntegrityError(
                "Last audit record is not valid JSON"
            ) from exc

        record_hash = str(
            record.get("record_hash") or ""
        )

        if (
            len(record_hash) != 64
            or _compute_record_hash(record) != record_hash
        ):
            raise AuditIntegrityError(
                "Last audit record failed integrity validation"
            )

        return record_hash

    def write_event(
        self,
        event: AuditEvent,
    ) -> AuditEvent:
        """Append an event after binding it to the current ledger head."""

        with self._lock:
            self.ensure_parent_directory()

            previous_hash = (
                self._last_hash_unlocked()
            )

            bound_event = self.create_event(
                actor=event.actor,
                action=event.action,
                target=event.target,
                status=event.status,
                message=event.message,
                metadata=event.metadata,
                previous_hash=previous_hash,
            )

            # Preserve the caller-generated event id/timestamp while rebuilding
            # the hash against the authoritative previous ledger hash.
            record = bound_event.to_dict()
            record["event_id"] = event.event_id
            record["timestamp"] = event.timestamp
            record["record_hash"] = _compute_record_hash(
                record
            )

            final_event = AuditEvent(
                **record
            )

            try:
                with self.log_path.open(
                    "a",
                    encoding="utf-8",
                ) as audit_file:
                    audit_file.write(
                        final_event.to_json()
                        + "\n"
                    )
                    audit_file.flush()
            except OSError as exc:
                raise AuditPersistenceError(
                    f"Failed to append audit event to {self.log_path}"
                ) from exc

            return final_event

    def log(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        status: str = "success",
        message: str = "",
        metadata: AuditMetadata | None = None,
    ) -> AuditEvent:
        event = self.create_event(
            actor=actor,
            action=action,
            target=target,
            status=status,
            message=message,
            metadata=metadata,
        )

        return self.write_event(
            event
        )

    def read_events(
        self,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= MAX_READ_LIMIT:
            raise ValueError(
                f"limit must be between 1 and {MAX_READ_LIMIT}"
            )

        if not self.log_path.exists():
            return []

        with self._lock:
            recent: deque[str] = deque(
                maxlen=limit
            )

            with self.log_path.open(
                "r",
                encoding="utf-8",
            ) as audit_file:
                for line in audit_file:
                    stripped = line.strip()
                    if stripped:
                        recent.append(
                            stripped
                        )

        events: list[dict[str, Any]] = []

        for line in recent:
            try:
                record = json.loads(
                    line
                )
            except json.JSONDecodeError as exc:
                raise AuditIntegrityError(
                    "Corrupt JSON encountered in audit ledger"
                ) from exc

            events.append(
                record
            )

        return events

    def verify_integrity(
        self,
    ) -> AuditVerificationResult:
        if not self.log_path.exists():
            return AuditVerificationResult(
                valid=True,
                records_checked=0,
                last_hash=GENESIS_HASH,
            )

        expected_previous = GENESIS_HASH
        records_checked = 0

        with self._lock:
            with self.log_path.open(
                "r",
                encoding="utf-8",
            ) as audit_file:
                for line_number, line in enumerate(
                    audit_file,
                    start=1,
                ):
                    if not line.strip():
                        continue

                    try:
                        record = json.loads(
                            line
                        )
                    except json.JSONDecodeError:
                        return AuditVerificationResult(
                            valid=False,
                            records_checked=records_checked,
                            last_hash=expected_previous,
                            error_line=line_number,
                            error="invalid_json",
                        )

                    previous_hash = str(
                        record.get(
                            "previous_hash"
                        )
                        or ""
                    )
                    record_hash = str(
                        record.get(
                            "record_hash"
                        )
                        or ""
                    )

                    if previous_hash != expected_previous:
                        return AuditVerificationResult(
                            valid=False,
                            records_checked=records_checked,
                            last_hash=expected_previous,
                            error_line=line_number,
                            error="previous_hash_mismatch",
                        )

                    calculated = _compute_record_hash(
                        record
                    )

                    if not secrets_compare_digest(
                        calculated,
                        record_hash,
                    ):
                        return AuditVerificationResult(
                            valid=False,
                            records_checked=records_checked,
                            last_hash=expected_previous,
                            error_line=line_number,
                            error="record_hash_mismatch",
                        )

                    expected_previous = record_hash
                    records_checked += 1

        return AuditVerificationResult(
            valid=True,
            records_checked=records_checked,
            last_hash=expected_previous,
        )


def secrets_compare_digest(
    left: str,
    right: str,
) -> bool:
    # Local import keeps the module surface focused and avoids another global
    # name solely for a tiny integrity helper.
    import secrets

    return secrets.compare_digest(
        left,
        right,
    )


_default_audit_logger: AuditLogger | None = None
_default_lock = threading.Lock()


def get_default_audit_logger() -> AuditLogger:
    global _default_audit_logger

    if _default_audit_logger is None:
        with _default_lock:
            if _default_audit_logger is None:
                _default_audit_logger = AuditLogger()

    return _default_audit_logger


def audit_event(
    *,
    actor: str,
    action: str,
    target: str,
    status: str = "success",
    message: str = "",
    metadata: AuditMetadata | None = None,
) -> AuditEvent:
    return get_default_audit_logger().log(
        actor=actor,
        action=action,
        target=target,
        status=status,
        message=message,
        metadata=metadata,
    )


__all__ = [
    "AuditError",
    "AuditEvent",
    "AuditIntegrityError",
    "AuditLogger",
    "AuditMetadata",
    "AuditPersistenceError",
    "AuditVerificationResult",
    "audit_event",
    "get_default_audit_logger",
]
