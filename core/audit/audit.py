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

"""Sentinel-43 non-authoritative JSONL audit mirror.

This module intentionally does NOT implement an independent audit ledger.

The authoritative local audit source is the SQLite/HMAC AuditStore. This
module exists only to serialize already-authoritative audit records to JSONL
for export, inspection, or operational tooling.

Security-sensitive code must not use this mirror as evidence of successful
audit persistence.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Final


logger = logging.getLogger(__name__)

MAX_RECORD_BYTES: Final[int] = 131_072
MAX_READ_LIMIT: Final[int] = 10_000


class AuditMirrorError(RuntimeError):
    """Base error for audit-mirror operations."""


class AuditMirrorPersistenceError(AuditMirrorError):
    """Raised when a JSONL mirror write fails in strict mode."""


class AuditMirrorFormatError(AuditMirrorError):
    """Raised when a mirrored record is malformed."""


class AuditMirrorEncoder(json.JSONEncoder):
    """JSON encoder matching supported audit payload value types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, Decimal):
            return str(obj)

        if isinstance(obj, datetime):
            if obj.tzinfo is None:
                raise TypeError(
                    "Naive datetime values are not permitted in audit records"
                )
            return obj.isoformat()

        return super().default(obj)


def _serialize_record(
    record: dict[str, Any],
) -> str:
    if not isinstance(record, dict):
        raise TypeError(
            "Audit mirror record must be a dictionary"
        )

    try:
        encoded = json.dumps(
            record,
            cls=AuditMirrorEncoder,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise AuditMirrorFormatError(
            "Audit mirror record is not JSON serializable"
        ) from exc

    if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
        raise AuditMirrorFormatError(
            f"Audit mirror record exceeds {MAX_RECORD_BYTES} bytes"
        )

    return encoded


class AuditJsonlMirror:
    """Best-effort JSONL mirror for authoritative audit records."""

    def __init__(
        self,
        path: str | Path,
        *,
        strict: bool = False,
    ) -> None:
        self.path = Path(path)
        self.strict = bool(strict)
        self._lock = threading.RLock()

    def ensure_parent_directory(self) -> None:
        """Create the mirror directory explicitly during startup."""
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def append(
        self,
        record: dict[str, Any],
    ) -> bool:
        """Append one already-authoritative audit record.

        Returns True on success. In non-strict mode, persistence failures are
        logged and return False. In strict mode they raise.
        """
        line = _serialize_record(
            dict(record)
        )

        with self._lock:
            try:
                self.ensure_parent_directory()

                with self.path.open(
                    "a",
                    encoding="utf-8",
                ) as mirror_file:
                    mirror_file.write(
                        line + "\n"
                    )
                    mirror_file.flush()
                    os.fsync(
                        mirror_file.fileno()
                    )

            except OSError as exc:
                if self.strict:
                    raise AuditMirrorPersistenceError(
                        f"Failed to append audit mirror record to {self.path}"
                    ) from exc

                logger.warning(
                    "Audit JSONL mirror write failed for %s",
                    self.path,
                    exc_info=True,
                )
                return False

        return True

    def read_recent(
        self,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Read recent mirrored records.

        This is operational convenience only. Returned records are not
        independently authenticated by this module.
        """
        if not 1 <= limit <= MAX_READ_LIMIT:
            raise ValueError(
                f"limit must be between 1 and {MAX_READ_LIMIT}"
            )

        if not self.path.exists():
            return []

        recent: deque[str] = deque(
            maxlen=limit
        )

        with self._lock:
            with self.path.open(
                "r",
                encoding="utf-8",
            ) as mirror_file:
                for line in mirror_file:
                    stripped = line.strip()

                    if stripped:
                        recent.append(
                            stripped
                        )

        records: list[dict[str, Any]] = []

        for line in recent:
            try:
                value = json.loads(
                    line
                )
            except json.JSONDecodeError as exc:
                raise AuditMirrorFormatError(
                    "Corrupt JSON encountered in audit mirror"
                ) from exc

            if not isinstance(
                value,
                dict,
            ):
                raise AuditMirrorFormatError(
                    "Audit mirror record is not a JSON object"
                )

            records.append(
                value
            )

        return records


__all__ = [
    "AuditJsonlMirror",
    "AuditMirrorEncoder",
    "AuditMirrorError",
    "AuditMirrorFormatError",
    "AuditMirrorPersistenceError",
]
