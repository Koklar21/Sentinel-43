# =============================================================================

# Sentinel-43

#

# Copyright (c) 2026 Justin Armstrong

# All Rights Reserved.

#

# This file is part of the Sentinel-43 platform and constitutes original

# intellectual property of the copyright holder.

#

# Sentinel-43 is distributed under a dual-license model:

#

# 1. GNU Affero General Public License (AGPL v3.0)

# for open-source use, modification, and distribution.

#

# 2. Commercial License

# for proprietary, enterprise, government, or other commercial use

# not permitted under the AGPL v3.0.

#

# Unauthorized copying, redistribution, relicensing, reverse engineering,

# or commercial exploitation outside the terms of the applicable license

# is strictly prohibited.

#

# By accessing, modifying, distributing, or using this software, you agree

# to comply with the terms of the applicable license.

#

# License Information:

# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html

#

# Commercial Licensing:

# Contact the copyright holder for commercial licensing terms.

#

# Sentinel-43™

# Original Work and Protected Intellectual Property.

# =============================================================================

from **future** import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Iterator, Optional

from .models import KeyUsageRecord, TokenHash, require_tz_aware

**all** = [
"KeyLedger",
]

_SCHEMA_VERSION = 1

class KeyLedger:
"""
Durable append-oriented key-usage audit ledger.

```
Storage:
    SQLite database with WAL mode enabled.

Design goals:
    - Preserve authentication audit records across process restarts.
    - Prevent unbounded in-memory growth.
    - Keep lookup operations indexed and bounded.
    - Expose no ordinary record-update interface.
    - Restrict destructive clearing to development and test environments.

Notes:
    This class is process-safe for ordinary SQLite-backed usage because
    each operation opens its own database connection.

    The RLock coordinates threads inside the current process. SQLite
    coordinates access across processes.

    Records are append-oriented through the public interface. Existing
    rows are never modified by ordinary application operations.
"""

def __init__(
    self,
    db_path: str = "data/s34_auth_ledger.sqlite3",
    *,
    sqlite_timeout_seconds: float = 15.0,
    max_query_limit: int = 500,
) -> None:
    if not isinstance(db_path, str) or not db_path.strip():
        raise ValueError(
            "db_path must be a non-empty string"
        )

    if float(sqlite_timeout_seconds) <= 0:
        raise ValueError(
            "sqlite_timeout_seconds must be greater than zero"
        )

    if int(max_query_limit) <= 0:
        raise ValueError(
            "max_query_limit must be greater than zero"
        )

    self._db_path = Path(
        db_path
    )

    self._sqlite_timeout_seconds = float(
        sqlite_timeout_seconds
    )

    self._max_query_limit = int(
        max_query_limit
    )

    self._lock = RLock()

    self._ensure_parent_directory()
    self._ensure_schema()

@property
def db_path(self) -> str:
    """
    Return the configured SQLite database path.
    """

    return str(
        self._db_path
    )

def record_usage(
    self,
    record: KeyUsageRecord,
) -> None:
    """
    Append a validated key-usage record to the durable ledger.

    Existing records are never overwritten.
    """

    if not isinstance(
        record,
        KeyUsageRecord,
    ):
        raise TypeError(
            "record must be KeyUsageRecord, "
            f"got {type(record).__name__}"
        )

    with self._lock:
        with self._conn() as cx:
            cx.execute(
                """
                INSERT INTO key_usage_records (
                    record_id,
                    subject_id,
                    device_id,
                    issuer,
                    key_id,
                    token_hash_alg,
                    token_hash_digest,
                    auth_method,
                    issued_at,
                    used_at,
                    expires_at,
                    source_ip,
                    node_id,
                    service,
                    valid,
                    reason
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                );
                """,
                (
                    record.record_id,
                    record.subject_id,
                    record.device_id,
                    record.issuer,
                    record.key_id,
                    record.token_hash.alg,
                    record.token_hash.digest,
                    record.auth_method,
                    self._serialize_datetime(
                        record.issued_at
                    ),
                    self._serialize_datetime(
                        record.used_at
                    ),
                    self._serialize_optional_datetime(
                        record.expires_at
                    ),
                    record.source_ip,
                    record.node_id,
                    record.service,
                    1 if record.valid else 0,
                    record.reason,
                ),
            )

def get_records_for_subject(
    self,
    subject_id: str,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[KeyUsageRecord]:
    """
    Return recent records for a given subject ID.
    """

    safe_subject_id = self._require_text(
        "subject_id",
        subject_id,
    )

    safe_limit, safe_offset = self._normalize_page(
        limit=limit,
        offset=offset,
    )

    with self._lock:
        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT *
                FROM key_usage_records
                WHERE subject_id = ?
                ORDER BY used_at DESC, record_id DESC
                LIMIT ? OFFSET ?;
                """,
                (
                    safe_subject_id,
                    safe_limit,
                    safe_offset,
                ),
            ).fetchall()

    return self._rows_to_records(
        rows
    )

def get_records_for_key(
    self,
    key_id: str,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[KeyUsageRecord]:
    """
    Return recent records for a given key ID.
    """

    safe_key_id = self._require_text(
        "key_id",
        key_id,
    )

    safe_limit, safe_offset = self._normalize_page(
        limit=limit,
        offset=offset,
    )

    with self._lock:
        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT *
                FROM key_usage_records
                WHERE key_id = ?
                ORDER BY used_at DESC, record_id DESC
                LIMIT ? OFFSET ?;
                """,
                (
                    safe_key_id,
                    safe_limit,
                    safe_offset,
                ),
            ).fetchall()

    return self._rows_to_records(
        rows
    )

def list_records(
    self,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[KeyUsageRecord]:
    """
    Return a bounded snapshot of recent ledger records.

    This method keeps the original public name while replacing the
    dangerous unbounded in-memory snapshot behavior.
    """

    return self.list_recent(
        limit=limit,
        offset=offset,
    )

def list_recent(
    self,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[KeyUsageRecord]:
    """
    Return recent ledger records in reverse chronological order.
    """

    safe_limit, safe_offset = self._normalize_page(
        limit=limit,
        offset=offset,
    )

    with self._lock:
        with self._conn() as cx:
            rows = cx.execute(
                """
                SELECT *
                FROM key_usage_records
                ORDER BY used_at DESC, record_id DESC
                LIMIT ? OFFSET ?;
                """,
                (
                    safe_limit,
                    safe_offset,
                ),
            ).fetchall()

    return self._rows_to_records(
        rows
    )

def count(self) -> int:
    """
    Return the total number of stored audit records.
    """

    with self._lock:
        with self._conn() as cx:
            row = cx.execute(
                """
                SELECT COUNT(*)
                FROM key_usage_records;
                """
            ).fetchone()

    return int(
        row[0]
    )

def count_invalid(self) -> int:
    """
    Return the total number of rejected or invalid key-usage records.
    """

    with self._lock:
        with self._conn() as cx:
            row = cx.execute(
                """
                SELECT COUNT(*)
                FROM key_usage_records
                WHERE valid = 0;
                """
            ).fetchone()

    return int(
        row[0]
    )

def prune_before(
    self,
    cutoff: datetime,
) -> int:
    """
    Delete records older than the supplied cutoff timestamp.

    This is an explicit retention-maintenance operation.

    It must never run implicitly during authentication requests.

    Returns:
        Number of deleted rows.
    """

    require_tz_aware(
        cutoff,
        "cutoff",
    )

    serialized_cutoff = self._serialize_datetime(
        cutoff
    )

    with self._lock:
        with self._conn() as cx:
            cursor = cx.execute(
                """
                DELETE FROM key_usage_records
                WHERE used_at < ?;
                """,
                (
                    serialized_cutoff,
                ),
            )

            deleted = int(
                cursor.rowcount
            )

    return deleted

def clear(self) -> None:
    """
    Delete all ledger records.

    This is restricted to development and test environments.

    Production audit history must not be casually erased because someone
    found a convenient helper and decided consequences were optional.
    """

    env = os.getenv(
        "S43_ENV",
        "",
    ).strip().lower()

    if env not in {
        "test",
        "testing",
        "development",
        "dev",
    }:
        raise RuntimeError(
            "KeyLedger.clear() is disabled outside "
            "test and development environments"
        )

    with self._lock:
        with self._conn() as cx:
            cx.execute(
                """
                DELETE FROM key_usage_records;
                """
            )

def _ensure_parent_directory(self) -> None:
    """
    Create the parent directory for the SQLite file when needed.
    """

    parent = self._db_path.parent

    if str(parent) in {
        "",
        ".",
    }:
        return

    parent.mkdir(
        parents=True,
        exist_ok=True,
    )

def _ensure_schema(self) -> None:
    """
    Create and validate the ledger schema.
    """

    with self._lock:
        with self._conn() as cx:
            # WAL mode persists in the SQLite file after initial setup.
            cx.execute(
                """
                PRAGMA journal_mode = WAL;
                """
            )

            cx.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

            cx.execute(
                """
                CREATE TABLE IF NOT EXISTS key_usage_records (
                    record_id TEXT PRIMARY KEY,

                    subject_id TEXT NOT NULL,
                    device_id TEXT NULL,
                    issuer TEXT NOT NULL,

                    key_id TEXT NOT NULL,
                    token_hash_alg TEXT NOT NULL,
                    token_hash_digest TEXT NOT NULL,
                    auth_method TEXT NOT NULL,

                    issued_at TEXT NOT NULL,
                    used_at TEXT NOT NULL,
                    expires_at TEXT NULL,

                    source_ip TEXT NULL,
                    node_id TEXT NULL,
                    service TEXT NULL,

                    valid INTEGER NOT NULL
                        CHECK (valid IN (0, 1)),

                    reason TEXT NULL,

                    CHECK (
                        (valid = 1 AND reason IS NULL)
                        OR
                        (
                            valid = 0
                            AND reason IS NOT NULL
                            AND length(trim(reason)) > 0
                        )
                    )
                );
                """
            )

            self._validate_or_create_schema_version(
                cx
            )

            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_key_usage_records_subject
                ON key_usage_records (
                    subject_id,
                    used_at DESC
                );
                """
            )

            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_key_usage_records_key
                ON key_usage_records (
                    key_id,
                    used_at DESC
                );
                """
            )

            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_key_usage_records_used_at
                ON key_usage_records (
                    used_at DESC
                );
                """
            )

            cx.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_key_usage_records_valid
                ON key_usage_records (
                    valid,
                    used_at DESC
                );
                """
            )

def _validate_or_create_schema_version(
    self,
    cx: sqlite3.Connection,
) -> None:
    """
    Store and validate the ledger schema version.
    """

    row = cx.execute(
        """
        SELECT value
        FROM schema_meta
        WHERE key = 's34_key_ledger_schema_version';
        """
    ).fetchone()

    if row is None:
        cx.execute(
            """
            INSERT INTO schema_meta (
                key,
                value
            )
            VALUES (
                's34_key_ledger_schema_version',
                ?
            );
            """,
            (
                str(_SCHEMA_VERSION),
            ),
        )

        return

    try:
        stored_version = int(
            row[0]
        )
    except (
        TypeError,
        ValueError,
    ) as exc:
        raise RuntimeError(
            "S34 key ledger schema version is invalid"
        ) from exc

    if stored_version != _SCHEMA_VERSION:
        raise RuntimeError(
            "S34 key ledger schema mismatch: "
            f"stored={stored_version}, "
            f"expected={_SCHEMA_VERSION}. "
            "Run the required migration before starting."
        )

@contextmanager
def _conn(
    self,
) -> Iterator[sqlite3.Connection]:
    """
    Open a SQLite connection with defensive settings.
    """

    cx = sqlite3.connect(
        str(
            self._db_path
        ),
        timeout=self._sqlite_timeout_seconds,
    )

    cx.row_factory = sqlite3.Row

    try:
        cx.execute(
            """
            PRAGMA foreign_keys = ON;
            """
        )

        cx.execute(
            """
            PRAGMA synchronous = NORMAL;
            """
        )

        yield cx

        cx.commit()
    except Exception:
        cx.rollback()
        raise
    finally:
        cx.close()

def _rows_to_records(
    self,
    rows: list[sqlite3.Row],
) -> list[KeyUsageRecord]:
    """
    Convert database rows into validated immutable model instances.
    """

    return [
        self._row_to_record(
            row
        )
        for row in rows
    ]

def _row_to_record(
    self,
    row: sqlite3.Row,
) -> KeyUsageRecord:
    """
    Convert one database row into a validated immutable model instance.
    """

    return KeyUsageRecord(
        record_id=str(
            row["record_id"]
        ),
        subject_id=str(
            row["subject_id"]
        ),
        device_id=self._optional_str(
            row["device_id"]
        ),
        issuer=str(
            row["issuer"]
        ),
        key_id=str(
            row["key_id"]
        ),
        token_hash=TokenHash(
            alg=str(
                row["token_hash_alg"]
            ),
            digest=str(
                row["token_hash_digest"]
            ),
        ),
        auth_method=str(
            row["auth_method"]
        ),
        issued_at=self._deserialize_datetime(
            row["issued_at"],
            "issued_at",
        ),
        used_at=self._deserialize_datetime(
            row["used_at"],
            "used_at",
        ),
        expires_at=self._deserialize_optional_datetime(
            row["expires_at"],
            "expires_at",
        ),
        source_ip=self._optional_str(
            row["source_ip"]
        ),
        node_id=self._optional_str(
            row["node_id"]
        ),
        service=self._optional_str(
            row["service"]
        ),
        valid=bool(
            row["valid"]
        ),
        reason=self._optional_str(
            row["reason"]
        ),
    )

def _normalize_page(
    self,
    *,
    limit: int,
    offset: int,
) -> tuple[int, int]:
    """
    Clamp pagination values to safe bounds.
    """

    safe_limit = max(
        1,
        min(
            int(limit),
            self._max_query_limit,
        ),
    )

    safe_offset = max(
        0,
        int(offset),
    )

    return (
        safe_limit,
        safe_offset,
    )

@staticmethod
def _require_text(
    field_name: str,
    value: object,
) -> str:
    """
    Require a non-empty string lookup value.
    """

    if not isinstance(
        value,
        str,
    ):
        raise TypeError(
            f"{field_name} must be a string"
        )

    cleaned = value.strip()

    if not cleaned:
        raise ValueError(
            f"{field_name} must not be empty"
        )

    return cleaned

@staticmethod
def _serialize_datetime(
    value: datetime,
) -> str:
    """
    Convert a timezone-aware timestamp to normalized UTC ISO-8601 text.
    """

    require_tz_aware(
        value,
        "datetime",
    )

    return value.astimezone(
        timezone.utc
    ).isoformat()

@classmethod
def _serialize_optional_datetime(
    cls,
    value: Optional[datetime],
) -> Optional[str]:
    """
    Serialize an optional datetime value.
    """

    if value is None:
        return None

    return cls._serialize_datetime(
        value
    )

@staticmethod
def _deserialize_datetime(
    value: object,
    field_name: str,
) -> datetime:
    """
    Deserialize a required ISO-8601 timestamp.
    """

    if not isinstance(
        value,
        str,
    ):
        raise TypeError(
            f"{field_name} must be stored as text"
        )

    try:
        parsed = datetime.fromisoformat(
            value
        )
    except ValueError as exc:
        raise RuntimeError(
            f"Invalid stored timestamp for {field_name}"
        ) from exc

    require_tz_aware(
        parsed,
        field_name,
    )

    return parsed.astimezone(
        timezone.utc
    )

@classmethod
def _deserialize_optional_datetime(
    cls,
    value: object,
    field_name: str,
) -> Optional[datetime]:
    """
    Deserialize an optional ISO-8601 timestamp.
    """

    if value is None:
        return None

    return cls._deserialize_datetime(
        value,
        field_name,
    )

@staticmethod
def _optional_str(
    value: object,
) -> Optional[str]:
    """
    Normalize an optional stored text value.
    """

    if value is None:
        return None

    return str(
        value
    )
```
