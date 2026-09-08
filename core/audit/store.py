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

"""Sentinel-43 authoritative local audit store.

Provides:
    - SQLite-backed append-only audit persistence
    - WAL + FULL synchronous durability posture
    - HMAC-SHA256 chained records
    - transactional anchor/tail verification before append
    - explicit full-chain integrity verification
    - optional best-effort JSONL mirror

The SQLite ledger is authoritative. The JSONL mirror is operational/export
support only and must never be treated as the source of truth.

The HMAC chain is tamper-evident while the signing key remains secret. It is
not equivalent to an external immutable/WORM audit service.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Final


logger = logging.getLogger(__name__)

GENESIS_HASH: Final[str] = "0" * 64
MIN_SIGNING_KEY_BYTES: Final[int] = 32
MAX_PAYLOAD_KEYS: Final[int] = 256
MAX_PAYLOAD_BYTES: Final[int] = 65_536


class AuditStoreError(RuntimeError):
    """Base error for authoritative audit-store operations."""


class AuditIntegrityError(AuditStoreError):
    """Raised when the audit chain or anchor is inconsistent."""


class AuditPersistenceError(AuditStoreError):
    """Raised when an authoritative audit write cannot be committed."""


class AuditConfigurationError(AuditStoreError):
    """Raised when the audit store is configured unsafely."""


class AuditEncoder(json.JSONEncoder):
    """JSON encoder for approved non-native audit value types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, Decimal):
            return str(obj)

        if isinstance(obj, datetime):
            if obj.tzinfo is None:
                raise TypeError(
                    "Naive datetime values are not permitted in audit payloads"
                )
            return obj.astimezone(
                timezone.utc
            ).isoformat()

        return super().default(obj)


def constant_time_compare(
    left: str,
    right: str,
) -> bool:
    return hmac.compare_digest(
        left,
        right,
    )


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _secret_from_str(
    raw: str,
) -> bytes:
    """Decode a hex key or UTF-8 key and enforce minimum strength."""
    value = (raw or "").strip()

    if not value:
        raise AuditConfigurationError(
            "Audit signing key is missing"
        )

    key: bytes

    if (
        len(value) % 2 == 0
        and all(
            char in "0123456789abcdefABCDEF"
            for char in value
        )
    ):
        try:
            key = bytes.fromhex(
                value
            )
        except ValueError as exc:
            raise AuditConfigurationError(
                "Audit signing key contains invalid hex"
            ) from exc
    else:
        key = value.encode(
            "utf-8"
        )

    if len(key) < MIN_SIGNING_KEY_BYTES:
        raise AuditConfigurationError(
            f"Audit signing key must provide at least "
            f"{MIN_SIGNING_KEY_BYTES} bytes"
        )

    return key


def _canonical_json(
    payload: dict[str, Any],
) -> str:
    try:
        return json.dumps(
            payload,
            cls=AuditEncoder,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Audit payload must be JSON serializable"
        ) from exc


def _validate_payload(
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(
        payload,
        dict,
    ):
        raise TypeError(
            "Audit payload must be a dictionary"
        )

    if len(payload) > MAX_PAYLOAD_KEYS:
        raise ValueError(
            f"Audit payload may contain at most {MAX_PAYLOAD_KEYS} keys"
        )

    copied = dict(
        payload
    )

    encoded = _canonical_json(
        copied
    ).encode(
        "utf-8"
    )

    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"Audit payload exceeds {MAX_PAYLOAD_BYTES} bytes"
        )

    return copied


@dataclass(frozen=True, slots=True)
class AuditConfig:
    sqlite_path: Path
    signing_key: str
    jsonl_path: Path | None = None
    sqlite_timeout_seconds: float = 5.0

    def validate(self) -> None:
        if not str(
            self.sqlite_path
        ).strip():
            raise AuditConfigurationError(
                "sqlite_path is required"
            )

        if not 0.1 <= self.sqlite_timeout_seconds <= 60.0:
            raise AuditConfigurationError(
                "sqlite_timeout_seconds must be between 0.1 and 60"
            )

        _secret_from_str(
            self.signing_key
        )


@dataclass(frozen=True, slots=True)
class AuditVerificationResult:
    valid: bool
    records_checked: int
    head_hash: str
    error: str | None = None
    error_record_id: int | None = None


class AuditStore:
    """Authoritative SQLite-backed HMAC-chained audit store."""

    def __init__(
        self,
        cfg: AuditConfig,
    ) -> None:
        cfg.validate()

        self.cfg = cfg
        self._lock = threading.RLock()
        self._key = _secret_from_str(
            cfg.signing_key
        )

    # ------------------------------------------------------------------
    # Startup / connection
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Create the audit directory and schema explicitly at startup."""
        self.cfg.sqlite_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        connection = self._connect()

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    decision_time TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_hmac TEXT NOT NULL,
                    prev_hash TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_anchor (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    head_hash TEXT NOT NULL
                )
                """
            )

            row = connection.execute(
                "SELECT head_hash FROM audit_anchor WHERE id = 1"
            ).fetchone()

            if row is None:
                connection.execute(
                    """
                    INSERT INTO audit_anchor (id, head_hash)
                    VALUES (1, ?)
                    """,
                    (
                        GENESIS_HASH,
                    ),
                )

            connection.commit()

            result = self.verify_integrity(
                connection=connection
            )

            if not result.valid:
                raise AuditIntegrityError(
                    f"Audit ledger failed startup integrity verification: "
                    f"{result.error}"
                )

        finally:
            connection.close()

    def _connect(
        self,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(
                self.cfg.sqlite_path
            ),
            timeout=self.cfg.sqlite_timeout_seconds,
        )

        connection.execute(
            "PRAGMA journal_mode=WAL"
        )
        connection.execute(
            "PRAGMA synchronous=FULL"
        )
        connection.execute(
            "PRAGMA foreign_keys=ON"
        )
        connection.execute(
            "PRAGMA busy_timeout=5000"
        )

        return connection

    # ------------------------------------------------------------------
    # Hashing / integrity
    # ------------------------------------------------------------------

    def compute_payload_hmac(
        self,
        payload: dict[str, Any],
        prev_hash: str,
    ) -> str:
        payload_json = _canonical_json(
            payload
        ).encode(
            "utf-8"
        )

        message = (
            payload_json
            + b"\n"
            + prev_hash.encode(
                "ascii"
            )
        )

        return hmac.new(
            self._key,
            message,
            hashlib.sha256,
        ).hexdigest()

    def _read_anchor(
        self,
        connection: sqlite3.Connection,
    ) -> str:
        row = connection.execute(
            "SELECT head_hash FROM audit_anchor WHERE id = 1"
        ).fetchone()

        if row is None:
            raise AuditIntegrityError(
                "Audit anchor row is missing"
            )

        return str(
            row[0]
        )

    def _read_tail(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[int, str] | None:
        row = connection.execute(
            """
            SELECT id, payload_hmac
            FROM audit_log
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

        if row is None:
            return None

        return (
            int(
                row[0]
            ),
            str(
                row[1]
            ),
        )

    def _verify_anchor_matches_tail(
        self,
        connection: sqlite3.Connection,
    ) -> str:
        anchor = self._read_anchor(
            connection
        )
        tail = self._read_tail(
            connection
        )

        expected = (
            GENESIS_HASH
            if tail is None
            else tail[1]
        )

        if not constant_time_compare(
            anchor,
            expected,
        ):
            raise AuditIntegrityError(
                "Audit anchor does not match ledger tail"
            )

        return anchor

    def get_head_hash(self) -> str:
        connection = self._connect()

        try:
            return self._verify_anchor_matches_tail(
                connection
            )
        finally:
            connection.close()

    # Backward-compatible name.
    def get_prev_hash(self) -> str:
        return self.get_head_hash()

    def verify_integrity(
        self,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> AuditVerificationResult:
        owns_connection = (
            connection is None
        )

        if connection is None:
            connection = self._connect()

        try:
            expected_previous = GENESIS_HASH
            records_checked = 0

            cursor = connection.execute(
                """
                SELECT
                    id,
                    payload_json,
                    payload_hmac,
                    prev_hash
                FROM audit_log
                ORDER BY id ASC
                """
            )

            for (
                record_id,
                payload_json,
                payload_hmac,
                prev_hash,
            ) in cursor:
                if not constant_time_compare(
                    str(
                        prev_hash
                    ),
                    expected_previous,
                ):
                    return AuditVerificationResult(
                        valid=False,
                        records_checked=records_checked,
                        head_hash=expected_previous,
                        error="previous_hash_mismatch",
                        error_record_id=int(
                            record_id
                        ),
                    )

                try:
                    payload = json.loads(
                        str(
                            payload_json
                        )
                    )
                except json.JSONDecodeError:
                    return AuditVerificationResult(
                        valid=False,
                        records_checked=records_checked,
                        head_hash=expected_previous,
                        error="invalid_payload_json",
                        error_record_id=int(
                            record_id
                        ),
                    )

                if not isinstance(
                    payload,
                    dict,
                ):
                    return AuditVerificationResult(
                        valid=False,
                        records_checked=records_checked,
                        head_hash=expected_previous,
                        error="payload_not_object",
                        error_record_id=int(
                            record_id
                        ),
                    )

                calculated = self.compute_payload_hmac(
                    payload,
                    expected_previous,
                )

                if not constant_time_compare(
                    calculated,
                    str(
                        payload_hmac
                    ),
                ):
                    return AuditVerificationResult(
                        valid=False,
                        records_checked=records_checked,
                        head_hash=expected_previous,
                        error="payload_hmac_mismatch",
                        error_record_id=int(
                            record_id
                        ),
                    )

                expected_previous = str(
                    payload_hmac
                )
                records_checked += 1

            anchor = self._read_anchor(
                connection
            )

            if not constant_time_compare(
                anchor,
                expected_previous,
            ):
                return AuditVerificationResult(
                    valid=False,
                    records_checked=records_checked,
                    head_hash=expected_previous,
                    error="anchor_mismatch",
                )

            return AuditVerificationResult(
                valid=True,
                records_checked=records_checked,
                head_hash=expected_previous,
            )

        finally:
            if owns_connection:
                connection.close()

    # ------------------------------------------------------------------
    # Append
    # ------------------------------------------------------------------

    def append(
        self,
        payload: dict[str, Any],
    ) -> str:
        """Atomically append one authoritative audit record."""
        payload_copy = _validate_payload(
            payload
        )

        payload_copy.setdefault(
            "event_id",
            str(
                uuid.uuid4()
            ),
        )
        payload_copy.setdefault(
            "decision_time",
            utc_now_iso(),
        )

        # Revalidate after generated fields are added.
        payload_copy = _validate_payload(
            payload_copy
        )

        with self._lock:
            connection = self._connect()

            try:
                connection.execute(
                    "BEGIN IMMEDIATE"
                )

                current_head = (
                    self._verify_anchor_matches_tail(
                        connection
                    )
                )

                payload_json = _canonical_json(
                    payload_copy
                )

                payload_hmac = (
                    self.compute_payload_hmac(
                        payload_copy,
                        current_head,
                    )
                )

                connection.execute(
                    """
                    INSERT INTO audit_log (
                        event_id,
                        decision_time,
                        payload_json,
                        payload_hmac,
                        prev_hash
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        str(
                            payload_copy[
                                "event_id"
                            ]
                        ),
                        str(
                            payload_copy[
                                "decision_time"
                            ]
                        ),
                        payload_json,
                        payload_hmac,
                        current_head,
                    ),
                )

                updated = connection.execute(
                    """
                    UPDATE audit_anchor
                    SET head_hash = ?
                    WHERE id = 1
                      AND head_hash = ?
                    """,
                    (
                        payload_hmac,
                        current_head,
                    ),
                )

                if updated.rowcount != 1:
                    raise AuditIntegrityError(
                        "Audit anchor changed during append"
                    )

                connection.commit()

            except AuditIntegrityError:
                connection.rollback()
                raise

            except sqlite3.Error as exc:
                connection.rollback()
                raise AuditPersistenceError(
                    "Authoritative audit append failed"
                ) from exc

            except Exception:
                connection.rollback()
                raise

            finally:
                connection.close()

        self._write_jsonl_mirror(
            payload=payload_copy,
            payload_hmac=payload_hmac,
            prev_hash=current_head,
        )

        return payload_hmac

    # ------------------------------------------------------------------
    # Optional JSONL mirror
    # ------------------------------------------------------------------

    def _write_jsonl_mirror(
        self,
        *,
        payload: dict[str, Any],
        payload_hmac: str,
        prev_hash: str,
    ) -> None:
        path = self.cfg.jsonl_path

        if path is None:
            return

        record = {
            "payload": payload,
            "payload_hmac": payload_hmac,
            "prev_hash": prev_hash,
        }

        try:
            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            line = (
                _canonical_json(
                    record
                )
                + "\n"
            )

            with path.open(
                "a",
                encoding="utf-8",
            ) as jsonl_file:
                jsonl_file.write(
                    line
                )
                jsonl_file.flush()
                os.fsync(
                    jsonl_file.fileno()
                )

        except OSError:
            logger.warning(
                "Audit JSONL mirror write failed for %s",
                path,
                exc_info=True,
            )


__all__ = [
    "AuditConfig",
    "AuditConfigurationError",
    "AuditEncoder",
    "AuditIntegrityError",
    "AuditPersistenceError",
    "AuditStore",
    "AuditStoreError",
    "AuditVerificationResult",
    "constant_time_compare",
    "utc_now_iso",
]
