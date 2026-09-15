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

import enum
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


class AuditStoreHealth(str, enum.Enum):
    """This store's own last-known health, from its own real operations.

    Deliberately not "is writable now" -- there is no way to prove that
    without performing a write, and a health check must not mutate the
    ledger to answer its own question. This is honestly a *last known*
    state, established by the store's genuine append()/verify_integrity()/
    initialize() calls, not a live guarantee about the next filesystem
    operation.
    """

    UNVERIFIED = "unverified"  # constructed, never yet successfully verified
    HEALTHY = "healthy"        # last append or integrity verification succeeded
    UNHEALTHY = "unhealthy"    # last append, verification, or init failed
    CLOSED = "closed"          # explicitly closed; not currently available


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


def _normalize_lookup_value(value: Any) -> str | None:
    """Normalize a component/correlation_id value for equality comparison.

    Both sides of a mismatch check can legitimately differ in Python type
    even when they represent "the same" value: SQLite's TEXT column
    affinity coerces a non-string value to its text form on insert, while
    the JSON payload preserves the original type exactly. Comparing
    str(x)-normalized forms (None stays None) avoids flagging that benign
    round-trip difference as a tamper mismatch while still catching a
    genuinely different value.
    """
    return None if value is None else str(value)


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
        self._health: AuditStoreHealth = AuditStoreHealth.UNVERIFIED

    @property
    def last_known_health(self) -> AuditStoreHealth:
        """This store's own last-known health -- see AuditStoreHealth."""
        with self._lock:
            return self._health

    def _set_health(
        self,
        health: AuditStoreHealth,
    ) -> None:
        with self._lock:
            self._health = health

    def close(self) -> None:
        """Mark this store CLOSED: no longer available for use.

        Each operation already opens and closes its own SQLite connection
        (there is no persistent connection to release here) -- this exists
        so a caller with a lingering reference, or a status check against
        the canonical registry, sees an honest "closed", rather than a
        stale "healthy" from before shutdown. A later successful
        verify_integrity() or append() (e.g. against a freshly reopened
        store object) can still restore HEALTHY -- CLOSED is not sticky
        against genuine subsequent operations.
        """
        self._set_health(AuditStoreHealth.CLOSED)

    # ------------------------------------------------------------------
    # Startup / connection
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Create the audit directory and schema explicitly at startup."""
        try:
            self._initialize_unguarded()
        except Exception:
            self._set_health(AuditStoreHealth.UNHEALTHY)
            raise

    def _initialize_unguarded(self) -> None:
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

            # Must run after audit_anchor exists: a one-time backfill here
            # may need to verify the existing HMAC chain first (see
            # _ensure_lookup_columns), which reads the anchor row.
            self._ensure_lookup_columns(connection)
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

    def _ensure_lookup_columns(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Add and backfill the denormalized component/correlation_id
        columns get_records() filters on, if this table predates them.

        These are plain copies extracted from payload_json at write time --
        not part of the HMAC chain (compute_payload_hmac only ever sees the
        canonical payload dict) -- purely so a bounded lookup can filter and
        order in SQL instead of materializing every row in Python. The
        smallest schema change that gets there: two nullable TEXT columns
        plus one covering index, added only if a pre-existing database
        doesn't already have them, with a one-time backfill for any rows
        already present so an old ledger's records remain findable.
        """
        existing = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(audit_log)"
            ).fetchall()
        }

        added = False
        if "component" not in existing:
            connection.execute(
                "ALTER TABLE audit_log ADD COLUMN component TEXT"
            )
            added = True
        if "correlation_id" not in existing:
            connection.execute(
                "ALTER TABLE audit_log ADD COLUMN correlation_id TEXT"
            )
            added = True

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_lookup "
            "ON audit_log (component, correlation_id, id)"
        )

        if not added:
            return

        # Only backfill from a chain that has already proven itself
        # authentic. Backfilling from an unverified/tampered chain would
        # let forged payload_json dictate the very columns full integrity
        # verification later trusts (see _verify_integrity_unguarded's
        # lookup-metadata check). This check is HMAC-chain-only
        # (check_lookup_metadata=False): the columns being backfilled here
        # are exactly what that check would otherwise compare against, and
        # they are legitimately NULL pre-backfill, not a mismatch. It also
        # bypasses the public verify_integrity() wrapper deliberately, so
        # this one-time pre-check does not prematurely flip last_known_health
        # -- the real _initialize_unguarded() caller runs the authoritative
        # full check (with metadata) right after this method returns.
        chain_check = self._verify_integrity_unguarded(
            connection=connection,
            check_lookup_metadata=False,
        )
        if not chain_check.valid:
            logger.warning(
                "Audit ledger HMAC chain failed verification before the "
                "component/correlation_id backfill; leaving legacy rows "
                "unbackfilled (error=%s, error_record_id=%s)",
                chain_check.error,
                chain_check.error_record_id,
            )
            return

        # One-time backfill: only rows written before this migration have
        # NULL in the new columns (append() populates them from here on).
        rows = connection.execute(
            "SELECT id, payload_json FROM audit_log WHERE component IS NULL"
        ).fetchall()

        for record_id, payload_json in rows:
            try:
                payload = json.loads(str(payload_json))
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            connection.execute(
                "UPDATE audit_log SET component = ?, correlation_id = ? "
                "WHERE id = ?",
                (
                    payload.get("component"),
                    payload.get("correlation_id"),
                    record_id,
                ),
            )

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
        """Full-chain integrity verification, updating last_known_health.

        Read-only against the ledger itself (no row is written) -- only
        this in-process Python attribute is updated, which is not "mutating
        the audit ledger". A passing result sets HEALTHY (this can restore
        HEALTHY even from CLOSED -- see AuditStore.close()); a failing
        result sets UNHEALTHY.
        """
        result = self._verify_integrity_unguarded(
            connection=connection
        )
        self._set_health(
            AuditStoreHealth.HEALTHY
            if result.valid
            else AuditStoreHealth.UNHEALTHY
        )
        return result

    def _verify_integrity_unguarded(
        self,
        *,
        connection: sqlite3.Connection | None = None,
        check_lookup_metadata: bool = True,
    ) -> AuditVerificationResult:
        """Full-chain verification, optionally including lookup metadata.

        ``check_lookup_metadata`` additionally verifies that each row's
        denormalized ``component``/``correlation_id`` columns (see
        _ensure_lookup_columns / get_records) exactly match the same fields
        inside that row's own HMAC-authenticated payload. Those columns are
        plain copies outside the HMAC chain -- editing them directly (UPDATE
        audit_log SET component = ...) would otherwise make a record appear
        under another producer, or vanish from every component-filtered
        lookup, without breaking the hash chain at all. False only for the
        one-time pre-backfill chain check in _ensure_lookup_columns, where
        the columns are legitimately still NULL and have not been backfilled
        yet -- never for a caller-facing verification.
        """
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
                    prev_hash,
                    component,
                    correlation_id
                FROM audit_log
                ORDER BY id ASC
                """
            )

            for (
                record_id,
                payload_json,
                payload_hmac,
                prev_hash,
                component_col,
                correlation_id_col,
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

                if check_lookup_metadata and (
                    _normalize_lookup_value(component_col)
                    != _normalize_lookup_value(payload.get("component"))
                    or _normalize_lookup_value(correlation_id_col)
                    != _normalize_lookup_value(payload.get("correlation_id"))
                ):
                    return AuditVerificationResult(
                        valid=False,
                        records_checked=records_checked,
                        head_hash=expected_previous,
                        error="lookup_metadata_mismatch",
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
    # Read
    # ------------------------------------------------------------------

    _MAX_RECORDS_LIMIT: Final[int] = 1000

    def get_records(
        self,
        *,
        component: str,
        correlation_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Bounded read of this store's own payloads, filtered in SQL.

        ``component`` and ``correlation_id`` (when given) are pushed into
        the WHERE clause against the denormalized columns append() writes
        (see _ensure_lookup_columns) -- always as bound parameters, never
        string-interpolated, so a caller-supplied value can never become
        raw SQL. ``ORDER BY id ASC LIMIT ?`` is likewise pushed into SQLite:
        this never fetches more than ``limit`` rows, regardless of ledger
        size, and ``id`` (an autoincrement primary key) gives a total,
        deterministic order even for records sharing a timestamp.

        ``component`` is mandatory and filters server-side before any row
        reaches the caller, so a consumer scoped to one producer (e.g. the
        Remote Gateway, passing component="remote_gateway") can never see
        another producer's records (governance decisions, etc.) whose field
        shape it hasn't examined.

        Fails closed on this store's own last-known health rather than
        re-running a full O(total ledger) chain verification on every
        ordinary read: that state is already established and kept current
        by initialize()/append()/verify_integrity() (see AuditStoreHealth).
        If the store is not currently HEALTHY -- unverified, unhealthy, or
        closed -- this raises rather than returning rows a caller could
        wrongly trust. Does not take self._lock: this is a read-only query
        against a WAL-mode database, which is safe to run concurrently with
        an in-progress append() and must not delay it.
        """
        if not 0 < limit <= self._MAX_RECORDS_LIMIT:
            raise ValueError(
                f"limit must be in (0, {self._MAX_RECORDS_LIMIT}]"
            )

        if self.last_known_health != AuditStoreHealth.HEALTHY:
            raise AuditIntegrityError(
                "Audit store is not currently healthy "
                f"(last_known_health={self.last_known_health.value}); "
                "refusing to serve reads until verify_integrity() succeeds"
            )

        connection = self._connect()
        try:
            if correlation_id is None:
                cursor = connection.execute(
                    "SELECT payload_json, component, correlation_id FROM audit_log "
                    "WHERE component = ? "
                    "ORDER BY id ASC LIMIT ?",
                    (component, limit),
                )
            else:
                cursor = connection.execute(
                    "SELECT payload_json, component, correlation_id FROM audit_log "
                    "WHERE component = ? AND correlation_id = ? "
                    "ORDER BY id ASC LIMIT ?",
                    (component, correlation_id, limit),
                )
            rows = cursor.fetchall()
        finally:
            connection.close()

        records: list[dict[str, Any]] = []
        for payload_json, component_col, correlation_id_col in rows:
            try:
                payload = json.loads(str(payload_json))
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue

            # The WHERE clause above already filtered on the denormalized
            # component/correlation_id columns for SQL-side bounding. Before
            # trusting that a returned row genuinely belongs to the
            # requested component/correlation_id, independently confirm
            # those columns match the same fields inside this row's own
            # HMAC-authenticated payload. A mismatch means the denormalized
            # columns were edited directly (outside the HMAC chain) --
            # trusting them here could return a record under the wrong
            # producer's history, or hide one from it. Fail closed rather
            # than silently return or omit a possibly misattributed record.
            if (
                _normalize_lookup_value(component_col)
                != _normalize_lookup_value(payload.get("component"))
                or _normalize_lookup_value(correlation_id_col)
                != _normalize_lookup_value(payload.get("correlation_id"))
            ):
                self._set_health(AuditStoreHealth.UNHEALTHY)
                raise AuditIntegrityError(
                    "Audit record's denormalized lookup metadata does not "
                    "match its authenticated payload"
                )

            records.append(payload)

        return records

    # ------------------------------------------------------------------
    # Append
    # ------------------------------------------------------------------

    def append(
        self,
        payload: dict[str, Any],
    ) -> str:
        """Atomically append one authoritative audit record.

        Updates last_known_health: HEALTHY on success (this can restore
        HEALTHY even from CLOSED), UNHEALTHY on any failure (validation,
        SQLite, locking, or integrity) before the exception propagates.
        """
        try:
            result = self._append_unguarded(payload)
        except Exception:
            self._set_health(AuditStoreHealth.UNHEALTHY)
            raise
        self._set_health(AuditStoreHealth.HEALTHY)
        return result

    def _append_unguarded(
        self,
        payload: dict[str, Any],
    ) -> str:
        # A confirmed integrity failure (lookup-metadata tampering or a
        # broken HMAC chain, discovered by verify_integrity() or a prior
        # get_records() mismatch) must keep blocking new writes -- and
        # therefore the mandatory Remote Gateway pre-action gate, which
        # calls append() -- until an operator repairs the ledger and an
        # explicit verify_integrity() call restores HEALTHY. This does not
        # apply to CLOSED/UNVERIFIED: append() succeeding from either of
        # those is the documented, intentional way health recovers (see
        # AuditStore.close()).
        if self.last_known_health == AuditStoreHealth.UNHEALTHY:
            raise AuditIntegrityError(
                "Audit store failed its last integrity check; refusing to "
                "append until verify_integrity() succeeds after repair"
            )

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
                        prev_hash,
                        component,
                        correlation_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
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
                        # Denormalized copies for get_records()'s bounded
                        # SQL filter -- not part of the HMAC chain, which
                        # is computed over payload_copy alone, above.
                        payload_copy.get("component"),
                        payload_copy.get("correlation_id"),
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
