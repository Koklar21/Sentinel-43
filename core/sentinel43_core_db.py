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

"""Persistent governance state store for Sentinel-43.

Responsibilities:
    - staged/pending governance actions
    - atomic status transitions
    - persistent dedupe TTL state
    - explicit retention cleanup

Non-responsibilities:
    - no environment reads
    - no operational event logging
    - no audit authority
    - no network I/O
    - no schema creation from the constructor
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


class ActionStatus(StrEnum):
    SHADOWED = "SHADOWED"
    STAGED = "STAGED"
    PENDING = "PENDING"
    VETOED = "VETOED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"


class IncidentStatus(StrEnum):
    """An incident record is internal follow-up work, not an enforcement
    effect: OPEN means a human approved opening it; RETRACTED means the
    decision that opened it was reverted before it could be recorded."""

    OPEN = "OPEN"
    RETRACTED = "RETRACTED"


_TERMINAL_ACTION_STATUSES = frozenset(
    {
        ActionStatus.VETOED,
        ActionStatus.APPROVED,
        ActionStatus.EXECUTED,
        ActionStatus.EXPIRED,
    }
)


@dataclass(frozen=True, slots=True)
class CoreStoreConfig:
    db_path: Path
    sqlite_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        db_path = Path(self.db_path)

        if not str(db_path).strip():
            raise ValueError("db_path is required")

        if not 0.1 <= self.sqlite_timeout_seconds <= 60.0:
            raise ValueError(
                "sqlite_timeout_seconds must be between 0.1 and 60"
            )

        object.__setattr__(self, "db_path", db_path)


@dataclass(frozen=True, slots=True)
class PendingAction:
    action_id: str
    created_at_ms: int
    status: ActionStatus

    target_type: str
    target_value: str

    primary_action: str
    actions: tuple[str, ...]

    severity: str
    kind: str
    source_kind: str
    score: float | None

    reason: str
    system_id: str

    execute_at_ms: int | None = None
    operator_id: str | None = None
    operator_reason: str | None = None
    #: The one account the evidence in this window belongs to, as the request
    #: pipeline established it (SecurityContext.principal_id). Empty when the
    #: source was unauthenticated, or when the window held more than one
    #: account and therefore names none.
    principal_id: str = ""

    def __post_init__(self) -> None:
        values = {
            "action_id": str(self.action_id).strip(),
            "target_type": str(self.target_type).strip(),
            "target_value": str(self.target_value).strip(),
            "primary_action": str(self.primary_action).strip(),
            "severity": str(self.severity).strip(),
            "kind": str(self.kind).strip(),
            "source_kind": str(self.source_kind).strip(),
            "reason": str(self.reason).strip(),
            "system_id": str(self.system_id).strip(),
        }

        for field_name, value in values.items():
            if not value:
                raise ValueError(f"{field_name} must not be empty")
            object.__setattr__(self, field_name, value)

        if self.created_at_ms < 0:
            raise ValueError("created_at_ms must be >= 0")

        if self.execute_at_ms is not None and self.execute_at_ms < 0:
            raise ValueError("execute_at_ms must be >= 0 when provided")

        normalized_actions = tuple(
            str(action).strip()
            for action in self.actions
            if str(action).strip()
        )

        if not normalized_actions:
            raise ValueError("actions must contain at least one action")

        object.__setattr__(self, "actions", normalized_actions)

        if self.score is not None:
            score = float(self.score)

            if not 0.0 <= score <= 100.0:
                raise ValueError(
                    "score must be between 0 and 100 when provided"
                )

            object.__setattr__(self, "score", score)

        object.__setattr__(
            self, "principal_id", str(self.principal_id or "").strip()
        )


class SentinelCoreStore:
    """SQLite-backed staged-action and dedupe store."""

    def __init__(self, config: CoreStoreConfig) -> None:
        if not isinstance(config, CoreStoreConfig):
            raise TypeError("config must be CoreStoreConfig")

        self._config = config

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self._config.db_path),
            timeout=self._config.sqlite_timeout_seconds,
        )

        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")

        return connection

    def initialize(self) -> None:
        """Create the database directory and schema explicitly at startup."""
        self._config.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS pending_actions (
                    action_id TEXT PRIMARY KEY,
                    created_at_ms INTEGER NOT NULL,
                    execute_at_ms INTEGER,
                    status TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    primary_action TEXT NOT NULL,
                    actions_json TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    score REAL,
                    reason TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    operator_id TEXT,
                    operator_reason TEXT,
                    principal_id TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_pending_status
                    ON pending_actions(status);

                CREATE INDEX IF NOT EXISTS idx_pending_created
                    ON pending_actions(created_at_ms);

                CREATE TABLE IF NOT EXISTS action_dedupe (
                    dedupe_key TEXT PRIMARY KEY,
                    expires_at_ms INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dedupe_exp
                    ON action_dedupe(expires_at_ms);

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    opened_at_ms INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    subject_type TEXT NOT NULL,
                    subject_value TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    engine_actions_json TEXT NOT NULL,
                    opened_by TEXT NOT NULL,
                    operator_reason TEXT NOT NULL,
                    retracted_reason TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_incident_action
                    ON incidents(action_id);

                CREATE INDEX IF NOT EXISTS idx_incident_opened
                    ON incidents(opened_at_ms);

                -- Evidence: what a producer reported, with the provenance it
                -- arrived with. Storing a record says nothing about whether
                -- it may COUNT: that is `state`, and only ELIGIBLE and
                -- HUMAN_RELEASED count (see core/evidence/model.py).
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    producer TEXT NOT NULL,
                    producer_trust TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    observed_at_ms INTEGER NOT NULL,
                    ingested_at_ms INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    payload_hash TEXT NOT NULL DEFAULT '',
                    subject_type TEXT NOT NULL DEFAULT '',
                    subject_value TEXT NOT NULL DEFAULT '',
                    account_id TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT '',
                    device_id TEXT NOT NULL DEFAULT '',
                    source_ip TEXT NOT NULL DEFAULT '',
                    correlation_id TEXT NOT NULL DEFAULT '',
                    incident_id TEXT NOT NULL DEFAULT '',
                    source_event_id TEXT NOT NULL DEFAULT '',
                    expires_at_ms INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL,
                    lock_reason TEXT NOT NULL DEFAULT '',
                    lock_detail TEXT NOT NULL DEFAULT '',
                    version INTEGER NOT NULL DEFAULT 1,
                    updated_at_ms INTEGER NOT NULL DEFAULT 0,
                    CHECK (state IN (
                        'OBSERVED', 'VERIFIED', 'ELIGIBLE', 'LOCKED',
                        'HUMAN_RELEASED', 'REJECTED', 'EXPIRED', 'INVALIDATED'
                    )),
                    CHECK (producer_trust IN (
                        'TRUSTED', 'OBSERVED_ONLY', 'REVOKED'
                    )),
                    CHECK (version >= 1),
                    CHECK (observed_at_ms >= 0 AND ingested_at_ms >= 0)
                );

                -- One producer reporting the same underlying fact twice is
                -- ONE piece of evidence: the unique constraint is what stops
                -- a replay from multiplying confidence.
                CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_dedupe
                    ON evidence(producer, content_hash);

                CREATE INDEX IF NOT EXISTS idx_evidence_state
                    ON evidence(state);

                CREATE INDEX IF NOT EXISTS idx_evidence_subject
                    ON evidence(subject_value, observed_at_ms);

                CREATE INDEX IF NOT EXISTS idx_evidence_correlation
                    ON evidence(correlation_id);

                -- Backs the bounded on-read freshness check in
                -- bundle_for_subject(): finding which of a subject's
                -- records have an effective expiry in the past is a lookup
                -- against this index, not a full-table scan, and never a
                -- background sweep.
                CREATE INDEX IF NOT EXISTS idx_evidence_expires_at
                    ON evidence(expires_at_ms) WHERE expires_at_ms > 0;

                -- idx_evidence_incident and idx_evidence_producer are NOT
                -- here: they cover columns (incident_id, and producer's own
                -- lookup index) that a database from an earlier revision may
                -- not have yet. They are created below, after the ALTER
                -- TABLE migration that guarantees the columns exist -- this
                -- script runs unconditionally on every startup, including
                -- against an existing database where CREATE TABLE IF NOT
                -- EXISTS is a no-op and an index on a not-yet-added column
                -- would fail closed on every subsequent restart.

                -- The durable trust registry. A producer does not grant
                -- itself trust: this table is the ONLY source eligibility
                -- reads current trust from (core/evidence/ledger.py), and it
                -- is written only by an explicit, audited registration or
                -- revocation call -- never from a producer's own payload.
                CREATE TABLE IF NOT EXISTS evidence_producers (
                    producer TEXT PRIMARY KEY,
                    trust TEXT NOT NULL,
                    registered_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    updated_by TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    CHECK (trust IN ('TRUSTED', 'OBSERVED_ONLY', 'REVOKED'))
                );

                -- Relationships. The child cannot be eligible while a
                -- relationship marked required is unverified, so this table
                -- is what keeps "B supports A" from being an assumption.
                CREATE TABLE IF NOT EXISTS evidence_relationships (
                    relationship_id TEXT PRIMARY KEY,
                    parent_evidence_id TEXT NOT NULL
                        REFERENCES evidence(evidence_id) ON DELETE CASCADE,
                    child_evidence_id TEXT NOT NULL
                        REFERENCES evidence(evidence_id) ON DELETE CASCADE,
                    relationship_type TEXT NOT NULL,
                    required_for_eligibility INTEGER NOT NULL DEFAULT 0,
                    state TEXT NOT NULL,
                    verification_method TEXT NOT NULL DEFAULT '',
                    created_at_ms INTEGER NOT NULL,
                    verified_at_ms INTEGER NOT NULL DEFAULT 0,
                    invalidated_reason TEXT NOT NULL DEFAULT '',
                    CHECK (parent_evidence_id <> child_evidence_id),
                    CHECK (state IN (
                        'PROPOSED', 'VERIFIED', 'REFUTED', 'INVALIDATED'
                    ))
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_relationship_unique
                    ON evidence_relationships(
                        parent_evidence_id, child_evidence_id, relationship_type
                    );

                CREATE INDEX IF NOT EXISTS idx_relationship_child
                    ON evidence_relationships(child_evidence_id);

                CREATE INDEX IF NOT EXISTS idx_relationship_parent
                    ON evidence_relationships(parent_evidence_id);

                -- Human decisions ABOUT EVIDENCE. Deliberately separate from
                -- pending_actions, which holds human decisions about
                -- RESPONSE ACTIONS: releasing evidence is not approving a
                -- response, and the two must never be read as one another.
                CREATE TABLE IF NOT EXISTS evidence_reviews (
                    review_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL
                        REFERENCES evidence(evidence_id) ON DELETE CASCADE,
                    -- The exact version the human saw. A later change bumps
                    -- the version, so a stale decision cannot be replayed
                    -- onto a record that has since changed.
                    evidence_version INTEGER NOT NULL,
                    disposition TEXT NOT NULL,
                    operator_id TEXT NOT NULL,
                    identity_type TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    decided_at_ms INTEGER NOT NULL,
                    -- The lock the record carried WHEN it was reviewed. A
                    -- release does not rewrite history.
                    prior_state TEXT NOT NULL,
                    prior_lock_reason TEXT NOT NULL DEFAULT '',
                    -- The authoritative audit ledger's own reference (its
                    -- HMAC) for the record of THIS decision, so a review row
                    -- can be cross-checked against the tamper-evident audit
                    -- chain rather than trusted as a bare database row.
                    audit_reference TEXT NOT NULL DEFAULT '',
                    CHECK (disposition IN ('RELEASED', 'REJECTED', 'HELD')),
                    CHECK (evidence_version >= 1)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_review_version
                    ON evidence_reviews(evidence_id, evidence_version, disposition);

                CREATE INDEX IF NOT EXISTS idx_review_evidence
                    ON evidence_reviews(evidence_id, decided_at_ms);
                """
            )

            # A database created before principal_id existed keeps its rows
            # and gains the column empty, which is exactly what those rows
            # mean: the account was never recorded for them.
            existing = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(pending_actions)"
                ).fetchall()
            }

            if "principal_id" not in existing:
                connection.execute(
                    "ALTER TABLE pending_actions "
                    "ADD COLUMN principal_id TEXT NOT NULL DEFAULT ''"
                )

            # A database created by the FIRST evidence schema (before
            # producers/incident_id/lock_detail/payload_hash/updated_at_ms
            # existed) keeps its rows; new columns arrive empty/zero, which
            # is exactly what those rows mean: this information was never
            # captured for them. Nothing is fabricated to fill the gap.
            evidence_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(evidence)"
                ).fetchall()
            }

            for column, ddl in (
                ("payload_hash", "TEXT NOT NULL DEFAULT ''"),
                ("incident_id", "TEXT NOT NULL DEFAULT ''"),
                ("lock_detail", "TEXT NOT NULL DEFAULT ''"),
                ("updated_at_ms", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in evidence_columns:
                    connection.execute(
                        f"ALTER TABLE evidence ADD COLUMN {column} {ddl}"
                    )

            review_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(evidence_reviews)"
                ).fetchall()
            }

            if "audit_reference" not in review_columns:
                connection.execute(
                    "ALTER TABLE evidence_reviews "
                    "ADD COLUMN audit_reference TEXT NOT NULL DEFAULT ''"
                )

            # Only safe to create now: the columns above are guaranteed to
            # exist, on a fresh database and a migrated one alike.
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_incident "
                "ON evidence(incident_id)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_producer "
                "ON evidence(producer)"
            )

    @staticmethod
    def _normalize_action_id(action_id: str) -> str:
        if not isinstance(action_id, str):
            raise TypeError("action_id must be a string")

        normalized = action_id.strip()

        if not normalized:
            raise ValueError("action_id must not be empty")

        if len(normalized) > 256:
            raise ValueError("action_id exceeds maximum length")

        return normalized

    @staticmethod
    def _normalize_dedupe_key(dedupe_key: str) -> str:
        if not isinstance(dedupe_key, str):
            raise TypeError("dedupe_key must be a string")

        normalized = dedupe_key.strip()

        if not normalized:
            raise ValueError("dedupe_key must not be empty")

        if len(normalized) > 512:
            raise ValueError("dedupe_key exceeds maximum length")

        return normalized

    def dedupe_allow(self, dedupe_key: str, ttl_seconds: int) -> bool:
        """Atomically reserve a dedupe key for the requested TTL."""
        key = self._normalize_dedupe_key(dedupe_key)

        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise TypeError("ttl_seconds must be an integer")

        if not 1 <= ttl_seconds <= 86_400 * 30:
            raise ValueError("ttl_seconds must be between 1 and 2592000")

        now_ms = int(time.time() * 1000)
        expires_at_ms = now_ms + ttl_seconds * 1000

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM action_dedupe WHERE expires_at_ms <= ?",
                (now_ms,),
            )
            connection.execute(
                """
                INSERT INTO action_dedupe
                    (dedupe_key, expires_at_ms)
                VALUES (?, ?)
                """,
                (key, expires_at_ms),
            )
            connection.commit()
            return True

        except sqlite3.IntegrityError:
            connection.rollback()
            return False

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def dedupe_cleanup(self, *, now_ms: int | None = None) -> int:
        effective_now_ms = (
            int(time.time() * 1000)
            if now_ms is None
            else int(now_ms)
        )

        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM action_dedupe WHERE expires_at_ms <= ?",
                (effective_now_ms,),
            )
            return int(cursor.rowcount or 0)

    def insert_pending(self, action: PendingAction) -> None:
        if not isinstance(action, PendingAction):
            raise TypeError("action must be PendingAction")

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pending_actions (
                    action_id,
                    created_at_ms,
                    execute_at_ms,
                    status,
                    target_type,
                    target_value,
                    primary_action,
                    actions_json,
                    severity,
                    kind,
                    source_kind,
                    score,
                    reason,
                    system_id,
                    operator_id,
                    operator_reason,
                    principal_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.action_id,
                    action.created_at_ms,
                    action.execute_at_ms,
                    action.status.value,
                    action.target_type,
                    action.target_value,
                    action.primary_action,
                    json.dumps(action.actions, separators=(",", ":")),
                    action.severity,
                    action.kind,
                    action.source_kind,
                    action.score,
                    action.reason,
                    action.system_id,
                    action.operator_id,
                    action.operator_reason,
                    action.principal_id,
                ),
            )

    def get_status(self, action_id: str) -> ActionStatus | None:
        normalized = self._normalize_action_id(action_id)

        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM pending_actions WHERE action_id = ?",
                (normalized,),
            ).fetchone()

        if row is None:
            return None

        try:
            return ActionStatus(str(row["status"]))
        except ValueError as exc:
            raise RuntimeError(
                f"stored action {normalized!r} has invalid status"
            ) from exc

    def transition_status(
        self,
        action_id: str,
        *,
        expected: ActionStatus,
        new_status: ActionStatus,
        operator_id: str | None = None,
        operator_reason: str | None = None,
    ) -> bool:
        """Atomically compare-and-set one action status."""
        normalized = self._normalize_action_id(action_id)

        if not isinstance(expected, ActionStatus):
            raise TypeError("expected must be ActionStatus")

        if not isinstance(new_status, ActionStatus):
            raise TypeError("new_status must be ActionStatus")

        normalized_operator = (
            operator_id.strip()
            if isinstance(operator_id, str) and operator_id.strip()
            else None
        )

        normalized_reason = (
            operator_reason.strip()
            if isinstance(operator_reason, str) and operator_reason.strip()
            else None
        )

        if normalized_operator is not None and len(normalized_operator) > 128:
            raise ValueError("operator_id exceeds maximum length")

        if normalized_reason is not None and len(normalized_reason) > 1000:
            raise ValueError("operator_reason exceeds maximum length")

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE pending_actions
                   SET status = ?,
                       operator_id = ?,
                       operator_reason = ?
                 WHERE action_id = ?
                   AND status = ?
                """,
                (
                    new_status.value,
                    normalized_operator,
                    normalized_reason,
                    normalized,
                    expected.value,
                ),
            )

            return (cursor.rowcount or 0) == 1

    def get_action(self, action_id: str) -> Mapping[str, Any] | None:
        """One durable row, or None. Read-only."""
        normalized = self._normalize_action_id(action_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pending_actions WHERE action_id = ?",
                (normalized,),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["actions"] = tuple(json.loads(item.pop("actions_json")))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise RuntimeError(
                f"stored action {item.get('action_id')!r} contains invalid actions_json"
            ) from exc
        return item

    def count_actions(self, *, status: ActionStatus | None = None) -> int:
        """Row count only -- the staging back-pressure check must not pay
        for materialising rows it will not read."""
        with self._connect() as connection:
            if status is None:
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM pending_actions"
                ).fetchone()
            else:
                if not isinstance(status, ActionStatus):
                    raise TypeError("status must be ActionStatus")
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM pending_actions WHERE status = ?",
                    (status.value,),
                ).fetchone()

        return int(row["n"]) if row is not None else 0

    def count_actions_for_target(
        self,
        *,
        target_value: str,
        since_ms: int,
    ) -> int:
        """How many actions were recorded against one target since
        ``since_ms``. Counts every status: an action that was staged and then
        vetoed still happened, and the budget is about how often this target
        is acted on, not about how those decisions turned out."""
        target = str(target_value).strip()

        if not target:
            raise ValueError("target_value must not be empty")

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS n
                FROM pending_actions
                WHERE target_value = ? AND created_at_ms >= ?
                """,
                (target, int(since_ms)),
            ).fetchone()

        return int(row["n"]) if row is not None else 0

    def list_actions(
        self,
        *,
        status: ActionStatus | None = None,
        limit: int = 200,
    ) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("limit must be an integer")

        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")

        with self._connect() as connection:
            if status is None:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM pending_actions
                    ORDER BY created_at_ms DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                if not isinstance(status, ActionStatus):
                    raise TypeError("status must be ActionStatus")

                rows = connection.execute(
                    """
                    SELECT *
                    FROM pending_actions
                    WHERE status = ?
                    ORDER BY created_at_ms DESC
                    LIMIT ?
                    """,
                    (status.value, limit),
                ).fetchall()

        results: list[Mapping[str, Any]] = []

        for row in rows:
            item = dict(row)

            try:
                item["actions"] = tuple(
                    json.loads(item.pop("actions_json"))
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"stored action {item.get('action_id')!r} "
                    "contains invalid actions_json"
                ) from exc

            results.append(MappingProxyType(item))

        return tuple(results)

    # -- incidents ----------------------------------------------------------
    @staticmethod
    def incident_id_for_action(action_id: str) -> str:
        """One incident per resolved recommendation, named after it: a repeated
        open for the same decision updates that record instead of multiplying
        incidents for one approval."""
        return f"incident:{SentinelCoreStore._normalize_action_id(action_id)}"

    def open_incident(
        self,
        *,
        action_id: str,
        severity: str,
        kind: str,
        subject_type: str,
        subject_value: str,
        summary: str,
        engine_actions: tuple[str, ...],
        opened_by: str,
        operator_reason: str = "",
        now_ms: int | None = None,
    ) -> str:
        """Open (or re-open) the incident for one approved recommendation and
        return its id. Durable and idempotent; opens nothing outside this
        system."""
        incident_id = self.incident_id_for_action(action_id)
        opened_at_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
        opened_by = str(opened_by).strip()

        if not opened_by:
            raise ValueError("opened_by must not be empty")

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id,
                    action_id,
                    opened_at_ms,
                    status,
                    severity,
                    kind,
                    subject_type,
                    subject_value,
                    summary,
                    engine_actions_json,
                    opened_by,
                    operator_reason,
                    retracted_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(incident_id) DO UPDATE SET
                    opened_at_ms = excluded.opened_at_ms,
                    status = excluded.status,
                    opened_by = excluded.opened_by,
                    operator_reason = excluded.operator_reason,
                    retracted_reason = NULL
                """,
                (
                    incident_id,
                    self._normalize_action_id(action_id),
                    opened_at_ms,
                    IncidentStatus.OPEN.value,
                    str(severity),
                    str(kind),
                    str(subject_type),
                    str(subject_value),
                    str(summary),
                    json.dumps(
                        [str(name) for name in engine_actions],
                        separators=(",", ":"),
                    ),
                    opened_by,
                    str(operator_reason),
                ),
            )

        return incident_id

    def retract_incident(self, incident_id: str, *, reason: str) -> bool:
        """Mark an incident retracted because the decision that opened it was
        reverted. The record is kept: it is evidence that it once existed."""
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE incidents
                SET status = ?, retracted_reason = ?
                WHERE incident_id = ? AND status = ?
                """,
                (
                    IncidentStatus.RETRACTED.value,
                    str(reason),
                    str(incident_id).strip(),
                    IncidentStatus.OPEN.value,
                ),
            )
            return int(cursor.rowcount or 0) == 1

    def get_incident(self, incident_id: str) -> Mapping[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (str(incident_id).strip(),),
            ).fetchone()

        if row is None:
            return None

        return self._incident_item(row)

    def list_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        limit: int = 200,
    ) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("limit must be an integer")

        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")

        with self._connect() as connection:
            if status is None:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM incidents
                    ORDER BY opened_at_ms DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                if not isinstance(status, IncidentStatus):
                    raise TypeError("status must be IncidentStatus")

                rows = connection.execute(
                    """
                    SELECT *
                    FROM incidents
                    WHERE status = ?
                    ORDER BY opened_at_ms DESC
                    LIMIT ?
                    """,
                    (status.value, limit),
                ).fetchall()

        return tuple(self._incident_item(row) for row in rows)

    def count_incidents(self, *, status: IncidentStatus | None = None) -> int:
        with self._connect() as connection:
            if status is None:
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM incidents"
                ).fetchone()
            else:
                if not isinstance(status, IncidentStatus):
                    raise TypeError("status must be IncidentStatus")
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM incidents WHERE status = ?",
                    (status.value,),
                ).fetchone()

        return int(row["n"]) if row is not None else 0

    @staticmethod
    def _incident_item(row: sqlite3.Row) -> Mapping[str, Any]:
        item = dict(row)

        try:
            item["engine_actions"] = tuple(
                json.loads(item.pop("engine_actions_json"))
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise RuntimeError(
                f"stored incident {item.get('incident_id')!r} "
                "contains invalid engine_actions_json"
            ) from exc

        return MappingProxyType(item)

    # -- evidence -----------------------------------------------------------
    #
    # Storage only. These methods record what was observed, what it is
    # related to, and the eligibility the RULES (core/evidence/model.py)
    # computed -- they never decide a response action, and nothing here is
    # consulted about what should be done.
    @staticmethod
    def _evidence_row(row: sqlite3.Row) -> Mapping[str, Any]:
        return MappingProxyType(dict(row))

    def record_evidence(
        self,
        *,
        evidence_id: str,
        producer: str,
        producer_trust: str,
        event_type: str,
        observed_at_ms: int,
        ingested_at_ms: int,
        content_hash: str,
        state: str,
        payload_hash: str = "",
        lock_reason: str = "",
        lock_detail: str = "",
        subject_type: str = "",
        subject_value: str = "",
        account_id: str = "",
        session_id: str = "",
        device_id: str = "",
        source_ip: str = "",
        correlation_id: str = "",
        incident_id: str = "",
        source_event_id: str = "",
        expires_at_ms: int = 0,
        connection: sqlite3.Connection | None = None,
    ) -> str | None:
        """Store one evidence record, or return the id of the record that
        already holds this producer's report of this fact.

        The unique index on (producer, content_hash) is what makes a replay
        a no-op instead of a second, confidence-multiplying record.
        """
        owns_connection = connection is None
        connection = connection or self._connect()
        now_ms = int(ingested_at_ms)

        try:
            connection.execute(
                """
                INSERT INTO evidence (
                    evidence_id, producer, producer_trust, event_type,
                    observed_at_ms, ingested_at_ms, content_hash, payload_hash,
                    subject_type, subject_value, account_id, session_id,
                    device_id, source_ip, correlation_id, incident_id,
                    source_event_id, expires_at_ms, state, lock_reason,
                    lock_detail, version, updated_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    str(evidence_id), str(producer), str(producer_trust),
                    str(event_type), int(observed_at_ms), now_ms,
                    str(content_hash), str(payload_hash), str(subject_type),
                    str(subject_value), str(account_id), str(session_id),
                    str(device_id), str(source_ip), str(correlation_id),
                    str(incident_id), str(source_event_id), int(expires_at_ms),
                    str(state), str(lock_reason), str(lock_detail), now_ms,
                ),
            )
            if owns_connection:
                connection.commit()
            return str(evidence_id)

        except sqlite3.IntegrityError:
            if owns_connection:
                connection.rollback()
            # Only the dedupe index's own collision is benign: it means a
            # producer replayed a report this store already has, and the
            # existing row's id is a legitimate answer. Any OTHER integrity
            # violation (a CHECK on producer_trust/state, a bad foreign key)
            # is a real defect in what the caller supplied and must not be
            # swallowed into a silent None -- so it is re-raised UNLESS the
            # lookup finds the specific row the dedupe index would collide
            # on, which is the only case this handler exists for.
            existing = connection.execute(
                "SELECT evidence_id FROM evidence "
                "WHERE producer = ? AND content_hash = ?",
                (str(producer), str(content_hash)),
            ).fetchone()
            if existing is None:
                raise
            return str(existing["evidence_id"])

        finally:
            if owns_connection:
                connection.close()

    def record_relationship(
        self,
        *,
        relationship_id: str,
        parent_evidence_id: str,
        child_evidence_id: str,
        relationship_type: str,
        required_for_eligibility: bool,
        state: str,
        verification_method: str = "",
        created_at_ms: int,
        verified_at_ms: int = 0,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        """Record a claimed link. False when this exact link already exists."""
        owns_connection = connection is None
        connection = connection or self._connect()

        try:
            connection.execute(
                """
                INSERT INTO evidence_relationships (
                    relationship_id, parent_evidence_id, child_evidence_id,
                    relationship_type, required_for_eligibility, state,
                    verification_method, created_at_ms, verified_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(relationship_id), str(parent_evidence_id),
                    str(child_evidence_id), str(relationship_type),
                    1 if required_for_eligibility else 0, str(state),
                    str(verification_method), int(created_at_ms),
                    int(verified_at_ms),
                ),
            )
            if owns_connection:
                connection.commit()
            return True

        except sqlite3.IntegrityError:
            if owns_connection:
                connection.rollback()
            return False

        finally:
            if owns_connection:
                connection.close()

    def get_evidence(self, evidence_id: str) -> Mapping[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM evidence WHERE evidence_id = ?",
                (str(evidence_id).strip(),),
            ).fetchone()
        return self._evidence_row(row) if row is not None else None

    def relationships_of(
        self, child_evidence_id: str
    ) -> tuple[Mapping[str, Any], ...]:
        """Every link where this record is the DEPENDENT one."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence_relationships WHERE child_evidence_id = ?",
                (str(child_evidence_id).strip(),),
            ).fetchall()
        return tuple(MappingProxyType(dict(row)) for row in rows)

    def contradictions_of(
        self, evidence_id: str
    ) -> tuple[Mapping[str, Any], ...]:
        """CONTRADICTS links touching this record, in EITHER direction.

        A contradiction is symmetric in meaning ("A contradicts B" IS "B
        contradicts A") even though it is stored once, in one direction. Both
        sides must see it: unlike a dependency, where only the child cares
        whether its parent holds up, a contradiction has to lock BOTH
        records, or one of them would keep counting on the strength of a
        fact its own contradiction already disputes.
        """
        identifier = str(evidence_id).strip()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM evidence_relationships
                WHERE relationship_type = 'CONTRADICTS'
                  AND (parent_evidence_id = ? OR child_evidence_id = ?)
                """,
                (identifier, identifier),
            ).fetchall()
        return tuple(MappingProxyType(dict(row)) for row in rows)

    def corroborations_of(
        self, evidence_id: str
    ) -> tuple[Mapping[str, Any], ...]:
        """Verified CORROBORATES links touching this record, in EITHER
        direction.

        "A corroborates B" and "B corroborates A" are the same fact; the row
        has to be stored one way round, so the read looks both ways rather
        than requiring two rows that could drift apart.
        """
        identifier = str(evidence_id).strip()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM evidence_relationships
                WHERE relationship_type = 'CORROBORATES'
                  AND state = 'VERIFIED'
                  AND (parent_evidence_id = ? OR child_evidence_id = ?)
                """,
                (identifier, identifier),
            ).fetchall()
        return tuple(MappingProxyType(dict(row)) for row in rows)

    def dependents_of(self, parent_evidence_id: str) -> tuple[str, ...]:
        """Ids that depend on this record, for propagation."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT child_evidence_id FROM evidence_relationships "
                "WHERE parent_evidence_id = ?",
                (str(parent_evidence_id).strip(),),
            ).fetchall()
        return tuple(str(row["child_evidence_id"]) for row in rows)

    def dependency_edges(self) -> dict[str, tuple[str, ...]]:
        """parent -> children, for a bounded traversal of the whole graph."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT parent_evidence_id, child_evidence_id "
                "FROM evidence_relationships"
            ).fetchall()

        edges: dict[str, list[str]] = {}
        for row in rows:
            edges.setdefault(str(row["parent_evidence_id"]), []).append(
                str(row["child_evidence_id"])
            )
        return {parent: tuple(children) for parent, children in edges.items()}

    def derived_from_edges(self) -> dict[str, tuple[str, ...]]:
        """child -> its DERIVED_FROM parents, over VERIFIED links only.

        For tracing corroboration to its roots (Step 8): two records that
        both ultimately derive from the same source are not two producers,
        however many hops apart -- and an unverified DERIVED_FROM claim has
        proved nothing yet, so it does not shrink anyone's independence.
        """
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT parent_evidence_id, child_evidence_id "
                "FROM evidence_relationships "
                "WHERE relationship_type = 'DERIVED_FROM' AND state = 'VERIFIED'"
            ).fetchall()

        edges: dict[str, list[str]] = {}
        for row in rows:
            edges.setdefault(str(row["child_evidence_id"]), []).append(
                str(row["parent_evidence_id"])
            )
        return {child: tuple(parents) for child, parents in edges.items()}

    def set_evidence_state(
        self,
        evidence_id: str,
        *,
        expected_version: int,
        state: str,
        lock_reason: str = "",
        lock_detail: str = "",
        now_ms: int | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> bool:
        """Compare-and-set one record's eligibility, bumping its version.

        Version-guarded, so two concurrent ingestion passes cannot leave
        contradictory eligibility: the loser sees False and re-reads.
        """
        owns_connection = connection is None
        connection = connection or self._connect()

        try:
            cursor = connection.execute(
                """
                UPDATE evidence
                SET state = ?, lock_reason = ?, lock_detail = ?,
                    version = version + 1, updated_at_ms = ?
                WHERE evidence_id = ? AND version = ?
                """,
                (
                    str(state), str(lock_reason), str(lock_detail),
                    int(now_ms if now_ms is not None else time.time() * 1000),
                    str(evidence_id).strip(), int(expected_version),
                ),
            )
            if owns_connection:
                connection.commit()
            return int(cursor.rowcount or 0) == 1

        except Exception:
            if owns_connection:
                connection.rollback()
            raise

        finally:
            if owns_connection:
                connection.close()

    def invalidate_relationship(
        self, relationship_id: str, *, reason: str
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE evidence_relationships
                SET state = 'INVALIDATED', invalidated_reason = ?
                WHERE relationship_id = ? AND state <> 'INVALIDATED'
                """,
                (str(reason), str(relationship_id).strip()),
            )
            return int(cursor.rowcount or 0) == 1

    def record_evidence_review(
        self,
        *,
        review_id: str,
        evidence_id: str,
        evidence_version: int,
        disposition: str,
        operator_id: str,
        identity_type: str,
        reason: str,
        decided_at_ms: int,
        new_state: str,
        new_lock_reason: str = "",
        new_lock_detail: str = "",
        audit_reference: str = "",
    ) -> bool:
        """Record one human decision about evidence AND apply it, atomically.

        Both happen in one transaction: a disposition that cannot be durably
        recorded must not change what the system will count. The review row
        keeps the state and lock the record carried when the human saw it, so
        a release never rewrites the history it was granted against.

        Returns False when the record changed since the human reviewed it --
        the decision is refused rather than applied to something else.
        """
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state, lock_reason, version FROM evidence "
                "WHERE evidence_id = ?",
                (str(evidence_id).strip(),),
            ).fetchone()

            if row is None or int(row["version"]) != int(evidence_version):
                connection.rollback()
                return False

            now_ms = int(decided_at_ms)

            connection.execute(
                """
                INSERT INTO evidence_reviews (
                    review_id, evidence_id, evidence_version, disposition,
                    operator_id, identity_type, reason, decided_at_ms,
                    prior_state, prior_lock_reason, audit_reference
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(review_id), str(evidence_id).strip(),
                    int(evidence_version), str(disposition), str(operator_id),
                    str(identity_type), str(reason), now_ms,
                    str(row["state"]), str(row["lock_reason"]),
                    str(audit_reference),
                ),
            )

            cursor = connection.execute(
                """
                UPDATE evidence
                SET state = ?, lock_reason = ?, lock_detail = ?,
                    version = version + 1, updated_at_ms = ?
                WHERE evidence_id = ? AND version = ?
                """,
                (
                    str(new_state), str(new_lock_reason), str(new_lock_detail),
                    now_ms, str(evidence_id).strip(), int(evidence_version),
                ),
            )
            if int(cursor.rowcount or 0) != 1:
                connection.rollback()
                return False

            connection.commit()
            return True

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def set_review_audit_reference(
        self, review_id: str, *, audit_reference: str
    ) -> bool:
        """Attach the audit ledger's reference to a review row already
        written -- used when the audit append happens (necessarily) after
        the review transaction commits, so the reference cannot be known
        until then. Best-effort: a failure here does not undo the review."""
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE evidence_reviews SET audit_reference = ? "
                "WHERE review_id = ?",
                (str(audit_reference), str(review_id).strip()),
            )
            return int(cursor.rowcount or 0) == 1

    def reviews_of(self, evidence_id: str) -> tuple[Mapping[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence_reviews WHERE evidence_id = ? "
                "ORDER BY decided_at_ms ASC",
                (str(evidence_id).strip(),),
            ).fetchall()
        return tuple(MappingProxyType(dict(row)) for row in rows)

    def list_evidence(
        self,
        *,
        state: str | None = None,
        subject_value: str | None = None,
        producer: str | None = None,
        incident_id: str | None = None,
        limit: int = 200,
    ) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("limit must be an integer")
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")

        clauses: list[str] = []
        params: list[Any] = []
        if state is not None:
            clauses.append("state = ?")
            params.append(str(state))
        if subject_value is not None:
            clauses.append("subject_value = ?")
            params.append(str(subject_value))
        if producer is not None:
            clauses.append("producer = ?")
            params.append(str(producer))
        if incident_id is not None:
            clauses.append("incident_id = ?")
            params.append(str(incident_id))

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM evidence {where} "
                "ORDER BY observed_at_ms DESC LIMIT ?",
                tuple(params),
            ).fetchall()

        return tuple(self._evidence_row(row) for row in rows)

    def count_evidence(self, *, state: str | None = None) -> int:
        with self._connect() as connection:
            if state is None:
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM evidence"
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM evidence WHERE state = ?",
                    (str(state),),
                ).fetchone()
        return int(row["n"]) if row is not None else 0

    # -- producer trust registry ---------------------------------------------
    #
    # The ONLY durable record of what a producer is trusted to do. Written
    # only by an explicit registration/revocation call (never from a
    # producer's own payload); read by the ledger at eligibility-evaluation
    # time so a revocation takes effect on re-evaluation without needing to
    # rewrite every evidence row it touches.
    def set_producer_trust(
        self,
        producer: str,
        *,
        trust: str,
        updated_by: str,
        reason: str = "",
        now_ms: int | None = None,
    ) -> None:
        producer = str(producer).strip()
        if not producer:
            raise ValueError("producer must not be empty")
        moment = int(now_ms if now_ms is not None else time.time() * 1000)

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO evidence_producers (
                    producer, trust, registered_at_ms, updated_at_ms,
                    updated_by, reason
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(producer) DO UPDATE SET
                    trust = excluded.trust,
                    updated_at_ms = excluded.updated_at_ms,
                    updated_by = excluded.updated_by,
                    reason = excluded.reason
                """,
                (producer, str(trust), moment, moment, str(updated_by), str(reason)),
            )

    def get_producer_trust(self, producer: str) -> Mapping[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM evidence_producers WHERE producer = ?",
                (str(producer).strip(),),
            ).fetchone()
        return MappingProxyType(dict(row)) if row is not None else None

    def list_producers(self) -> tuple[Mapping[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence_producers ORDER BY producer"
            ).fetchall()
        return tuple(MappingProxyType(dict(row)) for row in rows)

    def list_evidence_by_producer(
        self, producer: str, *, limit: int = 1000
    ) -> tuple[Mapping[str, Any], ...]:
        """Every record from one producer, for a revocation's re-evaluation
        pass. Bounded, like every other evidence read."""
        if not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence WHERE producer = ? "
                "ORDER BY observed_at_ms ASC LIMIT ?",
                (str(producer).strip(), int(limit)),
            ).fetchall()
        return tuple(self._evidence_row(row) for row in rows)

    def cleanup_terminal_actions(
        self,
        *,
        retention_days: int,
        now_ms: int | None = None,
    ) -> int:
        if not isinstance(retention_days, int) or isinstance(
            retention_days,
            bool,
        ):
            raise TypeError("retention_days must be an integer")

        if not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")

        effective_now_ms = (
            int(time.time() * 1000)
            if now_ms is None
            else int(now_ms)
        )

        cutoff_ms = (
            effective_now_ms
            - retention_days * 86_400 * 1000
        )

        terminal_values = tuple(
            status.value
            for status in _TERMINAL_ACTION_STATUSES
        )

        placeholders = ",".join(
            "?"
            for _ in terminal_values
        )

        query = (
            "DELETE FROM pending_actions "
            "WHERE created_at_ms < ? "
            f"AND status IN ({placeholders})"
        )

        with self._connect() as connection:
            cursor = connection.execute(
                query,
                (cutoff_ms, *terminal_values),
            )
            return int(cursor.rowcount or 0)


__all__ = [
    "ActionStatus",
    "CoreStoreConfig",
    "IncidentStatus",
    "PendingAction",
    "SentinelCoreStore",
]
