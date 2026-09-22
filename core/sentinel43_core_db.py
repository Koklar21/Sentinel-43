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
                    operator_reason TEXT
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
                """
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
                    operator_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    "PendingAction",
    "SentinelCoreStore",
]
