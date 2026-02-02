from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


# ============================================================
# DB CORE (Sentinel-43)
# - audit logs
# - staged actions
# - dedupe TTL
# - atomic status transitions
# ============================================================

DEFAULT_DB_DIR = Path(os.getenv("SENTINEL43_DATA_DIR", str(Path.cwd() / "sentinel43_state")))
DEFAULT_DB_PATH = Path(os.getenv("SENTINEL43_DB_PATH", str(DEFAULT_DB_DIR / "sentinel43.sqlite3")))

DEFAULT_LOG_RETENTION_DAYS = int(os.getenv("SENTINEL43_LOG_RETENTION_DAYS", "90"))
DEFAULT_ACTION_RETENTION_DAYS = int(os.getenv("SENTINEL43_ACTION_RETENTION_DAYS", "30"))


def _utc_iso() -> str:
    # microseconds for ordering; OK for logs
    import datetime as _dt
    return _dt.datetime.utcnow().isoformat(timespec="microseconds") + "Z"


def _json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _db_conn(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


class ActionStatus(str):
    # string “enum” to keep DB simple in one file
    SHADOWED = "SHADOWED"
    STAGED = "STAGED"
    PENDING = "PENDING"
    VETOED = "VETOED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class PendingActionRow:
    action_id: str
    created_at_ms: int
    execute_at_ms: Optional[int]
    status: str

    target_type: str
    target_value: str

    primary_action: str
    actions_json: str

    severity: str
    kind: str
    source_kind: str
    score: float

    reason: str
    system_id: str

    operator_id: Optional[str] = None
    operator_reason: Optional[str] = None


class SentinelCoreStore:
    """
    Core DB store:
    - keep it boring
    - no network I/O
    - no enforcement
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.ensure_schema()
        # best-effort cleanup at boot
        try:
            self.cleanup_old_logs(DEFAULT_LOG_RETENTION_DAYS)
            self.cleanup_old_actions(DEFAULT_ACTION_RETENTION_DAYS)
            self.dedupe_cleanup()
        except Exception:
            pass

    # -------------------------
    # Schema
    # -------------------------
    def ensure_schema(self) -> None:
        with _db_conn(self.db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS event_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    module TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context_json TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_event_logs_ts ON event_logs(timestamp);

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
                    score REAL NOT NULL,

                    reason TEXT NOT NULL,
                    system_id TEXT NOT NULL,

                    operator_id TEXT,
                    operator_reason TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_actions(status);
                CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_actions(created_at_ms);

                CREATE TABLE IF NOT EXISTS action_dedupe (
                    dedupe_key TEXT PRIMARY KEY,
                    expires_at_ms INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dedupe_exp ON action_dedupe(expires_at_ms);
                """
            )

    # -------------------------
    # Logging
    # -------------------------
    def log_event(self, level: str, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        with _db_conn(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO event_logs (timestamp, level, module, message, context_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (_utc_iso(), str(level), str(module), str(message), _json(context) if context else None),
            )

    # -------------------------
    # Dedupe (atomic)
    # -------------------------
    def dedupe_allow(self, dedupe_key: str, ttl_seconds: int) -> bool:
        """
        Returns True if allowed (not seen in TTL).
        Atomic insert with UNIQUE constraint.
        """
        now_ms = int(time.time() * 1000)
        exp_ms = now_ms + int(max(1, ttl_seconds) * 1000)

        k = (dedupe_key or "").strip()
        if not k:
            return True  # if caller gives nothing, don't brick the pipeline
        if len(k) > 512:
            k = k[:512]

        with _db_conn(self.db_path) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM action_dedupe WHERE expires_at_ms <= ?", (now_ms,))
                conn.execute("INSERT INTO action_dedupe (dedupe_key, expires_at_ms) VALUES (?, ?)", (k, exp_ms))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            except Exception:
                conn.rollback()
                raise

    def dedupe_cleanup(self) -> int:
        now_ms = int(time.time() * 1000)
        with _db_conn(self.db_path) as conn:
            cur = conn.execute("DELETE FROM action_dedupe WHERE expires_at_ms <= ?", (now_ms,))
            return int(cur.rowcount or 0)

    # -------------------------
    # Pending actions
    # -------------------------
    def insert_pending(self, row: PendingActionRow) -> None:
        with _db_conn(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO pending_actions (
                    action_id, created_at_ms, execute_at_ms, status,
                    target_type, target_value,
                    primary_action, actions_json,
                    severity, kind, source_kind, score,
                    reason, system_id,
                    operator_id, operator_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.action_id, row.created_at_ms, row.execute_at_ms, row.status,
                    row.target_type, row.target_value,
                    row.primary_action, row.actions_json,
                    row.severity, row.kind, row.source_kind, float(row.score),
                    row.reason, row.system_id,
                    row.operator_id, row.operator_reason,
                ),
            )

    def get_status(self, action_id: str) -> Optional[str]:
        with _db_conn(self.db_path) as conn:
            r = conn.execute("SELECT status FROM pending_actions WHERE action_id=?", (action_id,)).fetchone()
            return str(r["status"]) if r else None

    def transition_status(
        self,
        action_id: str,
        *,
        expected: str,
        new_status: str,
        operator_id: Optional[str] = None,
        operator_reason: Optional[str] = None,
    ) -> bool:
        """
        Atomic state transition: update only if current status matches expected.
        Prevents “approve twice” / “veto after executed” races.
        """
        op = (operator_id or "").strip()[:80] or None
        rsn = (operator_reason or "").strip()[:300] or None

        with _db_conn(self.db_path) as conn:
            cur = conn.execute(
                """
                UPDATE pending_actions
                   SET status=?, operator_id=?, operator_reason=?
                 WHERE action_id=?
                   AND status=?
                """,
                (new_status, op, rsn, action_id, expected),
            )
            return (cur.rowcount or 0) > 0

    def list_actions(self, *, status: Optional[str] = None, limit: int = 200) -> list[dict]:
        lim = max(1, min(int(limit), 1000))
        with _db_conn(self.db_path) as conn:
            if status:
                rows = conn.execute(
                    """
                    SELECT * FROM pending_actions
                     WHERE status=?
                     ORDER BY created_at_ms DESC
                     LIMIT ?
                    """,
                    (status, lim),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM pending_actions
                     ORDER BY created_at_ms DESC
                     LIMIT ?
                    """,
                    (lim,),
                ).fetchall()
            return [dict(r) for r in rows]

    # -------------------------
    # Retention cleanup
    # -------------------------
    def cleanup_old_logs(self, retention_days: int) -> int:
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(retention_days))
        cutoff_iso = cutoff.isoformat(timespec="seconds")
        with _db_conn(self.db_path) as conn:
            cur = conn.execute("DELETE FROM event_logs WHERE timestamp < ?", (cutoff_iso,))
            return int(cur.rowcount or 0)

    def cleanup_old_actions(self, retention_days: int) -> int:
        cutoff_ms = int((time.time() - (int(retention_days) * 86400)) * 1000)
        with _db_conn(self.db_path) as conn:
            cur = conn.execute(
                """
                DELETE FROM pending_actions
                 WHERE created_at_ms < ?
                   AND status IN (?, ?, ?, ?)
                """,
                (cutoff_ms, ActionStatus.VETOED, ActionStatus.APPROVED, ActionStatus.EXECUTED, ActionStatus.EXPIRED),
            )
            return int(cur.rowcount or 0)