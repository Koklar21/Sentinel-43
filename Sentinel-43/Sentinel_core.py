# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Justin
#
# SENTINEL-43: Intelligent Log Triage & Response Orchestrator (Hardened Foundation)
#
# Hardened features implemented (actually, not just claimed):
# - SQLite connection pool with proper cleanup
# - BEGIN IMMEDIATE transactions for all state operations (no lost updates)
# - Tamper-evident audit chain with optimistic locking + retry
# - heapq scheduler (O(log n)) + cancel race mitigation
# - Background cleanup thread (no cleanup on hot path)
# - Indexes for cleanup queries
# - Action execution timeout wrapper that does NOT deadlock scheduler threads
# - Graceful shutdown with queue drain
# - Immutable metadata copy
# - Input validation
# - Configurable delays + metrics

from __future__ import annotations

import datetime as _dt
import hashlib
import heapq
import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging (NO basicConfig here. Orchestration owns global logging.)
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

SYSTEM_ID = "SENTINEL-43-NODE-01"


# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------

class DeploymentMode(Enum):
    SHADOW = auto()           # Log-only, no actions executed
    HUMAN_GATED = auto()      # Actions staged, require explicit approval
    AUTONOMOUS_VETO = auto()  # Actions execute after delay unless vetoed


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EventType(Enum):
    SYSTEM = "SYSTEM"
    ALERT = "ALERT"
    ACTION_STAGE = "ACTION_STAGE"
    ACTION_EXECUTE = "ACTION_EXECUTE"
    ACTION_VETO = "ACTION_VETO"
    CONFIG = "CONFIG"
    ERROR = "ERROR"
    DROP = "DROP"
    REPLAY = "REPLAY"
    BUDGET = "BUDGET"
    CORROBORATE = "CORROBORATE"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class AnomalyRecord:
    module_id: str
    description: str
    severity: RiskLevel
    detected_at: _dt.datetime
    metadata: Dict[str, Any]
    event_id: str

    def __post_init__(self) -> None:
        # Copy to prevent external mutation. "Frozen" doesn't freeze nested dicts.
        object.__setattr__(self, "metadata", dict(self.metadata or {}))


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    description: str
    created_at: _dt.datetime
    delay_seconds: int
    risk_level: RiskLevel
    payload: Callable[[], None]
    principal_id: str


@dataclass
class Metrics:
    events_ingested: int = 0
    events_dropped_validation: int = 0
    events_dropped_replay: int = 0
    events_dropped_backpressure: int = 0
    actions_triggered: int = 0
    actions_budget_denied: int = 0
    actions_corroboration_wait: int = 0
    actions_executed: int = 0
    actions_vetoed: int = 0
    actions_timeout: int = 0

    def snapshot(self) -> Dict[str, int]:
        return {
            "events_ingested": self.events_ingested,
            "events_dropped_validation": self.events_dropped_validation,
            "events_dropped_replay": self.events_dropped_replay,
            "events_dropped_backpressure": self.events_dropped_backpressure,
            "actions_triggered": self.actions_triggered,
            "actions_budget_denied": self.actions_budget_denied,
            "actions_corroboration_wait": self.actions_corroboration_wait,
            "actions_executed": self.actions_executed,
            "actions_vetoed": self.actions_vetoed,
            "actions_timeout": self.actions_timeout,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> _dt.datetime:
    # Naive UTC for stable ISO handling in SQLite text fields.
    return _dt.datetime.utcnow().replace(tzinfo=None)


def _iso_utc(dt: _dt.datetime, *, seconds: bool = False) -> str:
    if seconds:
        return dt.isoformat(timespec="seconds") + "Z"
    return dt.isoformat(timespec="microseconds") + "Z"


def _safe_str(val: Any, *, max_len: int) -> str:
    s = str(val)
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s


def _canonical_json(obj: Any, *, max_len: int) -> str:
    s = json.dumps(obj, separators=(",", ":"), sort_keys=True, default=str)
    if len(s) > max_len:
        raise ValueError(f"context_json too large ({len(s)} > {max_len})")
    return s


def _hash_str(blob: str) -> str:
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _default_event_id(module_id: str, detected_at: _dt.datetime, description: str, metadata: Dict[str, Any]) -> str:
    base = {
        "module_id": module_id,
        "detected_at": _iso_utc(detected_at, seconds=True),
        "description": description,
        "meta_hash": _hash_str(_canonical_json(metadata or {}, max_len=20_000)),
    }
    return _hash_str(_canonical_json(base, max_len=20_000))


def execute_with_timeout(fn: Callable[[], None], *, timeout_seconds: int) -> Tuple[bool, Optional[str]]:
    """
    Thread-based timeout wrapper:
    - Prevents scheduler thread from blocking forever.
    - IMPORTANT LIMITATION: Python can't kill a stuck thread. If fn hangs, it may continue running.
      That's a reality problem, not a "you problem". Use subprocesses for hard-kill.
    """
    done = threading.Event()
    err: List[str] = []

    def _runner() -> None:
        try:
            fn()
        except Exception as exc:
            err.append(str(exc))
        finally:
            done.set()

    t = threading.Thread(target=_runner, daemon=True, name="sentinel43-action")
    t.start()

    if done.wait(timeout=max(0, int(timeout_seconds))):
        if err:
            return False, err[0]
        return True, None

    return False, f"timeout_after_{timeout_seconds}s"


# ---------------------------------------------------------------------------
# SQLite Audit + State (Connection Pool + Transactions + Chain)
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    - Pooled SQLite connections (check_same_thread=False)
    - BEGIN IMMEDIATE for correctness under concurrency
    - Append-only audit log with hash chaining
    - Replay table: seen_events
    - Budget table: action_budget
    - Corroboration table: corroboration
    """

    def __init__(self, db_path: Path, *, journal_mode: str = "WAL", pool_size: int = 5):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.journal_mode = journal_mode
        self._pool: "Queue[sqlite3.Connection]" = Queue(maxsize=max(1, int(pool_size)))
        self._pool_size = max(1, int(pool_size))

        # Serialize audit chain updates for ordering stability (chain correctness).
        self._chain_lock = threading.RLock()

        for _ in range(self._pool_size):
            self._pool.put(self._create_connection())

        self._init_db()

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=30,
            isolation_level=None,
        )
        conn.execute(f"PRAGMA journal_mode={self.journal_mode};")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    @contextmanager
    def _conn_txn(self) -> sqlite3.Connection:
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = self._pool.get(timeout=5.0)
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.execute("COMMIT;")
        except Empty as exc:
            raise RuntimeError("Connection pool exhausted") from exc
        except Exception:
            if conn is not None:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
            raise
        finally:
            if conn is not None:
                try:
                    self._pool.put(conn, timeout=5.0)
                except Full:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def close(self) -> None:
        while True:
            try:
                conn = self._pool.get_nowait()
            except Empty:
                break
            try:
                conn.close()
            except Exception:
                pass

    def _init_db(self) -> None:
        with self._conn_txn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    module TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context_json TEXT,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(timestamp);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_chain_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    last_hash TEXT NOT NULL
                );
                """
            )
            row = conn.execute("SELECT last_hash FROM audit_chain_state WHERE id=1;").fetchone()
            if not row:
                conn.execute("INSERT INTO audit_chain_state (id, last_hash) VALUES (1, ?);", ("0" * 64,))

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS staged_actions (
                    action_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    operator_id TEXT,
                    decided_at TEXT
                );
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_events (
                    event_id TEXT PRIMARY KEY,
                    first_seen_at TEXT NOT NULL,
                    module_id TEXT NOT NULL,
                    severity TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_seen_first ON seen_events(first_seen_at);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS action_budget (
                    principal_id TEXT PRIMARY KEY,
                    window_start TEXT NOT NULL,
                    used_count INTEGER NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_budget_window ON action_budget(window_start);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS corroboration (
                    key TEXT PRIMARY KEY,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    count INTEGER NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_last ON corroboration(last_seen_at);")

    @staticmethod
    def _hash_event(
        *,
        timestamp: str,
        system_id: str,
        event_type: str,
        module: str,
        message: str,
        context_json: Optional[str],
        prev_hash: str,
    ) -> str:
        payload = {
            "timestamp": timestamp,
            "system_id": system_id,
            "event_type": event_type,
            "module": module,
            "message": message,
            "context_json": context_json,
            "prev_hash": prev_hash,
        }
        blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def append(
        self,
        event_type: EventType,
        module: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        *,
        max_context_json: int = 20_000,
    ) -> None:
        ts = _iso_utc(_utcnow())
        context_json = _canonical_json(context, max_len=max_context_json) if context is not None else None

        max_retries = 5
        backoff = 0.01

        for attempt in range(max_retries):
            try:
                with self._chain_lock, self._conn_txn() as conn:
                    prev_hash = conn.execute(
                        "SELECT last_hash FROM audit_chain_state WHERE id=1;"
                    ).fetchone()[0]

                    event_hash = self._hash_event(
                        timestamp=ts,
                        system_id=SYSTEM_ID,
                        event_type=event_type.value,
                        module=module,
                        message=message,
                        context_json=context_json,
                        prev_hash=prev_hash,
                    )

                    conn.execute(
                        """
                        INSERT INTO audit_events
                        (timestamp, system_id, event_type, module, message, context_json, prev_hash, event_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (ts, SYSTEM_ID, event_type.value, module, message, context_json, prev_hash, event_hash),
                    )

                    rc = conn.execute(
                        "UPDATE audit_chain_state SET last_hash=? WHERE id=1 AND last_hash=?;",
                        (event_hash, prev_hash),
                    ).rowcount

                    if rc != 1:
                        raise sqlite3.IntegrityError("audit_chain_state_changed")

                    return
            except sqlite3.IntegrityError:
                if attempt == max_retries - 1:
                    raise
                time.sleep(backoff)
                backoff *= 2

    # ---- Staging (HUMAN_GATED) ----

    def stage_action(self, action_id: str, description: str, severity: RiskLevel, context: Dict[str, Any]) -> None:
        created_at = _iso_utc(_utcnow(), seconds=True)
        ctx = _canonical_json(context, max_len=20_000)
        with self._conn_txn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO staged_actions
                (action_id, created_at, description, severity, context_json, status)
                VALUES (?, ?, ?, ?, ?, 'STAGED');
                """,
                (action_id, created_at, description, severity.value, ctx),
            )

    def get_staged_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        with self._conn_txn() as conn:
            row = conn.execute(
                """
                SELECT action_id, created_at, description, severity, context_json, status, operator_id, decided_at
                FROM staged_actions WHERE action_id = ?;
                """,
                (action_id,),
            ).fetchone()

        if not row:
            return None

        return {
            "action_id": row[0],
            "created_at": row[1],
            "description": row[2],
            "severity": row[3],
            "context": json.loads(row[4]),
            "status": row[5],
            "operator_id": row[6],
            "decided_at": row[7],
        }

    def mark_action_decision(self, action_id: str, *, status: str, operator_id: str) -> None:
        decided_at = _iso_utc(_utcnow(), seconds=True)
        with self._conn_txn() as conn:
            conn.execute(
                """
                UPDATE staged_actions
                SET status=?, operator_id=?, decided_at=?
                WHERE action_id=?;
                """,
                (status, operator_id, decided_at, action_id),
            )

    # ---- Replay table ----

    def record_event_if_new(self, event_id: str, module_id: str, severity: RiskLevel) -> bool:
        now = _iso_utc(_utcnow(), seconds=True)
        with self._conn_txn() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO seen_events(event_id, first_seen_at, module_id, severity)
                    VALUES (?, ?, ?, ?);
                    """,
                    (event_id, now, module_id, severity.value),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def cleanup_seen_events(self, *, ttl_seconds: int) -> None:
        cutoff = _utcnow() - _dt.timedelta(seconds=int(ttl_seconds))
        cutoff_s = _iso_utc(cutoff, seconds=True)
        with self._conn_txn() as conn:
            conn.execute("DELETE FROM seen_events WHERE first_seen_at < ?;", (cutoff_s,))

    # ---- Budget ----

    def consume_action_budget(self, principal_id: str, *, window_seconds: int, max_actions: int) -> bool:
        now = _utcnow()
        window_start = now.replace(microsecond=0)
        window_start_s = _iso_utc(window_start, seconds=True)

        with self._conn_txn() as conn:
            row = conn.execute(
                "SELECT window_start, used_count FROM action_budget WHERE principal_id=?;",
                (principal_id,),
            ).fetchone()

            if not row:
                conn.execute(
                    "INSERT INTO action_budget(principal_id, window_start, used_count) VALUES (?, ?, ?);",
                    (principal_id, window_start_s, 1),
                )
                return True

            prev_start = _dt.datetime.fromisoformat(row[0].replace("Z", ""))
            used = int(row[1])

            if (now - prev_start).total_seconds() > float(window_seconds):
                conn.execute(
                    "UPDATE action_budget SET window_start=?, used_count=? WHERE principal_id=?;",
                    (window_start_s, 1, principal_id),
                )
                return True

            if used >= int(max_actions):
                return False

            conn.execute(
                "UPDATE action_budget SET used_count = used_count + 1 WHERE principal_id=?;",
                (principal_id,),
            )
            return True

    # ---- Corroboration ----

    def corroboration_bump(self, key: str, *, ttl_seconds: int) -> int:
        now = _utcnow()
        now_s = _iso_utc(now, seconds=True)

        with self._conn_txn() as conn:
            row = conn.execute(
                "SELECT first_seen_at, last_seen_at, count FROM corroboration WHERE key=?;",
                (key,),
            ).fetchone()

            if not row:
                conn.execute(
                    """
                    INSERT INTO corroboration(key, first_seen_at, last_seen_at, count)
                    VALUES (?, ?, ?, ?);
                    """,
                    (key, now_s, now_s, 1),
                )
                return 1

            last_seen = _dt.datetime.fromisoformat(row[1].replace("Z", ""))
            count = int(row[2])

            if (now - last_seen).total_seconds() > float(ttl_seconds):
                conn.execute(
                    """
                    UPDATE corroboration
                    SET first_seen_at=?, last_seen_at=?, count=?
                    WHERE key=?;
                    """,
                    (now_s, now_s, 1, key),
                )
                return 1

            conn.execute(
                """
                UPDATE corroboration
                SET last_seen_at=?, count=count+1
                WHERE key=?;
                """,
                (now_s, key),
            )
            return count + 1

    def cleanup_corroboration(self, *, ttl_seconds: int) -> None:
        cutoff = _utcnow() - _dt.timedelta(seconds=int(ttl_seconds))
        cutoff_s = _iso_utc(cutoff, seconds=True)
        with self._conn_txn() as conn:
            conn.execute("DELETE FROM corroboration WHERE last_seen_at < ?;", (cutoff_s,))


# ---------------------------------------------------------------------------
# Scheduler (heapq + cancel + no deadlock on hung payload)
# ---------------------------------------------------------------------------

@dataclass(order=True)
class _SchedItem:
    due_ts: float
    seq: int
    action_id: str = field(compare=False)
    run: Callable[[], None] = field(compare=False)


class Scheduler:
    def __init__(self, audit: AuditLogger):
        self._audit = audit
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)

        self._heap: List[_SchedItem] = []
        self._seq = 0
        self._cancelled: set[str] = set()
        self._executing: set[str] = set()
        self._stop = False

        self._thread = threading.Thread(target=self._loop, daemon=True, name="sentinel43-scheduler")
        self._thread.start()

    def schedule(self, action_id: str, delay_seconds: int, run: Callable[[], None]) -> None:
        due = time.time() + max(0, int(delay_seconds))
        with self._cv:
            self._seq += 1
            heapq.heappush(self._heap, _SchedItem(due, self._seq, action_id, run))
            self._cv.notify()

    def cancel(self, action_id: str) -> None:
        with self._cv:
            self._cancelled.add(action_id)
            self._cv.notify()

    def shutdown(self, *, timeout: float = 30.0) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify()

        start = time.time()
        while True:
            with self._cv:
                if not self._executing:
                    break
            if (time.time() - start) >= timeout:
                logger.warning("[SCHEDULER] Shutdown timeout: %s actions still executing.", len(self._executing))
                break
            time.sleep(0.1)

        self._thread.join(timeout=5)

    def _loop(self) -> None:
        while True:
            with self._cv:
                if self._stop:
                    return

                if not self._heap:
                    self._cv.wait(timeout=1.0)
                    continue

                item = self._heap[0]
                now = time.time()

                if item.due_ts > now:
                    self._cv.wait(timeout=min(1.0, item.due_ts - now))
                    continue

                heapq.heappop(self._heap)

                if item.action_id in self._cancelled:
                    self._cancelled.discard(item.action_id)
                    continue

                self._executing.add(item.action_id)

            try:
                item.run()
            except Exception as exc:
                self._audit.append(
                    EventType.ERROR, "SCHEDULER",
                    f"Execution failed for {item.action_id}: {exc}",
                    {"action_id": item.action_id},
                )
            finally:
                with self._cv:
                    self._executing.discard(item.action_id)
                    self._cancelled.discard(item.action_id)


# ---------------------------------------------------------------------------
# Oversight Engine (veto window + timeout-safe execution)
# ---------------------------------------------------------------------------

class OversightEngine:
    def __init__(
        self,
        audit: AuditLogger,
        scheduler: Scheduler,
        notify_callback: Callable[[str], None],
        metrics: Metrics,
        *,
        action_timeout_seconds: int = 30,
    ):
        self._audit = audit
        self._scheduler = scheduler
        self._notify = notify_callback
        self._metrics = metrics
        self._action_timeout_seconds = int(action_timeout_seconds)

        self._lock = threading.RLock()
        self._pending: Dict[str, PendingAction] = {}

    def schedule_vetoable_action(self, action: PendingAction) -> None:
        with self._lock:
            if action.action_id in self._pending:
                logger.warning("[OVERSIGHT] Duplicate pending action ignored: %s", action.action_id)
                return
            self._pending[action.action_id] = action

        msg = f"[PENDING] {action.description} | Risk={action.risk_level.value} | Exec in {action.delay_seconds}s unless vetoed."
        self._audit.append(
            EventType.ACTION_STAGE, "OVERSIGHT", msg,
            {"action_id": action.action_id, "principal_id": action.principal_id, "risk": action.risk_level.value,
             "delay_seconds": action.delay_seconds},
        )

        def _run() -> None:
            with self._lock:
                act = self._pending.pop(action.action_id, None)
            if not act:
                return

            msg2 = f"[AUTO] Executing: {act.description}"
            self._audit.append(
                EventType.ACTION_EXECUTE, "OVERSIGHT", msg2,
                {"action_id": act.action_id, "principal_id": act.principal_id},
            )

            ok, err = execute_with_timeout(act.payload, timeout_seconds=self._action_timeout_seconds)
            if ok:
                self._metrics.actions_executed += 1
                self._notify(f"Action executed: {act.description}")
                return

            if err and err.startswith("timeout_after_"):
                self._metrics.actions_timeout += 1
                self._audit.append(EventType.TIMEOUT, "OVERSIGHT", f"Action timed out: {act.action_id}", {
                    "action_id": act.action_id,
                    "timeout_seconds": self._action_timeout_seconds,
                })
                return

            self._audit.append(EventType.ERROR, "OVERSIGHT", f"Action failed: {act.action_id} | {err}", {
                "action_id": act.action_id,
                "error": err,
            })

        self._scheduler.schedule(action.action_id, action.delay_seconds, _run)

    def veto_action(self, action_id: str, operator_id: str, reason: str) -> bool:
        with self._lock:
            act = self._pending.pop(action_id, None)

        if not act:
            logger.warning("[OVERSIGHT] Veto failed (not pending): %s", action_id)
            return False

        self._scheduler.cancel(action_id)

        msg = f"[VETOED] {act.description} | Operator={operator_id} | Reason={_safe_str(reason, max_len=300)}"
        self._audit.append(
            EventType.ACTION_VETO, "OVERSIGHT", msg,
            {"action_id": act.action_id, "operator_id": operator_id, "reason": _safe_str(reason, max_len=300)},
        )
        self._metrics.actions_vetoed += 1
        self._notify(f"Action vetoed: {action_id} by {operator_id}")
        return True

    def snapshot_pending(self) -> List[PendingAction]:
        with self._lock:
            return list(self._pending.values())


# ---------------------------------------------------------------------------
# Watchtower (synthetic demo)
# ---------------------------------------------------------------------------

class WatchtowerConfig:
    def __init__(self, module_id: str, description: str, enabled: bool = True, sensitivity: float = 1.0):
        self.module_id = module_id
        self.description = description
        self.enabled = enabled
        self.sensitivity = float(sensitivity)
        self.last_scan: Optional[_dt.datetime] = None


class WatchtowerManager:
    def __init__(self, audit: AuditLogger):
        self._audit = audit
        self.modules: Dict[str, WatchtowerConfig] = {}
        self._init_standard_modules()

    def _init_standard_modules(self) -> None:
        self.modules["WT_01_RES_MON"] = WatchtowerConfig("WT_01_RES_MON", "System Resource Allocation Monitor")
        self.modules["WT_02_NET_ING"] = WatchtowerConfig("WT_02_NET_ING", "Network Ingress/Egress Traffic Analysis")
        self.modules["WT_03_IAM_AUD"] = WatchtowerConfig("WT_03_IAM_AUD", "Identity Access Management Audit Logger")
        self.modules["WT_04_INT_VER"] = WatchtowerConfig("WT_04_INT_VER", "File System Integrity Verification Service")

    def configure_module(self, module_id: str, *, enabled: Optional[bool] = None, sensitivity: Optional[float] = None) -> None:
        mod = self.modules.get(module_id)
        if not mod:
            self._audit.append(EventType.ERROR, "WATCHTOWER", f"Module not found: {module_id}")
            return

        if enabled is not None:
            mod.enabled = bool(enabled)
        if sensitivity is not None:
            mod.sensitivity = float(sensitivity)

        self._audit.append(
            EventType.CONFIG, "WATCHTOWER",
            f"Updated {module_id}: enabled={mod.enabled}, sensitivity={mod.sensitivity}",
        )

    def perform_scan(self) -> List[AnomalyRecord]:
        import random

        anomalies: List[AnomalyRecord] = []
        now = _utcnow()

        for module_id, mod in self.modules.items():
            if not mod.enabled:
                continue

            mod.last_scan = now
            risk_factor = random.random()
            threshold = 0.1 * mod.sensitivity

            if risk_factor < threshold:
                severity = RiskLevel.HIGH if mod.sensitivity >= 1.5 else RiskLevel.MEDIUM
                desc = f"Anomaly in {mod.description} (risk_factor={risk_factor:.3f}, threshold={threshold:.3f})"
                meta: Dict[str, Any] = {"risk_factor": risk_factor, "threshold": threshold}

                if module_id == "WT_03_IAM_AUD":
                    meta["principal_id"] = random.choice(
                        ["svc.billing", "svc.payments", "devops.oncall", "Unknown.Principal"]
                    )

                event_id = _default_event_id(module_id, now, desc, meta)
                anomalies.append(
                    AnomalyRecord(
                        module_id=module_id,
                        description=desc,
                        severity=severity,
                        detected_at=now,
                        metadata=meta,
                        event_id=event_id,
                    )
                )

        return anomalies


# ---------------------------------------------------------------------------
# Background Cleanup
# ---------------------------------------------------------------------------

class CleanupManager:
    def __init__(
        self,
        audit: AuditLogger,
        *,
        interval_seconds: int = 60,
        replay_ttl_seconds: int = 3600,
        corroboration_ttl_seconds: int = 600,
    ):
        self._audit = audit
        self._interval = int(interval_seconds)
        self._replay_ttl = int(replay_ttl_seconds)
        self._corr_ttl = int(corroboration_ttl_seconds)

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="sentinel43-cleanup")
        self._thread.start()

    def shutdown(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.wait(timeout=max(1, self._interval)):
            try:
                self._audit.cleanup_seen_events(ttl_seconds=self._replay_ttl)
                self._audit.cleanup_corroboration(ttl_seconds=self._corr_ttl)
            except Exception as exc:
                self._audit.append(EventType.ERROR, "CLEANUP", f"Cleanup failed: {exc}")


# ---------------------------------------------------------------------------
# Sentinel Node (Orchestrator)
# ---------------------------------------------------------------------------

class SentinelNode:
    def __init__(
        self,
        *,
        mode: DeploymentMode = DeploymentMode.SHADOW,
        audit_db_path: Optional[Path] = None,
        journal_mode: str = "WAL",
        pool_size: int = 5,
        # Hardening knobs
        max_metadata_json: int = 12_000,
        replay_ttl_seconds: int = 3600,
        max_queue_size: int = 500,
        max_ingest_wait_ms: int = 25,
        # Rate limits
        action_budget_window_seconds: int = 300,
        action_budget_max_actions: int = 5,
        # Corroboration
        require_two_signals_for_high: bool = True,
        corroboration_ttl_seconds: int = 600,
        # Time sanity
        max_clock_skew_seconds: int = 300,
        # Action execution
        action_timeout_seconds: int = 30,
        # Delays by severity
        delay_low_seconds: int = 60,
        delay_medium_seconds: int = 30,
        delay_high_seconds: int = 10,
    ):
        self._lock = threading.RLock()
        self.mode = mode
        self.metrics = Metrics()

        if audit_db_path is None:
            try:
                base = Path(__file__).resolve().parent
            except NameError:
                base = Path.cwd()
            audit_db_path = base / "sentinel43_audit.sqlite3"

        self.audit = AuditLogger(audit_db_path, journal_mode=journal_mode, pool_size=pool_size)
        self.scheduler = Scheduler(self.audit)
        self.oversight = OversightEngine(
            self.audit,
            self.scheduler,
            notify_callback=self._notify_operator,
            metrics=self.metrics,
            action_timeout_seconds=action_timeout_seconds,
        )
        self.watchtowers = WatchtowerManager(self.audit)
        self.cleanup_manager = CleanupManager(
            self.audit,
            replay_ttl_seconds=replay_ttl_seconds,
            corroboration_ttl_seconds=corroboration_ttl_seconds,
        )

        self.max_metadata_json = int(max_metadata_json)
        self.replay_ttl_seconds = int(replay_ttl_seconds)
        self.max_clock_skew_seconds = int(max_clock_skew_seconds)
        self.action_budget_window_seconds = int(action_budget_window_seconds)
        self.action_budget_max_actions = int(action_budget_max_actions)
        self.require_two_signals_for_high = bool(require_two_signals_for_high)
        self.corroboration_ttl_seconds = int(corroboration_ttl_seconds)

        self.delay_low_seconds = int(delay_low_seconds)
        self.delay_medium_seconds = int(delay_medium_seconds)
        self.delay_high_seconds = int(delay_high_seconds)

        self._queue: "Queue[AnomalyRecord]" = Queue(maxsize=int(max_queue_size))
        self._max_ingest_wait_ms = int(max_ingest_wait_ms)

        self._worker_stop = threading.Event()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True, name="sentinel43-worker")
        self._worker.start()

        self._log(EventType.SYSTEM, "SYSTEM", f"[{SYSTEM_ID}] Initialization complete.")
        self._log(EventType.SYSTEM, "SYSTEM", f"Watchtower modules loaded: {len(self.watchtowers.modules)}")
        self._log(EventType.SYSTEM, "SYSTEM", f"Deployment mode: {self.mode.name}")

    # ---- Logging ----

    def _log(self, event_type: EventType, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        try:
            self.audit.append(event_type, module, message, context)
        except Exception as exc:
            logger.error("[AUDIT_FAIL] %s %s: %s | %s", event_type.value, module, message, exc)
        logger.info("[%s] %s", module, message)

    def _notify_operator(self, message: str) -> None:
        self._log(EventType.SYSTEM, "NOTIFY", message)

    # ---- Shutdown ----

    def shutdown(self, *, drain_timeout: float = 10.0) -> None:
        self._log(EventType.SYSTEM, "SYSTEM", "Shutdown requested.")

        self._worker_stop.set()

        start = time.time()
        while not self._queue.empty() and (time.time() - start) < float(drain_timeout):
            time.sleep(0.1)

        if not self._queue.empty():
            logger.warning("[SHUTDOWN] Queue drain timeout: %s items remain.", self._queue.qsize())

        # wait for worker thread to exit cleanly
        self._worker.join(timeout=5)

        self.cleanup_manager.shutdown()
        self.scheduler.shutdown()

        # LOG BEFORE closing the audit DB
        self._log(EventType.SYSTEM, "SYSTEM", "Shutdown complete.")

        # close DB connections last
        self.audit.close()

    # ---- Worker Loop ----

    def _worker_loop(self) -> None:
        while not self._worker_stop.is_set():
            try:
                anomaly = self._queue.get(timeout=0.25)
            except Empty:
                continue

            try:
                self._handle_anomaly(anomaly)
            except Exception as exc:
                self._log(EventType.ERROR, "WORKER", f"Unhandled exception: {exc}", {
                    "event_id": getattr(anomaly, "event_id", "unknown"),
                    "module_id": getattr(anomaly, "module_id", "unknown"),
                })
            finally:
                try:
                    self._queue.task_done()
                except Exception:
                    pass

    # ---- Intake Validation ----

    def _validate_anomaly(self, anomaly: AnomalyRecord) -> Tuple[bool, str]:
        if not anomaly.module_id or len(anomaly.module_id) > 64:
            return False, "invalid_module_id"
        if not anomaly.event_id or len(anomaly.event_id) > 128:
            return False, "invalid_event_id"
        if not isinstance(anomaly.detected_at, _dt.datetime):
            return False, "invalid_detected_at"

        now = _utcnow()
        skew = abs((now - anomaly.detected_at).total_seconds())
        if skew > self.max_clock_skew_seconds:
            return False, f"clock_skew_too_large({int(skew)}s)"

        if not anomaly.description or len(anomaly.description) > 500:
            return False, "invalid_description"

        try:
            _canonical_json(anomaly.metadata or {}, max_len=self.max_metadata_json)
        except Exception as exc:
            return False, f"metadata_invalid({exc})"

        return True, "ok"

    # ---- Public API ----

    def run_watchtower_cycle(self) -> List[AnomalyRecord]:
        anomalies = self.watchtowers.perform_scan()
        for a in anomalies:
            self.ingest_anomaly(a)
        return anomalies

    def ingest_anomaly(self, anomaly: AnomalyRecord) -> None:
        ok, reason = self._validate_anomaly(anomaly)
        if not ok:
            self.metrics.events_dropped_validation += 1
            self._log(EventType.DROP, "INGEST", f"Dropped anomaly {anomaly.event_id}: {reason}", {
                "module_id": anomaly.module_id,
                "severity": anomaly.severity.value,
            })
            return

        is_new = self.audit.record_event_if_new(anomaly.event_id, anomaly.module_id, anomaly.severity)
        if not is_new:
            self.metrics.events_dropped_replay += 1
            self._log(EventType.REPLAY, "INGEST", f"Duplicate suppressed: {anomaly.event_id}", {
                "module_id": anomaly.module_id,
                "severity": anomaly.severity.value,
            })
            return

        try:
            self._queue.put(anomaly, timeout=self._max_ingest_wait_ms / 1000.0)
            self.metrics.events_ingested += 1
        except Full:
            self.metrics.events_dropped_backpressure += 1
            self._log(EventType.DROP, "INGEST", f"Queue full, dropping: {anomaly.event_id}", {
                "queue_max": self._queue.maxsize,
                "module_id": anomaly.module_id,
                "severity": anomaly.severity.value,
            })

    def list_pending_veto_actions(self) -> List[PendingAction]:
        return self.oversight.snapshot_pending()

    def veto_action(self, action_id: str, operator_id: str, reason: str) -> bool:
        return self.oversight.veto_action(action_id, operator_id, reason)

    def list_modules(self) -> Dict[str, WatchtowerConfig]:
        return dict(self.watchtowers.modules)

    def configure_module(self, module_id: str, *, enabled: Optional[bool] = None, sensitivity: Optional[float] = None) -> None:
        self.watchtowers.configure_module(module_id, enabled=enabled, sensitivity=sensitivity)

    def get_metrics(self) -> Dict[str, int]:
        return self.metrics.snapshot()

    # ---- Response Path ----

    def _execute_quarantine_target(self, principal_id: str, context: Dict[str, Any]) -> None:
        msg = f"Principal '{principal_id}' isolated via firewall / IAM ruleset."
        self._log(EventType.ACTION_EXECUTE, "DEFENSE_ACT", msg, context)

    def trigger_response(self, principal_id: str, reason: str, severity: RiskLevel, *, anomaly_event_id: str) -> str:
        principal_id = _safe_str((principal_id or "").strip() or "UNKNOWN", max_len=80)
        reason = _safe_str((reason or "").strip() or "unspecified", max_len=200)

        allowed = self.audit.consume_action_budget(
            principal_id,
            window_seconds=self.action_budget_window_seconds,
            max_actions=self.action_budget_max_actions,
        )
        if not allowed:
            self.metrics.actions_budget_denied += 1
            self._log(EventType.BUDGET, "ADVISORY", f"Budget exceeded for {principal_id}. Suppressing.", {
                "principal_id": principal_id,
                "severity": severity.value,
                "reason": reason,
            })
            return f"BUDGET-DENY-{principal_id}-{int(time.time())}"

        if severity is RiskLevel.HIGH and self.require_two_signals_for_high:
            corr_key = f"HIGH:{principal_id}:{reason}"
            count = self.audit.corroboration_bump(corr_key, ttl_seconds=self.corroboration_ttl_seconds)
            self._log(EventType.CORROBORATE, "ADVISORY", f"Corroboration {corr_key} -> {count}", {
                "principal_id": principal_id,
                "count": count,
                "anomaly_event_id": anomaly_event_id,
            })
            if count < 2:
                self.metrics.actions_corroboration_wait += 1
                self._log(EventType.ACTION_STAGE, "ADVISORY", "Waiting for second signal before acting on HIGH.", {
                    "principal_id": principal_id,
                    "reason": reason,
                    "severity": severity.value,
                    "anomaly_event_id": anomaly_event_id,
                })
                return f"CORR-WAIT-{principal_id}-{int(time.time())}"

        action_id = f"REVOKE-{principal_id.replace('.', '-')}-{int(time.time())}"
        description = f"Revoke access for {principal_id} ({reason})"
        context = {
            "principal_id": principal_id,
            "reason": reason,
            "severity": severity.value,
            "source_anomaly_event_id": anomaly_event_id,
        }

        self.metrics.actions_triggered += 1

        if self.mode == DeploymentMode.SHADOW:
            self._log(EventType.ACTION_STAGE, "ADVISORY", f"[SHADOW] Would perform {action_id}: {description}", context)
            return action_id

        if self.mode == DeploymentMode.HUMAN_GATED:
            self.audit.stage_action(action_id, description, severity, context)
            self._log(EventType.ACTION_STAGE, "ADVISORY", f"[HUMAN_GATED] Staged {action_id}: {description}", context)
            return action_id

        pending = PendingAction(
            action_id=action_id,
            description=description,
            created_at=_utcnow(),
            delay_seconds=self._resolve_delay_for_severity(severity),
            risk_level=severity,
            principal_id=principal_id,
            payload=lambda: self._execute_quarantine_target(principal_id, context),
        )
        self.oversight.schedule_vetoable_action(pending)
        return action_id

    def approve_staged_action(self, action_id: str, operator_id: str) -> bool:
        staged = self.audit.get_staged_action(action_id)
        if not staged or staged["status"] != "STAGED":
            self._log(EventType.ERROR, "ADVISORY", f"[APPROVE] {action_id} not found or not STAGED.")
            return False

        self.audit.mark_action_decision(action_id, status="APPROVED", operator_id=operator_id)
        self._log(EventType.ACTION_EXECUTE, "ADVISORY", f"[APPROVED] {action_id} by {operator_id}. Executing...")

        ctx = staged["context"]
        principal = _safe_str(ctx.get("principal_id", "Unknown.Principal"), max_len=80)

        ok, err = execute_with_timeout(lambda: self._execute_quarantine_target(principal, ctx), timeout_seconds=30)
        if ok:
            self.metrics.actions_executed += 1
            self.audit.mark_action_decision(action_id, status="EXECUTED", operator_id=operator_id)
            return True

        if err and err.startswith("timeout_after_"):
            self.metrics.actions_timeout += 1
            self._log(EventType.TIMEOUT, "ADVISORY", f"Approved action timed out: {action_id}", {"action_id": action_id})
            self.audit.mark_action_decision(action_id, status="TIMEOUT", operator_id=operator_id)
            return False

        self._log(EventType.ERROR, "ADVISORY", f"Approved action failed: {action_id} | {err}", {"action_id": action_id})
        self.audit.mark_action_decision(action_id, status="FAILED", operator_id=operator_id)
        return False

    # ---- Anomaly Handling ----

    def _handle_anomaly(self, anomaly: AnomalyRecord) -> None:
        alert_ctx = {"event_id": anomaly.event_id, "severity": anomaly.severity.value, **(anomaly.metadata or {})}
        self._log(EventType.ALERT, "ALERT", f"[{anomaly.module_id}] {anomaly.description}", context=alert_ctx)

        if anomaly.module_id == "WT_03_IAM_AUD":
            principal = _safe_str(anomaly.metadata.get("principal_id", "Unknown.Principal"), max_len=80)
            self.trigger_response(principal, "Suspicious IAM access pattern", anomaly.severity, anomaly_event_id=anomaly.event_id)

    # ---- Delay Policy ----

    def _resolve_delay_for_severity(self, severity: RiskLevel) -> int:
        if severity is RiskLevel.HIGH:
            return self.delay_high_seconds
        if severity is RiskLevel.MEDIUM:
            return self.delay_medium_seconds
        return self.delay_low_seconds