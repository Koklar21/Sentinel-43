"""
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Justin

SENTINEL-43: Intelligent Log Triage & Response Orchestrator (Hardened Foundation)

Fixes included (Murphy's Law / "internet goblin" hardening):
- Ingress validation + size limits (defensive JSON + metadata bounds)
- Event idempotency / replay defense (persistent seen_events table)
- Bounded queue + back-pressure (no inline execution during ingest/scan)
- Two-signal confirmation for high-impact actions (configurable, persistent)
- Action budgets per principal (rate limit response spam / baiting)
- Time sanity checks (clock skew guardrails)
- Canonical JSON hashing for audit chain stability
- Single scheduler thread (NO threading.Timer pileups)
- Clean shutdown: worker + scheduler stop

No demo harness. No auto-run loops. SOC-facing foundation.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from queue import Full, Queue
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(module)-18s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

SYSTEM_ID = "SENTINEL-43-NODE-01"


# ---------------------------------------------------------------------------
# Enums & Data Models
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
    DROP = "DROP"                 # Back-pressure / invalid events dropped
    REPLAY = "REPLAY"             # Duplicate event detected
    BUDGET = "BUDGET"             # Rate-limit / action budget exceeded
    CORROBORATE = "CORROBORATE"   # Two-signal confirmation events


@dataclass(frozen=True)
class AnomalyRecord:
    module_id: str
    description: str
    severity: RiskLevel
    detected_at: datetime.datetime
    metadata: Dict[str, Any]
    event_id: str                  # stable event id for replay defense


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    description: str
    created_at: datetime.datetime
    delay_seconds: int
    risk_level: RiskLevel
    payload: Callable[[], None]
    principal_id: str              # who/what the action is about


# ---------------------------------------------------------------------------
# Safety/Validation Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(tzinfo=None)


def _iso_utc(dt: datetime.datetime, *, seconds: bool = False) -> str:
    if seconds:
        return dt.isoformat(timespec="seconds") + "Z"
    return dt.isoformat(timespec="microseconds") + "Z"


def _canonical_json(obj: Any, *, max_len: int) -> str:
    """
    Canonical JSON with stable key order and compact separators.
    Enforces max_len to avoid giant payloads.
    """
    s = json.dumps(obj, separators=(",", ":"), sort_keys=True, default=str)
    if len(s) > max_len:
        raise ValueError(f"context_json too large ({len(s)} > {max_len})")
    return s


def _safe_str(s: Any, *, max_len: int) -> str:
    out = str(s)
    if len(out) > max_len:
        return out[:max_len] + "…"
    return out


def _hash_str(blob: str) -> str:
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _default_event_id(module_id: str, detected_at: datetime.datetime, description: str, metadata: Dict[str, Any]) -> str:
    base = {
        "module_id": module_id,
        "detected_at": _iso_utc(detected_at, seconds=True),
        "description": description,
        "meta_hash": _hash_str(_canonical_json(metadata, max_len=20_000)),
    }
    return _hash_str(_canonical_json(base, max_len=20_000))


# ---------------------------------------------------------------------------
# SQLite-backed Audit Logger + Replay/Rate Tables
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Append-only audit logger with tamper-evident hashing + supporting tables.

    Tables:
    - audit_events: hash-chained audit log
    - staged_actions: HUMAN_GATED staging persistence
    - seen_events: replay defense across restarts
    - action_budget: per-principal throttle
    - corroboration: persistent two-signal cache
    """

    def __init__(self, db_path: Path, *, journal_mode: str = "WAL"):
        self.db_path = Path(db_path)
        self.journal_mode = journal_mode
        self._lock = threading.RLock()
        self._init_db()

    def _ensure_parent_dir(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_conn(self) -> sqlite3.Connection:
        self._ensure_parent_dir()
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.execute(f"PRAGMA journal_mode={self.journal_mode};")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._get_conn() as conn:
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
                    prev_hash TEXT,
                    event_hash TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(timestamp);")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS staged_actions (
                    action_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    status TEXT NOT NULL,   -- STAGED | APPROVED | EXECUTED | REJECTED
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

    def _get_last_hash(self, conn: sqlite3.Connection) -> Optional[str]:
        row = conn.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1;").fetchone()
        return row[0] if row else None

    @staticmethod
    def _hash_event(
        *,
        timestamp: str,
        system_id: str,
        event_type: str,
        module: str,
        message: str,
        context_json: Optional[str],
        prev_hash: Optional[str],
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
        context_json = None
        if context is not None:
            context_json = _canonical_json(context, max_len=max_context_json)

        with self._lock, self._get_conn() as conn:
            prev_hash = self._get_last_hash(conn)
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

    # ---- HUMAN_GATED staging ----

    def stage_action(self, action_id: str, description: str, severity: RiskLevel, context: Dict[str, Any]) -> None:
        created_at = _iso_utc(_utcnow(), seconds=True)
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO staged_actions
                (action_id, created_at, description, severity, context_json, status)
                VALUES (?, ?, ?, ?, ?, 'STAGED');
                """,
                (action_id, created_at, description, severity.value, _canonical_json(context, max_len=20_000)),
            )

    def get_staged_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._get_conn() as conn:
            row = conn.execute(
                """
                SELECT action_id, created_at, description, severity, context_json, status
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
        }

    def mark_action_decision(self, action_id: str, *, status: str, operator_id: str) -> None:
        decided_at = _iso_utc(_utcnow(), seconds=True)
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                UPDATE staged_actions
                SET status = ?, operator_id = ?, decided_at = ?
                WHERE action_id = ?;
                """,
                (status, operator_id, decided_at, action_id),
            )

    # ---- Replay defense ----

    def record_event_if_new(self, event_id: str, module_id: str, severity: RiskLevel, *, ttl_seconds: int) -> bool:
        now = _utcnow()
        cutoff = now - datetime.timedelta(seconds=ttl_seconds)

        with self._lock, self._get_conn() as conn:
            conn.execute(
                "DELETE FROM seen_events WHERE first_seen_at < ?;",
                (_iso_utc(cutoff, seconds=True),),
            )
            try:
                conn.execute(
                    """
                    INSERT INTO seen_events(event_id, first_seen_at, module_id, severity)
                    VALUES (?, ?, ?, ?);
                    """,
                    (event_id, _iso_utc(now, seconds=True), module_id, severity.value),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    # ---- Action budget ----

    def consume_action_budget(self, principal_id: str, *, window_seconds: int, max_actions: int) -> bool:
        now = _utcnow()
        window_start = now.replace(microsecond=0)

        with self._lock, self._get_conn() as conn:
            row = conn.execute(
                "SELECT window_start, used_count FROM action_budget WHERE principal_id = ?;",
                (principal_id,),
            ).fetchone()

            if not row:
                conn.execute(
                    "INSERT INTO action_budget(principal_id, window_start, used_count) VALUES (?, ?, ?);",
                    (principal_id, _iso_utc(window_start, seconds=True), 1),
                )
                return True

            prev_start = datetime.datetime.fromisoformat(row[0].replace("Z", ""))
            used = int(row[1])

            if (now - prev_start).total_seconds() > window_seconds:
                conn.execute(
                    "UPDATE action_budget SET window_start = ?, used_count = ? WHERE principal_id = ?;",
                    (_iso_utc(window_start, seconds=True), 1, principal_id),
                )
                return True

            if used >= max_actions:
                return False

            conn.execute(
                "UPDATE action_budget SET used_count = used_count + 1 WHERE principal_id = ?;",
                (principal_id,),
            )
            return True

    # ---- Corroboration ----

    def corroboration_bump(self, key: str, *, ttl_seconds: int) -> int:
        now = _utcnow()
        cutoff = now - datetime.timedelta(seconds=ttl_seconds)

        with self._lock, self._get_conn() as conn:
            conn.execute(
                "DELETE FROM corroboration WHERE last_seen_at < ?;",
                (_iso_utc(cutoff, seconds=True),),
            )
            row = conn.execute(
                "SELECT count FROM corroboration WHERE key = ?;",
                (key,),
            ).fetchone()

            if not row:
                conn.execute(
                    """
                    INSERT INTO corroboration(key, first_seen_at, last_seen_at, count)
                    VALUES (?, ?, ?, ?);
                    """,
                    (key, _iso_utc(now, seconds=True), _iso_utc(now, seconds=True), 1),
                )
                return 1

            conn.execute(
                """
                UPDATE corroboration
                SET last_seen_at = ?, count = count + 1
                WHERE key = ?;
                """,
                (_iso_utc(now, seconds=True), key),
            )
            return int(row[0]) + 1


# ---------------------------------------------------------------------------
# Single Scheduler Thread (replaces threading.Timer)
# ---------------------------------------------------------------------------

@dataclass(order=True)
class _SchedItem:
    due_ts: float
    seq: int
    action_id: str
    run: Callable[[], None]


class Scheduler:
    """Single worker scheduler to avoid Timer thread pileups."""

    def __init__(self, audit: AuditLogger):
        self._audit = audit
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._heap: List[_SchedItem] = []
        self._seq = 0
        self._cancelled: set[str] = set()
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True, name="sentinel43-scheduler")
        self._thread.start()

    def schedule(self, action_id: str, delay_seconds: int, run: Callable[[], None]) -> None:
        due = time.time() + max(0, int(delay_seconds))
        with self._cv:
            self._seq += 1
            self._heap.append(_SchedItem(due, self._seq, action_id, run))
            self._heap.sort()  # heapq would be slightly faster; this is fine at small scale
            self._cv.notify()

    def cancel(self, action_id: str) -> None:
        with self._cv:
            self._cancelled.add(action_id)
            self._cv.notify()

    def shutdown(self) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify()
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

                self._heap.pop(0)

                if item.action_id in self._cancelled:
                    self._cancelled.discard(item.action_id)
                    continue

            try:
                item.run()
            except Exception as exc:
                self._audit.append(EventType.ERROR, "SCHEDULER", f"Execution failed for {item.action_id}: {exc}", {
                    "action_id": item.action_id
                })


# ---------------------------------------------------------------------------
# Oversight Engine (Time-Delayed Veto) using Scheduler
# ---------------------------------------------------------------------------

class OversightEngine:
    """Manages time-delayed veto workflow for actions (no Timer spam)."""

    def __init__(self, audit: AuditLogger, scheduler: Scheduler, notify_callback: Callable[[str], None]):
        self._audit = audit
        self._scheduler = scheduler
        self._notify_callback = notify_callback
        self._lock = threading.RLock()
        self._pending: Dict[str, PendingAction] = {}

    def schedule_vetoable_action(self, action: PendingAction) -> None:
        with self._lock:
            if action.action_id in self._pending:
                logging.warning(f"[OVERSIGHT] Action {action.action_id} already pending.")
                return
            self._pending[action.action_id] = action

        msg = (
            f"[PENDING] {action.description} | Risk={action.risk_level.value} | "
            f"Exec in {action.delay_seconds}s unless vetoed."
        )
        logging.info(f"[OVERSIGHT] {msg}")
        self._audit.append(EventType.ACTION_STAGE, "OVERSIGHT", msg, {
            "action_id": action.action_id,
            "principal_id": action.principal_id,
            "risk": action.risk_level.value,
            "delay_seconds": action.delay_seconds,
        })

        def _run() -> None:
            with self._lock:
                act = self._pending.pop(action.action_id, None)
            if not act:
                return

            msg2 = f"[TIMEOUT] Auto-approving: {act.description}"
            logging.info(f"[OVERSIGHT] {msg2}")
            self._audit.append(EventType.ACTION_EXECUTE, "OVERSIGHT", msg2, {
                "action_id": act.action_id,
                "principal_id": act.principal_id,
            })
            try:
                act.payload()
                self._notify_callback(f"Action '{act.description}' EXECUTED successfully.")
            except Exception as exc:
                err_msg = f"Execution failed for {act.action_id}: {exc}"
                logging.error(f"[OVERSIGHT] {err_msg}")
                self._audit.append(EventType.ERROR, "OVERSIGHT", err_msg, {"action_id": act.action_id})

        self._scheduler.schedule(action.action_id, action.delay_seconds, _run)

    def veto_action(self, action_id: str, operator_id: str, reason: str) -> bool:
        with self._lock:
            act = self._pending.pop(action_id, None)

        if not act:
            logging.warning(f"[OVERSIGHT] Cannot veto {action_id}: not pending.")
            return False

        self._scheduler.cancel(action_id)

        msg = f"[VETOED] {act.description} | Operator={operator_id} | Reason={reason}"
        logging.warning(f"[OVERSIGHT] {msg}")
        self._audit.append(EventType.ACTION_VETO, "OVERSIGHT", msg, {
            "action_id": act.action_id,
            "operator_id": operator_id,
            "reason": _safe_str(reason, max_len=300),
        })
        self._notify_callback(f"Action {action_id} vetoed by {operator_id}.")
        return True

    def snapshot_pending(self) -> List[PendingAction]:
        with self._lock:
            return list(self._pending.values())


# ---------------------------------------------------------------------------
# Watchtower Modules (synthetic)
# ---------------------------------------------------------------------------

class WatchtowerConfig:
    def __init__(self, module_id: str, description: str, enabled: bool = True, sensitivity: float = 1.0):
        self.module_id = module_id
        self.description = description
        self.enabled = enabled
        self.sensitivity = sensitivity
        self.last_scan: Optional[datetime.datetime] = None


class WatchtowerManager:
    """Manages discrete surveillance modules."""

    def __init__(self, audit: AuditLogger):
        self._audit = audit
        self.modules: Dict[str, WatchtowerConfig] = {}
        self._init_standard_modules()

    def _init_standard_modules(self) -> None:
        self.modules["WT_01_RES_MON"] = WatchtowerConfig("WT_01_RES_MON", "System Resource Allocation Monitor")
        self.modules["WT_02_NET_ING"] = WatchtowerConfig("WT_02_NET_ING", "Network Ingress/Egress Traffic Analysis")
        self.modules["WT_03_IAM_AUD"] = WatchtowerConfig("WT_03_IAM_AUD", "Identity Access Management Audit Logger")
        self.modules["WT_04_INT_VER"] = WatchtowerConfig("WT_04_INT_VER", "File System Integrity Verification Service")
        self.modules["WT_05_API_LAT"] = WatchtowerConfig("WT_05_API_LAT", "External API Latency Observer")
        self.modules["WT_06_DB_TXN"] = WatchtowerConfig("WT_06_DB_TXN", "Database Transaction Consistency Manager")
        self.modules["WT_07_CNF_MGT"] = WatchtowerConfig("WT_07_CNF_MGT", "Endpoint Configuration Drift Detector")
        self.modules["WT_08_REG_CMP"] = WatchtowerConfig("WT_08_REG_CMP", "Regulatory Compliance Reporting Agent")

    def configure_module(self, module_id: str, *, enabled: Optional[bool] = None, sensitivity: Optional[float] = None) -> None:
        mod = self.modules.get(module_id)
        if not mod:
            logging.error(f"[CONFIG] Module {module_id} not found.")
            return

        if enabled is not None:
            mod.enabled = enabled
        if sensitivity is not None:
            mod.sensitivity = float(sensitivity)

        msg = f"Updated {module_id}: enabled={mod.enabled}, sensitivity={mod.sensitivity}"
        logging.info(f"[CONFIG] {msg}")
        self._audit.append(EventType.CONFIG, "WATCHTOWER", msg)

    def perform_scan(self) -> List[AnomalyRecord]:
        """
        Still synthetic. Replace with real telemetry later.
        Emits event_id so orchestrator can dedupe.
        """
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
                desc = f"Anomaly detected in {mod.description} (risk_factor={risk_factor:.3f})"

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
# Sentinel Node (Core Orchestrator)
# ---------------------------------------------------------------------------

class SentinelNode:
    def __init__(
        self,
        *,
        mode: DeploymentMode = DeploymentMode.SHADOW,
        audit_db_path: Optional[Path] = None,
        journal_mode: str = "WAL",

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
    ):
        self._lock = threading.RLock()
        self.mode = mode

        if audit_db_path is None:
            try:
                base = Path(__file__).resolve().parent
            except NameError:
                base = Path.cwd()
            audit_db_path = base / "sentinel43_audit.db"

        self.audit = AuditLogger(audit_db_path, journal_mode=journal_mode)
        self.scheduler = Scheduler(self.audit)
        self.oversight = OversightEngine(self.audit, self.scheduler, notify_callback=self._notify_operator)
        self.watchtowers = WatchtowerManager(self.audit)

        # Hardening configuration
        self.max_metadata_json = int(max_metadata_json)
        self.replay_ttl_seconds = int(replay_ttl_seconds)
        self.max_clock_skew_seconds = int(max_clock_skew_seconds)

        self.action_budget_window_seconds = int(action_budget_window_seconds)
        self.action_budget_max_actions = int(action_budget_max_actions)

        self.require_two_signals_for_high = bool(require_two_signals_for_high)
        self.corroboration_ttl_seconds = int(corroboration_ttl_seconds)

        # Bounded work queue
        self._queue: Queue[AnomalyRecord] = Queue(maxsize=int(max_queue_size))
        self._max_ingest_wait_ms = int(max_ingest_wait_ms)

        # Worker thread
        self._worker = threading.Thread(target=self._worker_loop, daemon=True, name="sentinel43-worker")
        self._worker_stop = threading.Event()
        self._worker.start()

        self._log(EventType.SYSTEM, "SYSTEM", f"[{SYSTEM_ID}] Initialization complete.")
        self._log(EventType.SYSTEM, "SYSTEM", f"Watchtower modules loaded: {len(self.watchtowers.modules)}")
        self._log(EventType.SYSTEM, "SYSTEM", f"Deployment mode: {self.mode.name}")

    # ---------------------------- Logging ----------------------------

    def _log(self, event_type: EventType, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        try:
            self.audit.append(event_type, module, message, context, max_context_json=20_000)
        except Exception as exc:
            logging.error(f"[AUDIT_FAIL] {event_type.value} {module}: {message} | {exc}")
        logging.info(f"[{module}] {message}")

    def _notify_operator(self, message: str) -> None:
        self._log(EventType.SYSTEM, "NOTIFY", message)

    # ---------------------------- Lifecycle ----------------------------

    def shutdown(self) -> None:
        """Graceful stop: stop worker, stop scheduler."""
        self._log(EventType.SYSTEM, "SYSTEM", "Shutdown requested.")
        self._worker_stop.set()
        self.scheduler.shutdown()

    # ---------------------------- Worker Loop ----------------------------

    def _worker_loop(self) -> None:
        while not self._worker_stop.is_set():
            try:
                anomaly = self._queue.get(timeout=0.25)
            except Exception:
                continue
            try:
                self._handle_anomaly(anomaly)
            except Exception as exc:
                self._log(EventType.ERROR, "WORKER", f"Unhandled exception handling anomaly: {exc}", {
                    "event_id": getattr(anomaly, "event_id", "unknown"),
                    "module_id": getattr(anomaly, "module_id", "unknown"),
                })
            finally:
                try:
                    self._queue.task_done()
                except Exception:
                    pass

    # ---------------------------- Defensive Validations ----------------------------

    def _validate_anomaly(self, anomaly: AnomalyRecord) -> Tuple[bool, str]:
        if not anomaly.module_id or len(anomaly.module_id) > 64:
            return False, "invalid module_id"
        if not anomaly.event_id or len(anomaly.event_id) > 128:
            return False, "invalid event_id"
        if not isinstance(anomaly.detected_at, datetime.datetime):
            return False, "invalid detected_at"

        now = _utcnow()
        skew = abs((now - anomaly.detected_at).total_seconds())
        if skew > self.max_clock_skew_seconds:
            return False, f"clock_skew_too_large({int(skew)}s)"

        try:
            _canonical_json(anomaly.metadata, max_len=self.max_metadata_json)
        except Exception as exc:
            return False, f"metadata_invalid_or_too_large({exc})"

        if len(anomaly.description) > 500:
            return False, "description_too_large"

        return True, "ok"

    # ---------------------------- Actions (Execution Boundary) ----------------------------

    def _execute_quarantine_target(self, principal_id: str, context: Dict[str, Any]) -> None:
        # Real implementation should terminate into an IntegrationHub boundary.
        msg = f"Principal '{principal_id}' isolated via firewall / IAM ruleset."
        self._log(EventType.ACTION_EXECUTE, "DEFENSE_ACT", msg, context)

    # ------------------------- Public API -------------------------

    def run_watchtower_cycle(self) -> List[AnomalyRecord]:
        anomalies = self.watchtowers.perform_scan()
        for anomaly in anomalies:
            self.ingest_anomaly(anomaly)
        return anomalies

    def ingest_anomaly(self, anomaly: AnomalyRecord) -> None:
        ok, reason = self._validate_anomaly(anomaly)
        if not ok:
            self._log(EventType.DROP, "INGEST", f"Dropped anomaly {anomaly.event_id}: {reason}", {
                "module_id": anomaly.module_id,
                "severity": anomaly.severity.value,
            })
            return

        is_new = self.audit.record_event_if_new(
            anomaly.event_id, anomaly.module_id, anomaly.severity, ttl_seconds=self.replay_ttl_seconds
        )
        if not is_new:
            self._log(EventType.REPLAY, "INGEST", f"Duplicate anomaly suppressed: {anomaly.event_id}", {
                "module_id": anomaly.module_id,
                "severity": anomaly.severity.value,
            })
            return

        try:
            self._queue.put(anomaly, timeout=self._max_ingest_wait_ms / 1000.0)
        except Full:
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

    # ------------------------- Response Logic -------------------------

    def trigger_response(self, principal_id: str, reason: str, severity: RiskLevel, *, anomaly_event_id: str) -> str:
        principal_id = _safe_str(principal_id, max_len=80)
        reason = _safe_str(reason, max_len=200)

        allowed = self.audit.consume_action_budget(
            principal_id,
            window_seconds=self.action_budget_window_seconds,
            max_actions=self.action_budget_max_actions,
        )
        if not allowed:
            self._log(EventType.BUDGET, "ADVISORY", f"Action budget exceeded for {principal_id}. Suppressing response.", {
                "principal_id": principal_id,
                "severity": severity.value,
                "reason": reason,
            })
            return f"BUDGET-DENY-{principal_id}-{int(time.time())}"

        if severity is RiskLevel.HIGH and self.require_two_signals_for_high:
            corr_key = f"HIGH:{principal_id}:{reason}"
            count = self.audit.corroboration_bump(corr_key, ttl_seconds=self.corroboration_ttl_seconds)
            self._log(EventType.CORROBORATE, "ADVISORY", f"Corroboration bump {corr_key} -> {count}", {
                "principal_id": principal_id,
                "count": count,
                "anomaly_event_id": anomaly_event_id,
            })
            if count < 2:
                self._log(EventType.ACTION_STAGE, "ADVISORY", "[CORROBORATION] Waiting for second signal before acting on HIGH.", {
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
        principal = str(ctx.get("principal_id", "Unknown.Principal"))
        self._execute_quarantine_target(principal, ctx)

        self.audit.mark_action_decision(action_id, status="EXECUTED", operator_id=operator_id)
        return True

    # ------------------------- Rules -------------------------

    def _handle_anomaly(self, anomaly: AnomalyRecord) -> None:
        alert_ctx = {"event_id": anomaly.event_id, "severity": anomaly.severity.value, **anomaly.metadata}
        self._log(EventType.ALERT, "ALERT", f"[{anomaly.module_id}] {anomaly.description}", context=alert_ctx)

        if anomaly.module_id == "WT_03_IAM_AUD":
            principal = str(anomaly.metadata.get("principal_id", "Unknown.Principal"))
            reason = "Suspicious IAM access pattern"
            self.trigger_response(principal, reason, anomaly.severity, anomaly_event_id=anomaly.event_id)

    @staticmethod
    def _resolve_delay_for_severity(severity: RiskLevel) -> int:
        if severity is RiskLevel.HIGH:
            return 10
        if severity is RiskLevel.MEDIUM:
            return 30
        return 60