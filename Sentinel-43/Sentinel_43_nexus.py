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
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
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

from __future__ import annotations

import hashlib
import heapq
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from enum import Enum
from queue import Empty, Full, Queue
from typing import Callable, Dict, Optional, Tuple, Any, List


SYSTEM_ID = "SENTINEL-43-NEXUS-01"

# NOTE: No logging.basicConfig here. The application owns global logging config.
import logging
logger = logging.getLogger(__name__)


# ----------------------------- Enums ----------------------------------------

class OpMode(Enum):
    SHADOW = "SHADOW_ADVISORY"      # log-only, no execution
    HUMAN_GATED = "HUMAN_GATED"     # stage actions; requires approval
    ACTIVE = "AUTONOMOUS_VETO"      # delayed execution with veto window


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReasonCode(Enum):
    UNKNOWN = "UNKNOWN"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    MALWARE_BEACON = "MALWARE_BEACON"
    C2_TRAFFIC = "C2_TRAFFIC"
    AUTH_ABUSE = "AUTH_ABUSE"
    DOS_PATTERN = "DOS_PATTERN"
    SUSPICIOUS_ASN = "SUSPICIOUS_ASN"
    GEO_ANOMALY = "GEO_ANOMALY"


class DecisionType(Enum):
    NONE = "NONE"
    SHADOW_LOG = "SHADOW_LOG"
    STAGE_FOR_APPROVAL = "STAGE_FOR_APPROVAL"
    DELAYED_EXECUTE = "DELAYED_EXECUTE"


# ----------------------------- Models ---------------------------------------

@dataclass(frozen=True)
class Evidence:
    system: str
    sensor: str
    observed_at: int
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Prevent external mutation of nested dict.
        object.__setattr__(self, "details", dict(self.details or {}))


@dataclass(frozen=True)
class ThreatEvent:
    target: str                 # e.g., IP / principal / hostname
    threat_type: str            # free text (raw detector label)
    reason_code: ReasonCode     # normalized
    severity: Severity
    evidence: Evidence


@dataclass(frozen=True)
class Decision:
    decision_type: DecisionType
    target: str
    reason: str
    severity: Severity
    reason_code: ReasonCode
    delay_seconds: int
    cooldown_seconds: int
    evidence: Evidence


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    fingerprint: str
    target: str
    description: str
    delay_seconds: int
    cooldown_seconds: int
    severity: Severity
    reason: str
    reason_code: ReasonCode
    evidence: Evidence
    real_payload: Callable[[], None]
    shadow_payload: Callable[[], None]


@dataclass
class Metrics:
    threats_seen: int = 0
    decisions_none: int = 0
    actions_built: int = 0

    drops_backpressure: int = 0
    suppress_cooldown: int = 0
    suppress_dedupe: int = 0
    suppress_budget: int = 0
    corroboration_wait: int = 0

    gated_staged: int = 0
    gated_approved: int = 0
    vetoed: int = 0
    pending_armed: int = 0

    executed: int = 0
    shadow_logged: int = 0
    exec_timeout: int = 0
    exec_failed: int = 0

    def snapshot(self) -> Dict[str, int]:
        return {k: int(getattr(self, k)) for k in self.__dataclass_fields__.keys()}


# ----------------------- Utilities: Hash & JSON -----------------------------

def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _safe_str(val: Any, *, max_len: int) -> str:
    s = str(val)
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s


def stable_fingerprint(*, target: str, threat_type: str, reason_code: ReasonCode, reason: str, extra: Dict[str, Any]) -> str:
    payload = {
        "target": target,
        "threat_type": threat_type,
        "reason_code": reason_code.value,
        "reason": reason,
        "extra": extra or {},
    }
    raw = _json_dumps(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def execute_with_timeout(fn: Callable[[], None], *, timeout_seconds: int) -> Tuple[bool, Optional[str]]:
    """
    Thread-based timeout wrapper to keep scheduler thread non-blocking.

    Important limitation: Python cannot force-kill a stuck thread.
    If you need hard-kill, use subprocess isolation for actions.
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

    return False, f"timeout_after_{int(timeout_seconds)}s"


# ------------------------ Integration Hub (Boundary) ------------------------

class IntegrationHub:
    """
    All real-world effects terminate here.
    Replace with real integrations (firewall/WAF/IAM/SIEM/ticketing/paging).
    """

    @staticmethod
    def execute_firewall_block(target: str, *, reason: str, evidence: Evidence) -> bool:
        logger.warning("[FIREWALL] HARD BLOCK applied to %s | reason=%s | evidence=%s",
                       target, reason, asdict(evidence))
        return True

    @staticmethod
    def log_shadow_action(target: str, *, reason: str, evidence: Evidence) -> bool:
        logger.info("[SHADOW] WOULD have blocked %s | reason=%s | evidence=%s",
                    target, reason, asdict(evidence))
        return True


# ------------------------------ Clock ---------------------------------------

class Clock:
    """Pluggable time source for deterministic tests."""
    def now(self) -> float:
        return time.time()

    def now_int(self) -> int:
        return int(self.now())


# -------------------------- SQLite State Store ------------------------------

class StateStore:
    """
    Persistent guardrails to survive restarts:
    - dedupe (fingerprint TTL)
    - corroboration counts (fingerprint TTL)
    - budget windows per target
    - cooldown per target
    - audit chain state (prev hash) + audit_events (append-only)
    """

    def __init__(
        self,
        db_path: str,
        *,
        pool_size: int = 4,
        journal_mode: str = "WAL",
    ) -> None:
        self._db_path = db_path
        self._pool_size = max(1, int(pool_size))
        self._pool: "Queue[sqlite3.Connection]" = Queue(maxsize=self._pool_size)
        self._journal_mode = journal_mode
        self._lock = threading.RLock()

        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)

        for _ in range(self._pool_size):
            self._pool.put(self._connect())

        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._db_path,
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.execute(f"PRAGMA journal_mode={self._journal_mode};")
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
            raise RuntimeError("StateStore connection pool exhausted") from exc
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
                CREATE TABLE IF NOT EXISTS dedupe (
                    fingerprint TEXT PRIMARY KEY,
                    first_seen INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dedupe_first ON dedupe(first_seen)")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS corroboration (
                    fingerprint TEXT PRIMARY KEY,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    count INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_corr_last ON corroboration(last_seen)")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS budget (
                    target TEXT PRIMARY KEY,
                    window_start INTEGER NOT NULL,
                    used INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_budget_window ON budget(window_start)")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cooldown (
                    target TEXT PRIMARY KEY,
                    until_ts INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cooldown_until ON cooldown(until_ts)")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    prev_hash TEXT NOT NULL
                )
                """
            )
            row = conn.execute("SELECT prev_hash FROM audit_chain WHERE id=1").fetchone()
            if not row:
                conn.execute("INSERT INTO audit_chain (id, prev_hash) VALUES (1, ?)", ("0" * 64,))

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    ts INTEGER NOT NULL,
                    system_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)")

    # ---- Dedupe ----

    def dedupe_seen(self, fingerprint: str, *, now_ts: int, ttl_seconds: int) -> bool:
        """Returns True if duplicate within TTL, else records and returns False."""
        fp = _safe_str(fingerprint, max_len=256)
        with self._lock, self._conn_txn() as conn:
            row = conn.execute("SELECT first_seen FROM dedupe WHERE fingerprint=?", (fp,)).fetchone()
            if row:
                first_seen = int(row[0])
                if now_ts - first_seen <= int(ttl_seconds):
                    return True
                conn.execute("UPDATE dedupe SET first_seen=? WHERE fingerprint=?", (now_ts, fp))
                return False

            conn.execute("INSERT INTO dedupe (fingerprint, first_seen) VALUES (?, ?)", (fp, now_ts))
            return False

    def dedupe_cleanup(self, *, now_ts: int, ttl_seconds: int) -> None:
        cutoff = int(now_ts) - int(ttl_seconds)
        with self._lock, self._conn_txn() as conn:
            conn.execute("DELETE FROM dedupe WHERE first_seen < ?", (cutoff,))

    # ---- Corroboration ----

    def corroborate(self, fingerprint: str, *, now_ts: int, ttl_seconds: int) -> int:
        fp = _safe_str(fingerprint, max_len=256)
        with self._lock, self._conn_txn() as conn:
            row = conn.execute(
                "SELECT first_seen, last_seen, count FROM corroboration WHERE fingerprint=?",
                (fp,),
            ).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO corroboration (fingerprint, first_seen, last_seen, count) VALUES (?, ?, ?, ?)",
                    (fp, now_ts, now_ts, 1),
                )
                return 1

            last_seen = int(row[1])
            count = int(row[2])

            if now_ts - last_seen > int(ttl_seconds):
                conn.execute(
                    "UPDATE corroboration SET first_seen=?, last_seen=?, count=? WHERE fingerprint=?",
                    (now_ts, now_ts, 1, fp),
                )
                return 1

            count += 1
            conn.execute(
                "UPDATE corroboration SET last_seen=?, count=? WHERE fingerprint=?",
                (now_ts, count, fp),
            )
            return count

    def corroboration_cleanup(self, *, now_ts: int, ttl_seconds: int) -> None:
        cutoff = int(now_ts) - int(ttl_seconds)
        with self._lock, self._conn_txn() as conn:
            conn.execute("DELETE FROM corroboration WHERE last_seen < ?", (cutoff,))

    # ---- Budget ----

    def consume_budget(self, target: str, *, now_ts: int, window_seconds: int, max_actions: int) -> bool:
        tgt = _safe_str(target, max_len=256)
        with self._lock, self._conn_txn() as conn:
            row = conn.execute("SELECT window_start, used FROM budget WHERE target=?", (tgt,)).fetchone()
            if not row:
                conn.execute("INSERT INTO budget (target, window_start, used) VALUES (?, ?, ?)", (tgt, now_ts, 1))
                return True

            window_start, used = int(row[0]), int(row[1])
            if now_ts - window_start > int(window_seconds):
                conn.execute("UPDATE budget SET window_start=?, used=? WHERE target=?", (now_ts, 1, tgt))
                return True

            if used >= int(max_actions):
                return False

            conn.execute("UPDATE budget SET used=? WHERE target=?", (used + 1, tgt))
            return True

    # ---- Cooldown ----

    def in_cooldown(self, target: str, *, now_ts: int) -> bool:
        tgt = _safe_str(target, max_len=256)
        with self._lock, self._conn_txn() as conn:
            row = conn.execute("SELECT until_ts FROM cooldown WHERE target=?", (tgt,)).fetchone()
            if not row:
                return False
            return int(now_ts) < int(row[0])

    def set_cooldown_max(self, target: str, *, until_ts: int) -> None:
        """
        Set cooldown to max(existing, until_ts). Prevents shorter overwrites.
        """
        tgt = _safe_str(target, max_len=256)
        until_ts = int(until_ts)
        with self._lock, self._conn_txn() as conn:
            row = conn.execute("SELECT until_ts FROM cooldown WHERE target=?", (tgt,)).fetchone()
            if not row:
                conn.execute("INSERT INTO cooldown (target, until_ts) VALUES (?, ?)", (tgt, until_ts))
                return

            current = int(row[0])
            if until_ts > current:
                conn.execute("UPDATE cooldown SET until_ts=? WHERE target=?", (until_ts, tgt))

    # ---- Audit chain (optimistic + retry) ----

    def append_audit_event(self, *, ts: int, event_type: str, payload: Dict[str, Any], max_retries: int = 6) -> str:
        payload_json = _json_dumps(payload)
        backoff = 0.01

        for attempt in range(max_retries):
            try:
                with self._lock, self._conn_txn() as conn:
                    prev_hash = conn.execute("SELECT prev_hash FROM audit_chain WHERE id=1").fetchone()[0]
                    raw = (prev_hash + "|" + str(int(ts)) + "|" + str(event_type) + "|" + payload_json).encode("utf-8")
                    h = hashlib.sha256(raw).hexdigest()

                    conn.execute(
                        "INSERT INTO audit_events (ts, system_id, event_type, payload_json, prev_hash, hash) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (int(ts), SYSTEM_ID, str(event_type), payload_json, prev_hash, h),
                    )

                    rc = conn.execute(
                        "UPDATE audit_chain SET prev_hash=? WHERE id=1 AND prev_hash=?",
                        (h, prev_hash),
                    ).rowcount

                    if rc != 1:
                        raise sqlite3.IntegrityError("audit_chain_state_changed")

                    return h
            except sqlite3.IntegrityError:
                if attempt == max_retries - 1:
                    raise
                time.sleep(backoff)
                backoff *= 2

        # Unreachable, but keeps type checkers happy.
        raise RuntimeError("append_audit_event failed unexpectedly")


# --------------------------- Scheduler Thread -------------------------------

@dataclass(order=True)
class _ScheduledItem:
    due_ts: float
    seq: int
    action_id: str = field(compare=False)
    description: str = field(compare=False)
    payload: Callable[[], None] = field(compare=False)


class Scheduler:
    """
    Single scheduler thread running a heap of due actions.
    Avoids spawning Timer threads. Cancel race mitigated via executing set.
    """

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._heap: List[_ScheduledItem] = []
        self._seq = 0
        self._cancelled: set[str] = set()
        self._executing: set[str] = set()
        self._stopping = False
        self._thread = threading.Thread(target=self._run, name="sentinel43-scheduler", daemon=True)
        self._thread.start()

    def schedule(self, *, action_id: str, delay_seconds: int, description: str, payload: Callable[[], None]) -> None:
        due = self._clock.now() + max(0, int(delay_seconds))
        with self._cv:
            self._seq += 1
            heapq.heappush(self._heap, _ScheduledItem(due, self._seq, action_id, description, payload))
            self._cv.notify()

    def cancel(self, action_id: str) -> bool:
        with self._cv:
            self._cancelled.add(action_id)
            self._cv.notify()
            return True

    def shutdown(self, *, timeout: float = 5.0) -> None:
        with self._cv:
            self._stopping = True
            self._cv.notify()
        self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while True:
            with self._cv:
                if self._stopping:
                    return

                if not self._heap:
                    self._cv.wait(timeout=1.0)
                    continue

                item = self._heap[0]
                now = self._clock.now()
                if item.due_ts > now:
                    self._cv.wait(timeout=min(1.0, item.due_ts - now))
                    continue

                heapq.heappop(self._heap)

                # cancelled?
                if item.action_id in self._cancelled:
                    self._cancelled.discard(item.action_id)
                    continue

                # mark executing (mitigates cancel race)
                self._executing.add(item.action_id)

            try:
                # re-check cancel right before executing
                with self._cv:
                    if item.action_id in self._cancelled:
                        self._cancelled.discard(item.action_id)
                        continue

                logger.warning("[SCHEDULER] Executing: %s", item.description)
                item.payload()
            except Exception as exc:
                logger.error("[SCHEDULER] Execution failed for %s: %s", item.action_id, exc)
            finally:
                with self._cv:
                    self._executing.discard(item.action_id)
                    self._cancelled.discard(item.action_id)


# ----------------------------- Policy Engine --------------------------------

@dataclass(frozen=True)
class PolicyConfig:
    default_delay_seconds: int = 5
    cooldown_low_seconds: int = 30
    cooldown_medium_seconds: int = 60
    cooldown_high_seconds: int = 180
    cooldown_critical_seconds: int = 300


class PolicyEngine:
    """
    Converts ThreatEvent -> Decision.
    Keep this pure and testable.
    """

    def __init__(self, cfg: PolicyConfig) -> None:
        self._cfg = cfg

    def evaluate(self, threat: ThreatEvent) -> Decision:
        sev = threat.severity

        if sev is Severity.LOW:
            return Decision(
                decision_type=DecisionType.SHADOW_LOG,
                target=threat.target,
                reason=f"{threat.threat_type} detected",
                severity=sev,
                reason_code=threat.reason_code,
                delay_seconds=0,
                cooldown_seconds=self._cfg.cooldown_low_seconds,
                evidence=threat.evidence,
            )

        if sev is Severity.MEDIUM:
            return Decision(
                decision_type=DecisionType.STAGE_FOR_APPROVAL,
                target=threat.target,
                reason=f"{threat.threat_type} detected",
                severity=sev,
                reason_code=threat.reason_code,
                delay_seconds=self._cfg.default_delay_seconds,
                cooldown_seconds=self._cfg.cooldown_medium_seconds,
                evidence=threat.evidence,
            )

        if sev is Severity.HIGH:
            return Decision(
                decision_type=DecisionType.DELAYED_EXECUTE,
                target=threat.target,
                reason=f"{threat.threat_type} detected",
                severity=sev,
                reason_code=threat.reason_code,
                delay_seconds=self._cfg.default_delay_seconds,
                cooldown_seconds=self._cfg.cooldown_high_seconds,
                evidence=threat.evidence,
            )

        # CRITICAL
        return Decision(
            decision_type=DecisionType.DELAYED_EXECUTE,
            target=threat.target,
            reason=f"{threat.threat_type} detected",
            severity=sev,
            reason_code=threat.reason_code,
            delay_seconds=max(1, self._cfg.default_delay_seconds // 2),
            cooldown_seconds=self._cfg.cooldown_critical_seconds,
            evidence=threat.evidence,
        )


# -------------------------- Oversight (Boundary) ----------------------------

@dataclass(frozen=True)
class OversightConfig:
    dedupe_ttl_seconds: int = 120

    max_pending_or_gated: int = 500

    budget_window_seconds: int = 300
    budget_max_actions_per_target: int = 5

    require_two_signals_for_high: bool = True
    corroboration_ttl_seconds: int = 600

    cleanup_every_n_actions: int = 25

    # action execution guard
    action_timeout_seconds: int = 30


class OversightEngine:
    """
    Hardened boundary:
    - Restart-resistant dedupe via fingerprint (SQLite)
    - Per-target budget (SQLite)
    - Two-signal corroboration for HIGH+ (optional)
    - Gated approvals in HUMAN_GATED
    - Scheduler-based delayed execution in ACTIVE
    - Tamper-evident audit events
    """

    def __init__(
        self,
        *,
        mode_resolver: Callable[[], OpMode],
        store: StateStore,
        scheduler: Scheduler,
        clock: Clock,
        cfg: OversightConfig,
        metrics: Metrics,
    ) -> None:
        self._mode_resolver = mode_resolver
        self._store = store
        self._scheduler = scheduler
        self._clock = clock
        self._cfg = cfg
        self._m = metrics

        self._lock = threading.RLock()
        self._gated: Dict[str, ActionRequest] = {}
        self._pending: Dict[str, ActionRequest] = {}
        self._action_counter = 0

    def _audit(self, event_type: str, payload: Dict[str, Any]) -> None:
        ts = self._clock.now_int()
        self._store.append_audit_event(ts=ts, event_type=event_type, payload=payload)

    def schedule_action(self, req: ActionRequest) -> None:
        mode = self._mode_resolver()
        now_ts = self._clock.now_int()

        with self._lock:
            self._action_counter += 1
            if self._action_counter % max(1, self._cfg.cleanup_every_n_actions) == 0:
                self._store.dedupe_cleanup(now_ts=now_ts, ttl_seconds=self._cfg.dedupe_ttl_seconds)
                self._store.corroboration_cleanup(now_ts=now_ts, ttl_seconds=self._cfg.corroboration_ttl_seconds)

            if (len(self._pending) + len(self._gated)) >= self._cfg.max_pending_or_gated:
                self._m.drops_backpressure += 1
                logger.error("[OVERSIGHT] Back-pressure: pending/gated limit hit. Dropping %s", req.action_id)
                self._audit("drop_backpressure", {"action_id": req.action_id, "fingerprint": req.fingerprint})
                return

            if self._store.in_cooldown(req.target, now_ts=now_ts):
                self._m.suppress_cooldown += 1
                logger.info("[OVERSIGHT] Cooldown active for target=%s. Suppressing %s", req.target, req.action_id)
                self._audit("suppress_cooldown", {"action_id": req.action_id, "target": req.target})
                return

            if self._store.dedupe_seen(req.fingerprint, now_ts=now_ts, ttl_seconds=self._cfg.dedupe_ttl_seconds):
                self._m.suppress_dedupe += 1
                logger.info("[OVERSIGHT] Duplicate suppressed fp=%s...", req.fingerprint[:12])
                self._audit("suppress_dedupe", {"action_id": req.action_id, "fingerprint": req.fingerprint})
                return

            if not self._store.consume_budget(
                req.target,
                now_ts=now_ts,
                window_seconds=self._cfg.budget_window_seconds,
                max_actions=self._cfg.budget_max_actions_per_target,
            ):
                self._m.suppress_budget += 1
                logger.warning("[OVERSIGHT] Budget exceeded for target=%s. Suppressing %s", req.target, req.action_id)
                self._audit("suppress_budget", {"action_id": req.action_id, "target": req.target})
                return

            if req.severity in (Severity.HIGH, Severity.CRITICAL) and self._cfg.require_two_signals_for_high:
                count = self._store.corroborate(
                    req.fingerprint,
                    now_ts=now_ts,
                    ttl_seconds=self._cfg.corroboration_ttl_seconds,
                )
                self._audit("corroboration", {"fingerprint": req.fingerprint, "count": count})
                logger.info("[OVERSIGHT] Corroboration fp=%s... -> %d", req.fingerprint[:12], count)

                if count < 2:
                    self._m.corroboration_wait += 1
                    logger.info("[OVERSIGHT] Waiting for second signal before acting on HIGH+ (%s)", req.action_id)
                    if mode is OpMode.SHADOW:
                        req.shadow_payload()
                        self._m.shadow_logged += 1
                        self._audit("shadow_logged", {"action_id": req.action_id, "target": req.target})
                    return

            self._audit("action_received", {
                "mode": mode.value,
                "action_id": req.action_id,
                "fingerprint": req.fingerprint,
                "target": req.target,
                "severity": req.severity.value,
                "reason_code": req.reason_code.value,
                "reason": req.reason,
                "delay_seconds": int(req.delay_seconds),
                "cooldown_seconds": int(req.cooldown_seconds),
                "evidence": asdict(req.evidence),
            })

            # Set cooldown ONCE, using policy cooldown (max semantics)
            self._store.set_cooldown_max(req.target, until_ts=now_ts + max(0, int(req.cooldown_seconds)))

            logger.info("[OVERSIGHT] Mode=%s | %s", mode.value, req.description)

            if mode is OpMode.SHADOW:
                req.shadow_payload()
                self._m.shadow_logged += 1
                self._audit("shadow_logged", {"action_id": req.action_id, "target": req.target})
                return

            if mode is OpMode.HUMAN_GATED:
                self._gated[req.action_id] = req
                self._m.gated_staged += 1
                logger.warning("[OVERSIGHT] ACTION STAGED: %s. Awaiting approval.", req.action_id)
                self._audit("action_staged", {"action_id": req.action_id, "target": req.target})
                return

            # ACTIVE: delayed execution (veto window)
            self._pending[req.action_id] = req
            self._m.pending_armed += 1
            logger.warning("[OVERSIGHT] ACTION PENDING: %s. Executes in %ss unless vetoed.",
                           req.action_id, int(req.delay_seconds))
            self._audit("action_pending", {"action_id": req.action_id, "delay_seconds": int(req.delay_seconds)})

            def _payload_wrapper() -> None:
                with self._lock:
                    popped = self._pending.pop(req.action_id, None)
                if not popped:
                    return

                self._audit("action_execute", {"action_id": req.action_id, "target": req.target})
                logger.warning("[OVERSIGHT] AUTO-EXECUTING: %s", req.description)

                ok, err = execute_with_timeout(req.real_payload, timeout_seconds=self._cfg.action_timeout_seconds)
                if ok:
                    self._m.executed += 1
                    self._audit("action_executed", {"action_id": req.action_id, "target": req.target})
                    return

                if err and err.startswith("timeout_after_"):
                    self._m.exec_timeout += 1
                    self._audit("action_timeout", {
                        "action_id": req.action_id,
                        "target": req.target,
                        "timeout_seconds": int(self._cfg.action_timeout_seconds),
                    })
                    logger.error("[OVERSIGHT] Action timed out: %s", req.action_id)
                    return

                self._m.exec_failed += 1
                self._audit("action_failed", {"action_id": req.action_id, "target": req.target, "error": err})
                logger.error("[OVERSIGHT] Action failed: %s | %s", req.action_id, err)

            self._scheduler.schedule(
                action_id=req.action_id,
                delay_seconds=int(req.delay_seconds),
                description=req.description,
                payload=_payload_wrapper,
            )

    def veto_action(self, action_id: str, reason: str, *, operator_id: str = "unknown") -> bool:
        reason = (reason or "").strip()[:300]
        operator_id = (operator_id or "unknown").strip()[:80]

        with self._lock:
            if action_id in self._pending:
                self._pending.pop(action_id, None)
                self._scheduler.cancel(action_id)
                self._m.vetoed += 1
                logger.warning("[OVERSIGHT] VETOED %s. Operator=%s Reason=%s", action_id, operator_id, reason)
                self._audit("action_vetoed", {"action_id": action_id, "reason": reason, "operator_id": operator_id})
                return True

            if action_id in self._gated:
                self._gated.pop(action_id, None)
                self._m.vetoed += 1
                logger.warning("[OVERSIGHT] GATED ACTION DROPPED %s. Operator=%s Reason=%s", action_id, operator_id, reason)
                self._audit("gated_dropped", {"action_id": action_id, "reason": reason, "operator_id": operator_id})
                return True

        logger.warning("[OVERSIGHT] VETO FAILED: %s not found.", action_id)
        self._audit("veto_failed", {"action_id": action_id, "reason": reason, "operator_id": operator_id})
        return False

    def approve_gated_action(self, action_id: str, *, operator_id: str = "unknown") -> bool:
        operator_id = (operator_id or "unknown").strip()[:80]

        with self._lock:
            req = self._gated.pop(action_id, None)

        if not req:
            logger.warning("[OVERSIGHT] APPROVAL FAILED: %s not staged.", action_id)
            self._audit("approve_failed", {"action_id": action_id, "operator_id": operator_id})
            return False

        self._m.gated_approved += 1
        logger.warning("[OVERSIGHT] APPROVED: %s by %s. Executing now.", action_id, operator_id)
        self._audit("gated_approved", {"action_id": action_id, "target": req.target, "operator_id": operator_id})

        ok, err = execute_with_timeout(req.real_payload, timeout_seconds=self._cfg.action_timeout_seconds)
        if ok:
            self._m.executed += 1
            self._audit("gated_executed", {"action_id": action_id, "target": req.target})
            return True

        if err and err.startswith("timeout_after_"):
            self._m.exec_timeout += 1
            self._audit("gated_timeout", {"action_id": action_id, "target": req.target})
            logger.error("[OVERSIGHT] Approved action timed out: %s", action_id)
            return False

        self._m.exec_failed += 1
        self._audit("gated_failed", {"action_id": action_id, "target": req.target, "error": err})
        logger.error("[OVERSIGHT] Approved execution failed for %s: %s", action_id, err)
        return False

    def list_gated_actions(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {
                aid: {
                    "action_id": req.action_id,
                    "target": req.target,
                    "severity": req.severity.value,
                    "reason_code": req.reason_code.value,
                    "reason": req.reason,
                    "delay_seconds": int(req.delay_seconds),
                    "cooldown_seconds": int(req.cooldown_seconds),
                    "evidence": asdict(req.evidence),
                }
                for aid, req in self._gated.items()
            }


# ------------------------------ Nexus Config --------------------------------

@dataclass(frozen=True)
class SentinelConfig:
    db_path: str = "./sentinel43_state/sentinel43.sqlite3"

    default_sensor: str = "manual"
    default_confidence: float = 0.65

    policy: PolicyConfig = PolicyConfig()
    oversight: OversightConfig = OversightConfig()


# ------------------------------ Sentinel Nexus ------------------------------

class SentinelNexus:
    """
    Top-level controller:
    - Accept ThreatEvent
    - Evaluate policy
    - Build ActionRequest (fingerprint + stable IDs)
    - Hand off to OversightEngine
    """

    def __init__(
        self,
        *,
        cfg: SentinelConfig = SentinelConfig(),
        initial_mode: OpMode = OpMode.SHADOW,
        clock: Optional[Clock] = None,
    ) -> None:
        self._cfg = cfg
        self._mode = initial_mode
        self._clock = clock or Clock()
        self.metrics = Metrics()

        self._store = StateStore(cfg.db_path)
        self._scheduler = Scheduler(self._clock)
        self._policy = PolicyEngine(cfg.policy)

        self.oversight = OversightEngine(
            mode_resolver=self.get_mode,
            store=self._store,
            scheduler=self._scheduler,
            clock=self._clock,
            cfg=cfg.oversight,
            metrics=self.metrics,
        )

        logger.info("[%s] Nexus Online. Operational Mode=%s", SYSTEM_ID, self._mode.value)

        self._store.append_audit_event(
            ts=self._clock.now_int(),
            event_type="boot",
            payload={"system": SYSTEM_ID, "mode": self._mode.value},
        )

    def shutdown(self) -> None:
        """Graceful stop."""
        self._store.append_audit_event(
            ts=self._clock.now_int(),
            event_type="shutdown",
            payload={"system": SYSTEM_ID, "mode": self._mode.value},
        )
        self._scheduler.shutdown()
        self._store.close()

    def set_mode(self, mode: OpMode) -> None:
        self._mode = mode
        logger.warning("[%s] Mode switched to %s", SYSTEM_ID, self._mode.value)
        self._store.append_audit_event(
            ts=self._clock.now_int(),
            event_type="mode_switch",
            payload={"system": SYSTEM_ID, "mode": self._mode.value},
        )

    def get_mode(self) -> OpMode:
        return self._mode

    # ------------------------ Threat Intake Helpers ------------------------

    def build_threat(
        self,
        *,
        target: str,
        threat_type: str,
        severity: Severity = Severity.MEDIUM,
        reason_code: ReasonCode = ReasonCode.UNKNOWN,
        sensor: Optional[str] = None,
        confidence: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> ThreatEvent:
        tgt = (target or "").strip()
        if not tgt:
            raise ValueError("target is required")
        if len(tgt) > 256:
            raise ValueError("target too long")

        tt = (threat_type or "UNKNOWN").strip() or "UNKNOWN"
        tt = _safe_str(tt, max_len=120)

        conf = float(confidence if confidence is not None else self._cfg.default_confidence)
        if not (0.0 <= conf <= 1.0):
            raise ValueError("confidence must be within [0.0, 1.0]")

        det = dict(details or {})
        # crude guardrail: keep details from becoming a DB bomb
        if len(_json_dumps(det)) > 20_000:
            raise ValueError("details too large")

        ev = Evidence(
            system=SYSTEM_ID,
            sensor=_safe_str((sensor or self._cfg.default_sensor), max_len=64),
            observed_at=self._clock.now_int(),
            confidence=conf,
            details=det,
        )
        return ThreatEvent(
            target=tgt,
            threat_type=tt,
            reason_code=reason_code,
            severity=severity,
            evidence=ev,
        )

    def handle_threat(self, threat: ThreatEvent) -> Optional[str]:
        """
        Full pipeline:
        ThreatEvent -> Decision -> ActionRequest -> Oversight
        Returns action_id if an action was created, else None.
        """
        self.metrics.threats_seen += 1

        decision = self._policy.evaluate(threat)

        if decision.decision_type is DecisionType.NONE:
            self.metrics.decisions_none += 1
            self._store.append_audit_event(
                ts=self._clock.now_int(),
                event_type="decision_none",
                payload={"target": threat.target, "threat_type": threat.threat_type},
            )
            return None

        fp = stable_fingerprint(
            target=threat.target,
            threat_type=threat.threat_type,
            reason_code=threat.reason_code,
            reason=decision.reason,
            extra={
                "system": SYSTEM_ID,
                "sensor": threat.evidence.sensor,
                "reason_code": threat.reason_code.value,
            },
        )

        bucket = int(self._clock.now() // 30)
        safe_target = threat.target.replace(" ", "_")
        action_id = f"BLOCK-{safe_target}-{fp[:12]}-T{bucket}"

        req = ActionRequest(
            action_id=action_id,
            fingerprint=fp,
            target=threat.target,
            description=f"Block target {threat.target}",
            delay_seconds=int(decision.delay_seconds),
            cooldown_seconds=int(decision.cooldown_seconds),
            severity=decision.severity,
            reason=decision.reason,
            reason_code=decision.reason_code,
            evidence=decision.evidence,
            real_payload=lambda: IntegrationHub.execute_firewall_block(
                threat.target, reason=decision.reason, evidence=decision.evidence
            ),
            shadow_payload=lambda: IntegrationHub.log_shadow_action(
                threat.target, reason=decision.reason, evidence=decision.evidence
            ),
        )

        self.metrics.actions_built += 1

        logger.info(
            "[THREAT] type=%s target=%s severity=%s reason_code=%s sensor=%s conf=%.2f",
            threat.threat_type, threat.target, threat.severity.value, threat.reason_code.value,
            threat.evidence.sensor, threat.evidence.confidence,
        )

        self.oversight.schedule_action(req)
        return action_id