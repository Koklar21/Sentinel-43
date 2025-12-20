"""
SENTINEL-43 Nexus (sentinel43_nexus.py)

Public-facing, Murphy's-Law-hardened security nexus core:
- ThreatEvent ingestion (typed)
- Policy evaluation (deterministic, testable)
- Oversight boundary (dedupe, budget, corroboration, gating)
- Single-thread scheduler (no Timer pileups)
- Restart-resistant state (SQLite)
- Tamper-evident audit chain (hash-chained events)

All real-world effects must terminate in IntegrationHub.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Callable, Dict, Optional, Tuple, Any, List


SYSTEM_ID = "SENTINEL-43-NEXUS-01"


# ----------------------------- Logging --------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(module)-18s | %(message)s",
)


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


@dataclass(frozen=True)
class ThreatEvent:
    target: str                 # e.g., IP
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
    severity: Severity
    reason: str
    reason_code: ReasonCode
    evidence: Evidence
    real_payload: Callable[[], None]
    shadow_payload: Callable[[], None]


# ----------------------- Utilities: Hash & JSON -----------------------------

def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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


# ------------------------ Integration Hub (Boundary) ------------------------

class IntegrationHub:
    """
    All real-world effects terminate here.

    Replace these stubs with real integrations:
    - firewall provider / WAF / IAM / SIEM
    - ticketing system
    - paging / alerts
    """

    @staticmethod
    def execute_firewall_block(target: str, *, reason: str, evidence: Evidence) -> bool:
        logging.warning(f"[FIREWALL] HARD BLOCK applied to {target} | reason={reason} | evidence={asdict(evidence)}")
        return True

    @staticmethod
    def log_shadow_action(target: str, *, reason: str, evidence: Evidence) -> bool:
        logging.info(f"[SHADOW] WOULD have blocked {target} | reason={reason} | evidence={asdict(evidence)}")
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
    - cooldown per target (optional)
    - audit chain state (prev hash)
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dedupe (
                    fingerprint TEXT PRIMARY KEY,
                    first_seen INTEGER NOT NULL
                )
                """
            )
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS budget (
                    target TEXT PRIMARY KEY,
                    window_start INTEGER NOT NULL,
                    used INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cooldown (
                    target TEXT PRIMARY KEY,
                    until_ts INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    prev_hash TEXT NOT NULL
                )
                """
            )
            # initialize audit_chain row if missing
            cur = conn.execute("SELECT prev_hash FROM audit_chain WHERE id=1")
            row = cur.fetchone()
            if not row:
                conn.execute("INSERT INTO audit_chain (id, prev_hash) VALUES (1, ?)", ("0" * 64,))

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    ts INTEGER NOT NULL,
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
        with self._lock, self._connect() as conn:
            cur = conn.execute("SELECT first_seen FROM dedupe WHERE fingerprint=?", (fingerprint,))
            row = cur.fetchone()
            if row:
                first_seen = int(row[0])
                if now_ts - first_seen <= ttl_seconds:
                    return True
                # expired -> replace timestamp
                conn.execute("UPDATE dedupe SET first_seen=? WHERE fingerprint=?", (now_ts, fingerprint))
                return False

            conn.execute("INSERT INTO dedupe (fingerprint, first_seen) VALUES (?, ?)", (fingerprint, now_ts))
            return False

    def dedupe_cleanup(self, *, now_ts: int, ttl_seconds: int) -> None:
        with self._lock, self._connect() as conn:
            cutoff = now_ts - ttl_seconds
            conn.execute("DELETE FROM dedupe WHERE first_seen < ?", (cutoff,))

    # ---- Corroboration ----

    def corroborate(self, fingerprint: str, *, now_ts: int, ttl_seconds: int) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute("SELECT first_seen, last_seen, count FROM corroboration WHERE fingerprint=?", (fingerprint,))
            row = cur.fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO corroboration (fingerprint, first_seen, last_seen, count) VALUES (?, ?, ?, ?)",
                    (fingerprint, now_ts, now_ts, 1),
                )
                return 1

            first_seen, last_seen, count = int(row[0]), int(row[1]), int(row[2])
            if now_ts - last_seen > ttl_seconds:
                # expired window -> reset
                conn.execute(
                    "UPDATE corroboration SET first_seen=?, last_seen=?, count=? WHERE fingerprint=?",
                    (now_ts, now_ts, 1, fingerprint),
                )
                return 1

            count += 1
            conn.execute(
                "UPDATE corroboration SET last_seen=?, count=? WHERE fingerprint=?",
                (now_ts, count, fingerprint),
            )
            return count

    def corroboration_cleanup(self, *, now_ts: int, ttl_seconds: int) -> None:
        with self._lock, self._connect() as conn:
            cutoff = now_ts - ttl_seconds
            conn.execute("DELETE FROM corroboration WHERE last_seen < ?", (cutoff,))

    # ---- Budget ----

    def consume_budget(self, target: str, *, now_ts: int, window_seconds: int, max_actions: int) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("SELECT window_start, used FROM budget WHERE target=?", (target,))
            row = cur.fetchone()
            if not row:
                conn.execute("INSERT INTO budget (target, window_start, used) VALUES (?, ?, ?)", (target, now_ts, 1))
                return True

            window_start, used = int(row[0]), int(row[1])
            if now_ts - window_start > window_seconds:
                conn.execute("UPDATE budget SET window_start=?, used=? WHERE target=?", (now_ts, 1, target))
                return True

            if used >= max_actions:
                return False

            conn.execute("UPDATE budget SET used=? WHERE target=?", (used + 1, target))
            return True

    # ---- Cooldown ----

    def in_cooldown(self, target: str, *, now_ts: int) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("SELECT until_ts FROM cooldown WHERE target=?", (target,))
            row = cur.fetchone()
            if not row:
                return False
            until_ts = int(row[0])
            return now_ts < until_ts

    def set_cooldown(self, target: str, *, until_ts: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO cooldown (target, until_ts) VALUES (?, ?) "
                "ON CONFLICT(target) DO UPDATE SET until_ts=excluded.until_ts",
                (target, until_ts),
            )

    # ---- Audit chain ----

    def append_audit_event(self, *, ts: int, event_type: str, payload: Dict[str, Any]) -> str:
        payload_json = _json_dumps(payload)
        with self._lock, self._connect() as conn:
            cur = conn.execute("SELECT prev_hash FROM audit_chain WHERE id=1")
            prev_hash = cur.fetchone()[0]
            raw = (prev_hash + "|" + str(ts) + "|" + event_type + "|" + payload_json).encode("utf-8")
            h = hashlib.sha256(raw).hexdigest()
            conn.execute(
                "INSERT INTO audit_events (ts, event_type, payload_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
                (ts, event_type, payload_json, prev_hash, h),
            )
            conn.execute("UPDATE audit_chain SET prev_hash=? WHERE id=1", (h,))
            return h


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
    This avoids spawning tons of Timer threads.
    """

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._heap: List[_ScheduledItem] = []
        self._seq = 0
        self._cancelled: set[str] = set()
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

    def shutdown(self) -> None:
        with self._cv:
            self._stopping = True
            self._cv.notify()
        self._thread.join(timeout=5)

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

                if item.action_id in self._cancelled:
                    self._cancelled.discard(item.action_id)
                    continue

            # Execute outside lock
            logging.warning(f"[SCHEDULER] Executing: {item.description}")
            try:
                item.payload()
            except Exception as exc:
                logging.error(f"[SCHEDULER] Execution failed for {item.action_id}: {exc}")


# ----------------------------- Policy Engine --------------------------------

@dataclass(frozen=True)
class PolicyConfig:
    # high-level posture
    default_delay_seconds: int = 5
    # cooldowns
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

        # Basic ladder. Tune as needed.
        if sev in (Severity.LOW,):
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

        if sev in (Severity.MEDIUM,):
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

        if sev in (Severity.HIGH,):
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
    # replay defense
    dedupe_ttl_seconds: int = 120

    # backlog limits
    max_pending_or_gated: int = 500

    # budget
    budget_window_seconds: int = 300
    budget_max_actions_per_target: int = 5

    # corroboration
    require_two_signals_for_high: bool = True
    corroboration_ttl_seconds: int = 600

    # cleanup cadence
    cleanup_every_n_actions: int = 25


class OversightEngine:
    """
    Hardened boundary:
    - Restart-resistant dedupe via fingerprint
    - Per-target budget via SQLite
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
    ) -> None:
        self._mode_resolver = mode_resolver
        self._store = store
        self._scheduler = scheduler
        self._clock = clock
        self._cfg = cfg

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

            # backlog protection
            if (len(self._pending) + len(self._gated)) >= self._cfg.max_pending_or_gated:
                logging.error(f"[OVERSIGHT] Back-pressure: too many pending/gated actions. Dropping {req.action_id}")
                self._audit("drop_backpressure", {"action_id": req.action_id, "fingerprint": req.fingerprint})
                return

            # cooldown protection (stored)
            if self._store.in_cooldown(req.target, now_ts=now_ts):
                logging.info(f"[OVERSIGHT] Cooldown active for target={req.target}. Suppressing {req.action_id}")
                self._audit("suppress_cooldown", {"action_id": req.action_id, "target": req.target})
                return

            # dedupe by fingerprint
            if self._store.dedupe_seen(req.fingerprint, now_ts=now_ts, ttl_seconds=self._cfg.dedupe_ttl_seconds):
                logging.info(f"[OVERSIGHT] Duplicate suppressed (fingerprint): {req.fingerprint[:12]}...")
                self._audit("suppress_dedupe", {"action_id": req.action_id, "fingerprint": req.fingerprint})
                return

            # budget per target
            if not self._store.consume_budget(
                req.target,
                now_ts=now_ts,
                window_seconds=self._cfg.budget_window_seconds,
                max_actions=self._cfg.budget_max_actions_per_target,
            ):
                logging.warning(f"[OVERSIGHT] Budget exceeded for target={req.target}. Suppressing {req.action_id}")
                self._audit("suppress_budget", {"action_id": req.action_id, "target": req.target})
                return

            # corroboration for HIGH+ if enabled
            if req.severity in (Severity.HIGH, Severity.CRITICAL) and self._cfg.require_two_signals_for_high:
                count = self._store.corroborate(
                    req.fingerprint,
                    now_ts=now_ts,
                    ttl_seconds=self._cfg.corroboration_ttl_seconds,
                )
                logging.info(f"[OVERSIGHT] Corroboration fp={req.fingerprint[:12]}... -> {count}")
                self._audit("corroboration", {"fingerprint": req.fingerprint, "count": count})

                if count < 2:
                    # advisory-only on first signal
                    logging.info(f"[OVERSIGHT] Waiting for second signal before acting on HIGH+: {req.action_id}")
                    if mode is OpMode.SHADOW:
                        req.shadow_payload()
                    # HUMAN_GATED/ACTIVE: do not stage/arm yet
                    return

            logging.info(f"[OVERSIGHT] Mode={mode.value} | {req.description}")

            # Apply cooldown immediately once we accept the action into the pipeline
            cooldown_until = now_ts + max(0, int(30))  # baseline, can be tuned at policy layer too
            self._store.set_cooldown(req.target, until_ts=cooldown_until)

            self._audit("action_received", {
                "mode": mode.value,
                "action_id": req.action_id,
                "fingerprint": req.fingerprint,
                "target": req.target,
                "severity": req.severity.value,
                "reason_code": req.reason_code.value,
                "reason": req.reason,
                "evidence": asdict(req.evidence),
            })

            # Mode behaviors
            if mode is OpMode.SHADOW:
                req.shadow_payload()
                self._audit("shadow_logged", {"action_id": req.action_id, "target": req.target})
                return

            if mode is OpMode.HUMAN_GATED:
                self._gated[req.action_id] = req
                logging.warning(f"[OVERSIGHT] ACTION STAGED: {req.action_id}. Awaiting approval.")
                self._audit("action_staged", {"action_id": req.action_id, "target": req.target})
                return

            # ACTIVE: delayed execution (veto window)
            self._pending[req.action_id] = req
            logging.warning(
                f"[OVERSIGHT] ACTION PENDING: {req.action_id}. Executes in {req.delay_seconds}s unless vetoed."
            )
            self._audit("action_pending", {"action_id": req.action_id, "delay_seconds": req.delay_seconds})

            def _payload_wrapper() -> None:
                # Remove from pending only when we execute
                with self._lock:
                    popped = self._pending.pop(req.action_id, None)
                if not popped:
                    return
                logging.warning(f"[OVERSIGHT] AUTO-EXECUTING: {req.description}")
                self._audit("action_execute", {"action_id": req.action_id, "target": req.target})
                req.real_payload()

            self._scheduler.schedule(
                action_id=req.action_id,
                delay_seconds=req.delay_seconds,
                description=req.description,
                payload=_payload_wrapper,
            )

    def veto_action(self, action_id: str, reason: str) -> bool:
        reason = (reason or "").strip()[:300]
        with self._lock:
            if action_id in self._pending:
                self._pending.pop(action_id, None)
                self._scheduler.cancel(action_id)
                logging.warning(f"[OVERSIGHT] VETOED {action_id}. Reason: {reason}")
                self._audit("action_vetoed", {"action_id": action_id, "reason": reason})
                return True

            if action_id in self._gated:
                self._gated.pop(action_id, None)
                logging.warning(f"[OVERSIGHT] GATED ACTION DROPPED {action_id}. Reason: {reason}")
                self._audit("gated_dropped", {"action_id": action_id, "reason": reason})
                return True

        logging.warning(f"[OVERSIGHT] VETO FAILED: {action_id} not found.")
        self._audit("veto_failed", {"action_id": action_id, "reason": reason})
        return False

    def approve_gated_action(self, action_id: str) -> bool:
        with self._lock:
            req = self._gated.pop(action_id, None)

        if not req:
            logging.warning(f"[OVERSIGHT] APPROVAL FAILED: {action_id} not staged.")
            self._audit("approve_failed", {"action_id": action_id})
            return False

        logging.warning(f"[OVERSIGHT] APPROVED: {action_id}. Executing now.")
        self._audit("gated_approved", {"action_id": action_id, "target": req.target})
        try:
            req.real_payload()
            self._audit("gated_execute", {"action_id": action_id})
            return True
        except Exception as exc:
            logging.error(f"[OVERSIGHT] Approved execution failed for {action_id}: {exc}")
            self._audit("gated_execute_failed", {"action_id": action_id, "error": str(exc)})
            return False

    def list_gated_actions(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            out: Dict[str, Dict[str, Any]] = {}
            for aid, req in self._gated.items():
                out[aid] = {
                    "action_id": req.action_id,
                    "target": req.target,
                    "severity": req.severity.value,
                    "reason_code": req.reason_code.value,
                    "reason": req.reason,
                    "evidence": asdict(req.evidence),
                }
            return out


# ------------------------------ Nexus Config --------------------------------

@dataclass(frozen=True)
class SentinelConfig:
    db_path: str = "./sentinel43_state/sentinel43.sqlite3"

    # Evidence defaults (override per detector)
    default_sensor: str = "manual"
    default_confidence: float = 0.65

    # Oversight / policy
    policy: PolicyConfig = PolicyConfig()
    oversight: OversightConfig = OversightConfig()


# ------------------------------ Sentinel Nexus ------------------------------

class SentinelNexus:
    """
    Top-level controller:
    - Accept ThreatEvent (or raw inputs to construct it)
    - Evaluate policy
    - Build ActionRequest (fingerprint + stable IDs)
    - Hand off to OversightEngine
    """

    def __init__(self, *, cfg: SentinelConfig = SentinelConfig(), initial_mode: OpMode = OpMode.SHADOW, clock: Optional[Clock] = None) -> None:
        self._cfg = cfg
        self._mode = initial_mode
        self._clock = clock or Clock()

        self._store = StateStore(cfg.db_path)
        self._scheduler = Scheduler(self._clock)
        self._policy = PolicyEngine(cfg.policy)
        self.oversight = OversightEngine(
            mode_resolver=self.get_mode,
            store=self._store,
            scheduler=self._scheduler,
            clock=self._clock,
            cfg=cfg.oversight,
        )

        logging.info(f"[{SYSTEM_ID}] Nexus Online. Operational Mode={self._mode.value}")

        # Audit boot event
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

    def set_mode(self, mode: OpMode) -> None:
        self._mode = mode
        logging.warning(f"[{SYSTEM_ID}] Mode switched to {self._mode.value}")
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

        tt = (threat_type or "UNKNOWN").strip()

        ev = Evidence(
            system=SYSTEM_ID,
            sensor=(sensor or self._cfg.default_sensor),
            observed_at=self._clock.now_int(),
            confidence=float(confidence if confidence is not None else self._cfg.default_confidence),
            details=dict(details or {}),
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
        decision = self._policy.evaluate(threat)

        # None means ignore
        if decision.decision_type is DecisionType.NONE:
            self._store.append_audit_event(
                ts=self._clock.now_int(),
                event_type="decision_none",
                payload={"target": threat.target, "threat_type": threat.threat_type},
            )
            return None

        # Build stable fingerprint
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

        # Action ID uses fingerprint prefix + time bucket, for readability + grouping
        bucket = int(self._clock.now() // 30)  # coarse bucket for log grouping
        action_id = f"BLOCK-{threat.target}-{fp[:12]}-T{bucket}"

        # Action type mapping to mode intent happens inside Oversight (mode controls behavior)
        req = ActionRequest(
            action_id=action_id,
            fingerprint=fp,
            target=threat.target,
            description=f"Block target {threat.target}",
            delay_seconds=decision.delay_seconds,
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

        logging.info(
            f"[THREAT] {threat.threat_type} target={threat.target} "
            f"severity={threat.severity.value} reason_code={threat.reason_code.value} "
            f"sensor={threat.evidence.sensor} confidence={threat.evidence.confidence:.2f}"
        )

        # If policy says "shadow only", we can force the system into shadow behavior regardless of opmode,
        # but in a public release it's usually better to keep opmode authoritative.
        # We'll keep opmode authoritative and use req.shadow_payload in SHADOW mode.

        self.oversight.schedule_action(req)

        # Apply cooldown tuned by policy decision
        now_ts = self._clock.now_int()
        self._store.set_cooldown(threat.target, until_ts=now_ts + max(0, decision.cooldown_seconds))

        return action_id