"""sentinel43.core.governance.governance

Unified Governance Module for Sentinel-43

This file merges:

1. DATA-FIRST governance definitions (modes, actions, allow/deny rules)


2. Governance orchestrator utilities (authz gate, velocity guard, tamper-evident audit)



Design notes:

The policy definitions section is pure data + helpers (no I/O).

The orchestrator section intentionally performs I/O (SQLite/JSONL audit) and logging.


If you later want strict separation, split this file into:

governance_rules.py (data-first)

governance_orchestrator.py (runtime)


For now: one file, one source of truth. """

from future import annotations

import hashlib import hmac import json import logging import os import sqlite3 import threading from dataclasses import dataclass, field from datetime import datetime, timedelta, timezone from decimal import Decimal, InvalidOperation from pathlib import Path from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

============================================================================

LOG

============================================================================

_logger = logging.getLogger("sentinel43.governance")

============================================================================

SECTION 1: DATA-FIRST GOVERNANCE DEFINITIONS

(No runtime side effects. No I/O.)

============================================================================

----------------------------

Policy Modes

----------------------------

MODE_SHADOW = "SHADOW"  # observe-only; never execute high-impact actions MODE_HUMAN_GATED = "HUMAN_GATED"  # high-impact requires explicit human approval MODE_AUTONOMOUS_VETO = "AUTONOMOUS_VETO"  # conservative autonomous allow-list

ALLOWED_MODES: Set[str] = {MODE_SHADOW, MODE_HUMAN_GATED, MODE_AUTONOMOUS_VETO}

----------------------------

Action Taxonomy

----------------------------

ACTION_READ = "read" ACTION_WRITE = "write" ACTION_DELETE = "delete" ACTION_EXECUTE = "execute" ACTION_QUARANTINE = "quarantine" ACTION_ISOLATE = "isolate" ACTION_SHUTDOWN = "shutdown" ACTION_NETWORK_BLOCK = "network_block" ACTION_PRIV_ESC = "privilege_escalation"

@dataclass(frozen=True) class GovernanceRules: """Canonical policy ruleset.

- always_deny: actions never allowed under any mode
- human_required: actions requiring explicit human approval in HUMAN_GATED
- allowed_by_mode: explicit allow-lists per mode

Shadow mode is *observe-only*.
"""

always_deny: Set[str]
human_required: Set[str]
allowed_by_mode: Dict[str, Set[str]]

DEFAULT_GOVERNANCE = GovernanceRules( always_deny={ ACTION_PRIV_ESC, }, human_required={ ACTION_DELETE, ACTION_QUARANTINE, ACTION_ISOLATE, ACTION_SHUTDOWN, ACTION_NETWORK_BLOCK, }, allowed_by_mode={ # Shadow mode: you can evaluate anything you know about, but execution is not allowed. # Keep this as the broadest allow-list for observation, not enforcement. MODE_SHADOW: { ACTION_READ, ACTION_WRITE, ACTION_DELETE, ACTION_EXECUTE, ACTION_QUARANTINE, ACTION_ISOLATE, ACTION_SHUTDOWN, ACTION_NETWORK_BLOCK, }, MODE_HUMAN_GATED: { ACTION_READ, ACTION_WRITE, ACTION_EXECUTE, }, MODE_AUTONOMOUS_VETO: { ACTION_READ, ACTION_WRITE, }, }, )

----------------------------

Governance Decisions

----------------------------

GOV_DECISION_ALLOW = "ALLOW" GOV_DECISION_REQUIRE_HUMAN = "REQUIRE_HUMAN" GOV_DECISION_DENY = "DENY" GOV_DECISION_OBSERVE = "OBSERVE"  # shadow mode: do not execute, but record what would've happened

@dataclass(frozen=True) class GovernanceDecision: decision: str reason: str

def is_action_known(action: str) -> bool: """Return True if the action exists anywhere in governance.""" if action in DEFAULT_GOVERNANCE.always_deny: return True if action in DEFAULT_GOVERNANCE.human_required: return True for s in DEFAULT_GOVERNANCE.allowed_by_mode.values(): if action in s: return True return False

def is_always_denied(action: str) -> bool: return action in DEFAULT_GOVERNANCE.always_deny

def requires_human_approval(action: str) -> bool: return action in DEFAULT_GOVERNANCE.human_required

def is_allowed_in_mode(action: str, mode: str) -> bool: """Return True if action is explicitly allowed in the given mode.

Safety invariants:
- always_deny always wins
- unknown mode -> False
"""
if mode not in ALLOWED_MODES:
    return False
if is_always_denied(action):
    return False
return action in DEFAULT_GOVERNANCE.allowed_by_mode.get(mode, set())

def list_allowed_actions(mode: str) -> List[str]: return sorted(DEFAULT_GOVERNANCE.allowed_by_mode.get(mode, set()))

def evaluate_action(*, action: str, mode: str, human_approved: bool = False) -> GovernanceDecision: """Single source of truth for governance evaluation.

- In SHADOW: never allow execution; return OBSERVE if action is eligible for evaluation.
- always_deny: always DENY.
- HUMAN_GATED: if human_required and not approved -> REQUIRE_HUMAN.
- AUTONOMOUS_VETO: only allow what's on the allow-list.
"""

if mode not in ALLOWED_MODES:
    return GovernanceDecision(GOV_DECISION_DENY, "UNKNOWN_MODE")

if not is_action_known(action):
    return GovernanceDecision(GOV_DECISION_DENY, "UNKNOWN_ACTION")

if is_always_denied(action):
    return GovernanceDecision(GOV_DECISION_DENY, "ALWAYS_DENIED")

if not is_allowed_in_mode(action, mode):
    return GovernanceDecision(GOV_DECISION_DENY, "NOT_ALLOWED_IN_MODE")

# Shadow mode: observe-only.
if mode == MODE_SHADOW:
    return GovernanceDecision(GOV_DECISION_OBSERVE, "SHADOW_OBSERVE_ONLY")

if mode == MODE_HUMAN_GATED and requires_human_approval(action) and not human_approved:
    return GovernanceDecision(GOV_DECISION_REQUIRE_HUMAN, "HUMAN_APPROVAL_REQUIRED")

return GovernanceDecision(GOV_DECISION_ALLOW, "ALLOWED")

============================================================================

SECTION 2: ORCHESTRATOR + AUDIT (Runtime, I/O, Logging)

============================================================================

------------------------------------------------------------

CONFIG

------------------------------------------------------------

CONFIG: Dict[str, Any] = { "AUDIT_SQLITE_PATH": str(Path(os.getenv("SENTINEL_AUDIT_DB", "audit.db")).expanduser().resolve()), "AUDIT_JSONL_FILE": os.getenv("SENTINEL_AUDIT_JSONL", ""),  # optional

"VELOCITY_WINDOW_SECONDS": int(os.getenv("SENTINEL_VELOCITY_WINDOW_SECONDS", "60")),
"VELOCITY_LIMIT": int(os.getenv("SENTINEL_VELOCITY_LIMIT", "10")),
"VELOCITY_GC_INTERVAL_SECONDS": int(os.getenv("SENTINEL_VELOCITY_GC_INTERVAL_SECONDS", "300")),
"VELOCITY_MAX_ENTRIES_PER_USER": int(os.getenv("SENTINEL_VELOCITY_MAX_ENTRIES_PER_USER", "1000")),
"VELOCITY_MAX_DISTINCT_USERS": int(os.getenv("SENTINEL_VELOCITY_MAX_DISTINCT_USERS", "50000")),

# Auth replay/staleness guard
"AUTH_MAX_AGE_SECONDS": int(os.getenv("SENTINEL_AUTH_MAX_AGE_SECONDS", "900")),

# Audit behavior
"SENTINEL_ENV": (os.getenv("SENTINEL_ENV") or "prod").lower(),
"DEV_ALLOW_AUDIT_FAIL_OPEN": os.getenv("SENTINEL_DEV_ALLOW_AUDIT_FAIL_OPEN", "0") in {"1", "true", "TRUE"},

# Audit retry to reduce fork drops under concurrency
"AUDIT_MAX_RETRIES": int(os.getenv("SENTINEL_AUDIT_MAX_RETRIES", "3")),

}

class ReasonCodes: CLEARED = "CLEARED" AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED" AUTH_STALE = "AUTH_STALE"

AUDIT_CHAIN_FORK = "AUDIT_CHAIN_FORK"
AUDIT_CRYPTO_CONFIG_MISSING = "AUDIT_CRYPTO_CONFIG_MISSING"
AUDIT_APPEND_FAILED = "AUDIT_APPEND_FAILED"

VELOCITY_LIMIT = "VELOCITY_LIMIT"
VELOCITY_CAP_EXCEEDED = "VELOCITY_CAP_EXCEEDED"
VELOCITY_GLOBAL_CAP = "VELOCITY_GLOBAL_CAP"

INVALID_INPUT = "INVALID_INPUT"
INVALID_AMOUNT = "INVALID_AMOUNT"

class AuditEncoder(json.JSONEncoder): """Safe JSON encoder for Decimal/datetime."""

def default(self, obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    return super().default(obj)

def _get_hmac_secret() -> bytes: """Return HMAC secret bytes. FAILS CLOSED if missing."""

raw = os.getenv("GHOST_DEVICE_HASH_SECRET", "").strip()
if not raw:
    raise RuntimeError(
        "GHOST_DEVICE_HASH_SECRET is required. "
        "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

# Accept hex or raw text. If hex-like, decode.
try:
    if all(c in "0123456789abcdefABCDEF" for c in raw) and len(raw) >= 64 and len(raw) % 2 == 0:
        return bytes.fromhex(raw)
except Exception:
    pass

return raw.encode("utf-8")

def constant_time_compare(a: str, b: str) -> bool: return hmac.compare_digest(a, b)

class AuditStore: """Tamper-evident append-only audit chain (SQLite + optional JSONL sink).

NOTE: append() is transactionally atomic and fork-protected.
"""

def __init__(self, sqlite_path: str, jsonl_path: Optional[str] = None) -> None:
    self.sqlite_path = sqlite_path
    self.jsonl_path = jsonl_path or None
    self._lock = threading.Lock()
    self._ensure_schema()

def _connect(self) -> sqlite3.Connection:
    con = sqlite3.connect(self.sqlite_path, timeout=5.0)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=FULL;")
    return con

def _ensure_schema(self) -> None:
    Path(self.sqlite_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    con = self._connect()
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_time TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_anchor (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                prev_hash TEXT NOT NULL
            )
            """
        )
        row = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
        if row is None:
            con.execute("INSERT INTO audit_anchor (id, prev_hash) VALUES (1, ?)", ("GENESIS",))
        con.commit()
    finally:
        con.close()

def get_prev_hash(self) -> str:
    con = self._connect()
    try:
        (prev_hash,) = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
        return str(prev_hash)
    finally:
        con.close()

def append(self, payload: Dict[str, Any], payload_hash: str, prev_hash: str) -> None:
    """Atomic append with fork detection."""

    with self._lock:
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            (current_head,) = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
            current_head = str(current_head)

            if current_head != prev_hash:
                con.rollback()
                raise RuntimeError(f"Audit chain fork detected. expected={prev_hash} current_head={current_head}")

            decision_time = payload.get("decision_time") or datetime.now(timezone.utc).isoformat()
            payload_json = json.dumps(payload, cls=AuditEncoder, sort_keys=True, separators=(",", ":"))

            con.execute(
                "INSERT INTO audit_log (decision_time, payload_json, payload_hash, prev_hash) VALUES (?, ?, ?, ?)",
                (decision_time, payload_json, payload_hash, prev_hash),
            )
            con.execute("UPDATE audit_anchor SET prev_hash=? WHERE id=1", (payload_hash,))
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    # Best-effort JSONL sink outside DB transaction
    if self.jsonl_path:
        try:
            p = Path(self.jsonl_path).expanduser().resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="utf-8") as f:
                # IMPORTANT: newline must be a valid string literal.
                f.write(json.dumps({"payload": payload, "hash": payload_hash}, cls=AuditEncoder) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            _logger.error(f"JSONL sink failed (non-fatal): {e}")

@dataclass(frozen=True) class TransactionContext: user_id: str amount: Decimal timestamp: datetime location: str device_id: str metadata: Dict[str, Any] = field(default_factory=dict)

class SecureAuditLog: def init(self, store: AuditStore) -> None: self.store = store

def _hmac_device(self, device_id: str) -> str:
    secret = _get_hmac_secret()
    # hmac.new is valid; using explicit digestmod for clarity.
    return hmac.new(secret, device_id.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()

def _hash_metadata(self, meta: Dict[str, Any]) -> str:
    raw = json.dumps(meta or {}, cls=AuditEncoder, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def verify_device_hash(self, device_id: str, claimed_hash: str) -> bool:
    try:
        actual = self._hmac_device(device_id)
        return constant_time_compare(actual, claimed_hash)
    except Exception as e:
        _logger.error(f"Device hash verification failed: {e}")
        return False

def log_decision(
    self,
    context: TransactionContext,
    decision: str,
    reason_code: str,
    score: Decimal,
    filtered_meta: Dict[str, Any],
    extra: Dict[str, Any],
) -> bool:
    """Write audit record with retry on fork."""

    try:
        device_hash = self._hmac_device(context.device_id)
        meta_hash = self._hash_metadata(filtered_meta)

        payload: Dict[str, Any] = {
            "decision_time": datetime.now(timezone.utc).isoformat(),
            "user_id": context.user_id,
            "amount": str(context.amount),
            "location": context.location,
            "device_hash": device_hash,
            "metadata_hash": meta_hash,
            "decision": decision,
            "reason_code": reason_code,
            "score": str(score),
            "extra": extra or {},
        }

        max_retries = max(1, int(CONFIG.get("AUDIT_MAX_RETRIES", 3)))
        for attempt in range(1, max_retries + 1):
            prev_hash = self.store.get_prev_hash()
            payload_json = json.dumps(payload, cls=AuditEncoder, sort_keys=True, separators=(",", ":")).encode("utf-8")
            payload_hash = hashlib.sha256(payload_json + prev_hash.encode("utf-8")).hexdigest()

            try:
                self.store.append(payload=payload, payload_hash=payload_hash, prev_hash=prev_hash)
                return True
            except RuntimeError as e:
                msg = str(e)
                if "fork" in msg.lower() and attempt < max_retries:
                    continue
                _logger.critical(f"Audit failed (hard): {e}")
                return False

        return False

    except RuntimeError as e:
        _logger.critical(f"Audit failed (hard): {e}")
        return False
    except Exception as e:
        _logger.error(f"Audit failed: {e}")
        return False

class VelocityGuard: """In-memory velocity limiter with GC + caps against memory abuse."""

def __init__(
    self,
    *,
    window_seconds: int,
    limit: int,
    gc_interval_seconds: int,
    max_entries_per_user: int,
    max_distinct_users: int,
) -> None:
    self.window_seconds = int(window_seconds)
    self.limit = int(limit)
    self.gc_interval_seconds = int(gc_interval_seconds)
    self.max_entries_per_user = int(max_entries_per_user)
    self.max_distinct_users = int(max_distinct_users)

    self.user_events: Dict[str, Deque[datetime]] = {}
    self.lock = threading.Lock()
    self.last_gc = datetime.now(timezone.utc)

    from collections import deque

    self._deque = deque

def _garbage_collect(self, now: datetime) -> None:
    if (now - self.last_gc).total_seconds() < self.gc_interval_seconds:
        return

    cutoff = now - timedelta(seconds=self.window_seconds)
    dead_users: List[str] = []
    for user_id, dq in self.user_events.items():
        while dq and dq[0] < cutoff:
            dq.popleft()
        if not dq:
            dead_users.append(user_id)

    for user_id in dead_users:
        self.user_events.pop(user_id, None)

    self.last_gc = now

def allow(self, user_id: str, now: datetime) -> Tuple[bool, str]:
    """Returns (allowed, reason_code)."""

    with self.lock:
        self._garbage_collect(now)

        is_new_user = user_id not in self.user_events
        if is_new_user and len(self.user_events) >= self.max_distinct_users:
            _logger.warning(
                f"Velocity global cap exceeded distinct_users={len(self.user_events)} cap={self.max_distinct_users}"
            )
            return (False, ReasonCodes.VELOCITY_GLOBAL_CAP)

        dq = self.user_events.setdefault(user_id, self._deque())
        cutoff = now - timedelta(seconds=self.window_seconds)
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self.max_entries_per_user:
            _logger.warning(
                f"Velocity cap exceeded user={user_id} entries={len(dq)} cap={self.max_entries_per_user}"
            )
            return (False, ReasonCodes.VELOCITY_CAP_EXCEEDED)

        if len(dq) >= self.limit:
            return (False, ReasonCodes.VELOCITY_LIMIT)

        dq.append(now)
        return (True, ReasonCodes.CLEARED)

@dataclass(frozen=True) class CallerContext: caller_id: str caller_roles: Set[str] authenticated_at: datetime

@dataclass(frozen=True) class Decision: status: str score: Decimal reason: str

class SystemOrchestrator: """Governance gate.

NOTE: This is still a demo-oriented transaction example.
You will likely adapt it to: process_action(action, mode, target, human_approved, metadata).
"""

def __init__(
    self,
    *,
    authorizer: Optional[Callable[[CallerContext, str], bool]] = None,
    audit_sqlite_path: Optional[str] = None,
    audit_jsonl_path: Optional[str] = None,
) -> None:
    self.authorizer = authorizer or self._default_authorizer

    store = AuditStore(
        sqlite_path=audit_sqlite_path or CONFIG["AUDIT_SQLITE_PATH"],
        jsonl_path=(audit_jsonl_path or CONFIG["AUDIT_JSONL_FILE"] or None),
    )
    self.auditor = SecureAuditLog(store)

    self.velocity_guard = VelocityGuard(
        window_seconds=CONFIG["VELOCITY_WINDOW_SECONDS"],
        limit=CONFIG["VELOCITY_LIMIT"],
        gc_interval_seconds=CONFIG["VELOCITY_GC_INTERVAL_SECONDS"],
        max_entries_per_user=CONFIG["VELOCITY_MAX_ENTRIES_PER_USER"],
        max_distinct_users=CONFIG["VELOCITY_MAX_DISTINCT_USERS"],
    )

@staticmethod
def _default_authorizer(caller: CallerContext, target_user_id: str) -> bool:
    if caller.caller_id == target_user_id:
        return True
    if "admin" in caller.caller_roles or "system" in caller.caller_roles:
        return True
    return False

def process_transaction(
    self,
    *,
    caller: CallerContext,
    user_id: str,
    amount_str: str,
    metadata: Dict[str, Any],
) -> Decision:
    now = datetime.now(timezone.utc)

    # --- AUTHZ FIRST ---
    if not self.authorizer(caller, user_id):
        _logger.warning(f"Unauthorized: caller={caller.caller_id} -> user={user_id}")
        self._best_effort_audit_block(
            user_id=user_id,
            metadata=metadata,
            reason=ReasonCodes.AUTHORIZATION_FAILED,
            extra={"caller_id": caller.caller_id, "caller_roles": sorted(caller.caller_roles)},
        )
        return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.AUTHORIZATION_FAILED)

    # --- AUTH FRESHNESS ---
    try:
        max_age = int(CONFIG.get("AUTH_MAX_AGE_SECONDS", 900))
    except Exception:
        max_age = 900

    if (now - caller.authenticated_at).total_seconds() > max_age:
        _logger.warning(
            f"Stale auth context: caller={caller.caller_id} "
            f"age_s={(now - caller.authenticated_at).total_seconds():.0f}"
        )
        self._best_effort_audit_block(
            user_id=user_id,
            metadata=metadata,
            reason=ReasonCodes.AUTH_STALE,
            extra={"caller_id": caller.caller_id, "caller_roles": sorted(caller.caller_roles)},
        )
        return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.AUTH_STALE)

    # --- INPUT VALIDATION ---
    try:
        amount = Decimal(amount_str)
    except (InvalidOperation, ValueError, TypeError):
        self._best_effort_audit_block(
            user_id=user_id,
            metadata=metadata,
            reason=ReasonCodes.INVALID_INPUT,
            extra={"amount_str": amount_str},
        )
        return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.INVALID_INPUT)

    if (not amount.is_finite()) or amount < Decimal("0"):
        self._best_effort_audit_block(
            user_id=user_id,
            metadata=metadata,
            reason=ReasonCodes.INVALID_AMOUNT,
            extra={"amount_str": amount_str},
        )
        return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.INVALID_AMOUNT)

    # --- VELOCITY ---
    allowed, v_reason = self.velocity_guard.allow(user_id, now)
    if not allowed:
        self._best_effort_audit_block(
            user_id=user_id,
            metadata=metadata,
            reason=v_reason,
            extra={
                "window_seconds": CONFIG["VELOCITY_WINDOW_SECONDS"],
                "limit": CONFIG["VELOCITY_LIMIT"],
            },
        )
        return Decision(status="BLOCKED", score=Decimal("0"), reason=v_reason)

    # --- PLACEHOLDER DECISION LOGIC ---
    score = Decimal("0.5")
    decision = "APPROVED" if amount <= Decimal("1000") else "REVIEW"

    ctx = TransactionContext(
        user_id=user_id,
        amount=amount,
        timestamp=now,
        location=str(metadata.get("location", "UNKNOWN")),
        device_id=str(metadata.get("device_id", "UNKNOWN")),
        metadata=metadata or {},
    )

    ok = self.auditor.log_decision(
        ctx,
        decision=decision,
        reason_code=ReasonCodes.CLEARED if decision == "APPROVED" else "REVIEW",
        score=score,
        filtered_meta=self._filter_metadata(metadata),
        extra={"caller_id": caller.caller_id, "caller_roles": sorted(caller.caller_roles)},
    )

    if not ok:
        # Fail closed by default. Only allow dev fail-open if explicitly enabled.
        if not (CONFIG["SENTINEL_ENV"] == "dev" and CONFIG.get("DEV_ALLOW_AUDIT_FAIL_OPEN", False)):
            return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.AUDIT_APPEND_FAILED)

    return Decision(status=decision, score=score, reason=ReasonCodes.CLEARED)

def _filter_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Forensic-safe metadata filter.

    Keep this tight for privacy, but not so tight you lose incident context.
    """

    allowed: Dict[str, Any] = {}
    for k in (
        "location",
        "device_id",
        "txn_type",
        "channel",
        "risk_flags",
        "ip",
        "user_agent",
        "request_id",
        "trace_id",
    ):
        if k in metadata:
            allowed[k] = metadata[k]

    forensic = metadata.get("forensic")
    if isinstance(forensic, dict):
        allowed["forensic"] = forensic

    return allowed

def _best_effort_audit_block(
    self,
    *,
    user_id: str,
    metadata: Dict[str, Any],
    reason: str,
    extra: Dict[str, Any],
) -> None:
    try:
        ctx = TransactionContext(
            user_id=user_id,
            amount=Decimal("0"),
            timestamp=datetime.now(timezone.utc),
            location=str(metadata.get("location", "UNKNOWN")),
            device_id=str(metadata.get("device_id", "UNKNOWN")),
            metadata=metadata or {},
        )
        ok = self.auditor.log_decision(
            ctx,
            decision="BLOCKED",
            reason_code=reason,
            score=Decimal("0"),
            filtered_meta=self._filter_metadata(metadata),
            extra=extra or {},
        )
        if not ok:
            _logger.critical(f"Best-effort audit failed for BLOCKED decision reason={reason}")
    except Exception as e:
        _logger.critical(f"Best-effort audit exception reason={reason}: {e}")

============================================================================

TESTS

============================================================================

You currently only have a demo main. That is not a test suite.

The tests below are lightweight, run-only-when-invoked, and use temp files.

def _run_self_tests() -> None: import tempfile

# --- Governance tests ---
assert evaluate_action(action=ACTION_PRIV_ESC, mode=MODE_HUMAN_GATED).decision == GOV_DECISION_DENY
assert evaluate_action(action=ACTION_READ, mode=MODE_SHADOW).decision == GOV_DECISION_OBSERVE
assert evaluate_action(action=ACTION_DELETE, mode=MODE_HUMAN_GATED, human_approved=False).decision == GOV_DECISION_REQUIRE_HUMAN
assert evaluate_action(action=ACTION_DELETE, mode=MODE_HUMAN_GATED, human_approved=True).decision == GOV_DECISION_DENY  # not in allow-list
assert evaluate_action(action=ACTION_EXECUTE, mode=MODE_HUMAN_GATED).decision == GOV_DECISION_ALLOW

# --- Audit/Orchestrator tests ---
with tempfile.TemporaryDirectory() as td:
    db_path = str(Path(td) / "audit_test.db")
    jsonl_path = str(Path(td) / "audit_test.jsonl")

    # Secret must exist for audit to work.
    os.environ.setdefault("GHOST_DEVICE_HASH_SECRET", "a" * 64)

    orch = SystemOrchestrator(audit_sqlite_path=db_path, audit_jsonl_path=jsonl_path)
    caller = CallerContext(
        caller_id="user123",
        caller_roles={"user"},
        authenticated_at=datetime.now(timezone.utc),
    )

    # Happy path
    d = orch.process_transaction(
        caller=caller,
        user_id="user123",
        amount_str="25.00",
        metadata={"location": "US", "device_id": "device123", "txn_type": "test"},
    )
    assert d.status in {"APPROVED", "REVIEW"}

    # Reject NaN
    d2 = orch.process_transaction(
        caller=caller,
        user_id="user123",
        amount_str="NaN",
        metadata={"location": "US", "device_id": "device123"},
    )
    assert d2.status == "BLOCKED" and d2.reason == ReasonCodes.INVALID_AMOUNT

    # JSONL should contain at least one line when enabled
    if Path(jsonl_path).exists():
        txt = Path(jsonl_path).read_text(encoding="utf-8").strip()
        assert txt

if name == "main": logging.basicConfig(level=logging.INFO)

# Local test: set a secret or you will correctly fail closed.
os.environ.setdefault("GHOST_DEVICE_HASH_SECRET", "a" * 64)

# Demo run
orch = SystemOrchestrator()
caller = CallerContext(caller_id="user123", caller_roles={"user"}, authenticated_at=datetime.now(timezone.utc))

d = orch.process_transaction(
    caller=caller,
    user_id="user123",
    amount_str="25.00",
    metadata={"location": "US", "device_id": "device123", "txn_type": "test", "ip": "127.0.0.1"},
)
print(d)

# Self-tests (raise AssertionError if something is wrong)
_run_self_tests()