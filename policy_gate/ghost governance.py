from __future__ import annotations

import hmac
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Set, Tuple

_logger = logging.getLogger("sentinel43.ghost_governance")


# ============================================================
# CONFIG
# ============================================================

CONFIG: Dict[str, Any] = {
    "AUDIT_SQLITE_PATH": str(Path(os.getenv("SENTINEL_AUDIT_DB", "ghost_audit.db")).expanduser().resolve()),
    "AUDIT_JSONL_FILE": os.getenv("SENTINEL_AUDIT_JSONL", ""),  # optional
    "VELOCITY_WINDOW_SECONDS": int(os.getenv("SENTINEL_VELOCITY_WINDOW_SECONDS", "60")),
    "VELOCITY_LIMIT": int(os.getenv("SENTINEL_VELOCITY_LIMIT", "10")),
    "VELOCITY_GC_INTERVAL_SECONDS": int(os.getenv("SENTINEL_VELOCITY_GC_INTERVAL_SECONDS", "300")),
    "VELOCITY_MAX_ENTRIES_PER_USER": int(os.getenv("SENTINEL_VELOCITY_MAX_ENTRIES_PER_USER", "1000")),
    "SENTINEL_ENV": (os.getenv("SENTINEL_ENV") or "prod").lower(),
}

# ============================================================
# REASON CODES (minimal stub, integrate with your existing ones)
# ============================================================

class ReasonCodes:
    CLEARED = "CLEARED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    AUDIT_CHAIN_FORK = "AUDIT_CHAIN_FORK"
    AUDIT_CRYPTO_CONFIG_MISSING = "AUDIT_CRYPTO_CONFIG_MISSING"
    AUDIT_APPEND_FAILED = "AUDIT_APPEND_FAILED"
    VELOCITY_LIMIT = "VELOCITY_LIMIT"
    VELOCITY_CAP_EXCEEDED = "VELOCITY_CAP_EXCEEDED"
    INVALID_INPUT = "INVALID_INPUT"


# ============================================================
# UTIL: Safe JSON encoder for Decimal/datetime
# ============================================================

class AuditEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Decimal):
            return str(obj)
        if isinstance(obj, (datetime,)):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)


# ============================================================
# CRYPTO CONFIG
# ============================================================

def _get_hmac_secret() -> bytes:
    """
    Returns secret bytes. FAILS CLOSED if missing.
    Don't ever return placeholders. That's how audit trails become fiction.
    """
    raw = os.getenv("GHOST_DEVICE_HASH_SECRET", "").strip()
    if not raw:
        raise RuntimeError(
            "GHOST_DEVICE_HASH_SECRET is required. "
            "Generate with: python3 -c 'import secrets; print(secrets.token_hex(32))'"
        )

    # Accept hex or raw text. If hex-like, decode.
    try:
        if all(c in "0123456789abcdefABCDEF" for c in raw) and len(raw) >= 64 and len(raw) % 2 == 0:
            return bytes.fromhex(raw)
    except Exception:
        pass

    # Fallback: treat as utf-8 secret.
    return raw.encode("utf-8")


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time compare to reduce timing leaks."""
    return hmac.compare_digest(a, b)


# ============================================================
# AUDIT STORE (SQLite + optional JSONL sink)
# ============================================================

class AuditStore:
    """
    Tamper-evident append-only audit chain.
    Uses a single anchor row to store current head hash.
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
            # Initialize anchor if empty
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
        """
        Atomic append:
        - BEGIN IMMEDIATE to acquire write lock (multi-process safe)
        - Verify anchor head matches prev_hash (prevents forks)
        - Insert log row
        - Update anchor head
        """
        # Lock helps threads in-process; SQL transaction covers multi-process.
        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")

                (current_head,) = con.execute("SELECT prev_hash FROM audit_anchor WHERE id=1").fetchone()
                current_head = str(current_head)

                if current_head != prev_hash:
                    con.rollback()
                    raise RuntimeError(
                        f"Audit chain fork detected. expected={prev_hash} current_head={current_head}"
                    )

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

        # Best-effort JSONL sink outside the DB transaction
        if self.jsonl_path:
            try:
                p = Path(self.jsonl_path).expanduser().resolve()
                p.parent.mkdir(parents=True, exist_ok=True)
                with open(p, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"payload": payload, "hash": payload_hash}, cls=AuditEncoder) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                _logger.error(f"JSONL sink failed (non-fatal): {e}")


# ============================================================
# AUDITOR
# ============================================================

@dataclass(frozen=True)
class TransactionContext:
    user_id: str
    amount: Decimal
    timestamp: datetime
    location: str
    device_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecureAuditLog:
    def __init__(self, store: AuditStore) -> None:
        self.store = store

    def _hmac_device(self, device_id: str) -> str:
        """
        FAIL CLOSED if secret missing.
        No placeholder collisions. No pretend cryptography.
        """
        secret = _get_hmac_secret()
        digest = hmac.new(secret, device_id.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest

    def _hash_metadata(self, meta: Dict[str, Any]) -> str:
        # Deterministic metadata hash for integrity checks
        raw = json.dumps(meta or {}, cls=AuditEncoder, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def verify_device_hash(self, device_id: str, claimed_hash: str) -> bool:
        """Constant-time verify helper for any auth logic that compares device hashes."""
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
        """
        Writes an audit record with chain hash.
        Returns False on failure (and logs loud).
        """
        try:
            device_hash = self._hmac_device(context.device_id)
            meta_hash = self._hash_metadata(filtered_meta)

            prev_hash = self.store.get_prev_hash()

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

            payload_json = json.dumps(payload, cls=AuditEncoder, sort_keys=True, separators=(",", ":")).encode("utf-8")
            payload_hash = hashlib.sha256(payload_json + prev_hash.encode("utf-8")).hexdigest()

            self.store.append(payload=payload, payload_hash=payload_hash, prev_hash=prev_hash)
            return True

        except RuntimeError as e:
            # Crypto/config missing, chain fork, etc.
            _logger.critical(f"Audit failed (hard): {e}")
            return False
        except Exception as e:
            _logger.error(f"Audit failed: {e}")
            return False


# ============================================================
# VELOCITY GUARD (DoS/MEMORY HARDENED)
# ============================================================

class VelocityGuard:
    def __init__(
        self,
        *,
        window_seconds: int,
        limit: int,
        gc_interval_seconds: int,
        max_entries_per_user: int,
    ) -> None:
        self.window_seconds = int(window_seconds)
        self.limit = int(limit)
        self.gc_interval_seconds = int(gc_interval_seconds)
        self.max_entries_per_user = int(max_entries_per_user)

        self.user_events: Dict[str, "deque[datetime]"] = {}
        self.lock = threading.Lock()
        self.last_gc = datetime.now(timezone.utc)

        from collections import deque  # local import to keep top tidy
        self._deque = deque

    def _garbage_collect(self, now: datetime) -> None:
        if (now - self.last_gc).total_seconds() < self.gc_interval_seconds:
            return

        cutoff = now - timedelta(seconds=self.window_seconds)
        dead_users = []
        for user_id, dq in self.user_events.items():
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                dead_users.append(user_id)

        for user_id in dead_users:
            self.user_events.pop(user_id, None)

        self.last_gc = now

    def allow(self, user_id: str, now: datetime) -> Tuple[bool, str]:
        """
        Returns (allowed, reason_code).
        Fails closed when hitting hard cap.
        """
        with self.lock:
            self._garbage_collect(now)

            dq = self.user_events.setdefault(user_id, self._deque())
            cutoff = now - timedelta(seconds=self.window_seconds)
            while dq and dq[0] < cutoff:
                dq.popleft()

            # Hard cap first: prevent memory exhaustion, timestamp weirdness, clock skew abuse.
            if len(dq) >= self.max_entries_per_user:
                _logger.warning(
                    f"Velocity cap exceeded user={user_id} entries={len(dq)} cap={self.max_entries_per_user}"
                )
                return (False, ReasonCodes.VELOCITY_CAP_EXCEEDED)

            if len(dq) >= self.limit:
                return (False, ReasonCodes.VELOCITY_LIMIT)

            dq.append(now)
            return (True, ReasonCodes.CLEARED)


# ============================================================
# AUTHZ CONTEXT + DECISION MODEL
# ============================================================

@dataclass(frozen=True)
class CallerContext:
    caller_id: str
    caller_roles: Set[str]
    authenticated_at: datetime


@dataclass(frozen=True)
class Decision:
    status: str
    score: Decimal
    reason: str


# ============================================================
# GOVERNANCE / ORCHESTRATOR (AUTHZ-HARDENED)
# ============================================================

class SystemOrchestrator:
    """
    This is the "ghost governance" gate:
    - requires caller context
    - enforces authorization
    - enforces velocity limits
    - logs decisions with tamper-evident chain
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
        )

    @staticmethod
    def _default_authorizer(caller: CallerContext, target_user_id: str) -> bool:
        # Default: self-only unless privileged
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

        # --- INPUT VALIDATION ---
        try:
            amount = Decimal(amount_str)
        except Exception:
            self._best_effort_audit_block(
                user_id=user_id,
                metadata=metadata,
                reason=ReasonCodes.INVALID_INPUT,
                extra={"amount_str": amount_str},
            )
            return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.INVALID_INPUT)

        now = datetime.now(timezone.utc)

        allowed, v_reason = self.velocity_guard.allow(user_id, now)
        if not allowed:
            self._best_effort_audit_block(
                user_id=user_id,
                metadata=metadata,
                reason=v_reason,
                extra={"window_seconds": CONFIG["VELOCITY_WINDOW_SECONDS"], "limit": CONFIG["VELOCITY_LIMIT"]},
            )
            return Decision(status="BLOCKED", score=Decimal("0"), reason=v_reason)

        # --- POLICY/AI PLACEHOLDERS (your real logic goes here) ---
        # You can wire in your policy engine + scoring here.
        # For now: simple score placeholder
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
            # If audit fails, fail closed in prod.
            if CONFIG["SENTINEL_ENV"] != "dev":
                return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.AUDIT_APPEND_FAILED)

        return Decision(status=decision, score=score, reason=ReasonCodes.CLEARED)

    def _filter_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Minimal metadata filtering. Expand with your PII strategy.
        """
        allowed = {}
        for k in ("location", "device_id", "txn_type", "channel", "risk_flags"):
            if k in metadata:
                allowed[k] = metadata[k]
        return allowed

    def _best_effort_audit_block(self, *, user_id: str, metadata: Dict[str, Any], reason: str, extra: Dict[str, Any]) -> None:
        try:
            ctx = TransactionContext(
                user_id=user_id,
                amount=Decimal("0"),
                timestamp=datetime.now(timezone.utc),
                location=str(metadata.get("location", "UNKNOWN")),
                device_id=str(metadata.get("device_id", "UNKNOWN")),
                metadata=metadata or {},
            )
            self.auditor.log_decision(
                ctx,
                decision="BLOCKED",
                reason_code=reason,
                score=Decimal("0"),
                filtered_meta=self._filter_metadata(metadata),
                extra=extra or {},
            )
        except Exception:
            # If even best-effort audit fails, just don't crash.
            pass


# ============================================================
# Minimal sanity self-test (no side effects beyond local DB write)
# ============================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # For local test, set a secret or you will correctly fail closed.
    os.environ.setdefault("GHOST_DEVICE_HASH_SECRET", "a" * 64)

    orch = SystemOrchestrator()
    caller = CallerContext(
        caller_id="user123",
        caller_roles={"user"},
        authenticated_at=datetime.now(timezone.utc),
    )

    d = orch.process_transaction(
        caller=caller,
        user_id="user123",
        amount_str="25.00",
        metadata={"location": "US", "device_id": "device123", "txn_type": "test"},
    )
    print(d)