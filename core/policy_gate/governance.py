"""
sentinel43.core.governance.governance

Unified Governance Module for Sentinel-43.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Deque, Mapping

_logger = logging.getLogger("sentinel43.governance")


# ============================================================================
# CONFIG HELPERS
# ============================================================================

def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.getenv(name)

    if raw is None or raw == "":
        return default

    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc

    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}, got {value}")

    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)

    if raw is None or raw == "":
        return default

    return raw.strip().lower() in {"1", "true", "yes", "on"}


CONFIG: dict[str, Any] = {
    "AUDIT_SQLITE_PATH": str(
        Path(os.getenv("SENTINEL_AUDIT_DB", "audit.db")).expanduser().resolve()
    ),
    "AUDIT_JSONL_FILE": os.getenv("SENTINEL_AUDIT_JSONL", ""),
    "VELOCITY_WINDOW_SECONDS": _env_int(
        "SENTINEL_VELOCITY_WINDOW_SECONDS", 60
    ),
    "VELOCITY_LIMIT": _env_int("SENTINEL_VELOCITY_LIMIT", 10),
    "VELOCITY_GC_INTERVAL_SECONDS": _env_int(
        "SENTINEL_VELOCITY_GC_INTERVAL_SECONDS", 300
    ),
    "VELOCITY_MAX_ENTRIES_PER_USER": _env_int(
        "SENTINEL_VELOCITY_MAX_ENTRIES_PER_USER", 1000
    ),
    "VELOCITY_MAX_DISTINCT_USERS": _env_int(
        "SENTINEL_VELOCITY_MAX_DISTINCT_USERS", 50000
    ),
    "AUTH_MAX_AGE_SECONDS": _env_int("SENTINEL_AUTH_MAX_AGE_SECONDS", 900),
    "SENTINEL_ENV": (os.getenv("SENTINEL_ENV") or "prod").strip().lower(),
    "DEV_ALLOW_AUDIT_FAIL_OPEN": _env_bool(
        "SENTINEL_DEV_ALLOW_AUDIT_FAIL_OPEN", False
    ),
    "AUDIT_MAX_RETRIES": _env_int("SENTINEL_AUDIT_MAX_RETRIES", 3),
}


# ============================================================================
# GOVERNANCE DEFINITIONS
# ============================================================================

MODE_SHADOW = "SHADOW"
MODE_HUMAN_GATED = "HUMAN_GATED"
MODE_AUTONOMOUS_VETO = "AUTONOMOUS_VETO"

ALLOWED_MODES: frozenset[str] = frozenset(
    {
        MODE_SHADOW,
        MODE_HUMAN_GATED,
        MODE_AUTONOMOUS_VETO,
    }
)

ACTION_READ = "read"
ACTION_WRITE = "write"
ACTION_DELETE = "delete"
ACTION_EXECUTE = "execute"
ACTION_QUARANTINE = "quarantine"
ACTION_ISOLATE = "isolate"
ACTION_SHUTDOWN = "shutdown"
ACTION_NETWORK_BLOCK = "network_block"
ACTION_PRIV_ESC = "privilege_escalation"


@dataclass(frozen=True)
class GovernanceRules:
    """
    Canonical policy ruleset.

    MappingProxyType is used because frozen dataclasses do not freeze nested
    mutable objects.
    """

    always_deny: frozenset[str]
    human_required: frozenset[str]
    allowed_by_mode: Mapping[str, frozenset[str]]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_by_mode",
            MappingProxyType(dict(self.allowed_by_mode)),
        )


DEFAULT_GOVERNANCE = GovernanceRules(
    always_deny=frozenset(
        {
            ACTION_PRIV_ESC,
        }
    ),
    human_required=frozenset(
        {
            ACTION_DELETE,
            ACTION_QUARANTINE,
            ACTION_ISOLATE,
            ACTION_SHUTDOWN,
            ACTION_NETWORK_BLOCK,
        }
    ),
    allowed_by_mode={
        MODE_SHADOW: frozenset(
            {
                ACTION_READ,
                ACTION_WRITE,
                ACTION_DELETE,
                ACTION_EXECUTE,
                ACTION_QUARANTINE,
                ACTION_ISOLATE,
                ACTION_SHUTDOWN,
                ACTION_NETWORK_BLOCK,
            }
        ),
        MODE_HUMAN_GATED: frozenset(
            {
                ACTION_READ,
                ACTION_WRITE,
                ACTION_EXECUTE,
                ACTION_DELETE,
                ACTION_QUARANTINE,
                ACTION_ISOLATE,
                ACTION_SHUTDOWN,
                ACTION_NETWORK_BLOCK,
            }
        ),
        MODE_AUTONOMOUS_VETO: frozenset(
            {
                ACTION_READ,
                ACTION_WRITE,
            }
        ),
    },
)

GOV_DECISION_ALLOW = "ALLOW"
GOV_DECISION_REQUIRE_HUMAN = "REQUIRE_HUMAN"
GOV_DECISION_DENY = "DENY"
GOV_DECISION_OBSERVE = "OBSERVE"


@dataclass(frozen=True)
class GovernanceDecision:
    decision: str
    reason: str


def _normalize_action(action: str) -> str:
    return (action or "").strip().lower()


def _normalize_mode(mode: str) -> str:
    return (mode or "").strip().upper()


def is_action_known(action: str) -> bool:
    normalized = _normalize_action(action)

    if normalized in DEFAULT_GOVERNANCE.always_deny:
        return True

    if normalized in DEFAULT_GOVERNANCE.human_required:
        return True

    return any(
        normalized in actions
        for actions in DEFAULT_GOVERNANCE.allowed_by_mode.values()
    )


def is_always_denied(action: str) -> bool:
    return _normalize_action(action) in DEFAULT_GOVERNANCE.always_deny


def requires_human_approval(action: str) -> bool:
    return _normalize_action(action) in DEFAULT_GOVERNANCE.human_required


def is_allowed_in_mode(action: str, mode: str) -> bool:
    normalized_action = _normalize_action(action)
    normalized_mode = _normalize_mode(mode)

    if normalized_mode not in ALLOWED_MODES:
        return False

    if is_always_denied(normalized_action):
        return False

    return normalized_action in DEFAULT_GOVERNANCE.allowed_by_mode.get(
        normalized_mode,
        frozenset(),
    )


def list_allowed_actions(mode: str) -> list[str]:
    return sorted(DEFAULT_GOVERNANCE.allowed_by_mode.get(_normalize_mode(mode), frozenset()))


def evaluate_action(
    *,
    action: str,
    mode: str,
    human_approved: bool = False,
) -> GovernanceDecision:
    normalized_action = _normalize_action(action)
    normalized_mode = _normalize_mode(mode)

    if normalized_mode not in ALLOWED_MODES:
        return GovernanceDecision(GOV_DECISION_DENY, "UNKNOWN_MODE")

    if not is_action_known(normalized_action):
        return GovernanceDecision(GOV_DECISION_DENY, "UNKNOWN_ACTION")

    if is_always_denied(normalized_action):
        return GovernanceDecision(GOV_DECISION_DENY, "ALWAYS_DENIED")

    if not is_allowed_in_mode(normalized_action, normalized_mode):
        return GovernanceDecision(GOV_DECISION_DENY, "NOT_ALLOWED_IN_MODE")

    if normalized_mode == MODE_SHADOW:
        return GovernanceDecision(GOV_DECISION_OBSERVE, "SHADOW_OBSERVE_ONLY")

    if (
        normalized_mode == MODE_HUMAN_GATED
        and requires_human_approval(normalized_action)
        and not human_approved
    ):
        return GovernanceDecision(
            GOV_DECISION_REQUIRE_HUMAN,
            "HUMAN_APPROVAL_REQUIRED",
        )

    return GovernanceDecision(GOV_DECISION_ALLOW, "ALLOWED")


# ============================================================================
# REASON CODES
# ============================================================================

class ReasonCodes:
    CLEARED = "CLEARED"
    REVIEW = "REVIEW"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    AUTH_STALE = "AUTH_STALE"
    AUDIT_CHAIN_FORK = "AUDIT_CHAIN_FORK"
    AUDIT_CRYPTO_CONFIG_MISSING = "AUDIT_CRYPTO_CONFIG_MISSING"
    AUDIT_APPEND_FAILED = "AUDIT_APPEND_FAILED"
    VELOCITY_LIMIT = "VELOCITY_LIMIT"
    VELOCITY_CAP_EXCEEDED = "VELOCITY_CAP_EXCEEDED"
    VELOCITY_GLOBAL_CAP = "VELOCITY_GLOBAL_CAP"
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_AMOUNT = "INVALID_AMOUNT"


# ============================================================================
# AUDIT SUPPORT
# ============================================================================

class AuditEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Decimal):
            return str(obj)

        if isinstance(obj, datetime):
            return obj.isoformat()

        return super().default(obj)


def _get_hmac_secret() -> bytes:
    raw = os.getenv("GHOST_DEVICE_HASH_SECRET", "").strip()

    if not raw:
        raise RuntimeError(
            "GHOST_DEVICE_HASH_SECRET is required. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    try:
        if (
            all(c in "0123456789abcdefABCDEF" for c in raw)
            and len(raw) >= 64
            and len(raw) % 2 == 0
        ):
            return bytes.fromhex(raw)
    except Exception:
        pass

    return raw.encode("utf-8")


def constant_time_compare(a: str | bytes, b: str | bytes) -> bool:
    if type(a) is not type(b):
        return False

    return hmac.compare_digest(a, b)


class AuditStore:
    """
    Tamper-evident append-only audit chain.

    SQLite is the authoritative sink.
    JSONL is optional secondary output.
    """

    def __init__(self, sqlite_path: str, jsonl_path: str | None = None) -> None:
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
        Path(self.sqlite_path).expanduser().resolve().parent.mkdir(
            parents=True,
            exist_ok=True,
        )

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
            row = con.execute(
                "SELECT prev_hash FROM audit_anchor WHERE id = 1"
            ).fetchone()

            if row is None:
                con.execute(
                    "INSERT INTO audit_anchor (id, prev_hash) VALUES (1, ?)",
                    ("GENESIS",),
                )

            con.commit()
        finally:
            con.close()

    def get_prev_hash(self) -> str:
        with self._lock:
            con = self._connect()
            try:
                row = con.execute(
                    "SELECT prev_hash FROM audit_anchor WHERE id = 1"
                ).fetchone()

                if row is None:
                    raise RuntimeError("Audit anchor missing")

                return str(row[0])
            finally:
                con.close()

    def append(
        self,
        payload: dict[str, Any],
        payload_hash: str,
        prev_hash: str,
    ) -> None:
        """
        Append payload to the audit chain.

        The SQLite append and optional JSONL write are kept under the same
        process lock to preserve local ordering.
        """

        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")

                row = con.execute(
                    "SELECT prev_hash FROM audit_anchor WHERE id = 1"
                ).fetchone()

                if row is None:
                    con.rollback()
                    raise RuntimeError("Audit anchor missing")

                current_head = str(row[0])

                if current_head != prev_hash:
                    con.rollback()
                    raise RuntimeError(
                        "Audit chain fork detected. "
                        f"expected={prev_hash} current_head={current_head}"
                    )

                decision_time = payload.get("decision_time") or datetime.now(
                    timezone.utc
                ).isoformat()

                payload_json = json.dumps(
                    payload,
                    cls=AuditEncoder,
                    sort_keys=True,
                    separators=(",", ":"),
                )

                con.execute(
                    """
                    INSERT INTO audit_log
                    (decision_time, payload_json, payload_hash, prev_hash)
                    VALUES (?, ?, ?, ?)
                    """,
                    (decision_time, payload_json, payload_hash, prev_hash),
                )

                con.execute(
                    "UPDATE audit_anchor SET prev_hash = ? WHERE id = 1",
                    (payload_hash,),
                )

                con.commit()

                if self.jsonl_path:
                    self._append_jsonl_locked(payload, payload_hash)

            except Exception:
                con.rollback()
                raise
            finally:
                con.close()

    def _append_jsonl_locked(
        self,
        payload: dict[str, Any],
        payload_hash: str,
    ) -> None:
        """
        Append to JSONL sink.

        Caller must hold self._lock.
        """

        if not self.jsonl_path:
            return

        try:
            p = Path(self.jsonl_path).expanduser().resolve()
            p.parent.mkdir(parents=True, exist_ok=True)

            with open(p, "a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "payload": payload,
                            "hash": payload_hash,
                        },
                        cls=AuditEncoder,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                f.flush()
                os.fsync(f.fileno())

        except Exception as exc:
            _logger.error("JSONL sink failed: %s", exc)


@dataclass(frozen=True)
class TransactionContext:
    user_id: str
    amount: Decimal
    timestamp: datetime
    location: str
    device_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata)),
        )


class SecureAuditLog:
    def __init__(self, store: AuditStore) -> None:
        self.store = store

    def _hmac_device(self, device_id: str) -> str:
        secret = _get_hmac_secret()
        return hmac.new(
            secret,
            device_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _hash_metadata(self, meta: Mapping[str, Any]) -> str:
        raw = json.dumps(
            dict(meta or {}),
            cls=AuditEncoder,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(raw).hexdigest()

    def verify_device_hash(self, device_id: str, claimed_hash: str) -> bool:
        try:
            actual = self._hmac_device(device_id)
            return constant_time_compare(actual, claimed_hash)
        except Exception as exc:
            _logger.error("Device hash verification failed: %s", exc)
            return False

    def log_decision(
        self,
        context: TransactionContext,
        decision: str,
        reason_code: str,
        score: Decimal,
        filtered_meta: Mapping[str, Any],
        extra: Mapping[str, Any],
    ) -> bool:
        try:
            device_hash = self._hmac_device(context.device_id)
            meta_hash = self._hash_metadata(filtered_meta)

            payload: dict[str, Any] = {
                "decision_time": datetime.now(timezone.utc).isoformat(),
                "user_id": context.user_id,
                "amount": str(context.amount),
                "location": context.location,
                "device_hash": device_hash,
                "metadata_hash": meta_hash,
                "decision": decision,
                "reason_code": reason_code,
                "score": str(score),
                "extra": dict(extra or {}),
            }

            max_retries = max(1, int(CONFIG["AUDIT_MAX_RETRIES"]))

            for attempt in range(1, max_retries + 1):
                prev_hash = self.store.get_prev_hash()

                payload_json = json.dumps(
                    payload,
                    cls=AuditEncoder,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")

                payload_hash = hashlib.sha256(
                    payload_json + prev_hash.encode("utf-8")
                ).hexdigest()

                try:
                    self.store.append(
                        payload=payload,
                        payload_hash=payload_hash,
                        prev_hash=prev_hash,
                    )
                    return True

                except RuntimeError as exc:
                    if "fork" in str(exc).lower() and attempt < max_retries:
                        continue

                    _logger.critical("Audit failed: %s", exc)
                    return False

            _logger.critical(
                "Audit failed: retries exhausted after %s attempts",
                max_retries,
            )
            return False

        except RuntimeError as exc:
            _logger.critical("Audit failed: %s", exc)
            return False

        except Exception as exc:
            _logger.error("Audit failed: %s", exc)
            return False


# ============================================================================
# VELOCITY GUARD
# ============================================================================

class VelocityGuard:
    """
    In-memory velocity limiter with garbage collection and memory caps.
    """

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

        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if self.limit <= 0:
            raise ValueError("limit must be > 0")
        if self.gc_interval_seconds <= 0:
            raise ValueError("gc_interval_seconds must be > 0")
        if self.max_entries_per_user <= 0:
            raise ValueError("max_entries_per_user must be > 0")
        if self.max_distinct_users <= 0:
            raise ValueError("max_distinct_users must be > 0")

        self.user_events: dict[str, Deque[datetime]] = {}
        self.lock = threading.Lock()
        self.last_gc = datetime.now(timezone.utc)

    def _garbage_collect(self, now: datetime) -> None:
        if (now - self.last_gc).total_seconds() < self.gc_interval_seconds:
            return

        cutoff = now - timedelta(seconds=self.window_seconds)
        dead_users: list[str] = []

        for user_id, dq in self.user_events.items():
            while dq and dq[0] < cutoff:
                dq.popleft()

            if not dq:
                dead_users.append(user_id)

        for user_id in dead_users:
            self.user_events.pop(user_id, None)

        self.last_gc = now

    def allow(self, user_id: str, now: datetime) -> tuple[bool, str]:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        if not user_id:
            return False, ReasonCodes.INVALID_INPUT

        with self.lock:
            self._garbage_collect(now)

            is_new_user = user_id not in self.user_events

            if is_new_user and len(self.user_events) >= self.max_distinct_users:
                _logger.warning(
                    "Velocity global cap exceeded distinct_users=%s cap=%s",
                    len(self.user_events),
                    self.max_distinct_users,
                )
                return False, ReasonCodes.VELOCITY_GLOBAL_CAP

            dq = self.user_events.setdefault(user_id, deque())

            cutoff = now - timedelta(seconds=self.window_seconds)

            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= self.max_entries_per_user:
                _logger.warning(
                    "Velocity cap exceeded user=%s entries=%s cap=%s",
                    user_id,
                    len(dq),
                    self.max_entries_per_user,
                )
                return False, ReasonCodes.VELOCITY_CAP_EXCEEDED

            if len(dq) >= self.limit:
                return False, ReasonCodes.VELOCITY_LIMIT

            dq.append(now)
            return True, ReasonCodes.CLEARED


# ============================================================================
# ORCHESTRATOR
# ============================================================================

@dataclass(frozen=True)
class CallerContext:
    caller_id: str
    caller_roles: frozenset[str]
    authenticated_at: datetime

    def __post_init__(self) -> None:
        if self.authenticated_at.tzinfo is None:
            raise ValueError("authenticated_at must be timezone-aware")

        object.__setattr__(
            self,
            "caller_roles",
            frozenset(self.caller_roles),
        )


@dataclass(frozen=True)
class Decision:
    status: str
    score: Decimal
    reason: str


class SystemOrchestrator:
    def __init__(
        self,
        *,
        authorizer: Callable[[CallerContext, str], bool] | None = None,
        audit_sqlite_path: str | None = None,
        audit_jsonl_path: str | None = None,
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
        metadata: Mapping[str, Any],
    ) -> Decision:
        now = datetime.now(timezone.utc)
        metadata = MappingProxyType(dict(metadata or {}))

        if not isinstance(caller, CallerContext):
            raise TypeError(f"caller must be CallerContext, got {type(caller).__name__}")

        if not user_id:
            return Decision(
                status="BLOCKED",
                score=Decimal("0"),
                reason=ReasonCodes.INVALID_INPUT,
            )

        if not self.authorizer(caller, user_id):
            _logger.warning(
                "Unauthorized: caller=%s -> user=%s",
                caller.caller_id,
                user_id,
            )

            self._best_effort_audit_block(
                user_id=user_id,
                metadata=metadata,
                reason=ReasonCodes.AUTHORIZATION_FAILED,
                extra={
                    "caller_id": caller.caller_id,
                    "caller_roles": sorted(caller.caller_roles),
                },
            )

            return Decision(
                status="BLOCKED",
                score=Decimal("0"),
                reason=ReasonCodes.AUTHORIZATION_FAILED,
            )

        max_age = int(CONFIG["AUTH_MAX_AGE_SECONDS"])
        auth_age = (now - caller.authenticated_at).total_seconds()

        if auth_age > max_age:
            _logger.warning(
                "Stale auth context: caller=%s age_s=%.0f",
                caller.caller_id,
                auth_age,
            )

            self._best_effort_audit_block(
                user_id=user_id,
                metadata=metadata,
                reason=ReasonCodes.AUTH_STALE,
                extra={
                    "caller_id": caller.caller_id,
                    "caller_roles": sorted(caller.caller_roles),
                },
            )

            return Decision(
                status="BLOCKED",
                score=Decimal("0"),
                reason=ReasonCodes.AUTH_STALE,
            )

        try:
            amount = Decimal(amount_str)
        except (InvalidOperation, ValueError, TypeError):
            self._best_effort_audit_block(
                user_id=user_id,
                metadata=metadata,
                reason=ReasonCodes.INVALID_INPUT,
                extra={"amount_str": amount_str},
            )

            return Decision(
                status="BLOCKED",
                score=Decimal("0"),
                reason=ReasonCodes.INVALID_INPUT,
            )

        if not amount.is_finite() or amount < Decimal("0"):
            self._best_effort_audit_block(
                user_id=user_id,
                metadata=metadata,
                reason=ReasonCodes.INVALID_AMOUNT,
                extra={"amount_str": amount_str},
            )

            return Decision(
                status="BLOCKED",
                score=Decimal("0"),
                reason=ReasonCodes.INVALID_AMOUNT,
            )

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

            return Decision(
                status="BLOCKED",
                score=Decimal("0"),
                reason=v_reason,
            )

        score = Decimal("0.5")
        decision = "APPROVED" if amount <= Decimal("1000") else "REVIEW"

        ctx = TransactionContext(
            user_id=user_id,
            amount=amount,
            timestamp=now,
            location=str(metadata.get("location", "UNKNOWN")),
            device_id=str(metadata.get("device_id", "UNKNOWN")),
            metadata=metadata,
        )

        reason_code = (
            ReasonCodes.CLEARED
            if decision == "APPROVED"
            else ReasonCodes.REVIEW
        )

        ok = self.auditor.log_decision(
            ctx,
            decision=decision,
            reason_code=reason_code,
            score=score,
            filtered_meta=self._filter_metadata(metadata),
            extra={
                "caller_id": caller.caller_id,
                "caller_roles": sorted(caller.caller_roles),
            },
        )

        if not ok:
            fail_open = (
                CONFIG["SENTINEL_ENV"] == "dev"
                and CONFIG["DEV_ALLOW_AUDIT_FAIL_OPEN"]
            )

            if not fail_open:
                return Decision(
                    status="BLOCKED",
                    score=Decimal("0"),
                    reason=ReasonCodes.AUDIT_APPEND_FAILED,
                )

        return Decision(
            status=decision,
            score=score,
            reason=reason_code,
        )

    def _filter_metadata(self, metadata: Mapping[str, Any]) -> dict[str, Any]:
        allowed: dict[str, Any] = {}

        for key in (
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
            if key in metadata:
                allowed[key] = metadata[key]

        forensic = metadata.get("forensic")

        if isinstance(forensic, Mapping):
            allowed["forensic"] = dict(forensic)

        return allowed

    def _best_effort_audit_block(
        self,
        *,
        user_id: str,
        metadata: Mapping[str, Any],
        reason: str,
        extra: Mapping[str, Any],
    ) -> None:
        try:
            ctx = TransactionContext(
                user_id=user_id,
                amount=Decimal("0"),
                timestamp=datetime.now(timezone.utc),
                location=str(metadata.get("location", "UNKNOWN")),
                device_id=str(metadata.get("device_id", "UNKNOWN")),
                metadata=metadata,
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
                _logger.critical(
                    "Best-effort audit failed for BLOCKED decision reason=%s",
                    reason,
                )

        except Exception as exc:
            _logger.critical(
                "Best-effort audit exception reason=%s: %s",
                reason,
                exc,
            )


# ============================================================================
# SELF TESTS
# ============================================================================

def _run_self_tests() -> None:
    import tempfile

    assert (
        evaluate_action(action=ACTION_PRIV_ESC, mode=MODE_HUMAN_GATED).decision
        == GOV_DECISION_DENY
    )
    assert (
        evaluate_action(action=ACTION_READ, mode=MODE_SHADOW).decision
        == GOV_DECISION_OBSERVE
    )
    assert (
        evaluate_action(
            action=ACTION_DELETE,
            mode=MODE_HUMAN_GATED,
            human_approved=False,
        ).decision
        == GOV_DECISION_REQUIRE_HUMAN
    )
    assert (
        evaluate_action(
            action=ACTION_DELETE,
            mode=MODE_HUMAN_GATED,
            human_approved=True,
        ).decision
        == GOV_DECISION_ALLOW
    )
    assert (
        evaluate_action(action=ACTION_EXECUTE, mode=MODE_HUMAN_GATED).decision
        == GOV_DECISION_ALLOW
    )

    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "audit_test.db")
        jsonl_path = str(Path(td) / "audit_test.jsonl")

        os.environ.setdefault("GHOST_DEVICE_HASH_SECRET", "a" * 64)

        orch = SystemOrchestrator(
            audit_sqlite_path=db_path,
            audit_jsonl_path=jsonl_path,
        )

        caller = CallerContext(
            caller_id="user123",
            caller_roles=frozenset({"user"}),
            authenticated_at=datetime.now(timezone.utc),
        )

        d = orch.process_transaction(
            caller=caller,
            user_id="user123",
            amount_str="25.00",
            metadata={
                "location": "US",
                "device_id": "device123",
                "txn_type": "test",
            },
        )

        assert d.status in {"APPROVED", "REVIEW"}

        d2 = orch.process_transaction(
            caller=caller,
            user_id="user123",
            amount_str="NaN",
            metadata={
                "location": "US",
                "device_id": "device123",
            },
        )

        assert d2.status == "BLOCKED"
        assert d2.reason == ReasonCodes.INVALID_AMOUNT

        if Path(jsonl_path).exists():
            txt = Path(jsonl_path).read_text(encoding="utf-8").strip()
            assert txt


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    os.environ.setdefault("GHOST_DEVICE_HASH_SECRET", "a" * 64)

    orchestrator = SystemOrchestrator()

    caller_context = CallerContext(
        caller_id="user123",
        caller_roles=frozenset({"user"}),
        authenticated_at=datetime.now(timezone.utc),
    )

    result = orchestrator.process_transaction(
        caller=caller_context,
        user_id="user123",
        amount_str="25.00",
        metadata={
            "location": "US",
            "device_id": "device123",
            "txn_type": "test",
            "ip": "127.0.0.1",
        },
    )

    print(result)

    _run_self_tests()
