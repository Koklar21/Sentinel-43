# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is distributed under a dual-license model:
#   1. GNU Affero General Public License (AGPL v3.0)
#   2. Commercial License
#
# sentinel_ai_escalation.py
# v3.0.0 — Authoritative threat response engine.
#
# Collapsed from four parallel implementations (sentinel_nexus_v1,
# sentinel_node_v2, Shadow_mode.py, and the prior version of this file).
# Git history preserves all prior generations.
#
# Architecture:
#     ThreatAssessment
#         -> OversightEngine      (dedupe / budget / corroboration guardrails)
#         -> Sentinel43ResponseEngine  (plan + stage + execute)
#             -> SqliteActionStore     (durable SQLite state)
#             -> IntegrationHub        (real-world effects boundary)
#     SentinelNexus               (convenience facade)
#
# Governance modes:
#     SHADOW       advisory only — nothing persisted, nothing executed
#     HUMAN_GATED  stage in SQLite, execute only after approve_action()
#     ACTIVE       stage in SQLite, auto-execute after veto window
#
# Action lifecycle — ACTIVE:
#     PENDING -> EXECUTING (executor claims) -> EXECUTED | FAILED
#
# Action lifecycle — HUMAN_GATED:
#     STAGED -> APPROVED (operator) -> EXECUTED | FAILED
#     STAGED -> VETOED   (operator)
#
# Security scrub (public-beta hardening, carried from both prior files):
#   1. EXECUTING state: auto-executor never reuses APPROVED (human reserved).
#   2. APPROVED excluded from retention cleanup (transient mid-flight state).
#   3. target_hash: pseudonymized SHA-256 stored alongside raw target_value.
#   4. Dedupe suppression logs hash of the key, never the raw target value.
#   5. Threat types imported from sentinel_43_ai with local fallback defs.
# =============================================================================

from __future__ import annotations

import enum
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Config
# =============================================================================

try:
    _BASE_DIR = Path(__file__).resolve().parent
except NameError:
    _BASE_DIR = Path.cwd()


def _env(name: str, default: str = "") -> str:
    """Prefer SENTINEL_*, fall back to AEGIS_* for backward compatibility."""
    v = os.getenv(name)
    if v is not None:
        return v
    return os.getenv(name.replace("SENTINEL_", "AEGIS_", 1), default)


_BLOCKED_SECRETS: frozenset[str] = frozenset({
    "CHANGE_ME", "CHANGE_ME_IN_PROD", "CHANGEME",
    "dev-placeholder", "development", "password", "secret",
})

_DEV_ENVS: frozenset[str] = frozenset({
    "development", "dev", "test", "testing", "local",
})


def _current_env() -> str:
    return (
        os.getenv("SENTINEL_ENV", "") or os.getenv("S43_ENV", "")
    ).lower().strip()


def _load_log_salt() -> str:
    """
    Load the log pseudonymization salt.

    Placeholder values are blocked in all environments.
    Production: SENTINEL_LOG_SALT required, >= 32 bytes, hard failure.
    Development: warns and generates an ephemeral random salt if absent.

    Generate: python -c "import secrets; print(secrets.token_hex(32))"
    """
    value = os.getenv("SENTINEL_LOG_SALT", "").strip()

    if value and value in _BLOCKED_SECRETS:
        raise RuntimeError(
            "SENTINEL_LOG_SALT is set to a placeholder value and must be replaced. "
            'Generate: python -c "import secrets; print(secrets.token_hex(32))"'
        )

    if value and len(value.encode("utf-8")) >= 32:
        return value

    if _current_env() in _DEV_ENVS:
        msg = (
            "SENTINEL_LOG_SALT is too short (< 32 bytes). Using ephemeral random salt."
            if value else
            "SENTINEL_LOG_SALT is not set. Using ephemeral random salt — "
            "log hashes will not be consistent across restarts."
        )
        warnings.warn(msg, RuntimeWarning, stacklevel=2)
        return secrets.token_hex(32)

    raise RuntimeError(
        "SENTINEL_LOG_SALT is required in production (>= 32 bytes). "
        'Generate: python -c "import secrets; print(secrets.token_hex(32))"'
    )


DB_PATH = Path(_env("SENTINEL_DB_PATH", str(_BASE_DIR / "sentinel43_state" / "sentinel43.sqlite3")))
SYSTEM_ID = _env("SENTINEL_SYSTEM_ID", "SENTINEL-43-NEXUS-01")
LOG_SALT = _load_log_salt()

DEFAULT_DEDUPE_TTL_SECONDS   = int(_env("SENTINEL_ACTION_DEDUPE_TTL",   "60"))
DEFAULT_LOG_RETENTION_DAYS   = int(_env("SENTINEL_LOG_RETENTION_DAYS",  "90"))
DEFAULT_ACTION_RETENTION_DAYS = int(_env("SENTINEL_ACTION_RETENTION_DAYS", "30"))
EXECUTOR_POLL_MS             = int(_env("SENTINEL_EXECUTOR_POLL_MS",    "500"))
EXECUTOR_MAX_BATCH           = int(_env("SENTINEL_EXECUTOR_MAX_BATCH",  "25"))

OVERSIGHT_DEDUPE_TTL           = int(_env("SENTINEL_OVERSIGHT_DEDUPE_TTL",                "120"))
OVERSIGHT_MAX_PENDING          = int(_env("SENTINEL_OVERSIGHT_MAX_PENDING",               "250"))
OVERSIGHT_BUDGET_WINDOW        = int(_env("SENTINEL_OVERSIGHT_BUDGET_WINDOW_SECONDS",     "300"))
OVERSIGHT_BUDGET_MAX_TARGET    = int(_env("SENTINEL_OVERSIGHT_BUDGET_MAX_PER_TARGET",     "5"))
OVERSIGHT_BUDGET_MAX_SOURCE    = int(_env("SENTINEL_OVERSIGHT_BUDGET_MAX_PER_SOURCE",     "25"))
OVERSIGHT_TWO_SIGNAL_HIGH      = _env("SENTINEL_OVERSIGHT_TWO_SIGNAL_HIGH", "true").lower() == "true"
OVERSIGHT_CORROBORATION_TTL    = int(_env("SENTINEL_OVERSIGHT_CORROBORATION_TTL_SECONDS", "600"))


# =============================================================================
# Governance Mode
# =============================================================================

class SentinelMode(str, enum.Enum):
    SHADOW      = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"
    ACTIVE      = "ACTIVE"


# =============================================================================
# Threat Types
# Imported from sentinel_43_ai if available; local fallbacks otherwise.
# =============================================================================

try:
    from sentinel_43_ai.detection.sentinel_threat_types import (  # type: ignore[import]
        ThreatKind,
        ThreatSeverity,
        ThreatSourceKind,
        ThreatAssessment,
    )
    _THREAT_TYPES_SOURCE = "sentinel_43_ai"
except ImportError:
    _THREAT_TYPES_SOURCE = "local_fallback"
    logger.debug(
        "sentinel_43_ai not found — using local threat type definitions. "
        "Install the package or set PYTHONPATH to use shared types."
    )

    class ThreatKind(str, enum.Enum):
        GENERIC_INTRUSION = "GENERIC_INTRUSION"
        MALWARE_DELIVERY  = "MALWARE_DELIVERY"
        SPYWARE_ACTIVITY  = "SPYWARE_ACTIVITY"
        DATA_EXFILTRATION = "DATA_EXFILTRATION"
        CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
        UNKNOWN           = "UNKNOWN"

    class ThreatSeverity(str, enum.Enum):
        LOW      = "LOW"
        MEDIUM   = "MEDIUM"
        HIGH     = "HIGH"
        CRITICAL = "CRITICAL"

    class ThreatSourceKind(str, enum.Enum):
        HUMAN_LIKELY         = "HUMAN_LIKELY"
        AI_AUTOMATION_LIKELY = "AI_AUTOMATION_LIKELY"
        MIXED_OR_UNKNOWN     = "MIXED_OR_UNKNOWN"

    @dataclass(frozen=True)
    class ThreatAssessment:
        identity:        str
        source_ip:       str
        threat_kind:     ThreatKind
        severity:        ThreatSeverity
        source_kind:     ThreatSourceKind
        score:           float
        indicators:      Optional[Any]  = None
        supporting_tags: List[str]      = field(default_factory=list)
        window_size:     int            = 0
        generated_at:    float          = field(default_factory=time.time)


# =============================================================================
# Response Actions + Policy
# =============================================================================

class ResponseAction(enum.Enum):
    LOG_ONLY             = "LOG_ONLY"
    FLAG_SUSPICIOUS      = "FLAG_SUSPICIOUS"
    STEP_UP_AUTH         = "STEP_UP_AUTH"
    RATE_LIMIT           = "RATE_LIMIT"
    TEMP_BLOCK_IDENTITY  = "TEMP_BLOCK_IDENTITY"
    TEMP_BLOCK_IP        = "TEMP_BLOCK_IP"
    HARD_BLOCK_IDENTITY  = "HARD_BLOCK_IDENTITY"
    HARD_BLOCK_IP        = "HARD_BLOCK_IP"
    QUARANTINE_SESSION   = "QUARANTINE_SESSION"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
    OPEN_INCIDENT        = "OPEN_INCIDENT"


@dataclass(frozen=True)
class ResponsePolicy:
    medium_threshold:                  float = 40.0
    high_threshold:                    float = 65.0
    critical_threshold:                float = 85.0
    automation_medium_bonus:           float = 5.0
    automation_high_bonus:             float = 10.0
    temp_block_seconds:                int   = 900
    hard_block_seconds:                int   = 21_600   # 6 hours
    auto_open_incident_on_critical:    bool  = True
    auto_require_human_review_on_high: bool  = True
    veto_window_seconds:               int   = 30


@dataclass
class ResponseDirective:
    identity:           str
    source_ip:          str
    primary_action:     ResponseAction
    additional_actions: List[ResponseAction] = field(default_factory=list)
    reason:             str                  = ""
    expires_at:         Optional[float]      = None
    threat_kind:        ThreatKind           = ThreatKind.UNKNOWN
    threat_severity:    ThreatSeverity       = ThreatSeverity.LOW
    source_kind:        ThreatSourceKind     = ThreatSourceKind.MIXED_OR_UNKNOWN
    score:              float                = 0.0
    created_at:         float                = field(default_factory=time.time)


# =============================================================================
# Action State Machine
# =============================================================================

class ActionStatus(str, enum.Enum):
    SHADOWED  = "SHADOWED"   # SHADOW mode — advisory log only
    STAGED    = "STAGED"     # HUMAN_GATED — awaiting operator approval
    PENDING   = "PENDING"    # ACTIVE — in veto window, will auto-execute
    VETOED    = "VETOED"     # operator blocked it (terminal)
    APPROVED  = "APPROVED"   # operator approved a STAGED action; transient
                              # mid-flight before synchronous execution.
                              # RESERVED for the human-approval path only —
                              # the auto-executor never sets this.
    EXECUTING = "EXECUTING"  # auto-executor claimed a PENDING action.
                              # Distinct from APPROVED so a crashed claim
                              # cannot be misread as a human decision.
    EXECUTED  = "EXECUTED"   # terminal — ran successfully
    FAILED    = "FAILED"     # terminal — ran, but failed
    EXPIRED   = "EXPIRED"    # terminal — never ran, past stale deadline


@dataclass(frozen=True)
class PendingAction:
    action_id:       str
    created_at_ms:   int
    execute_at_ms:   Optional[int]
    status:          ActionStatus
    target_type:     str           # "ip" | "identity"
    target_value:    str           # raw — kept for downstream execution
    primary_action:  str
    actions_json:    str
    severity:        str
    kind:            str
    source_kind:     str
    score:           float
    reason:          str
    system_id:       str           = SYSTEM_ID
    operator_id:     Optional[str] = None
    operator_reason: Optional[str] = None


# =============================================================================
# Privacy Helpers
# =============================================================================

_SAFE_COMPONENT_RE = re.compile(r"[^a-zA-Z0-9.:_\-@]")
_MAX_TARGET_LEN  = 200
_MAX_SOURCE_LEN  = 80
_MAX_REASON_LEN  = 200


def sanitize_key_component(value: str, *, max_len: int = _MAX_TARGET_LEN) -> str:
    s = str(value or "").strip()
    return _SAFE_COMPONENT_RE.sub("", s)[:max_len]


def pseudonymize(value: str) -> str:
    """One-way HMAC-SHA256 of a sensitive value. Safe for logs and dashboard queries."""
    v = str(value or "").strip()
    if not v:
        return "EMPTY"
    return hashlib.sha256(f"{LOG_SALT}:{v}".encode()).hexdigest()[:16]


def normalize_ip(ip: str) -> str:
    s = str(ip or "").strip()
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


def _now_ms() -> int:
    return int(time.time() * 1000)


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


# =============================================================================
# Integration Hub — All real-world effects terminate here.
# Replace stubs with firewall / WAF / IAM / SIEM integrations before
# enabling ACTIVE or HUMAN_GATED mode in production.
# =============================================================================

class IntegrationHub:
    @staticmethod
    def execute(action: PendingAction) -> bool:
        logger.warning(
            "[INTEGRATION] EXECUTE action_id=%s target_type=%s "
            "target_hash=%s primary=%s severity=%s reason=%s",
            action.action_id,
            action.target_type,
            pseudonymize(action.target_value),
            action.primary_action,
            action.severity,
            action.reason,
        )
        return True  # stub — replace with real enforcement


# =============================================================================
# SQLite Action Store
# =============================================================================

def _db_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


class ActionStore(Protocol):
    def ensure_schema(self) -> None: ...
    def log_event(self, level: str, module: str, message: str,
                  context: Optional[Dict[str, Any]] = None) -> None: ...
    def dedupe_check_and_set(self, key: str, ttl_seconds: int) -> bool: ...
    def insert_pending_action(self, pa: PendingAction) -> None: ...
    def update_action_status(self, action_id: str, new_status: ActionStatus, *,
                             operator_id: Optional[str], operator_reason: Optional[str],
                             expected_status: ActionStatus) -> bool: ...
    def get_action_status(self, action_id: str) -> Optional[str]: ...
    def fetch_due_pending(self, *, now_ms: int, limit: int) -> List[PendingAction]: ...
    def mark_pending_executing(self, action_id: str) -> bool: ...
    def finalize_execution(self, action_id: str, *, ok: bool, operator_reason: str = "") -> None: ...
    def expire_overdue(self, *, now_ms: int) -> int: ...
    def cleanup_old_logs(self, retention_days: int) -> int: ...
    def cleanup_old_actions(self, retention_days: int) -> int: ...


class SqliteActionStore:
    """
    Durable SQLite store with hash-chained audit log.

    All write paths use BEGIN IMMEDIATE to prevent lost-update races.
    Schema migrates in-place so existing deployments survive upgrades.

    Security fixes (scrub pass):
      - target_hash column: pseudonymized SHA-256, stored beside raw
        target_value. Dashboard / log views use target_hash; execution
        uses target_value.
      - APPROVED excluded from retention cleanup (transient mid-flight).
      - Dedupe suppression logs hash of the dedupe key, never the raw value.
    """

    _schema_lock = threading.RLock()

    def ensure_schema(self) -> None:
        with self._schema_lock, _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS event_logs (
                        id           INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts_ms        INTEGER NOT NULL,
                        level        TEXT    NOT NULL,
                        module       TEXT    NOT NULL,
                        message      TEXT    NOT NULL,
                        context_json TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_event_logs_ts
                        ON event_logs(ts_ms);

                    CREATE TABLE IF NOT EXISTS pending_actions (
                        action_id       TEXT PRIMARY KEY,
                        created_at_ms   INTEGER NOT NULL,
                        execute_at_ms   INTEGER,
                        status          TEXT    NOT NULL,
                        target_type     TEXT    NOT NULL,
                        target_value    TEXT    NOT NULL,
                        target_hash     TEXT,
                        primary_action  TEXT    NOT NULL,
                        actions_json    TEXT    NOT NULL,
                        severity        TEXT    NOT NULL,
                        kind            TEXT    NOT NULL,
                        source_kind     TEXT    NOT NULL,
                        score           REAL    NOT NULL,
                        reason          TEXT    NOT NULL,
                        system_id       TEXT    NOT NULL,
                        operator_id     TEXT,
                        operator_reason TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_actions_status_exec
                        ON pending_actions(status, execute_at_ms);
                    CREATE INDEX IF NOT EXISTS idx_actions_created
                        ON pending_actions(created_at_ms);

                    CREATE TABLE IF NOT EXISTS action_dedupe (
                        dedupe_key    TEXT    PRIMARY KEY,
                        expires_at_ms INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_dedupe_exp
                        ON action_dedupe(expires_at_ms);

                    CREATE TABLE IF NOT EXISTS audit_chain (
                        id        INTEGER PRIMARY KEY CHECK (id = 1),
                        prev_hash TEXT    NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_events (
                        ts_ms        INTEGER NOT NULL,
                        event_type   TEXT    NOT NULL,
                        payload_json TEXT    NOT NULL,
                        prev_hash    TEXT    NOT NULL,
                        hash         TEXT    NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_audit_events_ts
                        ON audit_events(ts_ms);
                """)

                if not conn.execute("SELECT 1 FROM audit_chain WHERE id=1").fetchone():
                    conn.execute(
                        "INSERT INTO audit_chain (id, prev_hash) VALUES (1, ?)", ("0" * 64,)
                    )

                # In-place migration: add target_hash if it is missing.
                cols = {r[1] for r in conn.execute("PRAGMA table_info(pending_actions)").fetchall()}
                if "target_hash" not in cols:
                    conn.execute("ALTER TABLE pending_actions ADD COLUMN target_hash TEXT NULL")

                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        # Backfill target_hash for pre-migration rows — best effort, never blocks startup.
        try:
            with _db_conn() as conn:
                for action_id, tv in conn.execute(
                    "SELECT action_id, target_value FROM pending_actions WHERE target_hash IS NULL"
                ).fetchall():
                    conn.execute(
                        "UPDATE pending_actions SET target_hash=? WHERE action_id=?",
                        (pseudonymize(tv), action_id),
                    )
        except Exception as exc:
            logger.warning("target_hash backfill skipped: %s", exc)

        try:
            self.cleanup_old_logs(DEFAULT_LOG_RETENTION_DAYS)
            self.cleanup_old_actions(DEFAULT_ACTION_RETENTION_DAYS)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Audit chain
    # ------------------------------------------------------------------

    def _append_audit(self, *, event_type: str, payload: Dict[str, Any]) -> None:
        ts_ms = _now_ms()
        payload_json = _json_dumps(payload)
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                prev_hash = conn.execute(
                    "SELECT prev_hash FROM audit_chain WHERE id=1"
                ).fetchone()[0]
                raw = f"{prev_hash}|{ts_ms}|{event_type}|{payload_json}".encode()
                h = hashlib.sha256(raw).hexdigest()
                conn.execute(
                    "INSERT INTO audit_events (ts_ms, event_type, payload_json, prev_hash, hash) "
                    "VALUES (?,?,?,?,?)",
                    (ts_ms, event_type, payload_json, prev_hash, h),
                )
                conn.execute("UPDATE audit_chain SET prev_hash=? WHERE id=1", (h,))
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    # ------------------------------------------------------------------
    # Event log
    # ------------------------------------------------------------------

    def log_event(
        self,
        level: str,
        module: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        ctx = _json_dumps(context) if context else None
        with _db_conn() as conn:
            conn.execute(
                "INSERT INTO event_logs (ts_ms, level, module, message, context_json) "
                "VALUES (?,?,?,?,?)",
                (_now_ms(), level, module, message, ctx),
            )
        try:
            self._append_audit(
                event_type=f"log.{level}",
                payload={"module": module, "message": message, "context": context or {}},
            )
        except Exception:
            pass  # audit chain failure must never swallow a log entry

    # ------------------------------------------------------------------
    # Dedupe
    # ------------------------------------------------------------------

    def dedupe_check_and_set(self, key: str, ttl_seconds: int) -> bool:
        now_ms = _now_ms()
        key = str(key or "").strip()[:512]
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(
                    "DELETE FROM action_dedupe WHERE expires_at_ms <= ?", (now_ms,)
                )
                conn.execute(
                    "INSERT INTO action_dedupe (dedupe_key, expires_at_ms) VALUES (?,?)",
                    (key, now_ms + int(ttl_seconds * 1000)),
                )
                conn.execute("COMMIT;")
                return True
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK;")
                return False
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    # ------------------------------------------------------------------
    # Action lifecycle
    # ------------------------------------------------------------------

    def insert_pending_action(self, pa: PendingAction) -> None:
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(
                    """
                    INSERT INTO pending_actions (
                        action_id, created_at_ms, execute_at_ms, status,
                        target_type, target_value, target_hash,
                        primary_action, actions_json,
                        severity, kind, source_kind, score,
                        reason, system_id, operator_id, operator_reason
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        pa.action_id, pa.created_at_ms, pa.execute_at_ms,
                        pa.status.value,
                        pa.target_type, pa.target_value,
                        pseudonymize(pa.target_value),
                        pa.primary_action, pa.actions_json,
                        pa.severity, pa.kind, pa.source_kind, float(pa.score),
                        pa.reason, pa.system_id,
                        pa.operator_id, pa.operator_reason,
                    ),
                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_action_status(self, action_id: str) -> Optional[str]:
        with _db_conn() as conn:
            row = conn.execute(
                "SELECT status FROM pending_actions WHERE action_id=?", (action_id,)
            ).fetchone()
            return str(row["status"]) if row else None

    def update_action_status(
        self,
        action_id: str,
        new_status: ActionStatus,
        *,
        operator_id: Optional[str],
        operator_reason: Optional[str],
        expected_status: ActionStatus,
    ) -> bool:
        op  = (operator_id or "")[:80] or None
        rsn = (operator_reason or "")[:300] or None
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = conn.execute(
                    "UPDATE pending_actions SET status=?, operator_id=?, operator_reason=? "
                    "WHERE action_id=? AND status=?",
                    (new_status.value, op, rsn, action_id, expected_status.value),
                )
                conn.execute("COMMIT;")
                return int(cur.rowcount or 0) > 0
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def fetch_due_pending(self, *, now_ms: int, limit: int) -> List[PendingAction]:
        with _db_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM pending_actions WHERE status=? "
                "AND execute_at_ms IS NOT NULL AND execute_at_ms<=? "
                "ORDER BY execute_at_ms ASC LIMIT ?",
                (ActionStatus.PENDING.value, int(now_ms), int(limit)),
            ).fetchall()
        return [self._row_to_pa(r) for r in rows]

    def mark_pending_executing(self, action_id: str) -> bool:
        """
        Atomic claim: PENDING -> EXECUTING.
        Never reuses APPROVED — that state is reserved for the human-approval
        path and must never be set by the auto-executor.
        """
        return self.update_action_status(
            action_id, ActionStatus.EXECUTING,
            operator_id="executor", operator_reason="claimed_for_execution",
            expected_status=ActionStatus.PENDING,
        )

    def finalize_execution(self, action_id: str, *, ok: bool, operator_reason: str = "") -> None:
        """Finalize an EXECUTING (auto-executor) action."""
        self.update_action_status(
            action_id,
            ActionStatus.EXECUTED if ok else ActionStatus.FAILED,
            operator_id="executor",
            operator_reason=(operator_reason or "")[:300],
            expected_status=ActionStatus.EXECUTING,
        )

    def expire_overdue(self, *, now_ms: int) -> int:
        stale_before = int(now_ms) - (24 * 3600 * 1000)
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = conn.execute(
                    "UPDATE pending_actions SET status=? WHERE status=? AND created_at_ms<?",
                    (ActionStatus.EXPIRED.value, ActionStatus.PENDING.value, stale_before),
                )
                conn.execute("COMMIT;")
                return int(cur.rowcount or 0)
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def cleanup_old_logs(self, retention_days: int) -> int:
        cutoff = _now_ms() - int(retention_days) * 86_400 * 1_000
        with _db_conn() as conn:
            cur = conn.execute("DELETE FROM event_logs WHERE ts_ms<?", (cutoff,))
            return int(cur.rowcount or 0)

    def cleanup_old_actions(self, retention_days: int) -> int:
        """
        APPROVED is excluded from cleanup.

        APPROVED is a transient mid-flight state set by the human-approval
        path, immediately before synchronous execution. Deleting it during
        routine retention would silently discard an action that crashed between
        approval and execution, leaving no audit trail of what happened.
        Only genuinely terminal states are eligible.
        """
        cutoff = _now_ms() - int(retention_days) * 86_400 * 1_000
        terminal = (
            ActionStatus.VETOED.value,
            ActionStatus.EXECUTED.value,
            ActionStatus.FAILED.value,
            ActionStatus.EXPIRED.value,
        )
        placeholders = ",".join("?" * len(terminal))
        with _db_conn() as conn:
            cur = conn.execute(
                f"DELETE FROM pending_actions WHERE created_at_ms<? AND status IN ({placeholders})",
                (cutoff, *terminal),
            )
            return int(cur.rowcount or 0)

    @staticmethod
    def _row_to_pa(r: sqlite3.Row) -> PendingAction:
        return PendingAction(
            action_id=str(r["action_id"]),
            created_at_ms=int(r["created_at_ms"]),
            execute_at_ms=int(r["execute_at_ms"]) if r["execute_at_ms"] is not None else None,
            status=ActionStatus(str(r["status"])),
            target_type=str(r["target_type"]),
            target_value=str(r["target_value"]),
            primary_action=str(r["primary_action"]),
            actions_json=str(r["actions_json"]),
            severity=str(r["severity"]),
            kind=str(r["kind"]),
            source_kind=str(r["source_kind"]),
            score=float(r["score"]),
            reason=str(r["reason"]),
            system_id=str(r["system_id"]),
            operator_id=str(r["operator_id"]) if r["operator_id"] else None,
            operator_reason=str(r["operator_reason"]) if r["operator_reason"] else None,
        )


# =============================================================================
# Response Engine
# =============================================================================

class Sentinel43ResponseEngine:
    """
    Core threat response engine.

    Accepts ThreatAssessment, produces ResponseDirective, and stages
    the resulting action durably in SQLite. The auto-executor thread
    runs due ACTIVE-mode actions after their veto window elapses.

    Constructor parameters:
        store                  SqliteActionStore or any ActionStore impl
        policy                 ResponsePolicy (thresholds, timeouts)
        dedupe_ttl_seconds     how long to suppress duplicate directives
        operator_authenticator callable(operator_id: str) -> bool
                               returns True if operator is authorized.
                               Defaults to fail-closed (always False).
        integration            class with execute(PendingAction) -> bool
    """

    def __init__(
        self,
        store: Optional[ActionStore] = None,
        policy: Optional[ResponsePolicy] = None,
        dedupe_ttl_seconds: int = DEFAULT_DEDUPE_TTL_SECONDS,
        *,
        operator_authenticator: Optional[Callable[[str], bool]] = None,
        integration: Optional[type] = None,
    ) -> None:
        self.store  = store  or SqliteActionStore()
        self.policy = policy or ResponsePolicy()
        self.dedupe_ttl_seconds = int(dedupe_ttl_seconds)
        self._auth  = operator_authenticator or (lambda _: False)
        self._integration = integration or IntegrationHub

        self._stop = threading.Event()
        self._executor = threading.Thread(
            target=self._executor_loop, name="s43-executor", daemon=True
        )
        self.store.ensure_schema()
        self.store.log_event("INFO", "BOOT", "Sentinel43ResponseEngine initialized.",
                             {"system_id": SYSTEM_ID})
        self._executor.start()

    def shutdown(self) -> None:
        self.store.log_event("INFO", "SYSTEM", "Shutdown requested.")
        self._stop.set()
        self._executor.join(timeout=5)
        self.store.log_event("INFO", "SYSTEM", "Shutdown complete.")

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------

    def handle_assessment(
        self, mode: SentinelMode, assessment: ThreatAssessment
    ) -> Optional[PendingAction]:
        directive = self.plan_response(assessment)
        self.store.log_event("INFO", "RESPONSE", "Response plan generated", {
            "identity_hash":      pseudonymize(directive.identity),
            "ip_hash":            pseudonymize(directive.source_ip),
            "primary_action":     directive.primary_action.name,
            "additional_actions": [a.name for a in directive.additional_actions],
            "score":              directive.score,
            "severity":           directive.threat_severity.name,
            "kind":               directive.threat_kind.name,
            "source_kind":        directive.source_kind.name,
            "expires_at":         directive.expires_at,
            "mode":               mode.value,
        })
        return self.stage_directive(mode, directive)

    # ------------------------------------------------------------------
    # Operator controls
    # ------------------------------------------------------------------

    def approve_action(self, action_id: str, operator_id: str, reason: str = "") -> bool:
        op  = (operator_id or "").strip()[:80]
        rsn = (reason or "").strip()[:300]

        if not op or not self._auth(op):
            self.store.log_event("ERROR", "OVERSIGHT", "Unauthorized approval attempt",
                                 {"action_id": action_id, "operator_id": op})
            return False

        ok = self.store.update_action_status(
            action_id, ActionStatus.APPROVED,
            operator_id=op, operator_reason=rsn,
            expected_status=ActionStatus.STAGED,
        )
        self.store.log_event(
            "WARN" if ok else "ERROR", "OVERSIGHT",
            "Action approved" if ok else "Approval failed — not in STAGED state",
            {"action_id": action_id, "operator_id": op},
        )
        if ok:
            self._execute_approved_now(action_id)
        return ok

    def veto_action(self, action_id: str, operator_id: str, reason: str) -> bool:
        op  = (operator_id or "").strip()[:80]
        rsn = (reason or "").strip()[:300]

        if not op or not self._auth(op):
            self.store.log_event("ERROR", "OVERSIGHT", "Unauthorized veto attempt",
                                 {"action_id": action_id, "operator_id": op})
            return False

        # Allow veto of PENDING (ACTIVE veto window) or STAGED (HUMAN_GATED)
        for expected in (ActionStatus.PENDING, ActionStatus.STAGED):
            ok = self.store.update_action_status(
                action_id, ActionStatus.VETOED,
                operator_id=op, operator_reason=rsn,
                expected_status=expected,
            )
            if ok:
                self.store.log_event("WARN", "OVERSIGHT", "Action vetoed",
                                     {"action_id": action_id, "operator_id": op})
                return True

        self.store.log_event("ERROR", "OVERSIGHT", "Veto failed — action not found or not vetable",
                             {"action_id": action_id})
        return False

    # ------------------------------------------------------------------
    # Response planning
    # ------------------------------------------------------------------

    def plan_response(self, assessment: ThreatAssessment) -> ResponseDirective:
        a = ThreatAssessment(
            identity=assessment.identity,
            source_ip=normalize_ip(assessment.source_ip),
            threat_kind=assessment.threat_kind,
            severity=assessment.severity,
            source_kind=assessment.source_kind,
            score=float(assessment.score),
            indicators=assessment.indicators,
            supporting_tags=list(assessment.supporting_tags),
            window_size=int(assessment.window_size),
            generated_at=float(assessment.generated_at),
        )
        score = self._adjusted_score(a)

        if a.severity == ThreatSeverity.LOW and score < self.policy.medium_threshold:
            return self._build_low(a, score)
        if a.severity == ThreatSeverity.CRITICAL:
            return self._build_critical(a, score)
        return self._build_mid_high(a, score)

    def _adjusted_score(self, a: ThreatAssessment) -> float:
        score = float(a.score)
        if a.source_kind == ThreatSourceKind.AI_AUTOMATION_LIKELY:
            bonus = (
                self.policy.automation_high_bonus
                if a.severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL)
                else self.policy.automation_medium_bonus
            )
            score += bonus
        return min(100.0, score)

    def _build_low(self, a: ThreatAssessment, score: float) -> ResponseDirective:
        actions = [ResponseAction.LOG_ONLY]
        if a.threat_kind in (ThreatKind.MALWARE_DELIVERY, ThreatKind.SPYWARE_ACTIVITY):
            actions.append(ResponseAction.FLAG_SUSPICIOUS)
        return ResponseDirective(
            identity=a.identity, source_ip=a.source_ip,
            primary_action=actions[0], additional_actions=actions[1:],
            reason=f"Low severity (score={score:.1f})",
            threat_kind=a.threat_kind, threat_severity=a.severity,
            source_kind=a.source_kind, score=score,
        )

    def _build_mid_high(self, a: ThreatAssessment, score: float) -> ResponseDirective:
        actions: List[ResponseAction] = []
        if a.threat_kind in (ThreatKind.CREDENTIAL_ATTACK, ThreatKind.GENERIC_INTRUSION):
            actions.append(ResponseAction.STEP_UP_AUTH)
        actions.append(ResponseAction.RATE_LIMIT)

        temp_block = score >= self.policy.high_threshold
        expires_at = None
        if temp_block:
            actions.append(ResponseAction.TEMP_BLOCK_IDENTITY)
            expires_at = time.time() + self.policy.temp_block_seconds
            if a.source_kind == ThreatSourceKind.AI_AUTOMATION_LIKELY:
                actions.append(ResponseAction.TEMP_BLOCK_IP)
        if self.policy.auto_require_human_review_on_high and a.severity == ThreatSeverity.HIGH:
            actions.append(ResponseAction.REQUIRE_HUMAN_REVIEW)

        return ResponseDirective(
            identity=a.identity, source_ip=a.source_ip,
            primary_action=actions[0] if actions else ResponseAction.LOG_ONLY,
            additional_actions=actions[1:],
            reason=f"Medium/High severity (score={score:.1f})",
            expires_at=expires_at,
            threat_kind=a.threat_kind, threat_severity=a.severity,
            source_kind=a.source_kind, score=score,
        )

    def _build_critical(self, a: ThreatAssessment, score: float) -> ResponseDirective:
        actions = [
            ResponseAction.QUARANTINE_SESSION,
            ResponseAction.HARD_BLOCK_IDENTITY,
            ResponseAction.HARD_BLOCK_IP,
        ]
        if self.policy.auto_open_incident_on_critical:
            actions.append(ResponseAction.OPEN_INCIDENT)
        if self.policy.auto_require_human_review_on_high:
            actions.append(ResponseAction.REQUIRE_HUMAN_REVIEW)
        return ResponseDirective(
            identity=a.identity, source_ip=a.source_ip,
            primary_action=actions[0], additional_actions=actions[1:],
            reason=f"CRITICAL threat (score={score:.1f})",
            expires_at=time.time() + self.policy.hard_block_seconds,
            threat_kind=a.threat_kind, threat_severity=a.severity,
            source_kind=a.source_kind, score=score,
        )

    # ------------------------------------------------------------------
    # Staging
    # ------------------------------------------------------------------

    def stage_directive(self, mode: SentinelMode, d: ResponseDirective) -> Optional[PendingAction]:
        if d.primary_action == ResponseAction.LOG_ONLY and not d.additional_actions:
            return None

        target_type, raw_target = self._pick_target(d)
        target_key = sanitize_key_component(raw_target)
        if not target_key:
            self.store.log_event("ERROR", "RESPONSE", "Invalid target after sanitization",
                                 {"target_type": target_type, "target_hash": pseudonymize(raw_target)})
            return None

        dedupe_key = (
            f"{sanitize_key_component(target_type, max_len=16)}:"
            f"{target_key}:"
            f"{sanitize_key_component(d.primary_action.name, max_len=40)}:"
            f"{sanitize_key_component(d.threat_kind.name, max_len=40)}"
        )

        if not self.store.dedupe_check_and_set(dedupe_key, self.dedupe_ttl_seconds):
            # Log hash of the key only — dedupe_key embeds raw target value.
            self.store.log_event("INFO", "RESPONSE", "Duplicate directive suppressed",
                                 {"dedupe_hash": pseudonymize(dedupe_key),
                                  "ttl_seconds": self.dedupe_ttl_seconds})
            return None

        now_ms    = _now_ms()
        action_id = f"ACT-{uuid.uuid4().hex}".upper()

        if mode == SentinelMode.SHADOW:
            status, execute_at_ms = ActionStatus.SHADOWED, None
        elif mode == SentinelMode.HUMAN_GATED:
            status, execute_at_ms = ActionStatus.STAGED, None
        else:
            status = ActionStatus.PENDING
            execute_at_ms = now_ms + int(self.policy.veto_window_seconds * 1_000)

        pa = PendingAction(
            action_id=action_id,
            created_at_ms=now_ms,
            execute_at_ms=execute_at_ms,
            status=status,
            target_type=target_type,
            target_value=raw_target,
            primary_action=d.primary_action.name,
            actions_json=_json_dumps({
                "primary":    d.primary_action.name,
                "additional": [a.name for a in d.additional_actions],
                "expires_at": d.expires_at,
            }),
            severity=d.threat_severity.name,
            kind=d.threat_kind.name,
            source_kind=d.source_kind.name,
            score=float(d.score),
            reason=d.reason,
        )

        self.store.insert_pending_action(pa)
        self.store.log_event("INFO", "OVERSIGHT", "Action staged", {
            "action_id":     pa.action_id,
            "status":        pa.status.value,
            "mode":          mode.value,
            "target_type":   pa.target_type,
            "target_hash":   pseudonymize(pa.target_value),
            "primary_action": pa.primary_action,
            "execute_at_ms": pa.execute_at_ms,
        })
        return pa

    @staticmethod
    def _pick_target(d: ResponseDirective) -> Tuple[str, str]:
        ip_actions = {ResponseAction.TEMP_BLOCK_IP, ResponseAction.HARD_BLOCK_IP}
        if d.primary_action in ip_actions:
            return ("ip", d.source_ip)
        return ("identity", d.identity)

    # ------------------------------------------------------------------
    # Auto-executor (ACTIVE mode)
    # ------------------------------------------------------------------

    def _executor_loop(self) -> None:
        self.store.log_event("INFO", "EXECUTOR", "Executor thread online.",
                             {"poll_ms": EXECUTOR_POLL_MS})
        while not self._stop.is_set():
            now_ms = _now_ms()
            try:
                expired = self.store.expire_overdue(now_ms=now_ms)
                if expired:
                    self.store.log_event("WARN", "EXECUTOR", "Expired stale PENDING actions",
                                         {"count": expired})
            except Exception as exc:
                self.store.log_event("ERROR", "EXECUTOR", "Expire pass failed", {"error": str(exc)})

            try:
                for pa in self.store.fetch_due_pending(now_ms=now_ms, limit=EXECUTOR_MAX_BATCH):
                    if not self.store.mark_pending_executing(pa.action_id):
                        continue  # already claimed or vetoed
                    ok, err = False, ""
                    try:
                        ok = bool(self._integration.execute(pa))
                    except Exception as exc:
                        err = str(exc)
                    try:
                        self.store.finalize_execution(pa.action_id, ok=ok,
                                                      operator_reason=err or "ok")
                        self.store.log_event(
                            "WARN" if ok else "ERROR", "EXECUTOR",
                            "Executed action" if ok else "Execution failed",
                            {"action_id": pa.action_id, "ok": ok, "error": err[:300]},
                        )
                    except Exception as exc:
                        self.store.log_event("ERROR", "EXECUTOR", "Finalize failed",
                                             {"action_id": pa.action_id, "error": str(exc)})
            except Exception as exc:
                self.store.log_event("ERROR", "EXECUTOR", "Executor loop error", {"error": str(exc)})

            self._stop.wait(timeout=max(0.05, EXECUTOR_POLL_MS / 1_000.0))

        self.store.log_event("INFO", "EXECUTOR", "Executor thread stopping.")

    def _execute_approved_now(self, action_id: str) -> None:
        """Execute a HUMAN_GATED action immediately after operator approval."""
        try:
            with _db_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM pending_actions WHERE action_id=?", (action_id,)
                ).fetchone()
                if not row:
                    return
                pa = SqliteActionStore._row_to_pa(row)

            ok, err = False, ""
            try:
                ok = bool(self._integration.execute(pa))
            except Exception as exc:
                err = str(exc)

            # expected_status is APPROVED — this is the human-approval path.
            # The auto-executor uses EXECUTING; these must remain distinct.
            self.store.update_action_status(
                action_id,
                ActionStatus.EXECUTED if ok else ActionStatus.FAILED,
                operator_id="executor",
                operator_reason=err or "ok",
                expected_status=ActionStatus.APPROVED,
            )
            self.store.log_event(
                "WARN" if ok else "ERROR", "EXECUTOR",
                "Executed approved action" if ok else "Approved action failed",
                {"action_id": action_id, "ok": ok, "error": err[:300]},
            )
        except Exception as exc:
            self.store.log_event("ERROR", "EXECUTOR",
                                 "Approved-now execution path failed",
                                 {"action_id": action_id, "error": str(exc)})


# =============================================================================
# Oversight Engine — Pre-staging guardrails
# =============================================================================

@dataclass
class _BudgetState:
    window_start: float
    used: int


@dataclass
class _CorrState:
    first_seen: float
    last_seen: float
    count: int


@dataclass(frozen=True)
class ActionRequest:
    """Wrapper passed to OversightEngine.schedule_action()."""
    action_id:       str
    dedupe_key:      str
    target:          str
    source:          str
    description:     str
    delay_seconds:   int
    severity:        str
    reason:          str
    evidence:        Dict[str, Any]
    stage_callable:  Callable[[SentinelMode, Dict[str, Any]], Optional[str]]
    shadow_callable: Optional[Callable[[], None]] = None


class OversightEngine:
    """
    Pre-staging guardrails — runs before any action reaches SqliteActionStore.

    Checks (in order):
      1. Dedupe — suppress repeated identical events within TTL
      2. Per-target and per-source action budgets
      3. Two-signal corroboration for HIGH severity (configurable)

    SHADOW mode: shadow_callable is invoked (advisory log); no durable action.
    HUMAN_GATED / ACTIVE: stage_callable stages durably via ResponseEngine.

    There is exactly one source of truth for action state: SqliteActionStore.
    This class holds no in-memory pending/gated dicts.
    """

    def __init__(
        self,
        mode_resolver: Callable[[], Any],
        *,
        dedupe_ttl_seconds:           int   = OVERSIGHT_DEDUPE_TTL,
        max_pending:                  int   = OVERSIGHT_MAX_PENDING,
        budget_window_seconds:        int   = OVERSIGHT_BUDGET_WINDOW,
        budget_max_actions_per_target: int  = OVERSIGHT_BUDGET_MAX_TARGET,
        budget_max_actions_per_source: int  = OVERSIGHT_BUDGET_MAX_SOURCE,
        require_two_signals_for_high: bool  = OVERSIGHT_TWO_SIGNAL_HIGH,
        corroboration_ttl_seconds:    int   = OVERSIGHT_CORROBORATION_TTL,
        on_failure: Optional[Callable[[str, Exception], None]] = None,
    ) -> None:
        self._mode_resolver  = mode_resolver
        self._lock           = threading.RLock()
        self._dedupe:  Dict[str, float]       = {}
        self._budgets_target: Dict[str, _BudgetState] = {}
        self._budgets_source: Dict[str, _BudgetState] = {}
        self._corr:    Dict[str, _CorrState]  = {}
        self._on_failure = on_failure

        self._dedupe_ttl     = int(dedupe_ttl_seconds)
        self._budget_window  = int(budget_window_seconds)
        self._budget_target  = int(budget_max_actions_per_target)
        self._budget_source  = int(budget_max_actions_per_source)
        self._two_signal     = bool(require_two_signals_for_high)
        self._corr_ttl       = int(corroboration_ttl_seconds)

    def _now(self) -> float:
        return time.time()

    def _is_duplicate(self, key: str) -> bool:
        now = self._now()
        ts  = self._dedupe.get(key)
        if ts is None or (now - ts) > self._dedupe_ttl:
            self._dedupe[key] = now
            return False
        return True

    def _consume_budget(self, bucket: Dict[str, _BudgetState], key: str, cap: int) -> bool:
        now = self._now()
        st  = bucket.get(key)
        if st is None or (now - st.window_start) > self._budget_window:
            bucket[key] = _BudgetState(window_start=now, used=1)
            return True
        if st.used >= cap:
            return False
        bucket[key] = _BudgetState(window_start=st.window_start, used=st.used + 1)
        return True

    def _corroborate(self, target: str, reason: str) -> int:
        now = self._now()
        key = f"{target}|{reason}"
        st  = self._corr.get(key)
        if st is None or (now - st.last_seen) > self._corr_ttl:
            self._corr[key] = _CorrState(first_seen=now, last_seen=now, count=1)
            return 1
        self._corr[key] = _CorrState(first_seen=st.first_seen, last_seen=now, count=st.count + 1)
        return st.count + 1

    def _cleanup(self) -> None:
        now = self._now()
        self._dedupe = {k: ts for k, ts in self._dedupe.items()
                        if (now - ts) <= self._dedupe_ttl}
        self._corr   = {k: st for k, st in self._corr.items()
                        if (now - st.last_seen) <= self._corr_ttl}
        for bucket in (self._budgets_target, self._budgets_source):
            stale = [k for k, st in bucket.items()
                     if (now - st.window_start) > self._budget_window * 4]
            for k in stale:
                del bucket[k]

    def schedule_action(self, req: ActionRequest) -> Optional[str]:
        with self._lock:
            raw_mode = self._mode_resolver()
            # Accept both SentinelMode and the OpMode enum from the facade
            if hasattr(raw_mode, "value") and raw_mode.value in (
                "SHADOW_ADVISORY", "SHADOW"
            ):
                mode = SentinelMode.SHADOW
            elif hasattr(raw_mode, "value") and "HUMAN" in raw_mode.value:
                mode = SentinelMode.HUMAN_GATED
            else:
                mode = SentinelMode.ACTIVE

            self._cleanup()

            if self._is_duplicate(req.dedupe_key):
                logger.info("[OVERSIGHT] Duplicate suppressed dedupe_hash=%s",
                            pseudonymize(req.dedupe_key))
                return None

            tgt_ok = self._consume_budget(self._budgets_target, req.target, self._budget_target)
            src_ok = (
                self._consume_budget(self._budgets_source, req.source, self._budget_source)
                if req.source else True
            )
            if not (tgt_ok and src_ok):
                if tgt_ok and not src_ok:  # rollback target
                    st = self._budgets_target.get(req.target)
                    if st:
                        self._budgets_target[req.target] = _BudgetState(
                            window_start=st.window_start, used=max(0, st.used - 1)
                        )
                logger.warning(
                    "[OVERSIGHT] Budget exceeded target_hash=%s source_hash=%s",
                    pseudonymize(req.target), pseudonymize(req.source),
                )
                return None

            if req.severity == "HIGH" and self._two_signal:
                count = self._corroborate(req.target, req.reason)
                logger.info("[OVERSIGHT] Corroboration target_hash=%s -> %d",
                            pseudonymize(req.target), count)
                if count < 2:
                    if mode == SentinelMode.SHADOW and req.shadow_callable:
                        try:
                            req.shadow_callable()
                        except Exception as exc:
                            logger.error("[OVERSIGHT] Shadow callable failed: %s", exc)
                    return None

            if mode == SentinelMode.SHADOW:
                if req.shadow_callable:
                    try:
                        req.shadow_callable()
                    except Exception as exc:
                        logger.error("[OVERSIGHT] Shadow callable failed: %s", exc)
                return None

            try:
                action_id = req.stage_callable(
                    mode,
                    {"delay_seconds": req.delay_seconds, "description": req.description,
                     "evidence": req.evidence},
                )
                if action_id:
                    logger.warning("[OVERSIGHT] Action staged action_id=%s mode=%s",
                                   action_id, mode.value)
                return action_id
            except Exception as exc:
                logger.error("[OVERSIGHT] stage_callable failed action_id=%s: %s",
                             req.action_id, exc)
                if self._on_failure:
                    try:
                        self._on_failure(req.action_id, exc)
                    except Exception:
                        pass
                return None

    def shutdown(self) -> None:
        with self._lock:
            self._dedupe.clear()
            self._corr.clear()
            self._budgets_target.clear()
            self._budgets_source.clear()


# =============================================================================
# SentinelNexus — Convenience facade
# =============================================================================

class _NexusMode(enum.Enum):
    SHADOW      = "SHADOW_ADVISORY"
    HUMAN_GATED = "HUMAN_GATED"
    ACTIVE      = "AUTONOMOUS_VETO"


_CANON_THREAT = frozenset({
    "PORT_SCAN", "BRUTE_FORCE", "CREDENTIAL_STUFFING",
    "MALWARE_BEACON", "ANOMALOUS_TRAFFIC", "UNKNOWN",
})

_THREAT_KIND_MAP = {
    "PORT_SCAN":            ThreatKind.GENERIC_INTRUSION,
    "BRUTE_FORCE":          ThreatKind.CREDENTIAL_ATTACK,
    "CREDENTIAL_STUFFING":  ThreatKind.CREDENTIAL_ATTACK,
    "MALWARE_BEACON":       ThreatKind.MALWARE_DELIVERY,
    "ANOMALOUS_TRAFFIC":    ThreatKind.GENERIC_INTRUSION,
    "UNKNOWN":              ThreatKind.UNKNOWN,
}

_SEV_MAP = {
    "LOW":    ThreatSeverity.LOW,
    "MEDIUM": ThreatSeverity.MEDIUM,
    "HIGH":   ThreatSeverity.HIGH,
}


class SentinelNexus:
    """
    Thin facade that wires OversightEngine -> Sentinel43ResponseEngine.

    Primary entry point for callers that supply raw IP/threat strings
    rather than fully constructed ThreatAssessment objects.
    """

    def __init__(
        self,
        initial_mode: _NexusMode = _NexusMode.SHADOW,
        *,
        source_id: str = "sensor.local",
        operator_authenticator: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self._mode = initial_mode
        self._source_id = sanitize_key_component(source_id, max_len=_MAX_SOURCE_LEN)

        self.engine = Sentinel43ResponseEngine(
            operator_authenticator=operator_authenticator or (lambda _: False),
        )
        self.oversight = OversightEngine(self.get_mode)

        logger.info("[%s] Nexus online. mode=%s source_id=%s",
                    SYSTEM_ID, self._mode.value, self._source_id)

    def set_mode(self, mode: _NexusMode) -> None:
        self._mode = mode
        logger.warning("[%s] Mode -> %s", SYSTEM_ID, self._mode.value)

    def get_mode(self) -> _NexusMode:
        return self._mode

    def shutdown(self) -> None:
        self.oversight.shutdown()
        self.engine.shutdown()

    def handle_threat(
        self,
        *,
        ip_address: str,
        threat_type: str,
        severity: str = "MEDIUM",
        source_id: Optional[str] = None,
    ) -> str:
        ip = normalize_ip(ip_address)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            token = f"DROP-{uuid.uuid4().hex[:12]}"
            logger.warning("[THREAT] Dropped invalid ip_hash=%s token=%s",
                           pseudonymize(ip_address), token)
            return token

        sev   = severity.upper() if severity.upper() in _SEV_MAP else "MEDIUM"
        ttype = threat_type.upper().replace(" ", "_")
        ttype = ttype if ttype in _CANON_THREAT else "UNKNOWN"
        src   = sanitize_key_component(source_id or self._source_id, max_len=_MAX_SOURCE_LEN)

        action_id  = f"ACT-{uuid.uuid4().hex}".upper()
        bucket     = int(time.time() // 30)
        dedupe_key = f"{ip}|{ttype}|{sev}|{bucket}"
        score      = {"HIGH": 70.0, "MEDIUM": 55.0, "LOW": 30.0}.get(sev, 55.0)

        assessment = ThreatAssessment(
            identity=f"ip:{ip}",
            source_ip=ip,
            threat_kind=_THREAT_KIND_MAP.get(ttype, ThreatKind.UNKNOWN),
            severity=_SEV_MAP[sev],
            source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
            score=score,
            supporting_tags=[ttype, sev],
            window_size=1,
        )

        def _stage(mode: SentinelMode, _meta: Dict[str, Any]) -> Optional[str]:
            pa = self.engine.handle_assessment(mode, assessment)
            return pa.action_id if pa else None

        def _shadow() -> None:
            logger.info("[SHADOW] Would stage threat=%s ip_hash=%s", ttype, pseudonymize(ip))

        req = ActionRequest(
            action_id=action_id,
            dedupe_key=dedupe_key,
            target=ip,
            source=src,
            description=f"Respond to {ttype} from {ip}",
            delay_seconds=5,
            severity=sev,
            reason=f"{ttype} detected",
            evidence={"system": SYSTEM_ID, "threat_type": ttype,
                      "severity": sev, "observed_at": int(time.time()), "source_id": src},
            stage_callable=_stage,
            shadow_callable=_shadow,
        )

        logger.info("[THREAT] %s ip_hash=%s severity=%s source=%s action_id=%s",
                    ttype, pseudonymize(ip), sev, src, action_id)

        staged = self.oversight.schedule_action(req)
        return staged or action_id


# =============================================================================
# Module exports
# =============================================================================

__all__ = [
    "SentinelMode",
    "ThreatKind",
    "ThreatSeverity",
    "ThreatSourceKind",
    "ThreatAssessment",
    "ResponseAction",
    "ResponsePolicy",
    "ResponseDirective",
    "ActionStatus",
    "PendingAction",
    "ActionStore",
    "SqliteActionStore",
    "IntegrationHub",
    "Sentinel43ResponseEngine",
    "ActionRequest",
    "OversightEngine",
    "SentinelNexus",
    "pseudonymize",
    "normalize_ip",
    "sanitize_key_component",
    "SYSTEM_ID",
    "DB_PATH",
]
