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
# 1. GNU Affero General Public License (AGPL v3.0)
# for open-source use, modification, and distribution.
#
# 2. Commercial License
# for proprietary, enterprise, government, or other commercial use
# not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
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

import enum
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple


# ============================================================
# Logging (NO basicConfig here. Caller owns global logging.)
# ============================================================

logger = logging.getLogger(__name__)

# ============================================================
# Public-beta security scrub — changelog (this pass)
# ============================================================
#   Brought in line with the same hardening pass applied to Shadow_mode.py.
#   This file's _required_env_secret() / LOG_SALT handling was independently
#   already correct (fails closed, blocks known placeholder values, enforces
#   min_bytes) and is untouched here. The remaining four fixes:
#
#   1. ActionStatus.EXECUTING added. mark_pending_executing() now claims a
#      PENDING (auto-execute / ACTIVE-mode) action by transitioning it to
#      EXECUTING instead of APPROVED. finalize_execution() now expects
#      EXECUTING. APPROVED is reserved exclusively for the human-approval
#      path (STAGED -> APPROVED via approve_action(), executed synchronously
#      in _execute_approved_now()). Reusing APPROVED for both made the
#      action lifecycle ambiguous — a crashed auto-execute claim could be
#      misread as a human decision, or vice versa.
#   2. cleanup_old_actions() no longer deletes APPROVED rows. APPROVED is a
#      transient mid-flight state; deleting it during routine retention
#      cleanup could silently discard an action that crashed between
#      approval and execution, with no audit trail of what happened to it.
#   3. pending_actions gained a target_hash column (pseudonymized SHA-256,
#      same scheme used in logs and the audit chain). target_value remains
#      stored raw because execution needs the real IP/identity; target_hash
#      lets dashboards and log views display/query without touching the
#      raw value. Existing databases are migrated in place (ALTER TABLE)
#      and backfilled on next startup.
#   4. stage_directive()'s "Duplicate directive suppressed" log embedded the
#      raw dedupe_key (which contains the raw target value) directly into
#      the persisted event_logs table, defeating pseudonymize() for every
#      suppressed duplicate. Now logs the hash instead.
#   5. ThreatKind / ThreatSeverity / ThreatSourceKind / ThreatAssessment
#      were defined locally here as plain enum.Enum (auto()-valued),
#      independently and incompatibly from sentinel_threat_detector.py's
#      own str-Enum versions of the same names. Now imported from a single
#      shared sentinel_threat_types.py that both layers use. See the
#      import block further down in this file for the compatibility
#      analysis of why this was safe here.
# ============================================================


# ============================================================
# SENTINEL-43 CONFIG
# ============================================================

try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path.cwd()


def _env(name: str, default: str) -> str:
    """
    Backwards-compatible env resolver:
    - prefers SENTINEL_*
    - falls back to AEGIS_* if present
    """
    v = os.getenv(name)
    if v is not None:
        return v
    legacy = name.replace("SENTINEL_", "AEGIS_", 1)
    return os.getenv(legacy, default)


def _required_env_secret(
    name: str,
    *,
    min_bytes: int = 32,
    legacy_prefix: str = "AEGIS_",
) -> str:
    """
    Resolve a required secret from the environment and fail closed if absent.

    This intentionally does NOT provide a placeholder fallback. A missing, blank,
    weak, or obvious placeholder secret must stop startup before any internet-
    facing beta deployment can expose developer defaults.
    """
    value = os.getenv(name)

    if value is None and name.startswith("SENTINEL_"):
        legacy_name = name.replace("SENTINEL_", legacy_prefix, 1)
        value = os.getenv(legacy_name)

    value = (value or "").strip()

    if not value:
        raise RuntimeError(
            f"Missing required secret: {name}. "
            'Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )

    blocked_placeholders = {
        "CHANGE_ME",
        "CHANGE_ME_IN_PROD",
        "CHANGEME",
        "dev-placeholder",
        "development",
        "password",
        "secret",
    }
    if value in blocked_placeholders:
        raise RuntimeError(f"{name} is set to a placeholder value and must be replaced.")

    if len(value.encode("utf-8")) < int(min_bytes):
        raise RuntimeError(
            f"{name} must be at least {min_bytes} bytes when encoded as UTF-8 "
            f"(current: {len(value.encode('utf-8'))} bytes)."
        )

    return value


DB_PATH = Path(_env("SENTINEL_DB_PATH", str(BASE_DIR / "sentinel43_state" / "sentinel43.sqlite3")))
SYSTEM_ID = _env("SENTINEL_SYSTEM_ID", "SENTINEL-43-NEXUS-01")

DEFAULT_DEDUPE_TTL_SECONDS = int(_env("SENTINEL_ACTION_DEDUPE_TTL", "60"))
DEFAULT_LOG_RETENTION_DAYS = int(_env("SENTINEL_LOG_RETENTION_DAYS", "90"))
DEFAULT_ACTION_RETENTION_DAYS = int(_env("SENTINEL_ACTION_RETENTION_DAYS", "30"))

# Required salt for privacy-safe log pseudonymization. No dev/prod fallback.
LOG_SALT = _required_env_secret("SENTINEL_LOG_SALT", min_bytes=32)

# ACTIVE executor behavior
EXECUTOR_POLL_MS = int(_env("SENTINEL_EXECUTOR_POLL_MS", "500"))
EXECUTOR_MAX_BATCH = int(_env("SENTINEL_EXECUTOR_MAX_BATCH", "25"))


# ============================================================
# MODE
# ============================================================

class SentinelMode(str, enum.Enum):
    SHADOW = "SHADOW"           # log + stage as shadowed only (no execution)
    HUMAN_GATED = "HUMAN_GATED" # stage, requires approval
    ACTIVE = "ACTIVE"           # stage, will auto-execute after veto window


# ============================================================
# THREAT TYPES (INPUT CONTRACT)
# AI stays elsewhere. Sentinel consumes assessments only.
#
# Fix (scrub, public-beta hardening): ThreatKind / ThreatSourceKind /
# ThreatSeverity / ThreatAssessment used to be defined locally here as
# plain enum.Enum (auto()-valued). sentinel_threat_detector.py
# independently defined its own incompatible versions (str-Enum) with the
# same names. Wiring the detector's output directly into
# Sentinel43ResponseEngine.handle_assessment() would silently break on any
# isinstance/identity check. All four now live in one place,
# sentinel_threat_types.py, and every consumer imports the same
# definitions. Verified safe for this file specifically: the only place
# `indicators` is touched is a pure pass-through copy in plan_response()
# (`indicators=assessment.indicators`), never inspected or branched on, so
# the default changing from None to {} has zero behavioral effect here.
#
# Import path note: adjust if your package layout differs from
# sentinel_43_ai/detection/sentinel_threat_types.py.
# ============================================================

from sentinel_43_ai.detection.sentinel_threat_types import (
    ThreatKind,
    ThreatSeverity,
    ThreatSourceKind,
    ThreatAssessment,
)


# ============================================================
# RESPONSE ACTIONS (OUTPUT CONTRACT)
# ============================================================

class ResponseAction(enum.Enum):
    LOG_ONLY = enum.auto()
    FLAG_SUSPICIOUS = enum.auto()
    STEP_UP_AUTH = enum.auto()
    RATE_LIMIT = enum.auto()
    TEMP_BLOCK_IDENTITY = enum.auto()
    TEMP_BLOCK_IP = enum.auto()
    HARD_BLOCK_IDENTITY = enum.auto()
    HARD_BLOCK_IP = enum.auto()
    QUARANTINE_SESSION = enum.auto()
    REQUIRE_HUMAN_REVIEW = enum.auto()
    OPEN_INCIDENT = enum.auto()


@dataclass(frozen=True)
class ResponsePolicy:
    medium_threshold: float = 40.0
    high_threshold: float = 65.0
    critical_threshold: float = 85.0

    automation_medium_bonus: float = 5.0
    automation_high_bonus: float = 10.0

    temp_block_seconds: int = 900        # 15 minutes
    hard_block_seconds: int = 3600 * 6   # 6 hours

    auto_open_incident_on_critical: bool = True
    auto_require_human_review_on_high: bool = True

    veto_window_seconds: int = 30


@dataclass
class ResponseDirective:
    identity: str
    source_ip: str
    primary_action: ResponseAction
    additional_actions: List[ResponseAction] = field(default_factory=list)
    reason: str = ""
    expires_at: Optional[float] = None

    threat_kind: ThreatKind = ThreatKind.UNKNOWN
    threat_severity: ThreatSeverity = ThreatSeverity.LOW
    source_kind: ThreatSourceKind = ThreatSourceKind.MIXED_OR_UNKNOWN
    score: float = 0.0

    created_at: float = field(default_factory=time.time)


# ============================================================
# PERSISTED ACTION MODEL
# ============================================================

class ActionStatus(str, enum.Enum):
    SHADOWED = "SHADOWED"
    STAGED = "STAGED"
    PENDING = "PENDING"
    VETOED = "VETOED"
    APPROVED = "APPROVED"     # human approved (STAGED -> APPROVED), about to
                               # execute synchronously. Reserved exclusively
                               # for the human-approval path; never set by
                               # the auto-execute executor (see EXECUTING).
    EXECUTING = "EXECUTING"    # executor claimed a PENDING (ACTIVE-mode,
                               # post-veto-window) action for auto-execution.
                               # Distinct from APPROVED — see changelog #1.
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    created_at_ms: int
    execute_at_ms: Optional[int]
    status: ActionStatus

    target_type: str     # "ip" | "identity"
    target_value: str

    primary_action: str
    actions_json: str

    severity: str
    kind: str
    source_kind: str
    score: float

    reason: str
    system_id: str = SYSTEM_ID

    operator_id: Optional[str] = None
    operator_reason: Optional[str] = None


# ============================================================
# HELPERS: privacy-safe logging + bounded keys
# ============================================================

_SAFE_COMPONENT_RE = re.compile(r"[^a-zA-Z0-9.:_\-@]")


def sanitize_key_component(value: str, *, max_len: int = 200) -> str:
    s = "" if value is None else str(value)
    s = s.strip()
    s = _SAFE_COMPONENT_RE.sub("", s)
    if len(s) > max_len:
        s = s[:max_len]
    return s


def pseudonymize(value: str) -> str:
    v = "" if value is None else str(value)
    v = v.strip()
    if not v:
        return "EMPTY"
    h = hashlib.sha256(f"{LOG_SALT}:{v}".encode("utf-8")).hexdigest()
    return h[:16]


def normalize_ip(ip: str) -> str:
    s = "" if ip is None else str(ip).strip()
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return s


def _now_ms() -> int:
    return int(time.time() * 1000)


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


# ============================================================
# INTEGRATION HUB (REAL-WORLD EFFECTS LIVE HERE)
# ============================================================

class IntegrationHub:
    """
    Replace these with actual integrations:
    - firewall / WAF / IAM / SIEM / ticketing / paging
    Keep this as the terminal boundary for effects.
    """

    @staticmethod
    def execute(directive: PendingAction) -> bool:
        # Stub: do NOT do real blocking here unless you wire it intentionally.
        # This function is the only place you're allowed to touch the outside world.
        logger.warning(
            "[INTEGRATION] EXECUTE %s target_type=%s target_hash=%s primary=%s severity=%s reason=%s",
            directive.action_id,
            directive.target_type,
            pseudonymize(directive.target_value),
            directive.primary_action,
            directive.severity,
            directive.reason,
        )
        return True


# ============================================================
# STORAGE LAYER
# ============================================================

class ActionStore(Protocol):
    def ensure_schema(self) -> None: ...
    def log_event(self, level: str, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None: ...
    def dedupe_check_and_set(self, key: str, ttl_seconds: int) -> bool: ...
    def insert_pending_action(self, pa: PendingAction) -> None: ...
    def update_action_status(self, action_id: str, new_status: ActionStatus, *, operator_id: Optional[str], operator_reason: Optional[str], expected_status: ActionStatus) -> bool: ...
    def get_action_status(self, action_id: str) -> Optional[str]: ...
    def fetch_due_pending(self, *, now_ms: int, limit: int) -> List[PendingAction]: ...
    def mark_pending_executing(self, action_id: str) -> bool: ...
    def finalize_execution(self, action_id: str, *, ok: bool, operator_reason: str = "") -> None: ...
    def expire_overdue(self, *, now_ms: int) -> int: ...
    def cleanup_old_logs(self, retention_days: int) -> int: ...
    def cleanup_old_actions(self, retention_days: int) -> int: ...


def _db_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


class SqliteActionStore:
    """
    Critical fixes:
    - event_logs uses ts_ms INTEGER (no ISO comparison bugs)
    - update_action_status uses cursor.rowcount (not conn.total_changes)
    - all write paths use BEGIN IMMEDIATE to avoid lost-update races
    """

    _schema_lock = threading.RLock()

    def ensure_schema(self) -> None:
        with self._schema_lock, _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS event_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts_ms INTEGER NOT NULL,
                        level TEXT NOT NULL,
                        module TEXT NOT NULL,
                        message TEXT NOT NULL,
                        context_json TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_event_logs_ts ON event_logs(ts_ms)")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pending_actions (
                        action_id TEXT PRIMARY KEY,
                        created_at_ms INTEGER NOT NULL,
                        execute_at_ms INTEGER,
                        status TEXT NOT NULL,
                        target_type TEXT NOT NULL,
                        target_value TEXT NOT NULL,
                        target_hash TEXT,
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
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_status_exec ON pending_actions(status, execute_at_ms)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_created ON pending_actions(created_at_ms)")

                # Fix (scrub #3): migrate databases created before target_hash
                # existed. New installs already have it from CREATE TABLE
                # above; this handles in-place upgrades of existing DBs.
                existing_cols = {
                    row[1] for row in conn.execute("PRAGMA table_info(pending_actions)").fetchall()
                }
                if "target_hash" not in existing_cols:
                    conn.execute("ALTER TABLE pending_actions ADD COLUMN target_hash TEXT NULL")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS action_dedupe (
                        dedupe_key TEXT PRIMARY KEY,
                        expires_at_ms INTEGER NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_dedupe_exp ON action_dedupe(expires_at_ms)")

                # Optional: tamper-evident audit chain (lightweight)
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
                        ts_ms INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        hash TEXT NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts_ms)")

                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        # Fix (scrub #3): backfill target_hash for rows written before this
        # column existed, so every row has one going forward. Best-effort —
        # a failure here must not block startup.
        try:
            with _db_conn() as backfill_conn:
                rows = backfill_conn.execute(
                    "SELECT action_id, target_value FROM pending_actions WHERE target_hash IS NULL"
                ).fetchall()
                for action_id, target_value in rows:
                    backfill_conn.execute(
                        "UPDATE pending_actions SET target_hash=? WHERE action_id=?",
                        (pseudonymize(target_value), action_id),
                    )
        except Exception as exc:
            logger.warning("target_hash backfill skipped: %s", exc)

        # best-effort cleanup (never block boot)
        try:
            self.cleanup_old_logs(DEFAULT_LOG_RETENTION_DAYS)
            self.cleanup_old_actions(DEFAULT_ACTION_RETENTION_DAYS)
        except Exception:
            pass

    # --------------------
    # Audit chain (optional)
    # --------------------
    def _append_audit(self, *, event_type: str, payload: Dict[str, Any]) -> None:
        ts_ms = _now_ms()
        payload_json = _json_dumps(payload)
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                prev_hash = conn.execute("SELECT prev_hash FROM audit_chain WHERE id=1").fetchone()[0]
                raw = (prev_hash + "|" + str(ts_ms) + "|" + event_type + "|" + payload_json).encode("utf-8")
                h = hashlib.sha256(raw).hexdigest()
                conn.execute(
                    "INSERT INTO audit_events (ts_ms, event_type, payload_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
                    (ts_ms, event_type, payload_json, prev_hash, h),
                )
                conn.execute("UPDATE audit_chain SET prev_hash=? WHERE id=1", (h,))
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    # --------------------
    # Event logs
    # --------------------
    def log_event(self, level: str, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        ts_ms = _now_ms()
        ctx = _json_dumps(context) if context else None
        with _db_conn() as conn:
            conn.execute(
                "INSERT INTO event_logs (ts_ms, level, module, message, context_json) VALUES (?, ?, ?, ?, ?)",
                (ts_ms, level, module, message, ctx),
            )
        # also chain it (best-effort)
        try:
            self._append_audit(event_type=f"log.{level}", payload={"module": module, "message": message, "context": context or {}})
        except Exception:
            pass

    # --------------------
    # Dedupe
    # --------------------
    def dedupe_check_and_set(self, key: str, ttl_seconds: int) -> bool:
        now_ms = _now_ms()
        exp_ms = now_ms + int(ttl_seconds * 1000)

        key = ("" if key is None else str(key)).strip()
        if len(key) > 512:
            key = key[:512]

        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute("DELETE FROM action_dedupe WHERE expires_at_ms <= ?", (now_ms,))
                conn.execute(
                    "INSERT INTO action_dedupe (dedupe_key, expires_at_ms) VALUES (?, ?)",
                    (key, exp_ms),
                )
                conn.execute("COMMIT;")
                return True
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK;")
                return False
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    # --------------------
    # Actions
    # --------------------
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
                        reason, system_id,
                        operator_id, operator_reason
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        pa.action_id,
                        pa.created_at_ms,
                        pa.execute_at_ms,
                        pa.status.value,
                        pa.target_type,
                        pa.target_value,
                        pseudonymize(pa.target_value),
                        pa.primary_action,
                        pa.actions_json,
                        pa.severity,
                        pa.kind,
                        pa.source_kind,
                        float(pa.score),
                        pa.reason,
                        pa.system_id,
                        pa.operator_id,
                        pa.operator_reason,
                    ),
                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_action_status(self, action_id: str) -> Optional[str]:
        with _db_conn() as conn:
            row = conn.execute("SELECT status FROM pending_actions WHERE action_id=?", (action_id,)).fetchone()
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
        op = operator_id[:80] if operator_id else None
        rsn = operator_reason[:300] if operator_reason else None

        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = conn.execute(
                    """
                    UPDATE pending_actions
                       SET status=?, operator_id=?, operator_reason=?
                     WHERE action_id=?
                       AND status=?
                    """,
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
                """
                SELECT * FROM pending_actions
                 WHERE status = ?
                   AND execute_at_ms IS NOT NULL
                   AND execute_at_ms <= ?
                 ORDER BY execute_at_ms ASC
                 LIMIT ?
                """,
                (ActionStatus.PENDING.value, int(now_ms), int(limit)),
            ).fetchall()

        out: List[PendingAction] = []
        for r in rows:
            out.append(
                PendingAction(
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
                    operator_id=str(r["operator_id"]) if r["operator_id"] is not None else None,
                    operator_reason=str(r["operator_reason"]) if r["operator_reason"] is not None else None,
                )
            )
        return out

    def mark_pending_executing(self, action_id: str) -> bool:
        """
        Claim the action atomically so only one executor runs it.

        Fix (scrub #1): transitions PENDING -> EXECUTING, not APPROVED.
        APPROVED is reserved for the human-approval lifecycle (STAGED ->
        APPROVED via approve_action()). Reusing APPROVED for both "a human
        approved this" and "the executor claimed this for auto-run" made
        the state machine ambiguous — a crashed claim could be misread as
        a human decision, or vice versa.
        """
        return self.update_action_status(
            action_id,
            ActionStatus.EXECUTING,
            operator_id="executor",
            operator_reason="claimed_for_execution",
            expected_status=ActionStatus.PENDING,
        )

    def finalize_execution(self, action_id: str, *, ok: bool, operator_reason: str = "") -> None:
        new_status = ActionStatus.EXECUTED if ok else ActionStatus.FAILED
        # Fix (scrub #1): expected_status is EXECUTING (executor claimed it
        # via mark_pending_executing()), not APPROVED. This only affects
        # the ACTIVE/auto-execute path; _execute_approved_now() below still
        # correctly expects APPROVED for the human-approval path.
        self.update_action_status(
            action_id,
            new_status,
            operator_id="executor",
            operator_reason=(operator_reason or "")[:300],
            expected_status=ActionStatus.EXECUTING,
        )

    def expire_overdue(self, *, now_ms: int) -> int:
        """
        Safety valve: expire ancient PENDING actions that never got executed.
        (You can tune this if you want longer windows.)
        """
        stale_before = int(now_ms) - (24 * 3600 * 1000)  # 24h
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = conn.execute(
                    """
                    UPDATE pending_actions
                       SET status=?
                     WHERE status=?
                       AND created_at_ms < ?
                    """,
                    (ActionStatus.EXPIRED.value, ActionStatus.PENDING.value, stale_before),
                )
                conn.execute("COMMIT;")
                return int(cur.rowcount or 0)
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def cleanup_old_logs(self, retention_days: int) -> int:
        cutoff_ms = _now_ms() - int(retention_days) * 86400 * 1000
        with _db_conn() as conn:
            cur = conn.execute("DELETE FROM event_logs WHERE ts_ms < ?", (cutoff_ms,))
            return int(cur.rowcount or 0)

    def cleanup_old_actions(self, retention_days: int) -> int:
        # Fix (scrub #2): APPROVED removed from the deletion list. APPROVED
        # is a transient mid-flight state (human approved, about to execute
        # synchronously inside the same call). Deleting it during routine
        # retention cleanup could discard an action that crashed between
        # approval and execution with zero audit trail of what happened.
        # Only genuinely terminal states are eligible for cleanup.
        cutoff_ms = _now_ms() - int(retention_days) * 86400 * 1000
        with _db_conn() as conn:
            cur = conn.execute(
                """
                DELETE FROM pending_actions
                 WHERE created_at_ms < ?
                   AND status IN (?, ?, ?, ?)
                """,
                (
                    cutoff_ms,
                    ActionStatus.VETOED.value,
                    ActionStatus.EXECUTED.value,
                    ActionStatus.FAILED.value,
                    ActionStatus.EXPIRED.value,
                ),
            )
            return int(cur.rowcount or 0)


# ============================================================
# RESPONSE ENGINE (NO DETECTOR INSIDE)
# ============================================================

class Sentinel43ResponseEngine:
    """
    Single-file Nexus:
      - consumes ThreatAssessment
      - produces ResponseDirective
      - stages actions in SQLite
      - ACTIVE mode auto-executes due actions via an executor thread
      - approvals/veto are authenticated via provided authenticator callback
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
        self.store = store or SqliteActionStore()
        self.policy = policy or ResponsePolicy()
        self.dedupe_ttl_seconds = int(dedupe_ttl_seconds)

        # Fail-closed: if you want approvals, you must provide auth.
        self._operator_authenticator = operator_authenticator or (lambda _op: False)

        self._integration = integration or IntegrationHub

        self._stop = threading.Event()
        self._executor_thread = threading.Thread(target=self._executor_loop, name="sentinel43-executor", daemon=True)

        self.store.ensure_schema()
        self.store.log_event("INFO", "BOOT", "Sentinel-43 Nexus initialized.", {"system_id": SYSTEM_ID})

        # Start executor
        self._executor_thread.start()

    # ------------------------------
    # Shutdown
    # ------------------------------
    def shutdown(self) -> None:
        self.store.log_event("INFO", "SYSTEM", "Shutdown requested.", {"system_id": SYSTEM_ID})
        self._stop.set()
        self._executor_thread.join(timeout=5)
        self.store.log_event("INFO", "SYSTEM", "Shutdown complete.", {"system_id": SYSTEM_ID})

    # ------------------------------
    # PUBLIC ENTRY
    # ------------------------------
    def handle_assessment(self, mode: SentinelMode, assessment: ThreatAssessment) -> Optional[PendingAction]:
        directive = self.plan_response(assessment)

        # PII-safe logs
        self.store.log_event(
            "INFO",
            "RESPONSE",
            "Response plan generated",
            {
                "identity_hash": pseudonymize(directive.identity),
                "ip_hash": pseudonymize(directive.source_ip),
                "primary_action": directive.primary_action.name,
                "additional_actions": [a.name for a in directive.additional_actions],
                "score": directive.score,
                "severity": directive.threat_severity.name,
                "kind": directive.threat_kind.name,
                "source_kind": directive.source_kind.name,
                "expires_at": directive.expires_at,
                "mode": mode.value,
            },
        )

        return self.stage_directive(mode, directive)

    # ------------------------------
    # OPERATOR CONTROLS
    # ------------------------------
    def approve_action(self, action_id: str, operator_id: str, reason: str = "") -> bool:
        op = (operator_id or "").strip()[:80]
        rsn = (reason or "").strip()[:300]

        if not op or not self._operator_authenticator(op):
            self.store.log_event("ERROR", "OVERSIGHT", "Unauthorized approval attempt",
                                 {"action_id": action_id, "operator_id": op})
            return False

        ok = self.store.update_action_status(
            action_id,
            ActionStatus.APPROVED,
            operator_id=op,
            operator_reason=rsn,
            expected_status=ActionStatus.STAGED,
        )

        self.store.log_event(
            "WARN" if ok else "ERROR",
            "OVERSIGHT",
            "Action approved" if ok else "Approval failed",
            {"action_id": action_id, "operator_id": op},
        )

        # In HUMAN_GATED, approval means execute NOW.
        if ok:
            self._execute_approved_now(action_id)

        return ok

    def veto_action(self, action_id: str, operator_id: str, reason: str) -> bool:
        op = (operator_id or "").strip()[:80]
        rsn = (reason or "").strip()[:300]

        if not op or not self._operator_authenticator(op):
            self.store.log_event("ERROR", "OVERSIGHT", "Unauthorized veto attempt",
                                 {"action_id": action_id, "operator_id": op})
            return False

        ok = self.store.update_action_status(
            action_id,
            ActionStatus.VETOED,
            operator_id=op,
            operator_reason=rsn,
            expected_status=ActionStatus.PENDING,
        )

        # also allow veto of STAGED (human gated)
        if not ok:
            ok = self.store.update_action_status(
                action_id,
                ActionStatus.VETOED,
                operator_id=op,
                operator_reason=rsn,
                expected_status=ActionStatus.STAGED,
            )

        self.store.log_event(
            "WARN" if ok else "ERROR",
            "OVERSIGHT",
            "Action vetoed" if ok else "Veto failed",
            {"action_id": action_id, "operator_id": op},
        )
        return ok

    # ------------------------------
    # PLANNING
    # ------------------------------
    def plan_response(self, assessment: ThreatAssessment) -> ResponseDirective:
        assessment_ip = normalize_ip(assessment.source_ip)

        a = ThreatAssessment(
            identity=assessment.identity,
            source_ip=assessment_ip,
            threat_kind=assessment.threat_kind,
            severity=assessment.severity,
            source_kind=assessment.source_kind,
            score=float(assessment.score),
            indicators=assessment.indicators,
            supporting_tags=list(assessment.supporting_tags),
            window_size=int(assessment.window_size),
            generated_at=float(assessment.generated_at),
        )

        effective_score = self._apply_automation_risk_adjustment(a)

        if a.severity == ThreatSeverity.LOW and effective_score < self.policy.medium_threshold:
            return self._build_low(a, effective_score)

        if a.severity in (ThreatSeverity.MEDIUM, ThreatSeverity.HIGH):
            return self._build_mid_high(a, effective_score)

        if a.severity == ThreatSeverity.CRITICAL:
            return self._build_critical(a, effective_score)

        return self._build_mid_high(a, effective_score)

    def _apply_automation_risk_adjustment(self, assessment: ThreatAssessment) -> float:
        score = float(assessment.score)
        if assessment.source_kind == ThreatSourceKind.AI_AUTOMATION_LIKELY:
            if assessment.severity in (ThreatSeverity.LOW, ThreatSeverity.MEDIUM):
                score += self.policy.automation_medium_bonus
            else:
                score += self.policy.automation_high_bonus
        return min(100.0, score)

    def _build_low(self, a: ThreatAssessment, score: float) -> ResponseDirective:
        actions = [ResponseAction.LOG_ONLY]
        if a.threat_kind in (ThreatKind.MALWARE_DELIVERY, ThreatKind.SPYWARE_ACTIVITY):
            actions.append(ResponseAction.FLAG_SUSPICIOUS)

        return ResponseDirective(
            identity=a.identity,
            source_ip=a.source_ip,
            primary_action=actions[0],
            additional_actions=actions[1:],
            reason=f"Low severity (score={score:.1f})",
            threat_kind=a.threat_kind,
            threat_severity=a.severity,
            source_kind=a.source_kind,
            score=score,
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

        if a.source_kind == ThreatSourceKind.AI_AUTOMATION_LIKELY and temp_block:
            actions.append(ResponseAction.TEMP_BLOCK_IP)

        if self.policy.auto_require_human_review_on_high and a.severity == ThreatSeverity.HIGH:
            actions.append(ResponseAction.REQUIRE_HUMAN_REVIEW)

        primary = actions[0] if actions else ResponseAction.LOG_ONLY

        return ResponseDirective(
            identity=a.identity,
            source_ip=a.source_ip,
            primary_action=primary,
            additional_actions=actions[1:],
            reason=f"Medium/High severity (score={score:.1f})",
            expires_at=expires_at,
            threat_kind=a.threat_kind,
            threat_severity=a.severity,
            source_kind=a.source_kind,
            score=score,
        )

    def _build_critical(self, a: ThreatAssessment, score: float) -> ResponseDirective:
        actions: List[ResponseAction] = [
            ResponseAction.QUARANTINE_SESSION,
            ResponseAction.HARD_BLOCK_IDENTITY,
            ResponseAction.HARD_BLOCK_IP,
        ]

        if self.policy.auto_open_incident_on_critical:
            actions.append(ResponseAction.OPEN_INCIDENT)

        if self.policy.auto_require_human_review_on_high:
            actions.append(ResponseAction.REQUIRE_HUMAN_REVIEW)

        expires_at = time.time() + self.policy.hard_block_seconds

        return ResponseDirective(
            identity=a.identity,
            source_ip=a.source_ip,
            primary_action=actions[0],
            additional_actions=actions[1:],
            reason=f"CRITICAL threat (score={score:.1f})",
            expires_at=expires_at,
            threat_kind=a.threat_kind,
            threat_severity=a.severity,
            source_kind=a.source_kind,
            score=score,
        )

    # ------------------------------
    # STAGING / PERSISTENCE
    # ------------------------------
    def stage_directive(self, mode: SentinelMode, d: ResponseDirective) -> Optional[PendingAction]:
        if d.primary_action == ResponseAction.LOG_ONLY and not d.additional_actions:
            return None

        target_type, raw_target_value = self._pick_primary_target(d)

        target_value = sanitize_key_component(raw_target_value, max_len=200)
        if not target_value:
            self.store.log_event(
                "ERROR",
                "RESPONSE",
                "Invalid target_value after sanitization",
                {"target_type": target_type, "target_hash": pseudonymize(raw_target_value)},
            )
            return None

        dedupe_key = (
            f"{sanitize_key_component(target_type, max_len=16)}:"
            f"{target_value}:"
            f"{sanitize_key_component(d.primary_action.name, max_len=40)}:"
            f"{sanitize_key_component(d.threat_kind.name, max_len=40)}"
        )

        if not self.store.dedupe_check_and_set(dedupe_key, self.dedupe_ttl_seconds):
            # Fix (scrub #4): dedupe_key embeds the raw target value
            # (f"{target_type}:{target_value}:..."). Logging it verbatim
            # into the persisted event_logs table defeated pseudonymize()
            # for every suppressed duplicate. Log the hash instead.
            self.store.log_event(
                "INFO",
                "RESPONSE",
                "Duplicate directive suppressed (dedupe window)",
                {"dedupe_hash": pseudonymize(dedupe_key), "ttl_seconds": self.dedupe_ttl_seconds},
            )
            return None

        action_id = self._new_action_id()
        now_ms = _now_ms()

        if mode == SentinelMode.SHADOW:
            status = ActionStatus.SHADOWED
            execute_at_ms = None
        elif mode == SentinelMode.HUMAN_GATED:
            status = ActionStatus.STAGED
            execute_at_ms = None
        else:
            status = ActionStatus.PENDING
            execute_at_ms = now_ms + int(self.policy.veto_window_seconds * 1000)

        actions_json = _json_dumps(
            {
                "primary": d.primary_action.name,
                "additional": [a.name for a in d.additional_actions],
                "expires_at": d.expires_at,
            }
        )

        pa = PendingAction(
            action_id=action_id,
            created_at_ms=now_ms,
            execute_at_ms=execute_at_ms,
            status=status,
            target_type=target_type,
            target_value=raw_target_value,  # raw is kept in DB for downstream execution
            primary_action=d.primary_action.name,
            actions_json=actions_json,
            severity=d.threat_severity.name,
            kind=d.threat_kind.name,
            source_kind=d.source_kind.name,
            score=float(d.score),
            reason=d.reason,
            system_id=SYSTEM_ID,
        )

        self.store.insert_pending_action(pa)

        self.store.log_event(
            "INFO",
            "OVERSIGHT",
            "Action staged",
            {
                "action_id": pa.action_id,
                "status": pa.status.value,
                "mode": mode.value,
                "target_type": pa.target_type,
                "target_hash": pseudonymize(pa.target_value),
                "primary_action": pa.primary_action,
                "execute_at_ms": pa.execute_at_ms,
            },
        )

        return pa

    def _pick_primary_target(self, d: ResponseDirective) -> Tuple[str, str]:
        ip_actions = {
            ResponseAction.TEMP_BLOCK_IP,
            ResponseAction.HARD_BLOCK_IP,
        }
        if d.primary_action in ip_actions:
            return ("ip", d.source_ip)
        return ("identity", d.identity)

    def _new_action_id(self) -> str:
        return f"ACT-{uuid.uuid4().hex}".upper()

    # ------------------------------
    # ACTIVE EXECUTOR (the missing part)
    # ------------------------------
    def _executor_loop(self) -> None:
        self.store.log_event("INFO", "EXECUTOR", "Executor thread online.", {"poll_ms": EXECUTOR_POLL_MS})
        while not self._stop.is_set():
            now_ms = _now_ms()

            # best-effort expirations + hygiene
            try:
                expired = self.store.expire_overdue(now_ms=now_ms)
                if expired:
                    self.store.log_event("WARN", "EXECUTOR", "Expired stale pending actions", {"count": expired})
            except Exception as exc:
                self.store.log_event("ERROR", "EXECUTOR", "Expire pass failed", {"error": str(exc)})

            try:
                due = self.store.fetch_due_pending(now_ms=now_ms, limit=EXECUTOR_MAX_BATCH)
                for pa in due:
                    # Claim it atomically
                    if not self.store.mark_pending_executing(pa.action_id):
                        continue  # someone else claimed/vetoed it

                    # Execute
                    ok = False
                    err = ""
                    try:
                        ok = bool(self._integration.execute(pa))
                    except Exception as exc:
                        err = str(exc)

                    # Finalize
                    try:
                        self.store.finalize_execution(pa.action_id, ok=ok, operator_reason=(err or "ok"))
                        self.store.log_event(
                            "WARN" if ok else "ERROR",
                            "EXECUTOR",
                            "Executed action" if ok else "Execution failed",
                            {"action_id": pa.action_id, "ok": ok, "error": err[:300]},
                        )
                    except Exception as exc:
                        self.store.log_event("ERROR", "EXECUTOR", "Finalize failed", {"action_id": pa.action_id, "error": str(exc)})
            except Exception as exc:
                self.store.log_event("ERROR", "EXECUTOR", "Executor loop error", {"error": str(exc)})

            self._stop.wait(timeout=max(0.05, EXECUTOR_POLL_MS / 1000.0))

        self.store.log_event("INFO", "EXECUTOR", "Executor thread stopping.", {})

    def _execute_approved_now(self, action_id: str) -> None:
        """
        HUMAN_GATED approval executes immediately.
        We reuse the claim/execution pipeline by:
          APPROVED (operator) -> EXECUTED/FAILED here directly.
        """
        # Minimal: just mark as EXECUTED if integration succeeds.
        # If you want stronger semantics, add a fetch-by-id + execute.
        try:
            # Can't rely on in-memory; load it
            with _db_conn() as conn:
                row = conn.execute("SELECT * FROM pending_actions WHERE action_id=?", (action_id,)).fetchone()
                if not row:
                    return
                pa = PendingAction(
                    action_id=str(row["action_id"]),
                    created_at_ms=int(row["created_at_ms"]),
                    execute_at_ms=int(row["execute_at_ms"]) if row["execute_at_ms"] is not None else None,
                    status=ActionStatus(str(row["status"])),
                    target_type=str(row["target_type"]),
                    target_value=str(row["target_value"]),
                    primary_action=str(row["primary_action"]),
                    actions_json=str(row["actions_json"]),
                    severity=str(row["severity"]),
                    kind=str(row["kind"]),
                    source_kind=str(row["source_kind"]),
                    score=float(row["score"]),
                    reason=str(row["reason"]),
                    system_id=str(row["system_id"]),
                    operator_id=str(row["operator_id"]) if row["operator_id"] is not None else None,
                    operator_reason=str(row["operator_reason"]) if row["operator_reason"] is not None else None,
                )

            ok = False
            err = ""
            try:
                ok = bool(self._integration.execute(pa))
            except Exception as exc:
                err = str(exc)

            # IMPORTANT: expected_status is APPROVED (operator set it).
            # This stays APPROVED, not EXECUTING — see changelog #1.
            self.store.update_action_status(
                action_id,
                ActionStatus.EXECUTED if ok else ActionStatus.FAILED,
                operator_id="executor",
                operator_reason=(err or "ok"),
                expected_status=ActionStatus.APPROVED,
            )
            self.store.log_event(
                "WARN" if ok else "ERROR",
                "EXECUTOR",
                "Executed approved action" if ok else "Approved action failed",
                {"action_id": action_id, "ok": ok, "error": err[:300]},
            )
        except Exception as exc:
            self.store.log_event("ERROR", "EXECUTOR", "Approved-now execution path failed", {"action_id": action_id, "error": str(exc)})


# ============================================================
# SIMPLE SELF-TEST
# ============================================================

if __name__ == "__main__":
    # Example authenticator: allow only IDs listed in env
    allowed = {s.strip() for s in _env("SENTINEL_ALLOWED_OPERATORS", "admin,ops").split(",") if s.strip()}

    engine = Sentinel43ResponseEngine(
        operator_authenticator=lambda op: op in allowed
    )

    a = ThreatAssessment(
        identity="ai-bot-777",
        source_ip="192.0.2.10",
        threat_kind=ThreatKind.CREDENTIAL_ATTACK,
        severity=ThreatSeverity.HIGH,
        source_kind=ThreatSourceKind.AI_AUTOMATION_LIKELY,
        score=72.5,
        supporting_tags=["failed_login"],
        window_size=12,
    )

    pa = engine.handle_assessment(SentinelMode.ACTIVE, a)
    print("Staged (active):", pa)

    # Demonstrate approval flow (HUMAN_GATED)
    pa2 = engine.handle_assessment(SentinelMode.HUMAN_GATED, a)
    if pa2:
        print("Staged (gated):", pa2.action_id)
        ok = engine.approve_action(pa2.action_id, operator_id="admin", reason="reviewed")
        print("Approved:", ok)

    # give executor a moment to run due actions
    time.sleep(2)
    engine.shutdown()
