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

# ============================================================
# CONFIG
# ============================================================

try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path.cwd()


def _env(name: str, default: str) -> str:
    v = os.getenv(name)
    if v is not None:
        return v
    legacy = name.replace("SENTINEL_", "AEGIS_", 1)
    return os.getenv(legacy, default)


SYSTEM_ID = _env("SENTINEL_SYSTEM_ID", "SENTINEL-43-NEXUS-01")
DB_PATH = Path(_env("SENTINEL_DB_PATH", str(BASE_DIR / "sentinel43_state" / "sentinel43.sqlite3")))


def _load_log_salt() -> str:
    """
    Load the log pseudonymization salt from the environment.

    Scrub fix: removes hardcoded "CHANGE_ME_IN_PROD" default. A known salt
    defeats pseudonymization — anyone with the salt can precompute SHA-256
    hashes of common IP addresses and identities to de-anonymize log output.

    Production: SENTINEL_LOG_SALT must be set; raises RuntimeError on startup
    if absent so the server refuses to start rather than silently logging
    reversible pseudonyms.

    Dev environments: warns and generates an ephemeral random salt. Hashes
    will not be consistent across restarts but no predictable value is ever
    used as a fallback.

    Generate: python -c "import secrets; print(secrets.token_hex(32))"
    """
    salt = os.getenv("SENTINEL_LOG_SALT", "").strip()
    if salt:
        return salt

    env = (
        os.getenv("SENTINEL_ENV", "") or os.getenv("S43_ENV", "")
    ).lower().strip()
    _dev_envs: frozenset[str] = frozenset({
        "development", "dev", "test", "testing", "local"
    })

    if env in _dev_envs:
        warnings.warn(
            "SENTINEL_LOG_SALT is not set. Using an ephemeral random salt — "
            "pseudonymized log hashes will not be consistent across restarts. "
            "Set SENTINEL_LOG_SALT in .env for persistent pseudonymization.",
            RuntimeWarning,
            stacklevel=2,
        )
        return secrets.token_hex(16)

    raise RuntimeError(
        "SENTINEL_LOG_SALT is required in production. "
        'Generate with: python -c "import secrets; print(secrets.token_hex(32))"'
    )


LOG_SALT = _load_log_salt()

DEFAULT_DEDUPE_TTL_SECONDS = int(_env("SENTINEL_ACTION_DEDUPE_TTL", "60"))
DEFAULT_LOG_RETENTION_DAYS = int(_env("SENTINEL_LOG_RETENTION_DAYS", "90"))
DEFAULT_ACTION_RETENTION_DAYS = int(_env("SENTINEL_ACTION_RETENTION_DAYS", "30"))

# executor
EXECUTOR_POLL_MS = int(_env("SENTINEL_EXECUTOR_POLL_MS", "500"))
EXECUTOR_MAX_BATCH = int(_env("SENTINEL_EXECUTOR_MAX_BATCH", "25"))

# oversight behavior
OVERSIGHT_DEDUPE_TTL_SECONDS = int(_env("SENTINEL_OVERSIGHT_DEDUPE_TTL", "120"))
OVERSIGHT_MAX_PENDING = int(_env("SENTINEL_OVERSIGHT_MAX_PENDING", "250"))
OVERSIGHT_BUDGET_WINDOW_SECONDS = int(_env("SENTINEL_OVERSIGHT_BUDGET_WINDOW_SECONDS", "300"))
OVERSIGHT_BUDGET_MAX_PER_TARGET = int(_env("SENTINEL_OVERSIGHT_BUDGET_MAX_PER_TARGET", "5"))
OVERSIGHT_BUDGET_MAX_PER_SOURCE = int(_env("SENTINEL_OVERSIGHT_BUDGET_MAX_PER_SOURCE", "25"))
OVERSIGHT_REQUIRE_TWO_SIGNALS_FOR_HIGH = (_env("SENTINEL_OVERSIGHT_TWO_SIGNAL_HIGH", "true").lower() == "true")
OVERSIGHT_CORROBORATION_TTL_SECONDS = int(_env("SENTINEL_OVERSIGHT_CORROBORATION_TTL_SECONDS", "600"))

# ============================================================
# MODES
# ============================================================

class SentinelMode(str, enum.Enum):
    SHADOW = "SHADOW"           # log + stage as shadowed only (no execution)
    HUMAN_GATED = "HUMAN_GATED" # stage, requires approval
    ACTIVE = "ACTIVE"           # stage, will auto-execute after veto window


class OpMode(enum.Enum):
    SHADOW = "SHADOW_ADVISORY"
    HUMAN_GATED = "HUMAN_GATED"
    ACTIVE = "AUTONOMOUS_VETO"


def _map_mode(m: OpMode) -> SentinelMode:
    if m is OpMode.SHADOW:
        return SentinelMode.SHADOW
    if m is OpMode.HUMAN_GATED:
        return SentinelMode.HUMAN_GATED
    return SentinelMode.ACTIVE


# ============================================================
# THREAT TYPES (INPUT CONTRACT)
# ============================================================

class ThreatKind(enum.Enum):
    GENERIC_INTRUSION = enum.auto()
    MALWARE_DELIVERY = enum.auto()
    SPYWARE_ACTIVITY = enum.auto()
    DATA_EXFILTRATION = enum.auto()
    CREDENTIAL_ATTACK = enum.auto()
    UNKNOWN = enum.auto()


class ThreatSourceKind(enum.Enum):
    HUMAN_LIKELY = enum.auto()
    AI_AUTOMATION_LIKELY = enum.auto()
    MIXED_OR_UNKNOWN = enum.auto()


class ThreatSeverity(enum.Enum):
    LOW = enum.auto()
    MEDIUM = enum.auto()
    HIGH = enum.auto()
    CRITICAL = enum.auto()


@dataclass(frozen=True)
class ThreatAssessment:
    identity: str
    source_ip: str
    threat_kind: ThreatKind
    severity: ThreatSeverity
    source_kind: ThreatSourceKind
    score: float
    indicators: Optional[object] = None
    supporting_tags: List[str] = field(default_factory=list)
    window_size: int = 0
    generated_at: float = field(default_factory=time.time)


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
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    created_at_ms: int
    execute_at_ms: Optional[int]
    status: ActionStatus

    target_type: str
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
# HELPERS
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
# INTEGRATION HUB (Execution Boundary)
# ============================================================

class IntegrationHub:
    """
    All real-world effects terminate here.
    Wire this to your firewall/WAF/IAM/SIEM/ticketing stack.
    """

    @staticmethod
    def execute(action: PendingAction) -> bool:
        logger.warning(
            "[INTEGRATION] EXECUTE action_id=%s target_type=%s target_hash=%s primary=%s severity=%s kind=%s reason=%s",
            action.action_id,
            action.target_type,
            pseudonymize(action.target_value),
            action.primary_action,
            action.severity,
            action.kind,
            action.reason,
        )
        return True


# ============================================================
# STORAGE LAYER (SQLite, durable)
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

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS action_dedupe (
                        dedupe_key TEXT PRIMARY KEY,
                        expires_at_ms INTEGER NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_dedupe_exp ON action_dedupe(expires_at_ms)")

                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        try:
            self.cleanup_old_logs(DEFAULT_LOG_RETENTION_DAYS)
            self.cleanup_old_actions(DEFAULT_ACTION_RETENTION_DAYS)
        except Exception:
            pass

    def log_event(self, level: str, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        ts_ms = _now_ms()
        ctx = _json_dumps(context) if context else None
        with _db_conn() as conn:
            conn.execute(
                "INSERT INTO event_logs (ts_ms, level, module, message, context_json) VALUES (?, ?, ?, ?, ?)",
                (ts_ms, level, module, message, ctx),
            )

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

    def insert_pending_action(self, pa: PendingAction) -> None:
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
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
                        pa.action_id,
                        pa.created_at_ms,
                        pa.execute_at_ms,
                        pa.status.value,
                        pa.target_type,
                        pa.target_value,
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
        return self.update_action_status(
            action_id,
            ActionStatus.APPROVED,
            operator_id="executor",
            operator_reason="claimed_for_execution",
            expected_status=ActionStatus.PENDING,
        )

    def finalize_execution(self, action_id: str, *, ok: bool, operator_reason: str = "") -> None:
        new_status = ActionStatus.EXECUTED if ok else ActionStatus.FAILED
        self.update_action_status(
            action_id,
            new_status,
            operator_id="executor",
            operator_reason=(operator_reason or "")[:300],
            expected_status=ActionStatus.APPROVED,
        )

    def expire_overdue(self, *, now_ms: int) -> int:
        stale_before = int(now_ms) - (24 * 3600 * 1000)
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
        cutoff_ms = _now_ms() - int(retention_days) * 86400 * 1000
        with _db_conn() as conn:
            cur = conn.execute(
                """
                DELETE FROM pending_actions
                 WHERE created_at_ms < ?
                   AND status IN (?, ?, ?, ?, ?)
                """,
                (
                    cutoff_ms,
                    ActionStatus.VETOED.value,
                    ActionStatus.EXECUTED.value,
                    ActionStatus.APPROVED.value,
                    ActionStatus.FAILED.value,
                    ActionStatus.EXPIRED.value,
                ),
            )
            return int(cur.rowcount or 0)


# ============================================================
# RESPONSE ENGINE
# ============================================================

class Sentinel43ResponseEngine:
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

        self._operator_authenticator = operator_authenticator or (lambda _op: False)
        self._integration = integration or IntegrationHub

        self._stop = threading.Event()
        self._executor_thread = threading.Thread(target=self._executor_loop, name="sentinel43-executor", daemon=True)

        self.store.ensure_schema()
        self.store.log_event("INFO", "BOOT", "Sentinel-43 initialized.", {"system_id": SYSTEM_ID})

        self._executor_thread.start()

    def shutdown(self) -> None:
        self.store.log_event("INFO", "SYSTEM", "Shutdown requested.", {"system_id": SYSTEM_ID})
        self._stop.set()
        self._executor_thread.join(timeout=5)
        self.store.log_event("INFO", "SYSTEM", "Shutdown complete.", {"system_id": SYSTEM_ID})

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

    def handle_assessment(self, mode: SentinelMode, assessment: ThreatAssessment) -> Optional[PendingAction]:
        directive = self.plan_response(assessment)

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

    def stage_directive(self, mode: SentinelMode, d: ResponseDirective) -> Optional[PendingAction]:
        if d.primary_action == ResponseAction.LOG_ONLY and not d.additional_actions:
            return None

        target_type, raw_target_value = self._pick_primary_target(d)

        target_value_for_key = sanitize_key_component(raw_target_value, max_len=200)
        if not target_value_for_key:
            self.store.log_event(
                "ERROR",
                "RESPONSE",
                "Invalid target_value after sanitization",
                {"target_type": target_type, "target_hash": pseudonymize(raw_target_value)},
            )
            return None

        dedupe_key = (
            f"{sanitize_key_component(target_type, max_len=16)}:"
            f"{target_value_for_key}:"
            f"{sanitize_key_component(d.primary_action.name, max_len=40)}:"
            f"{sanitize_key_component(d.threat_kind.name, max_len=40)}"
        )

        if not self.store.dedupe_check_and_set(dedupe_key, self.dedupe_ttl_seconds):
            self.store.log_event(
                "INFO",
                "RESPONSE",
                "Duplicate directive suppressed (dedupe window)",
                {"dedupe_key": dedupe_key, "ttl_seconds": self.dedupe_ttl_seconds},
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
            target_value=raw_target_value,
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
        ip_actions = {ResponseAction.TEMP_BLOCK_IP, ResponseAction.HARD_BLOCK_IP}
        if d.primary_action in ip_actions:
            return ("ip", d.source_ip)
        return ("identity", d.identity)

    def _new_action_id(self) -> str:
        return f"ACT-{uuid.uuid4().hex}".upper()

    def _executor_loop(self) -> None:
        self.store.log_event("INFO", "EXECUTOR", "Executor thread online.", {"poll_ms": EXECUTOR_POLL_MS})
        while not self._stop.is_set():
            now_ms = _now_ms()

            try:
                expired = self.store.expire_overdue(now_ms=now_ms)
                if expired:
                    self.store.log_event("WARN", "EXECUTOR", "Expired stale pending actions", {"count": expired})
            except Exception as exc:
                self.store.log_event("ERROR", "EXECUTOR", "Expire pass failed", {"error": str(exc)})

            try:
                due = self.store.fetch_due_pending(now_ms=now_ms, limit=EXECUTOR_MAX_BATCH)
                for pa in due:
                    if not self.store.mark_pending_executing(pa.action_id):
                        continue

                    ok = False
                    err = ""
                    try:
                        ok = bool(self._integration.execute(pa))
                    except Exception as exc:
                        err = str(exc)

                    try:
                        self.store.finalize_execution(pa.action_id, ok=ok, operator_reason=(err or "ok"))
                        self.store.log_event(
                            "WARN" if ok else "ERROR",
                            "EXECUTOR",
                            "Executed action" if ok else "Execution failed",
                            {"action_id": pa.action_id, "ok": ok, "error": err[:300]},
                        )
                    except Exception as exc:
                        self.store.log_event("ERROR", "EXECUTOR", "Finalize failed",
                                             {"action_id": pa.action_id, "error": str(exc)})

            except Exception as exc:
                self.store.log_event("ERROR", "EXECUTOR", "Executor loop error", {"error": str(exc)})

            self._stop.wait(timeout=max(0.05, EXECUTOR_POLL_MS / 1000.0))

        self.store.log_event("INFO", "EXECUTOR", "Executor thread stopping.", {})

    def _execute_approved_now(self, action_id: str) -> None:
        try:
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

            self.store.update_action_status(
                action_id,
                ActionStatus.EXECUTED if ok else ActionStatus.FAILED,
                operator_id="executor",
                operator_reason=(err or "ok"),
                expected_status=ActionStatus.APPROVED,
            )
        except Exception as exc:
            self.store.log_event("ERROR", "EXECUTOR", "Approved-now execution path failed",
                                 {"action_id": action_id, "error": str(exc)})


# ============================================================
# OVERSIGHT ENGINE
# ============================================================

@dataclass(frozen=True)
class BudgetState:
    window_start: float
    used: int


@dataclass
class CorroborationState:
    first_seen: float
    last_seen: float
    count: int


@dataclass
class ExecutionFailure:
    at: float
    action_id: str
    error_type: str
    error_message: str


_MAX_TARGET_LEN = 64
_MAX_SOURCE_LEN = 80
_MAX_REASON_LEN = 200
_MAX_EVIDENCE_KEYS = 64


def _safe_str(v: object, *, max_len: int) -> str:
    s = str(v) if v is not None else ""
    s = s.strip()
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s


def _validate_ip(ip: str) -> Tuple[bool, str]:
    ip = _safe_str(ip, max_len=_MAX_TARGET_LEN)
    if not ip:
        return False, "empty_ip"
    try:
        ipaddress.ip_address(ip)
        return True, ip
    except ValueError:
        return False, "invalid_ip"


def _sanitize_evidence(evidence: dict) -> dict:
    if not isinstance(evidence, dict):
        return {"_evidence_error": "evidence_not_dict"}

    out: dict = {}
    for i, (k, v) in enumerate(evidence.items()):
        if i >= _MAX_EVIDENCE_KEYS:
            out["_truncated"] = True
            break
        key = _safe_str(k, max_len=64)
        out[key] = _safe_str(v, max_len=300)
    return out


_CANON_THREAT = {
    "PORT_SCAN",
    "BRUTE_FORCE",
    "CREDENTIAL_STUFFING",
    "MALWARE_BEACON",
    "ANOMALOUS_TRAFFIC",
    "UNKNOWN",
}


def _normalize_threat_type(t: str) -> str:
    t2 = _safe_str(t, max_len=64).upper().replace(" ", "_")
    return t2 if t2 in _CANON_THREAT else "UNKNOWN"


_ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH"}


def _normalize_severity(s: str) -> str:
    s2 = (s or "MEDIUM").strip().upper()
    return s2 if s2 in _ALLOWED_SEVERITIES else "MEDIUM"


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    dedupe_key: str
    target: str
    source: str
    description: str
    delay_seconds: int
    severity: str
    reason: str
    evidence: dict

    stage_callable: Callable[[SentinelMode, dict], Optional[str]]
    shadow_callable: Optional[Callable[[], None]] = None


class OversightEngine:
    def __init__(
        self,
        mode_resolver: Callable[[], OpMode],
        *,
        dedupe_ttl_seconds: int = OVERSIGHT_DEDUPE_TTL_SECONDS,
        max_pending: int = OVERSIGHT_MAX_PENDING,
        budget_window_seconds: int = OVERSIGHT_BUDGET_WINDOW_SECONDS,
        budget_max_actions_per_target: int = OVERSIGHT_BUDGET_MAX_PER_TARGET,
        budget_max_actions_per_source: int = OVERSIGHT_BUDGET_MAX_PER_SOURCE,
        require_two_signals_for_high: bool = OVERSIGHT_REQUIRE_TWO_SIGNALS_FOR_HIGH,
        corroboration_ttl_seconds: int = OVERSIGHT_CORROBORATION_TTL_SECONDS,
        operator_authenticator: Optional[Callable[[str], bool]] = None,
        on_execution_failure: Optional[Callable[[str, Exception, Optional[ActionRequest]], None]] = None,
        max_failure_ledger: int = 500,
    ) -> None:
        self._mode_resolver = mode_resolver
        self._lock = threading.RLock()

        self._gated_actions: Dict[str, ActionRequest] = {}
        self._recent_dedupe: Dict[str, float] = {}
        self._budget_target: Dict[str, BudgetState] = {}
        self._budget_source: Dict[str, BudgetState] = {}
        self._corroboration: Dict[str, CorroborationState] = {}
        self._failures: Dict[str, ExecutionFailure] = {}
        self._max_failure_ledger = int(max_failure_ledger)

        self._operator_authenticator = operator_authenticator
        self._on_execution_failure = on_execution_failure

        self._dedupe_ttl_seconds = int(dedupe_ttl_seconds)
        self._max_pending = int(max_pending)
        self._budget_window_seconds = int(budget_window_seconds)
        self._budget_max_actions_per_target = int(budget_max_actions_per_target)
        self._budget_max_actions_per_source = int(budget_max_actions_per_source)
        self._require_two_signals_for_high = bool(require_two_signals_for_high)
        self._corroboration_ttl_seconds = int(corroboration_ttl_seconds)

    def _now(self) -> float:
        return time.time()

    def _cleanup(self) -> None:
        now = self._now()

        for k, ts in list(self._recent_dedupe.items()):
            if now - ts > self._dedupe_ttl_seconds:
                self._recent_dedupe.pop(k, None)

        for k, st in list(self._corroboration.items()):
            if now - st.last_seen > self._corroboration_ttl_seconds:
                self._corroboration.pop(k, None)

        for target, st in list(self._budget_target.items()):
            if now - st.window_start > self._budget_window_seconds * 4:
                self._budget_target.pop(target, None)

        for source, st in list(self._budget_source.items()):
            if now - st.window_start > self._budget_window_seconds * 4:
                self._budget_source.pop(source, None)

        if len(self._failures) > self._max_failure_ledger:
            items = sorted(self._failures.values(), key=lambda f: f.at)
            to_remove = len(items) - self._max_failure_ledger
            for f in items[:to_remove]:
                self._failures.pop(f.action_id, None)

    def _is_duplicate(self, dedupe_key: str) -> bool:
        now = self._now()
        ts = self._recent_dedupe.get(dedupe_key)
        if ts is None:
            self._recent_dedupe[dedupe_key] = now
            return False
        return (now - ts) <= self._dedupe_ttl_seconds

    def _consume_budget(self, bucket: Dict[str, BudgetState], key: str, max_actions: int) -> bool:
        now = self._now()
        st = bucket.get(key)
        if st is None:
            bucket[key] = BudgetState(window_start=now, used=1)
            return True

        if now - st.window_start > self._budget_window_seconds:
            bucket[key] = BudgetState(window_start=now, used=1)
            return True

        if st.used >= max_actions:
            return False

        bucket[key] = BudgetState(window_start=st.window_start, used=st.used + 1)
        return True

    def _consume_budgets_atomic(self, *, target: str, source: str) -> bool:
        target_ok = self._consume_budget(self._budget_target, target, self._budget_max_actions_per_target)
        source_ok = True
        if source:
            source_ok = self._consume_budget(self._budget_source, source, self._budget_max_actions_per_source)

        if target_ok and source_ok:
            return True

        if target_ok and not source_ok:
            st = self._budget_target.get(target)
            if st:
                self._budget_target[target] = BudgetState(window_start=st.window_start, used=max(0, st.used - 1))
        return False

    def _corroborate(self, *, target: str, reason: str) -> int:
        now = self._now()
        key = f"{target}|{reason}"
        st = self._corroboration.get(key)
        if st is None:
            self._corroboration[key] = CorroborationState(first_seen=now, last_seen=now, count=1)
            return 1
        self._corroboration[key] = CorroborationState(first_seen=st.first_seen, last_seen=now, count=st.count + 1)
        return st.count + 1

    def _record_failure(self, action_id: str, exc: Exception) -> None:
        self._failures[action_id] = ExecutionFailure(
            at=self._now(),
            action_id=action_id,
            error_type=type(exc).__name__,
            error_message=_safe_str(str(exc), max_len=500),
        )

    def schedule_action(self, req: ActionRequest) -> Optional[str]:
        with self._lock:
            mode = self._mode_resolver()
            self._cleanup()

            if len(self._gated_actions) >= self._max_pending:
                logger.error("[OVERSIGHT] Back-pressure: too many gated actions. Dropping %s", req.action_id)
                return None

            if self._is_duplicate(req.dedupe_key):
                logger.info("[OVERSIGHT] Duplicate suppressed dedupe_key=%s", req.dedupe_key)
                return None

            if not self._consume_budgets_atomic(target=req.target, source=req.source):
                logger.warning("[OVERSIGHT] Budget exceeded target=%s source=%s suppressing %s", req.target, req.source, req.action_id)
                return None

            if req.severity == "HIGH" and self._require_two_signals_for_high:
                count = self._corroborate(target=req.target, reason=req.reason)
                logger.info("[OVERSIGHT] Corroboration target=%s reason=%s -> %d", req.target, req.reason, count)
                if count < 2:
                    if mode is OpMode.SHADOW and req.shadow_callable:
                        try:
                            req.shadow_callable()
                        except Exception as exc:
                            self._record_failure(req.action_id, exc)
                            logger.error("[OVERSIGHT] Shadow callable failed action_id=%s err=%s", req.action_id, exc)
                    return None

            if mode is OpMode.SHADOW:
                if req.shadow_callable:
                    try:
                        req.shadow_callable()
                    except Exception as exc:
                        self._record_failure(req.action_id, exc)
                        logger.error("[OVERSIGHT] Shadow callable failed action_id=%s err=%s", req.action_id, exc)
                logger.info("[OVERSIGHT] Advisory only. No execution.")
                return None

            if mode is OpMode.HUMAN_GATED:
                self._gated_actions[req.action_id] = req
                logger.warning("[OVERSIGHT] ACTION STAGED gated action_id=%s", req.action_id)
                return req.action_id

            try:
                staged_action_id = req.stage_callable(
                    _map_mode(mode),
                    {
                        "delay_seconds": req.delay_seconds,
                        "description": req.description,
                        "evidence": req.evidence,
                    },
                )
                return staged_action_id
            except Exception as exc:
                self._record_failure(req.action_id, exc)
                logger.error("[OVERSIGHT] stage_callable failed action_id=%s err=%s", req.action_id, exc)
                if self._on_execution_failure:
                    try:
                        self._on_execution_failure(req.action_id, exc, req)
                    except Exception as cb_exc:
                        logger.critical("[OVERSIGHT] failure callback failed action_id=%s err=%s", req.action_id, cb_exc)
                return None

    def approve_gated_action(self, action_id: str, *, operator_id: str = "unknown") -> bool:
        operator_id = _safe_str(operator_id, max_len=80)
        if self._operator_authenticator is not None and not self._operator_authenticator(operator_id):
            logger.error("[OVERSIGHT] APPROVAL REJECTED operator not authenticated operator=%s", operator_id)
            return False

        with self._lock:
            req = self._gated_actions.pop(action_id, None)

        if not req:
            logger.warning("[OVERSIGHT] APPROVAL FAILED not staged action_id=%s", action_id)
            return False

        try:
            _ = req.stage_callable(SentinelMode.HUMAN_GATED, {"description": req.description, "evidence": req.evidence})
            return True
        except Exception as exc:
            with self._lock:
                self._record_failure(action_id, exc)
            logger.error("[OVERSIGHT] gated stage failed action_id=%s err=%s", action_id, exc)
            return False

    def veto_gated_action(self, action_id: str, reason: str, *, operator_id: str = "unknown") -> bool:
        operator_id = _safe_str(operator_id, max_len=80)
        if self._operator_authenticator is not None and not self._operator_authenticator(operator_id):
            logger.error("[OVERSIGHT] VETO REJECTED operator not authenticated operator=%s", operator_id)
            return False

        with self._lock:
            existed = action_id in self._gated_actions
            self._gated_actions.pop(action_id, None)
        if existed:
            logger.warning("[OVERSIGHT] GATED ACTION DROPPED action_id=%s operator=%s reason=%s", action_id, operator_id, _safe_str(reason, max_len=300))
            return True

        logger.warning("[OVERSIGHT] VETO FAILED not found action_id=%s", action_id)
        return False

    def shutdown(self) -> None:
        with self._lock:
            self._gated_actions.clear()
            self._recent_dedupe.clear()
            self._corroboration.clear()
            self._budget_target.clear()
            self._budget_source.clear()
            self._failures.clear()


# ============================================================
# SENTINEL NEXUS
# ============================================================

class SentinelNexus:
    def __init__(
        self,
        initial_mode: OpMode = OpMode.SHADOW,
        *,
        source_id: str = "sensor.local",
        operator_authenticator: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self._mode = initial_mode
        self._source_id = _safe_str(source_id, max_len=_MAX_SOURCE_LEN)

        self.engine = Sentinel43ResponseEngine(
            operator_authenticator=operator_authenticator or (lambda _op: False),
            integration=IntegrationHub,
        )

        self.oversight = OversightEngine(
            self.get_mode,
            operator_authenticator=operator_authenticator,
        )

        logger.info("[%s] Nexus Online. Mode=%s source_id=%s", SYSTEM_ID, self._mode.value, self._source_id)

    def set_mode(self, mode: OpMode) -> None:
        self._mode = mode
        logger.warning("[%s] Mode switched to %s", SYSTEM_ID, self._mode.value)

    def get_mode(self) -> OpMode:
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
        ok, ip = _validate_ip(ip_address)
        if not ok:
            token = f"DROP-{uuid.uuid4().hex[:12]}"
            logger.warning("[THREAT] Dropped invalid ip_address=%s token=%s", _safe_str(ip_address, max_len=120), token)
            return token

        sev = _normalize_severity(severity)
        ttype = _normalize_threat_type(threat_type)
        src = _safe_str(source_id or self._source_id, max_len=_MAX_SOURCE_LEN)

        action_id = f"ACT-{uuid.uuid4().hex}".upper()
        bucket = int(time.time() // 30)
        dedupe_key = f"{ip}|{ttype}|{sev}|{bucket}"

        reason = f"{ttype} detected"
        evidence = _sanitize_evidence(
            {
                "system": SYSTEM_ID,
                "threat_type": ttype,
                "severity": sev,
                "observed_at": int(time.time()),
                "source_id": src,
            }
        )

        severity_map = {
            "LOW": ThreatSeverity.LOW,
            "MEDIUM": ThreatSeverity.MEDIUM,
            "HIGH": ThreatSeverity.HIGH,
        }
        threat_kind_map = {
            "PORT_SCAN": ThreatKind.GENERIC_INTRUSION,
            "BRUTE_FORCE": ThreatKind.CREDENTIAL_ATTACK,
            "CREDENTIAL_STUFFING": ThreatKind.CREDENTIAL_ATTACK,
            "MALWARE_BEACON": ThreatKind.MALWARE_DELIVERY,
            "ANOMALOUS_TRAFFIC": ThreatKind.GENERIC_INTRUSION,
            "UNKNOWN": ThreatKind.UNKNOWN,
        }

        assessment = ThreatAssessment(
            identity=f"ip:{ip}",
            source_ip=ip,
            threat_kind=threat_kind_map.get(ttype, ThreatKind.UNKNOWN),
            severity=severity_map.get(sev, ThreatSeverity.MEDIUM),
            source_kind=ThreatSourceKind.MIXED_OR_UNKNOWN,
            score=70.0 if sev == "HIGH" else 55.0 if sev == "MEDIUM" else 30.0,
            supporting_tags=[ttype, sev],
            window_size=1,
        )

        def stage_callable(mode: SentinelMode, meta: dict) -> Optional[str]:
            pa = self.engine.handle_assessment(mode, assessment)
            if not pa:
                return None

            if mode == SentinelMode.ACTIVE:
                delay_s = int(meta.get("delay_seconds", 5))
                execute_at_ms = _now_ms() + delay_s * 1000

                with _db_conn() as conn:
                    conn.execute("BEGIN IMMEDIATE;")
                    try:
                        cur = conn.execute(
                            """
                            UPDATE pending_actions
                               SET execute_at_ms=?
                             WHERE action_id=?
                               AND status=?
                            """,
                            (execute_at_ms, pa.action_id, ActionStatus.PENDING.value),
                        )
                        conn.execute("COMMIT;")
                        if int(cur.rowcount or 0) == 0:
                            return pa.action_id
                    except Exception:
                        conn.execute("ROLLBACK;")
                        raise

            return pa.action_id

        def shadow_callable() -> None:
            logger.info("[SHADOW] WOULD stage threat=%s ip=%s", ttype, pseudonymize(ip))

        req = ActionRequest(
            action_id=action_id,
            dedupe_key=dedupe_key,
            target=ip,
            source=src,
            description=f"Respond to threat {ttype} from {ip}",
            delay_seconds=5,
            severity=sev,
            reason=_safe_str(reason, max_len=_MAX_REASON_LEN),
            evidence=evidence,
            stage_callable=stage_callable,
            shadow_callable=shadow_callable,
        )

        logger.info("[THREAT] %s from %s severity=%s source=%s action_id=%s", ttype, ip, sev, src, action_id)
        staged = self.oversight.schedule_action(req)
        return staged or action_id


# ============================================================
# SELF-TEST
# ============================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")

    allowed = {s.strip() for s in _env("SENTINEL_ALLOWED_OPERATORS", "admin,ops").split(",") if s.strip()}
    auth = lambda op: op in allowed

    nexus = SentinelNexus(initial_mode=OpMode.ACTIVE, source_id="sensor.local", operator_authenticator=auth)

    act = nexus.handle_threat(ip_address="192.0.2.10", threat_type="BRUTE_FORCE", severity="HIGH", source_id="sensor.a")
    print("Action:", act)

    time.sleep(2)
    nexus.shutdown()
