from __future__ import annotations

import enum
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple


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


DB_PATH = Path(_env("SENTINEL_DB_PATH", str(BASE_DIR / "sentinel_secure.db")))
SYSTEM_ID = _env("SENTINEL_SYSTEM_ID", "SENTINEL-43-NEXUS-01")

# Dedupe TTL: prevents queue spam for identical directives
DEFAULT_DEDUPE_TTL_SECONDS = int(_env("SENTINEL_ACTION_DEDUPE_TTL", "60"))

# Log + action retention (prevents SQLite growth DoS)
DEFAULT_LOG_RETENTION_DAYS = int(_env("SENTINEL_LOG_RETENTION_DAYS", "90"))
DEFAULT_ACTION_RETENTION_DAYS = int(_env("SENTINEL_ACTION_RETENTION_DAYS", "30"))

# Hash salt for privacy-safe logs (do not leave default in anything you ship)
LOG_SALT = _env("SENTINEL_LOG_SALT", "CHANGE_ME_IN_PROD")


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
    # Score thresholds
    medium_threshold: float = 40.0
    high_threshold: float = 65.0
    critical_threshold: float = 85.0

    # Automation escalation bump
    automation_medium_bonus: float = 5.0
    automation_high_bonus: float = 10.0

    # Durations
    temp_block_seconds: int = 900        # 15 minutes
    hard_block_seconds: int = 3600 * 6   # 6 hours

    # Auto-escalation toggles
    auto_open_incident_on_critical: bool = True
    auto_require_human_review_on_high: bool = True

    # ACTIVE mode veto window default (UI countdown)
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
    SHADOWED = "SHADOWED"     # recorded only
    STAGED = "STAGED"         # waiting for approval (HUMAN_GATED)
    PENDING = "PENDING"       # veto window open (ACTIVE)
    VETOED = "VETOED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    created_at_ms: int
    execute_at_ms: Optional[int]  # only used in ACTIVE (veto window)
    status: ActionStatus

    target_type: str     # "ip" | "identity" | "session"
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
    """
    Canonicalize IP formatting if valid, else return stripped original.
    We do NOT hard-fail because you may feed internal identifiers sometimes,
    but we normalize when we can.
    """
    s = "" if ip is None else str(ip).strip()
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return s


def utc_iso() -> str:
    return __import__("datetime").datetime.utcnow().isoformat(timespec="microseconds") + "Z"


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
    def cleanup_old_logs(self, retention_days: int) -> int: ...
    def cleanup_old_actions(self, retention_days: int) -> int: ...


def _db_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


class SqliteActionStore:
    def ensure_schema(self) -> None:
        with _db_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    module TEXT NOT NULL,
                    message TEXT NOT NULL,
                    context_json TEXT
                )
                """
            )

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

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS action_dedupe (
                    dedupe_key TEXT PRIMARY KEY,
                    expires_at_ms INTEGER NOT NULL
                )
                """
            )

            # hygiene: remove expired dedupe entries
            now_ms = int(time.time() * 1000)
            conn.execute("DELETE FROM action_dedupe WHERE expires_at_ms <= ?", (now_ms,))

        # cleanup on startup (best-effort)
        try:
            self.cleanup_old_logs(DEFAULT_LOG_RETENTION_DAYS)
            self.cleanup_old_actions(DEFAULT_ACTION_RETENTION_DAYS)
        except Exception:
            # don't block boot on housekeeping failures
            pass

    def log_event(self, level: str, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        ts = utc_iso()
        ctx = json.dumps(context, default=str) if context else None
        with _db_conn() as conn:
            conn.execute(
                """
                INSERT INTO event_logs (timestamp, level, module, message, context_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (ts, level, module, message, ctx),
            )

    def dedupe_check_and_set(self, key: str, ttl_seconds: int) -> bool:
        """
        Returns True if allowed (not a duplicate in TTL window).
        Atomic under concurrency (no SELECT-then-act race).
        """
        now_ms = int(time.time() * 1000)
        exp_ms = now_ms + int(ttl_seconds * 1000)

        # Hard cap to prevent key-bloat attacks
        key = ("" if key is None else str(key)).strip()
        if len(key) > 512:
            key = key[:512]

        with _db_conn() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM action_dedupe WHERE expires_at_ms <= ?", (now_ms,))
                conn.execute(
                    "INSERT INTO action_dedupe (dedupe_key, expires_at_ms) VALUES (?, ?)",
                    (key, exp_ms),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            except Exception:
                conn.rollback()
                raise

    def insert_pending_action(self, pa: PendingAction) -> None:
        with _db_conn() as conn:
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

    def get_action_status(self, action_id: str) -> Optional[str]:
        with _db_conn() as conn:
            row = conn.execute(
                "SELECT status FROM pending_actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
            if not row:
                return None
            return str(row["status"])

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
            conn.execute(
                """
                UPDATE pending_actions
                   SET status = ?, operator_id = ?, operator_reason = ?
                 WHERE action_id = ?
                   AND status = ?
                """,
                (new_status.value, op, rsn, action_id, expected_status.value),
            )
            return conn.total_changes > 0

    def cleanup_old_logs(self, retention_days: int) -> int:
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(retention_days))
        cutoff_iso = cutoff.isoformat(timespec="seconds")
        with _db_conn() as conn:
            cur = conn.execute("DELETE FROM event_logs WHERE timestamp < ?", (cutoff_iso,))
            return int(cur.rowcount or 0)

    def cleanup_old_actions(self, retention_days: int) -> int:
        cutoff_ms = int((time.time() - (int(retention_days) * 86400)) * 1000)
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
                    ActionStatus.APPROVED.value,
                    ActionStatus.EXECUTED.value,
                    ActionStatus.EXPIRED.value,
                ),
            )
            return int(cur.rowcount or 0)


# ============================================================
# RESPONSE ENGINE (NO DETECTOR INSIDE)
# ============================================================

class Sentinel43ResponseEngine:
    """
    Sentinel-43 response engine:
      - consumes ThreatAssessment (from detector layer)
      - produces ResponseDirective
      - stages/persists PendingAction according to mode
      - logs (PII-safe via hashing in event logs)
      - dedupes action spam (atomic DB dedupe)
      - provides authenticated approval/veto APIs
    """

    def __init__(
        self,
        store: Optional[ActionStore] = None,
        policy: Optional[ResponsePolicy] = None,
        dedupe_ttl_seconds: int = DEFAULT_DEDUPE_TTL_SECONDS,
        *,
        operator_authenticator: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.store = store or SqliteActionStore()
        self.policy = policy or ResponsePolicy()
        self.dedupe_ttl_seconds = int(dedupe_ttl_seconds)

        # Fail-closed by default: if you want approvals, you must provide auth.
        self._operator_authenticator = operator_authenticator or (lambda _op: False)

        self.store.ensure_schema()
        self.store.log_event("INFO", "BOOT", "Sentinel-43 Response Engine initialized.", {"system_id": SYSTEM_ID})

    # ------------------------------
    # PUBLIC ENTRY
    # ------------------------------
    def handle_assessment(self, mode: SentinelMode, assessment: ThreatAssessment) -> Optional[PendingAction]:
        directive = self.plan_response(assessment)

        # PII-safe: hash identity + ip in logs
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
        # normalize IP for consistency
        assessment_ip = normalize_ip(assessment.source_ip)

        # Keep identity as provided; sanitize later for dedupe keys.
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

        # Sanitize dedupe inputs (prevents keyspace abuse and keeps DB tidy)
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
            self.store.log_event(
                "INFO",
                "RESPONSE",
                "Duplicate directive suppressed (dedupe window)",
                {"dedupe_key": dedupe_key, "ttl_seconds": self.dedupe_ttl_seconds},
            )
            return None

        action_id = self._new_action_id()
        now_ms = int(time.time() * 1000)

        if mode == SentinelMode.SHADOW:
            status = ActionStatus.SHADOWED
            execute_at_ms = None
        elif mode == SentinelMode.HUMAN_GATED:
            status = ActionStatus.STAGED
            execute_at_ms = None
        else:
            status = ActionStatus.PENDING
            execute_at_ms = now_ms + int(self.policy.veto_window_seconds * 1000)

        actions_json = json.dumps(
            {
                "primary": d.primary_action.name,
                "additional": [a.name for a in d.additional_actions],
                "expires_at": d.expires_at,
            },
            default=str,
        )

        # Store raw target_value in pending_actions (needed for real execution downstream).
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

        # PII-safe staging log: hash target, do not dump raw target into event_logs
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
        # Non-guessable and collision-resistant
        return f"ACT-{uuid.uuid4().hex}".upper()


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
    print("Staged:", pa)

    # Demonstrate approval flow (would only make sense for HUMAN_GATED)
    pa2 = engine.handle_assessment(SentinelMode.HUMAN_GATED, a)
    if pa2:
        print("Staged (gated):", pa2.action_id)
        ok = engine.approve_action(pa2.action_id, operator_id="admin", reason="reviewed")
        print("Approved:", ok)