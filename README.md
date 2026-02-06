# # sentinel43_nexus_onefile_advisory.py
#
# Sentinel-43 is dual-licensed:
#   1) GNU Affero General Public License v3.0 (AGPLv3), or
#   2) A commercial license (separate terms).
#
# You may use, modify, and distribute this software under the terms of the AGPLv3
# unless you have purchased/received a commercial license from the copyright holder.
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# NOTE: If you deploy this software to users over a network, the AGPL generally
# requires you to provide the Corresponding Source to those users.
#
# Commercial licensing inquiries: see COMMERCIAL_LICENSE.md
"""
SENTINEL-43: Advisory Risk + Response Recommendation Engine (Hardened, Public Version)

Quick Summary (Public Version)
Sentinel-43 is a risk assessment + response recommendation engine.

It helps humans make consistent decisions by turning events into:
- a risk score
- a policy-based recommendation
- a written explanation
- an audit record

It does not execute enforcement.
It doesn’t block users, shut down systems, or take action unless you wire that in separately.

Core design constraints (non-negotiable):
- No autonomous enforcement
- No covert surveillance or harvesting
- No hidden integrations or side effects
- No opaque “black box” decisions
- No bypassing human/legal/organizational authority

Architectural model:
- Core: analysis + scoring + policy + audit (NO network I/O, NO enforcement)
- Adapters: optional integrations (queues/services/control planes), replaceable, reviewable
- Interfaces: dashboards and review tools (human control surfaces)

Default: ADVISORY mode
- Events analyzed, recommendations produced, audit stored
- Execution is always external to the core
"""
"""
...
Licensing
This project is dual-licensed under:
- AGPLv3 (see LICENSE-AGPLv3.md), or
- A commercial license (see COMMERCIAL_LICENSE.md).

If you use this over a network, AGPLv3 generally requires offering the Corresponding Source.
"""
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
# CONFIG
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


SYSTEM_ID = _env("SENTINEL_SYSTEM_ID", "SENTINEL-43-NEXUS-01")
DB_PATH = Path(_env("SENTINEL_DB_PATH", str(BASE_DIR / "sentinel43_state" / "sentinel43.sqlite3")))

# Prevent queue spam for identical directives
DEFAULT_DEDUPE_TTL_SECONDS = int(_env("SENTINEL_ACTION_DEDUPE_TTL", "60"))

# Retention prevents SQLite growth DoS
DEFAULT_LOG_RETENTION_DAYS = int(_env("SENTINEL_LOG_RETENTION_DAYS", "90"))
DEFAULT_ACTION_RETENTION_DAYS = int(_env("SENTINEL_ACTION_RETENTION_DAYS", "30"))

# Privacy-safe logs (do not ship with default)
LOG_SALT = _env("SENTINEL_LOG_SALT", "CHANGE_ME_IN_PROD")


# ============================================================
# MODES (WORKFLOW STATES ONLY, NOT EXECUTION)
# ============================================================

class SentinelMode(str, enum.Enum):
    """
    These modes only affect how recommendations are staged for review,
    not whether anything is executed (core never executes).
    """
    ADVISORY = "ADVISORY"         # analyze + recommend + log (default)
    HUMAN_GATED = "HUMAN_GATED"   # stage recommendations for explicit approval
    ACTIVE_PLANNING = "ACTIVE_PLANNING"  # produces "time-sensitive" plans, still no execution


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
    """
    Detector layer is separate. Sentinel consumes assessments only.
    """
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
# RECOMMENDED RESPONSE ACTIONS (OUTPUT CONTRACT)
# ============================================================

class RecommendedAction(enum.Enum):
    """
    These are RECOMMENDATIONS ONLY.
    Anything that "does a thing" must be implemented outside core by an adapter.
    """
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

    # Suggested durations (recommendation metadata only)
    temp_block_seconds: int = 900        # 15 minutes
    hard_block_seconds: int = 3600 * 6   # 6 hours

    # Recommendation toggles
    recommend_open_incident_on_critical: bool = True
    recommend_human_review_on_high: bool = True

    # Planning hint: suggested response time window (not a veto window for execution)
    suggested_review_window_seconds: int = 30


@dataclass
class ResponseDirective:
    """
    Explainable, policy-bound recommendation. No enforcement.
    """
    identity: str
    source_ip: str
    primary_action: RecommendedAction
    additional_actions: List[RecommendedAction] = field(default_factory=list)
    reason: str = ""
    expires_at: Optional[float] = None  # advisory metadata only

    threat_kind: ThreatKind = ThreatKind.UNKNOWN
    threat_severity: ThreatSeverity = ThreatSeverity.LOW
    source_kind: ThreatSourceKind = ThreatSourceKind.MIXED_OR_UNKNOWN
    score: float = 0.0

    explanation: str = ""  # written explanation for humans
    created_at: float = field(default_factory=time.time)


# ============================================================
# PERSISTED DECISION / RECOMMENDATION MODEL
# ============================================================

class DecisionStatus(str, enum.Enum):
    """
    Decision workflow states (still no execution).
    """
    RECORDED = "RECORDED"     # stored for audit
    STAGED = "STAGED"         # waiting for human review/approval
    APPROVED = "APPROVED"     # approved recommendation (adapter may consume)
    REJECTED = "REJECTED"     # rejected by human
    EXPIRED = "EXPIRED"       # stale


@dataclass(frozen=True)
class DecisionRecord:
    """
    Durable record of what Sentinel recommended and why.
    """
    decision_id: str
    created_at_ms: int
    status: DecisionStatus

    target_type: str     # "ip" | "identity"
    target_value: str

    primary_action: str
    actions_json: str

    severity: str
    kind: str
    source_kind: str
    score: float

    reason: str
    explanation: str
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
# STORAGE LAYER (SQLite, durable, NO side effects)
# ============================================================

class DecisionStore(Protocol):
    def ensure_schema(self) -> None: ...
    def log_event(self, level: str, module: str, message: str, context: Optional[Dict[str, Any]] = None) -> None: ...
    def dedupe_check_and_set(self, key: str, ttl_seconds: int) -> bool: ...
    def insert_decision(self, rec: DecisionRecord) -> None: ...
    def update_decision_status(self, decision_id: str, new_status: DecisionStatus, *, operator_id: Optional[str], operator_reason: Optional[str], expected_status: DecisionStatus) -> bool: ...
    def get_decision_status(self, decision_id: str) -> Optional[str]: ...
    def list_decisions(self, *, status: Optional[DecisionStatus] = None, limit: int = 50) -> List[DecisionRecord]: ...
    def export_approved(self, *, limit: int = 50) -> List[dict]: ...
    def cleanup_old_logs(self, retention_days: int) -> int: ...
    def cleanup_old_decisions(self, retention_days: int) -> int: ...


def _db_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


class SqliteDecisionStore:
    def ensure_schema(self) -> None:
        with _db_conn() as conn:
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
                    CREATE TABLE IF NOT EXISTS decisions (
                        decision_id TEXT PRIMARY KEY,
                        created_at_ms INTEGER NOT NULL,
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
                        explanation TEXT NOT NULL,
                        system_id TEXT NOT NULL,

                        operator_id TEXT,
                        operator_reason TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_status_created ON decisions(status, created_at_ms)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_created ON decisions(created_at_ms)")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS decision_dedupe (
                        dedupe_key TEXT PRIMARY KEY,
                        expires_at_ms INTEGER NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_decision_dedupe_exp ON decision_dedupe(expires_at_ms)")

                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

        # best-effort cleanup
        try:
            self.cleanup_old_logs(DEFAULT_LOG_RETENTION_DAYS)
            self.cleanup_old_decisions(DEFAULT_ACTION_RETENTION_DAYS)
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
                conn.execute("DELETE FROM decision_dedupe WHERE expires_at_ms <= ?", (now_ms,))
                conn.execute(
                    "INSERT INTO decision_dedupe (dedupe_key, expires_at_ms) VALUES (?, ?)",
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

    def insert_decision(self, rec: DecisionRecord) -> None:
        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                conn.execute(
                    """
                    INSERT INTO decisions (
                        decision_id, created_at_ms, status,
                        target_type, target_value,
                        primary_action, actions_json,
                        severity, kind, source_kind, score,
                        reason, explanation, system_id,
                        operator_id, operator_reason
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rec.decision_id,
                        rec.created_at_ms,
                        rec.status.value,
                        rec.target_type,
                        rec.target_value,
                        rec.primary_action,
                        rec.actions_json,
                        rec.severity,
                        rec.kind,
                        rec.source_kind,
                        float(rec.score),
                        rec.reason,
                        rec.explanation,
                        rec.system_id,
                        rec.operator_id,
                        rec.operator_reason,
                    ),
                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def get_decision_status(self, decision_id: str) -> Optional[str]:
        with _db_conn() as conn:
            row = conn.execute("SELECT status FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
            return str(row["status"]) if row else None

    def update_decision_status(
        self,
        decision_id: str,
        new_status: DecisionStatus,
        *,
        operator_id: Optional[str],
        operator_reason: Optional[str],
        expected_status: DecisionStatus,
    ) -> bool:
        op = operator_id[:80] if operator_id else None
        rsn = operator_reason[:300] if operator_reason else None

        with _db_conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = conn.execute(
                    """
                    UPDATE decisions
                       SET status=?, operator_id=?, operator_reason=?
                     WHERE decision_id=?
                       AND status=?
                    """,
                    (new_status.value, op, rsn, decision_id, expected_status.value),
                )
                conn.execute("COMMIT;")
                return int(cur.rowcount or 0) > 0
            except Exception:
                conn.execute("ROLLBACK;")
                raise

    def list_decisions(self, *, status: Optional[DecisionStatus] = None, limit: int = 50) -> List[DecisionRecord]:
        q = "SELECT * FROM decisions "
        args: List[Any] = []
        if status is not None:
            q += "WHERE status=? "
            args.append(status.value)
        q += "ORDER BY created_at_ms DESC LIMIT ?"
        args.append(int(limit))

        with _db_conn() as conn:
            rows = conn.execute(q, tuple(args)).fetchall()

        out: List[DecisionRecord] = []
        for r in rows:
            out.append(
                DecisionRecord(
                    decision_id=str(r["decision_id"]),
                    created_at_ms=int(r["created_at_ms"]),
                    status=DecisionStatus(str(r["status"])),
                    target_type=str(r["target_type"]),
                    target_value=str(r["target_value"]),
                    primary_action=str(r["primary_action"]),
                    actions_json=str(r["actions_json"]),
                    severity=str(r["severity"]),
                    kind=str(r["kind"]),
                    source_kind=str(r["source_kind"]),
                    score=float(r["score"]),
                    reason=str(r["reason"]),
                    explanation=str(r["explanation"]),
                    system_id=str(r["system_id"]),
                    operator_id=str(r["operator_id"]) if r["operator_id"] is not None else None,
                    operator_reason=str(r["operator_reason"]) if r["operator_reason"] is not None else None,
                )
            )
        return out

    def export_approved(self, *, limit: int = 50) -> List[dict]:
        """
        Adapter handoff: export APPROVED decisions in a JSON-friendly format.
        Core still doesn't execute anything. This is for external consumers.
        """
        recs = self.list_decisions(status=DecisionStatus.APPROVED, limit=limit)
        out: List[dict] = []
        for r in recs:
            out.append(
                {
                    "decision_id": r.decision_id,
                    "created_at_ms": r.created_at_ms,
                    "target_type": r.target_type,
                    "target_value": r.target_value,
                    "primary_action": r.primary_action,
                    "actions": json.loads(r.actions_json),
                    "severity": r.severity,
                    "kind": r.kind,
                    "source_kind": r.source_kind,
                    "score": r.score,
                    "reason": r.reason,
                    "explanation": r.explanation,
                    "system_id": r.system_id,
                    "operator_id": r.operator_id,
                    "operator_reason": r.operator_reason,
                }
            )
        return out

    def cleanup_old_logs(self, retention_days: int) -> int:
        cutoff_ms = _now_ms() - int(retention_days) * 86400 * 1000
        with _db_conn() as conn:
            cur = conn.execute("DELETE FROM event_logs WHERE ts_ms < ?", (cutoff_ms,))
            return int(cur.rowcount or 0)

    def cleanup_old_decisions(self, retention_days: int) -> int:
        cutoff_ms = _now_ms() - int(retention_days) * 86400 * 1000
        with _db_conn() as conn:
            cur = conn.execute(
                """
                DELETE FROM decisions
                 WHERE created_at_ms < ?
                   AND status IN (?, ?, ?)
                """,
                (
                    cutoff_ms,
                    DecisionStatus.APPROVED.value,
                    DecisionStatus.REJECTED.value,
                    DecisionStatus.EXPIRED.value,
                ),
            )
            return int(cur.rowcount or 0)


# ============================================================
# SENTINEL-43 CORE ENGINE (analysis + recommendation + audit)
# ============================================================

class Sentinel43Engine:
    """
    Deterministic, auditable decision-support core.
    - consumes ThreatAssessment
    - produces ResponseDirective (recommendation + explanation)
    - persists DecisionRecord (audit)
    - NEVER executes enforcement
    """

    def __init__(
        self,
        store: Optional[DecisionStore] = None,
        policy: Optional[ResponsePolicy] = None,
        dedupe_ttl_seconds: int = DEFAULT_DEDUPE_TTL_SECONDS,
        *,
        operator_authenticator: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self.store = store or SqliteDecisionStore()
        self.policy = policy or ResponsePolicy()
        self.dedupe_ttl_seconds = int(dedupe_ttl_seconds)

        # Fail-closed by default (approval/rejection requires auth).
        self._operator_authenticator = operator_authenticator or (lambda _op: False)

        self.store.ensure_schema()
        self.store.log_event("INFO", "BOOT", "Sentinel-43 advisory engine initialized.", {"system_id": SYSTEM_ID})

    # ------------------------------
    # PUBLIC ENTRY
    # ------------------------------
    def handle_assessment(self, mode: SentinelMode, assessment: ThreatAssessment) -> Optional[DecisionRecord]:
        directive = self.plan_response(assessment)

        self.store.log_event(
            "INFO",
            "RESPONSE",
            "Recommendation generated",
            {
                "identity_hash": pseudonymize(directive.identity),
                "ip_hash": pseudonymize(directive.source_ip),
                "primary_action": directive.primary_action.name,
                "additional_actions": [a.name for a in directive.additional_actions],
                "score": directive.score,
                "severity": directive.threat_severity.name,
                "kind": directive.threat_kind.name,
                "source_kind": directive.source_kind.name,
                "mode": mode.value,
            },
        )

        return self.record_directive(mode, directive)

    # ------------------------------
    # OPERATOR WORKFLOW (no execution)
    # ------------------------------
    def approve(self, decision_id: str, operator_id: str, reason: str = "") -> bool:
        op = (operator_id or "").strip()[:80]
        rsn = (reason or "").strip()[:300]

        if not op or not self._operator_authenticator(op):
            self.store.log_event("ERROR", "OVERSIGHT", "Unauthorized approval attempt",
                                 {"decision_id": decision_id, "operator_id": op})
            return False

        ok = self.store.update_decision_status(
            decision_id,
            DecisionStatus.APPROVED,
            operator_id=op,
            operator_reason=rsn,
            expected_status=DecisionStatus.STAGED,
        )

        self.store.log_event(
            "WARN" if ok else "ERROR",
            "OVERSIGHT",
            "Decision approved" if ok else "Approval failed",
            {"decision_id": decision_id, "operator_id": op},
        )
        return ok

    def reject(self, decision_id: str, operator_id: str, reason: str) -> bool:
        op = (operator_id or "").strip()[:80]
        rsn = (reason or "").strip()[:300]

        if not op or not self._operator_authenticator(op):
            self.store.log_event("ERROR", "OVERSIGHT", "Unauthorized rejection attempt",
                                 {"decision_id": decision_id, "operator_id": op})
            return False

        ok = self.store.update_decision_status(
            decision_id,
            DecisionStatus.REJECTED,
            operator_id=op,
            operator_reason=rsn,
            expected_status=DecisionStatus.STAGED,
        )

        self.store.log_event(
            "WARN" if ok else "ERROR",
            "OVERSIGHT",
            "Decision rejected" if ok else "Rejection failed",
            {"decision_id": decision_id, "operator_id": op},
        )
        return ok

    # ------------------------------
    # PLANNING
    # ------------------------------
    def plan_response(self, assessment: ThreatAssessment) -> ResponseDirective:
        # normalize IP for consistency
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

    def _explain(self, a: ThreatAssessment, score: float, actions: List[RecommendedAction], *, note: str) -> str:
        """
        Human-readable explanation (deterministic, policy-bound).
        """
        parts = [
            f"Assessment: severity={a.severity.name}, kind={a.threat_kind.name}, source_kind={a.source_kind.name}.",
            f"Score: {score:.1f} (policy thresholds: medium={self.policy.medium_threshold}, high={self.policy.high_threshold}, critical={self.policy.critical_threshold}).",
            f"Recommendation: primary={actions[0].name if actions else RecommendedAction.LOG_ONLY.name}, additional={[x.name for x in actions[1:]]}.",
            f"Rationale: {note}",
            "Important: This is advisory only. No enforcement is performed by Sentinel-43.",
        ]
        return " ".join(parts)

    def _build_low(self, a: ThreatAssessment, score: float) -> ResponseDirective:
        actions = [RecommendedAction.LOG_ONLY]
        note = "Low severity and below medium threshold. Record for audit; avoid unnecessary disruption."
        if a.threat_kind in (ThreatKind.MALWARE_DELIVERY, ThreatKind.SPYWARE_ACTIVITY):
            actions.append(RecommendedAction.FLAG_SUSPICIOUS)
            note = "Low severity but malware/spyware-related indicator present. Flag for analyst context."

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
            explanation=self._explain(a, score, actions, note=note),
        )

    def _build_mid_high(self, a: ThreatAssessment, score: float) -> ResponseDirective:
        actions: List[RecommendedAction] = []

        note_bits: List[str] = []

        if a.threat_kind in (ThreatKind.CREDENTIAL_ATTACK, ThreatKind.GENERIC_INTRUSION):
            actions.append(RecommendedAction.STEP_UP_AUTH)
            note_bits.append("Credential/intrusion pattern suggests authentication hardening.")

        actions.append(RecommendedAction.RATE_LIMIT)
        note_bits.append("Rate limiting reduces impact while preserving service continuity.")

        temp_block = score >= self.policy.high_threshold
        expires_at = None

        if temp_block:
            actions.append(RecommendedAction.TEMP_BLOCK_IDENTITY)
            expires_at = time.time() + self.policy.temp_block_seconds
            note_bits.append("Score meets high threshold; recommend temporary identity block (adapter-controlled).")

        if a.source_kind == ThreatSourceKind.AI_AUTOMATION_LIKELY and temp_block:
            actions.append(RecommendedAction.TEMP_BLOCK_IP)
            note_bits.append("Automation-likely source; IP-based temporary block recommended as additional containment.")

        if self.policy.recommend_human_review_on_high and a.severity == ThreatSeverity.HIGH:
            actions.append(RecommendedAction.REQUIRE_HUMAN_REVIEW)
            note_bits.append("High severity requires human review checkpoint.")

        primary = actions[0] if actions else RecommendedAction.LOG_ONLY

        note = " ".join(note_bits) if note_bits else "Policy-mapped mid/high response recommendation."

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
            explanation=self._explain(a, score, actions, note=note),
        )

    def _build_critical(self, a: ThreatAssessment, score: float) -> ResponseDirective:
        actions: List[RecommendedAction] = [
            RecommendedAction.QUARANTINE_SESSION,
            RecommendedAction.HARD_BLOCK_IDENTITY,
            RecommendedAction.HARD_BLOCK_IP,
        ]

        note_bits = [
            "Critical severity indicates immediate containment recommendations.",
            "Session quarantine reduces lateral movement and evidence loss.",
            "Hard blocks recommended (adapter-controlled, must be reviewed/authorized externally).",
        ]

        if self.policy.recommend_open_incident_on_critical:
            actions.append(RecommendedAction.OPEN_INCIDENT)
            note_bits.append("Open an incident for tracking and accountability.")

        if self.policy.recommend_human_review_on_high:
            actions.append(RecommendedAction.REQUIRE_HUMAN_REVIEW)
            note_bits.append("Human review required due to impact risk and accountability requirements.")

        expires_at = time.time() + self.policy.hard_block_seconds
        note = " ".join(note_bits)

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
            explanation=self._explain(a, score, actions, note=note),
        )

    # ------------------------------
    # RECORDING / AUDIT
    # ------------------------------
    def record_directive(self, mode: SentinelMode, d: ResponseDirective) -> Optional[DecisionRecord]:
        if d.primary_action == RecommendedAction.LOG_ONLY and not d.additional_actions:
            # Still log to event_logs; skip decision table to reduce noise.
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
                "Duplicate recommendation suppressed (dedupe window)",
                {"dedupe_key": dedupe_key, "ttl_seconds": self.dedupe_ttl_seconds},
            )
            return None

        decision_id = self._new_decision_id()
        now_ms = _now_ms()

        # Mode controls workflow staging only:
        status = DecisionStatus.STAGED if mode in (SentinelMode.HUMAN_GATED,) else DecisionStatus.RECORDED

        actions_json = _json_dumps(
            {
                "primary": d.primary_action.name,
                "additional": [a.name for a in d.additional_actions],
                "expires_at": d.expires_at,
                "suggested_review_window_seconds": self.policy.suggested_review_window_seconds,
            }
        )

        rec = DecisionRecord(
            decision_id=decision_id,
            created_at_ms=now_ms,
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
            explanation=d.explanation,
            system_id=SYSTEM_ID,
        )

        self.store.insert_decision(rec)

        # PII-safe logging: hash target
        self.store.log_event(
            "INFO",
            "AUDIT",
            "Decision recorded",
            {
                "decision_id": rec.decision_id,
                "status": rec.status.value,
                "mode": mode.value,
                "target_type": rec.target_type,
                "target_hash": pseudonymize(rec.target_value),
                "primary_action": rec.primary_action,
                "severity": rec.severity,
                "kind": rec.kind,
                "score": rec.score,
            },
        )

        return rec

    def _pick_primary_target(self, d: ResponseDirective) -> Tuple[str, str]:
        ip_actions = {RecommendedAction.TEMP_BLOCK_IP, RecommendedAction.HARD_BLOCK_IP}
        if d.primary_action in ip_actions:
            return ("ip", d.source_ip)
        return ("identity", d.identity)

    def _new_decision_id(self) -> str:
        return f"DEC-{uuid.uuid4().hex}".upper()


# ============================================================
# SENTINEL NEXUS (human-facing wrapper, still advisory-only)
# ============================================================

class SentinelNexus:
    """
    Thin facade for simple event intake -> assessment mapping -> recommendation record.
    This is NOT a detector and does NOT execute anything.
    """

    def __init__(
        self,
        *,
        mode: SentinelMode = SentinelMode.ADVISORY,
        source_id: str = "sensor.local",
        operator_authenticator: Optional[Callable[[str], bool]] = None,
        store: Optional[DecisionStore] = None,
        policy: Optional[ResponsePolicy] = None,
    ) -> None:
        self._mode = mode
        self._source_id = sanitize_key_component(source_id, max_len=80) or "sensor.local"

        self.engine = Sentinel43Engine(
            store=store,
            policy=policy,
            operator_authenticator=operator_authenticator,
        )

        self.engine.store.log_event(
            "INFO",
            "NEXUS",
            "Nexus online (advisory-only).",
            {"system_id": SYSTEM_ID, "mode": self._mode.value, "source_id": self._source_id},
        )

    def set_mode(self, mode: SentinelMode) -> None:
        self._mode = mode
        self.engine.store.log_event("WARN", "NEXUS", "Mode changed", {"mode": self._mode.value})

    def get_mode(self) -> SentinelMode:
        return self._mode

    def handle_event(
        self,
        *,
        identity: str,
        source_ip: str,
        event_kind: str,
        severity: str,
        score: float,
        source_kind: str = "MIXED_OR_UNKNOWN",
        tags: Optional[List[str]] = None,
    ) -> Optional[DecisionRecord]:
        """
        Public-safe event handler:
        - normalizes IP
        - maps string fields into enums deterministically
        - records recommendation + explanation + audit
        """
        ip = normalize_ip(source_ip)

        kind_map = {
            "GENERIC_INTRUSION": ThreatKind.GENERIC_INTRUSION,
            "MALWARE_DELIVERY": ThreatKind.MALWARE_DELIVERY,
            "SPYWARE_ACTIVITY": ThreatKind.SPYWARE_ACTIVITY,
            "DATA_EXFILTRATION": ThreatKind.DATA_EXFILTRATION,
            "CREDENTIAL_ATTACK": ThreatKind.CREDENTIAL_ATTACK,
        }
        sev_map = {
            "LOW": ThreatSeverity.LOW,
            "MEDIUM": ThreatSeverity.MEDIUM,
            "HIGH": ThreatSeverity.HIGH,
            "CRITICAL": ThreatSeverity.CRITICAL,
        }
        src_map = {
            "HUMAN_LIKELY": ThreatSourceKind.HUMAN_LIKELY,
            "AI_AUTOMATION_LIKELY": ThreatSourceKind.AI_AUTOMATION_LIKELY,
            "MIXED_OR_UNKNOWN": ThreatSourceKind.MIXED_OR_UNKNOWN,
        }

        k = kind_map.get((event_kind or "").strip().upper(), ThreatKind.UNKNOWN)
        s = sev_map.get((severity or "").strip().upper(), ThreatSeverity.MEDIUM)
        sk = src_map.get((source_kind or "").strip().upper(), ThreatSourceKind.MIXED_OR_UNKNOWN)

        a = ThreatAssessment(
            identity=str(identity or "").strip() or "unknown",
            source_ip=ip,
            threat_kind=k,
            severity=s,
            source_kind=sk,
            score=float(score),
            supporting_tags=list(tags or []),
            window_size=0,
        )

        return self.engine.handle_assessment(self._mode, a)

    # Adapter support:
    def export_approved(self, limit: int = 50) -> List[dict]:
        """
        Approved decisions can be pulled by external adapters.
        Core does not execute; it only exports.
        """
        return self.engine.store.export_approved(limit=limit)


# ============================================================
# SELF-TEST (safe: logs + DB only)
# ============================================================

if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")

    allowed = {s.strip() for s in _env("SENTINEL_ALLOWED_OPERATORS", "admin,ops").split(",") if s.strip()}
    auth = lambda op: op in allowed

    nexus = SentinelNexus(mode=SentinelMode.HUMAN_GATED, source_id="sensor.local", operator_authenticator=auth)

    rec = nexus.handle_event(
        identity="ai-bot-777",
        source_ip="192.0.2.10",
        event_kind="CREDENTIAL_ATTACK",
        severity="HIGH",
        score=72.5,
        source_kind="AI_AUTOMATION_LIKELY",
        tags=["failed_login"],
    )

    print("Decision:", rec)

    # Approve (still no execution; only status changes for adapters)
    if rec and rec.status == DecisionStatus.STAGED:
        ok = nexus.engine.approve(rec.decision_id, operator_id="admin", reason="reviewed and approved for adapter")
        print("Approved:", ok)

    print("Export approved:", nexus.export_approved(limit=10))

    
