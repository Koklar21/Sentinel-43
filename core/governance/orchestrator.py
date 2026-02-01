from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set

from core.audit.store import AuditConfig, AuditStore
from core.guards.velocity import VelocityConfig, VelocityGuard
from core.policy_gate import PolicyContext, evaluate  # uses your Option A exports

_logger = logging.getLogger("sentinel43.governance")


# ------------------------------------------------------------
# Reason Codes (keep minimal here; expand later as a shared module)
# ------------------------------------------------------------

class ReasonCodes:
    CLEARED = "CLEARED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    AUDIT_APPEND_FAILED = "AUDIT_APPEND_FAILED"
    VELOCITY_LIMIT = "VELOCITY_LIMIT"
    VELOCITY_CAP_EXCEEDED = "VELOCITY_CAP_EXCEEDED"
    INVALID_INPUT = "INVALID_INPUT"
    POLICY_DENY = "POLICY_DENY"
    POLICY_REQUIRES_HUMAN = "POLICY_REQUIRES_HUMAN"


# ------------------------------------------------------------
# Data models
# ------------------------------------------------------------

@dataclass(frozen=True)
class CallerContext:
    caller_id: str
    caller_roles: Set[str]
    authenticated_at: datetime


@dataclass(frozen=True)
class TransactionContext:
    user_id: str
    amount: Decimal
    timestamp: datetime
    location: str
    device_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    status: str  # APPROVED | REVIEW | BLOCKED
    score: Decimal
    reason: str


# ------------------------------------------------------------
# Settings bridge
# ------------------------------------------------------------

def build_orchestrator_from_settings(settings) -> "SystemOrchestrator":
    """
    settings: your core.config.Settings object (pydantic)
    """
    env = getattr(settings, "env", "prod")
    strict = bool(getattr(settings, "strict_mode", True))

    # Paths
    data_dir: Path = getattr(settings, "data_dir")
    audit_db = data_dir / "ghost_audit.db"

    # Optional JSONL sink (explicit opt-in env only)
    jsonl_raw = (getattr(settings, "audit_jsonl_path", "") or "").strip()
    jsonl_path = Path(jsonl_raw).expanduser().resolve() if jsonl_raw else None

    # Signing key: prefer settings.audit_signing_key
    signing_key = (getattr(settings, "audit_signing_key", "") or "").strip()
    if not signing_key:
        # allow dev non-strict to run without it
        if strict and env != "dev":
            raise RuntimeError("audit_signing_key is required for tamper-resistant audit in non-dev strict mode.")
        signing_key = "dev-only-change-me"  # ok only if strict is off or env is dev

    audit_cfg = AuditConfig(
        sqlite_path=audit_db,
        jsonl_path=jsonl_path,
        signing_key=signing_key,
    )

    vel_cfg = VelocityConfig(
        window_seconds=int(getattr(settings, "velocity_window_seconds", 60)),
        limit=int(getattr(settings, "velocity_limit", 10)),
        gc_interval_seconds=int(getattr(settings, "velocity_gc_interval_seconds", 300)),
        max_entries_per_user=int(getattr(settings, "velocity_max_entries_per_user", 1000)),
    )

    return SystemOrchestrator(
        audit_store=AuditStore(audit_cfg),
        velocity_guard=VelocityGuard(vel_cfg),
        env=env,
        strict_mode=strict,
        default_mode=str(getattr(settings, "default_mode", "SHADOW")),
    )


# ------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------

class SystemOrchestrator:
    """
    Governance orchestrator:
    - authorization
    - velocity guard
    - calls PolicyGate for allow/deny/require-human
    - writes tamper-resistant audit record
    """

    def __init__(
        self,
        *,
        audit_store: AuditStore,
        velocity_guard: VelocityGuard,
        env: str,
        strict_mode: bool,
        default_mode: str,
        authorizer: Optional[Callable[[CallerContext, str], bool]] = None,
    ) -> None:
        self.audit_store = audit_store
        self.velocity_guard = velocity_guard
        self.env = (env or "prod").lower()
        self.strict_mode = bool(strict_mode)
        self.default_mode = (default_mode or "SHADOW").upper()
        self.authorizer = authorizer or self._default_authorizer

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
        mode: Optional[str] = None,
    ) -> Decision:
        # --- AUTHZ FIRST ---
        if not self.authorizer(caller, user_id):
            self._best_effort_audit(
                context=None,
                decision="BLOCKED",
                reason_code=ReasonCodes.AUTHORIZATION_FAILED,
                score=Decimal("0"),
                extra={"caller_id": caller.caller_id, "caller_roles": sorted(caller.caller_roles)},
                metadata=metadata,
                user_id=user_id,
            )
            return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.AUTHORIZATION_FAILED)

        # --- INPUT VALIDATION ---
        try:
            amount = Decimal(amount_str)
        except Exception:
            self._best_effort_audit(
                context=None,
                decision="BLOCKED",
                reason_code=ReasonCodes.INVALID_INPUT,
                score=Decimal("0"),
                extra={"amount_str": amount_str, "caller_id": caller.caller_id},
                metadata=metadata,
                user_id=user_id,
            )
            return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.INVALID_INPUT)

        now = datetime.now(timezone.utc)

        allowed, v_reason = self.velocity_guard.allow(user_id, now)
        if not allowed:
            reason = ReasonCodes.VELOCITY_LIMIT if v_reason == "VELOCITY_LIMIT" else ReasonCodes.VELOCITY_CAP_EXCEEDED
            self._best_effort_audit(
                context=None,
                decision="BLOCKED",
                reason_code=reason,
                score=Decimal("0"),
                extra={"window_seconds": self.velocity_guard.cfg.window_seconds, "limit": self.velocity_guard.cfg.limit},
                metadata=metadata,
                user_id=user_id,
            )
            return Decision(status="BLOCKED", score=Decimal("0"), reason=reason)

        # --- POLICYGATE DECISION (single source of truth) ---
        tctx = TransactionContext(
            user_id=user_id,
            amount=amount,
            timestamp=now,
            location=str(metadata.get("location", "UNKNOWN")),
            device_id=str(metadata.get("device_id", "UNKNOWN")),
            metadata=metadata or {},
        )

        # map transaction → policy action (keep it simple; expand taxonomy later)
        action = "write"

        pctx = PolicyContext(
            action=action,
            actor_id=caller.caller_id,
            tenant_id=str(metadata.get("tenant_id", "default")),
            resource=f"txn:{user_id}",
            mode=(mode or self.default_mode),
            metadata={"amount": str(amount), **(metadata or {})},
        )

        pdec = evaluate(pctx)

        # Basic score placeholder (wire your scoring engine later)
        score = Decimal("0.5")

        if not pdec.allowed:
            if pdec.status == "REQUIRES_HUMAN":
                self._best_effort_audit(
                    context=tctx,
                    decision="REVIEW",
                    reason_code=ReasonCodes.POLICY_REQUIRES_HUMAN,
                    score=score,
                    extra={"policy": pdec.to_dict(), "caller_id": caller.caller_id},
                    metadata=metadata,
                    user_id=user_id,
                )
                return Decision(status="REVIEW", score=score, reason=ReasonCodes.POLICY_REQUIRES_HUMAN)

            self._best_effort_audit(
                context=tctx,
                decision="BLOCKED",
                reason_code=ReasonCodes.POLICY_DENY,
                score=Decimal("0"),
                extra={"policy": pdec.to_dict(), "caller_id": caller.caller_id},
                metadata=metadata,
                user_id=user_id,
            )
            return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.POLICY_DENY)

        # Allowed
        ok = self._best_effort_audit(
            context=tctx,
            decision="APPROVED",
            reason_code=ReasonCodes.CLEARED,
            score=score,
            extra={"policy": pdec.to_dict(), "caller_id": caller.caller_id},
            metadata=metadata,
            user_id=user_id,
        )

        # If audit fails, fail closed in non-dev strict mode
        if not ok and self.env != "dev" and self.strict_mode:
            return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.AUDIT_APPEND_FAILED)

        return Decision(status="APPROVED", score=score, reason=ReasonCodes.CLEARED)

    def _filter_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        allowed: Dict[str, Any] = {}
        for k in ("location", "device_id", "txn_type", "channel", "risk_flags", "tenant_id"):
            if k in metadata:
                allowed[k] = metadata[k]
        return allowed

    def _best_effort_audit(
        self,
        *,
        context: Optional[TransactionContext],
        decision: str,
        reason_code: str,
        score: Decimal,
        extra: Dict[str, Any],
        metadata: Dict[str, Any],
        user_id: str,
    ) -> bool:
        try:
            filtered = self._filter_metadata(metadata or {})
            payload: Dict[str, Any] = {
                "decision_time": datetime.now(timezone.utc).isoformat(),
                "user_id": user_id,
                "decision": decision,
                "reason_code": reason_code,
                "score": str(score),
                "filtered_meta": filtered,
                "extra": extra or {},
            }
            if context is not None:
                payload.update(
                    {
                        "amount": str(context.amount),
                        "location": context.location,
                        "device_id": context.device_id,  # raw device_id allowed? you can change to hashed later
                        "timestamp": context.timestamp.isoformat(),
                    }
                )

            self.audit_store.append(payload)
            return True
        except Exception as e:
            _logger.error("Audit append failed: %s", e)
            return False