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

import hashlib
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, Mapping, Optional, Set
from uuid import uuid4

from core.audit.store import AuditConfig, AuditStore
from core.guards.velocity import VelocityConfig, VelocityGuard
from core.policy_gate import PolicyContext, evaluate

_logger = logging.getLogger("sentinel43.governance")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# Reason codes
# =============================================================================

class ReasonCodes:
    CLEARED               = "CLEARED"
    AUTHORIZATION_FAILED  = "AUTHORIZATION_FAILED"
    AUDIT_APPEND_FAILED   = "AUDIT_APPEND_FAILED"
    VELOCITY_LIMIT        = "VELOCITY_LIMIT"
    VELOCITY_CAP_EXCEEDED = "VELOCITY_CAP_EXCEEDED"
    INVALID_INPUT         = "INVALID_INPUT"
    POLICY_DENY           = "POLICY_DENY"
    POLICY_REQUIRES_HUMAN = "POLICY_REQUIRES_HUMAN"
    HUMAN_APPROVED        = "HUMAN_APPROVED"
    HUMAN_VETOED          = "HUMAN_VETOED"
    REVIEW_NOT_FOUND      = "REVIEW_NOT_FOUND"


# =============================================================================
# Governance modes
# =============================================================================

ALLOWED_MODES: Set[str] = {"SHADOW", "HUMAN_GATED", "AUTONOMOUS_VETO"}

MAX_TRANSACTION_AMOUNT = Decimal("1e15")


# =============================================================================
# Data models
# =============================================================================

@dataclass(frozen=True)
class CallerContext:
    caller_id: str
    caller_roles: Set[str]
    authenticated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "caller_roles", frozenset(self.caller_roles))


@dataclass(frozen=True)
class TransactionContext:
    user_id: str
    amount: Decimal
    timestamp: datetime
    location: str
    device_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True)
class Decision:
    status: str          # APPROVED | REVIEW | BLOCKED
    score: Decimal
    reason: str
    # Populated for REVIEW decisions so callers can route the decision_id
    # to the mobile approve/veto queue and later call resolve_human_decision().
    decision_id: str = ""


# =============================================================================
# Settings bridge
# =============================================================================

def build_orchestrator_from_settings(
    settings,
    *,
    monitoring_manager: Optional[Any] = None,
) -> "SystemOrchestrator":
    """
    Build a SystemOrchestrator from a pydantic Settings object.

    monitoring_manager: optional MonitoringManager. When supplied, governance
    security events (auth failures, REVIEW decisions, audit failures) are
    routed through the monitoring pipeline for Watchtower alerting and
    SentinelWindowStore threat scoring.

    Set S43_JORM_ENABLED=true to swap the plain AuditStore for a
    JormungandrNode (AEAD-encrypted, hash-chained audit log). The signing
    key from settings.audit_signing_key is used as the Jormungandr root key.
    In production, supply a KMS-derived key via this setting.
    """
    env    = getattr(settings, "env", "prod")
    strict = bool(getattr(settings, "strict_mode", True))

    data_dir_raw = getattr(settings, "data_dir", None)
    if not data_dir_raw:
        raise RuntimeError("settings.data_dir is required to build the audit store path.")
    data_dir  = Path(data_dir_raw)
    audit_db  = data_dir / "ghost_audit.db"

    jsonl_raw  = (getattr(settings, "audit_jsonl_path", "") or "").strip()
    jsonl_path = Path(jsonl_raw).expanduser().resolve() if jsonl_raw else None

    signing_key = (getattr(settings, "audit_signing_key", "") or "").strip()
    if not signing_key:
        if env == "dev":
            signing_key = "dev-only-change-me"
            _logger.warning(
                "audit_signing_key not set; using insecure dev default. "
                "Never use outside env='dev'."
            )
        else:
            raise RuntimeError(
                f"audit_signing_key is required for tamper-resistant audit "
                f"outside of env='dev' (env={env!r})."
            )

    # Optional Jormungandr swap: S43_JORM_ENABLED=true replaces the plain
    # AuditStore with a JormungandrNode (AEAD-encrypted, hash-chained log).
    import os
    use_jorm = os.getenv("S43_JORM_ENABLED", "").lower() in {"1", "true", "yes"}
    if use_jorm:
        try:
            from core.monitoring import build_jormungandr
            audit_store: Any = build_jormungandr(
                root_key=signing_key.encode(),
                monitoring_manager=monitoring_manager,
            )
            _logger.info("Governance audit store: JormungandrNode (AEAD-encrypted)")
        except ImportError:
            _logger.warning(
                "S43_JORM_ENABLED=true but JormungandrNode is unavailable "
                "(cryptography package missing?). Falling back to AuditStore."
            )
            use_jorm = False

    if not use_jorm:
        audit_cfg   = AuditConfig(
            sqlite_path=audit_db,
            jsonl_path=jsonl_path,
            signing_key=signing_key,
        )
        audit_store = AuditStore(audit_cfg)
        _logger.info("Governance audit store: AuditStore (SQLite)")

    vel_cfg = VelocityConfig(
        window_seconds=int(getattr(settings, "velocity_window_seconds", 60)),
        limit=int(getattr(settings, "velocity_limit", 10)),
        gc_interval_seconds=int(getattr(settings, "velocity_gc_interval_seconds", 300)),
        max_entries_per_user=int(getattr(settings, "velocity_max_entries_per_user", 1000)),
    )

    return SystemOrchestrator(
        audit_store=audit_store,
        velocity_guard=VelocityGuard(vel_cfg),
        env=env,
        strict_mode=strict,
        default_mode=str(getattr(settings, "default_mode", "SHADOW")),
        hash_device_ids=bool(getattr(settings, "hash_device_ids", False)),
        monitoring_manager=monitoring_manager,
    )


# =============================================================================
# Orchestrator
# =============================================================================

class SystemOrchestrator:
    """
    Governance orchestrator:
    - authorization
    - velocity guard
    - PolicyGate evaluation (SHADOW / HUMAN_GATED / AUTONOMOUS_VETO)
    - tamper-resistant audit (AuditStore or JormungandrNode)
    - pending REVIEW decision tracking for mobile approve/veto

    MonitoringManager integration
    -----------------------------
    When monitoring_manager is supplied, security-relevant events
    (auth failures, REVIEW decisions, audit write failures) are routed
    through analyze_event() so they surface in Watchtower alerts and
    accumulate in SentinelWindowStore for threat scoring.

    Human-gated workflow
    --------------------
    When default_mode=HUMAN_GATED and a transaction requires human review,
    process_transaction() returns Decision(status="REVIEW", decision_id=...)
    and stores the pending review internally. The caller (e.g. main.py
    approve/veto route or the remote gateway APPROVE_DECISION handler)
    calls resolve_human_decision(decision_id, approved=...) to complete
    the flow and write the final audit record.
    """

    def __init__(
        self,
        *,
        audit_store: Any,           # AuditStore or JormungandrNode (both have append())
        velocity_guard: VelocityGuard,
        env: str,
        strict_mode: bool,
        default_mode: str,
        authorizer: Optional[Callable[[CallerContext, str], bool]] = None,
        hash_device_ids: bool = False,
        monitoring_manager: Optional[Any] = None,
    ) -> None:
        self.audit_store       = audit_store
        self.velocity_guard    = velocity_guard
        self.env               = (env or "prod").lower()
        self.strict_mode       = bool(strict_mode)
        self.hash_device_ids   = bool(hash_device_ids)
        self._monitoring_manager = monitoring_manager

        normalized = (default_mode or "SHADOW").upper()
        if normalized not in ALLOWED_MODES:
            raise ValueError(
                f"default_mode={default_mode!r} is not a recognized governance mode "
                f"(expected one of {sorted(ALLOWED_MODES)})."
            )
        self.default_mode = normalized
        self.authorizer   = authorizer or self._default_authorizer

        # Pending HUMAN_GATED reviews awaiting operator decision.
        # decision_id -> {user_id, amount, score, caller_id, created_at, context}
        self._pending_reviews: dict[str, dict[str, Any]] = {}
        self._pending_reviews_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Authorisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _default_authorizer(caller: CallerContext, target_user_id: str) -> bool:
        if caller.caller_id == target_user_id:
            return True
        return "admin" in caller.caller_roles or "system" in caller.caller_roles

    @staticmethod
    def _is_privileged(caller: CallerContext) -> bool:
        return "admin" in caller.caller_roles or "system" in caller.caller_roles

    def _resolve_mode(self, caller: CallerContext, requested_mode: Optional[str]) -> str:
        if requested_mode is None:
            return self.default_mode

        normalized = requested_mode.strip().upper()
        if normalized not in ALLOWED_MODES:
            _logger.warning(
                "Ignoring unrecognized governance mode %r from caller_id=%s; "
                "using default_mode=%s",
                requested_mode, caller.caller_id, self.default_mode,
            )
            return self.default_mode

        if normalized != self.default_mode and not self._is_privileged(caller):
            _logger.warning(
                "Ignoring mode override to %r from non-privileged caller_id=%s; "
                "using default_mode=%s",
                normalized, caller.caller_id, self.default_mode,
            )
            return self.default_mode

        return normalized

    # ------------------------------------------------------------------
    # MonitoringManager integration
    # ------------------------------------------------------------------

    def _notify_monitoring(self, event: dict[str, Any]) -> None:
        """Route a governance security event into the monitoring pipeline. Best-effort."""
        if self._monitoring_manager is None:
            return
        try:
            import threading as _t
            _t.Thread(
                target=self._monitoring_manager.analyze_event,
                args=(event,),
                daemon=True,
            ).start()
        except Exception as exc:
            _logger.debug("MonitoringManager notification failed: %s", exc)

    # ------------------------------------------------------------------
    # Transaction processing
    # ------------------------------------------------------------------

    def process_transaction(
        self,
        *,
        caller: CallerContext,
        user_id: str,
        amount_str: str,
        metadata: Dict[str, Any],
        mode: Optional[str] = None,
    ) -> Decision:

        # --- AUTHZ ---
        if not self.authorizer(caller, user_id):
            self._best_effort_audit(
                context=None, decision="BLOCKED",
                reason_code=ReasonCodes.AUTHORIZATION_FAILED,
                score=Decimal("0"),
                extra={"caller_id": caller.caller_id, "caller_roles": sorted(caller.caller_roles)},
                metadata=metadata, user_id=user_id,
            )
            self._notify_monitoring({
                "kind": "security", "auth_failure": True,
                "event_category": "governance_authz_failure",
                "caller_id": caller.caller_id,
            })
            return Decision(status="BLOCKED", score=Decimal("0"),
                            reason=ReasonCodes.AUTHORIZATION_FAILED)

        # --- AMOUNT VALIDATION ---
        try:
            amount = Decimal(amount_str)
        except Exception:
            self._best_effort_audit(
                context=None, decision="BLOCKED",
                reason_code=ReasonCodes.INVALID_INPUT, score=Decimal("0"),
                extra={"amount_str": amount_str, "caller_id": caller.caller_id},
                metadata=metadata, user_id=user_id,
            )
            return Decision(status="BLOCKED", score=Decimal("0"),
                            reason=ReasonCodes.INVALID_INPUT)

        if (
            not amount.is_finite()
            or amount > MAX_TRANSACTION_AMOUNT
            or amount < -MAX_TRANSACTION_AMOUNT
        ):
            self._best_effort_audit(
                context=None, decision="BLOCKED",
                reason_code=ReasonCodes.INVALID_INPUT, score=Decimal("0"),
                extra={"amount_str": amount_str, "caller_id": caller.caller_id},
                metadata=metadata, user_id=user_id,
            )
            return Decision(status="BLOCKED", score=Decimal("0"),
                            reason=ReasonCodes.INVALID_INPUT)

        now = datetime.now(timezone.utc)

        # --- VELOCITY ---
        allowed, v_reason = self.velocity_guard.allow(user_id, now)
        if not allowed:
            reason = (ReasonCodes.VELOCITY_LIMIT
                      if v_reason == "VELOCITY_LIMIT"
                      else ReasonCodes.VELOCITY_CAP_EXCEEDED)
            self._best_effort_audit(
                context=None, decision="BLOCKED", reason_code=reason,
                score=Decimal("0"),
                extra={"window_seconds": self.velocity_guard.cfg.window_seconds,
                       "limit": self.velocity_guard.cfg.limit},
                metadata=metadata, user_id=user_id,
            )
            return Decision(status="BLOCKED", score=Decimal("0"), reason=reason)

        # --- POLICY ---
        tctx = TransactionContext(
            user_id=user_id, amount=amount, timestamp=now,
            location=str(metadata.get("location", "UNKNOWN")),
            device_id=str(metadata.get("device_id", "UNKNOWN")),
            metadata=metadata or {},
        )
        effective_mode = self._resolve_mode(caller, mode)
        pctx = PolicyContext(
            action="write",
            actor_id=caller.caller_id,
            tenant_id=str(metadata.get("tenant_id", "default")),
            resource=f"txn:{user_id}",
            mode=effective_mode,
            metadata={
                "amount": str(amount),
                "requested_mode": mode,
                "effective_mode": effective_mode,
                **(metadata or {}),
            },
        )
        pdec   = evaluate(pctx)
        score  = Decimal("0.5")  # placeholder — wire scoring engine here

        if not pdec.allowed:
            if pdec.status == "REQUIRES_HUMAN":
                decision_id = str(uuid4())

                ok = self._best_effort_audit(
                    context=tctx, decision="REVIEW",
                    reason_code=ReasonCodes.POLICY_REQUIRES_HUMAN,
                    score=score,
                    extra={"policy": pdec.to_dict(), "caller_id": caller.caller_id,
                           "decision_id": decision_id},
                    metadata=metadata, user_id=user_id,
                )

                if not ok and self.env != "dev" and self.strict_mode:
                    return Decision(status="BLOCKED", score=Decimal("0"),
                                    reason=ReasonCodes.AUDIT_APPEND_FAILED)

                # Store for resolve_human_decision()
                with self._pending_reviews_lock:
                    self._pending_reviews[decision_id] = {
                        "decision_id": decision_id,
                        "user_id": user_id,
                        "amount": str(amount),
                        "caller_id": caller.caller_id,
                        "score": str(score),
                        "effective_mode": effective_mode,
                        "created_at": _utc_now(),
                        "transaction_context": {
                            "location": tctx.location,
                            "device_id": tctx.device_id,
                        },
                    }

                self._notify_monitoring({
                    "kind": "security",
                    "event_category": "governance_human_review_pending",
                    "decision_id": decision_id,
                    "user_id": user_id,
                    "effective_mode": effective_mode,
                })

                return Decision(status="REVIEW", score=score,
                                reason=ReasonCodes.POLICY_REQUIRES_HUMAN,
                                decision_id=decision_id)

            self._best_effort_audit(
                context=tctx, decision="BLOCKED",
                reason_code=ReasonCodes.POLICY_DENY, score=Decimal("0"),
                extra={"policy": pdec.to_dict(), "caller_id": caller.caller_id},
                metadata=metadata, user_id=user_id,
            )
            return Decision(status="BLOCKED", score=Decimal("0"),
                            reason=ReasonCodes.POLICY_DENY)

        ok = self._best_effort_audit(
            context=tctx, decision="APPROVED",
            reason_code=ReasonCodes.CLEARED, score=score,
            extra={"policy": pdec.to_dict(), "caller_id": caller.caller_id},
            metadata=metadata, user_id=user_id,
        )

        if not ok and self.env != "dev" and self.strict_mode:
            return Decision(status="BLOCKED", score=Decimal("0"),
                            reason=ReasonCodes.AUDIT_APPEND_FAILED)

        return Decision(status="APPROVED", score=score, reason=ReasonCodes.CLEARED)

    # ------------------------------------------------------------------
    # Human-gated resolution
    # ------------------------------------------------------------------

    def resolve_human_decision(
        self,
        decision_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """
        Complete a pending HUMAN_GATED decision.

        Called by:
        - main.py /actions/{id}/approve and /veto HTTP handlers
        - remote_gateway._dispatch_remote_event for APPROVE_DECISION / VETO_DECISION

        Returns the resolved review record.
        Raises KeyError if decision_id is not found in pending reviews.
        """
        with self._pending_reviews_lock:
            review = self._pending_reviews.pop(decision_id, None)

        if review is None:
            raise KeyError(
                f"No pending human review found for decision_id={decision_id!r}. "
                "It may have already been resolved, expired, or never existed."
            )

        outcome      = "APPROVED" if approved else "VETOED"
        reason_code  = ReasonCodes.HUMAN_APPROVED if approved else ReasonCodes.HUMAN_VETOED
        resolved_at  = _utc_now()

        self._best_effort_audit(
            context=None,
            decision=outcome,
            reason_code=reason_code,
            score=Decimal(review.get("score", "0.5")),
            extra={
                "decision_id": decision_id,
                "operator_id": operator_id,
                "resolution_reason": reason,
                "original_caller_id": review.get("caller_id"),
                "resolved_at": resolved_at,
            },
            metadata=review.get("transaction_context", {}),
            user_id=review.get("user_id", "unknown"),
        )

        self._notify_monitoring({
            "kind": "log",
            "event_category": "governance_human_decision_resolved",
            "decision_id": decision_id,
            "outcome": outcome,
            "operator_id": operator_id,
        })

        _logger.info(
            "Human decision resolved: decision_id=%s outcome=%s operator=%s",
            decision_id, outcome, operator_id,
        )

        return {
            "decision_id": decision_id,
            "outcome": outcome,
            "operator_id": operator_id,
            "resolved_at": resolved_at,
            "original": review,
        }

    def list_pending_reviews(self) -> list[dict[str, Any]]:
        """Return a snapshot of all pending HUMAN_GATED decisions."""
        with self._pending_reviews_lock:
            return list(self._pending_reviews.values())

    # ------------------------------------------------------------------
    # Audit helpers
    # ------------------------------------------------------------------

    def _filter_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        allowed: Dict[str, Any] = {}
        for k in ("location", "device_id", "txn_type", "channel", "risk_flags", "tenant_id"):
            if k in metadata:
                allowed[k] = metadata[k]
        return allowed

    def _maybe_hash_device_id(self, device_id: str) -> str:
        if not self.hash_device_ids:
            return device_id
        return f"sha256:{hashlib.sha256(device_id.encode()).hexdigest()}"

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
            if "device_id" in filtered:
                filtered["device_id"] = self._maybe_hash_device_id(str(filtered["device_id"]))

            payload: Dict[str, Any] = {
                "decision_time": _utc_now(),
                "user_id": user_id,
                "decision": decision,
                "reason_code": reason_code,
                "score": str(score),
                "filtered_meta": filtered,
                "extra": extra or {},
            }
            if context is not None:
                payload.update({
                    "amount": str(context.amount),
                    "location": context.location,
                    "device_id": self._maybe_hash_device_id(context.device_id),
                    "timestamp": context.timestamp.isoformat(),
                })

            self.audit_store.append(payload)
            return True

        except Exception as exc:
            _logger.error("Audit append failed: %s", exc)
            self._notify_monitoring({
                "kind": "log",
                "audit_write_failed": True,
                "event_category": "governance_audit_failure",
                "decision": decision,
                "error": str(exc),
            })
            return False
