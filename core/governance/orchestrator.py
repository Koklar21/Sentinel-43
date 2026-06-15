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

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, Mapping, Optional, Set

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
# Governance modes
# ------------------------------------------------------------

# Fix #2: explicit allow-list of governance modes. Anything outside this
# set (or any caller-requested override of the configured default_mode by
# a non-privileged caller) is rejected/ignored rather than passed straight
# through to the policy gate.
ALLOWED_MODES: Set[str] = {"SHADOW", "HUMAN_GATED", "AUTONOMOUS_VETO"}


# ------------------------------------------------------------
# Sanity bounds for transaction amounts
# ------------------------------------------------------------

# Fix #3: Decimal("NaN") / Decimal("Infinity") / Decimal("1E+999999999") all
# construct successfully with no exception, which previously let them
# through as "valid" amounts. is_finite() rejects NaN/Infinity/-Infinity;
# this bound additionally rejects absurdly large magnitudes that could
# cause downstream issues (string blow-up, scoring overflow, etc).
#
# NOTE: this intentionally does NOT enforce amount > 0 -- whether zero or
# negative amounts (e.g. refunds/reversals) are valid is a business-rule
# decision for the policy layer, not this orchestrator.
MAX_TRANSACTION_AMOUNT = Decimal("1e15")


# ------------------------------------------------------------
# Data models
# ------------------------------------------------------------

@dataclass(frozen=True)
class CallerContext:
    caller_id: str
    caller_roles: Set[str]
    authenticated_at: datetime

    def __post_init__(self) -> None:
        # Fix #5: normalize to an immutable frozenset so a mutable Set[str]
        # passed in by the caller can't be mutated out from under this
        # "frozen" dataclass after construction (mutable-container-in-
        # frozen-dataclass pattern).
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
        # Fix #5: previously `metadata=metadata or {}` aliased the caller's
        # dict directly, so mutating the caller's dict after construction
        # would mutate this "frozen" context too. Take a defensive copy and
        # wrap it in an immutable view.
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


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
    # Fix #8: previously `getattr(settings, "data_dir")` had no default and
    # raised a bare AttributeError with no context if missing.
    data_dir_raw = getattr(settings, "data_dir", None)
    if not data_dir_raw:
        raise RuntimeError("settings.data_dir is required to build the audit store path.")
    data_dir = Path(data_dir_raw)
    audit_db = data_dir / "ghost_audit.db"

    # Optional JSONL sink (explicit opt-in env only)
    jsonl_raw = (getattr(settings, "audit_jsonl_path", "") or "").strip()
    jsonl_path = Path(jsonl_raw).expanduser().resolve() if jsonl_raw else None

    # Signing key: prefer settings.audit_signing_key
    signing_key = (getattr(settings, "audit_signing_key", "") or "").strip()
    if not signing_key:
        # Fix #1: the dev-only fallback key used to be gated on
        # `strict and env != "dev"`, meaning ANY deployment with
        # strict_mode=False (including prod) would silently fall back to
        # this hardcoded, publicly-known signing key -- completely
        # defeating tamper-resistant audit. The fallback is now gated
        # solely on env == "dev", independent of strict_mode.
        if env == "dev":
            signing_key = "dev-only-change-me"
            _logger.warning(
                "audit_signing_key not set; using insecure development "
                "default signing key. This must never be used outside env='dev'."
            )
        else:
            raise RuntimeError(
                f"audit_signing_key is required for tamper-resistant audit "
                f"outside of env='dev' (env={env!r})."
            )

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
        hash_device_ids=bool(getattr(settings, "hash_device_ids", False)),
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
        hash_device_ids: bool = False,
    ) -> None:
        self.audit_store = audit_store
        self.velocity_guard = velocity_guard
        self.env = (env or "prod").lower()
        self.strict_mode = bool(strict_mode)

        normalized_default_mode = (default_mode or "SHADOW").upper()
        if normalized_default_mode not in ALLOWED_MODES:
            raise ValueError(
                f"default_mode={default_mode!r} is not a recognized governance "
                f"mode (expected one of {sorted(ALLOWED_MODES)})."
            )
        self.default_mode = normalized_default_mode

        self.authorizer = authorizer or self._default_authorizer

        # Fix #10: raw device_id was stored unhashed in the audit log with
        # only a comment flagging it as a TODO. Make hashing an explicit,
        # opt-in setting -- defaults preserve existing behavior, but this
        # gives an easy switch ahead of the mobile rollout where device_id
        # is more likely to be a long-lived per-device identifier.
        self.hash_device_ids = bool(hash_device_ids)

    @staticmethod
    def _default_authorizer(caller: CallerContext, target_user_id: str) -> bool:
        # Default: self-only unless privileged
        if caller.caller_id == target_user_id:
            return True
        if "admin" in caller.caller_roles or "system" in caller.caller_roles:
            return True
        return False

    @staticmethod
    def _is_privileged(caller: CallerContext) -> bool:
        return "admin" in caller.caller_roles or "system" in caller.caller_roles

    def _resolve_mode(self, caller: CallerContext, requested_mode: Optional[str]) -> str:
        """
        Fix #2: previously `mode=(mode or self.default_mode)` passed any
        caller-supplied string straight to PolicyContext, with no
        validation and no authorization check -- letting any caller
        override the configured governance mode (e.g. force SHADOW to
        bypass HUMAN_GATED/AUTONOMOUS_VETO enforcement).

        Now: unrecognized mode strings are ignored (fall back to
        default_mode), and overriding the configured default_mode to a
        *different* recognized mode requires the caller to be privileged
        (admin/system).
        """
        if requested_mode is None:
            return self.default_mode

        normalized = requested_mode.strip().upper()

        if normalized not in ALLOWED_MODES:
            _logger.warning(
                "Ignoring unrecognized governance mode %r requested by caller_id=%s; "
                "using default_mode=%s",
                requested_mode, caller.caller_id, self.default_mode,
            )
            return self.default_mode

        if normalized != self.default_mode and not self._is_privileged(caller):
            _logger.warning(
                "Ignoring mode override to %r requested by non-privileged "
                "caller_id=%s; using default_mode=%s",
                normalized, caller.caller_id, self.default_mode,
            )
            return self.default_mode

        return normalized

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

        # Fix #3: Decimal("NaN")/Decimal("Infinity")/Decimal("-Infinity") and
        # absurdly large exponents all construct successfully above with no
        # exception. NaN in particular is dangerous: any threshold check of
        # the form `amount >= limit` is always False for NaN, silently
        # bypassing amount-based policy thresholds (e.g. "require human
        # review above $X").
        #
        # `not amount.is_finite()` covers NaN/Infinity/-Infinity and
        # short-circuits before the comparisons below (NaN comparisons
        # raise InvalidOperation under the default context). For the
        # magnitude check, deliberately avoid abs(amount): for a huge but
        # finite Decimal (e.g. 1E+999999999), abs() itself raises
        # decimal.Overflow under the default context, so compare against
        # +/- the bound directly instead.
        if (
            not amount.is_finite()
            or amount > MAX_TRANSACTION_AMOUNT
            or amount < -MAX_TRANSACTION_AMOUNT
        ):
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

        effective_mode = self._resolve_mode(caller, mode)

        pctx = PolicyContext(
            action=action,
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

        pdec = evaluate(pctx)

        # Basic score placeholder (wire your scoring engine later)
        score = Decimal("0.5")

        if not pdec.allowed:
            if pdec.status == "REQUIRES_HUMAN":
                # Fix #4: previously the audit-append result was discarded
                # here, unlike the APPROVED path below. If the audit store
                # is down, a REVIEW decision would be returned to the
                # caller but never persisted -- meaning it would likely
                # never reach the human-gated approval queue, with no
                # signal that this happened. Apply the same fail-closed
                # behavior as the APPROVED path.
                ok = self._best_effort_audit(
                    context=tctx,
                    decision="REVIEW",
                    reason_code=ReasonCodes.POLICY_REQUIRES_HUMAN,
                    score=score,
                    extra={"policy": pdec.to_dict(), "caller_id": caller.caller_id},
                    metadata=metadata,
                    user_id=user_id,
                )

                if not ok and self.env != "dev" and self.strict_mode:
                    return Decision(status="BLOCKED", score=Decimal("0"), reason=ReasonCodes.AUDIT_APPEND_FAILED)

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

    def _maybe_hash_device_id(self, device_id: str) -> str:
        if not self.hash_device_ids:
            return device_id
        digest = hashlib.sha256(device_id.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

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
                        "device_id": self._maybe_hash_device_id(context.device_id),
                        "timestamp": context.timestamp.isoformat(),
                    }
                )

            self.audit_store.append(payload)
            return True
        except Exception as e:
            _logger.error("Audit append failed: %s", e)
            return False
