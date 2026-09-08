# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Human-governed Sentinel-43 transaction governance.

Responsibilities:
    - authorize the caller
    - apply velocity limits
    - evaluate policy
    - create HUMAN_GATED review records
    - resolve reviews through explicit human approval/veto
    - append authoritative audit records

Non-responsibilities:
    - autonomous enforcement
    - storage backend selection
    - audit key generation
    - background thread creation
    - monitoring lifecycle management
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Protocol
from uuid import uuid4

from core.guards.velocity import VelocityGuard
from core.policy_gate import PolicyContext, evaluate


logger = logging.getLogger("sentinel43.governance")


MAX_TRANSACTION_AMOUNT: Final[Decimal] = Decimal("1e15")
MAX_PENDING_REVIEWS: Final[int] = 10_000
DEFAULT_REVIEW_TTL_SECONDS: Final[int] = 30 * 60


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class GovernanceMode(str, Enum):
    SHADOW = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"


class DecisionStatus(str, Enum):
    APPROVED = "APPROVED"
    REVIEW = "REVIEW"
    BLOCKED = "BLOCKED"


class ReasonCode(str, Enum):
    CLEARED = "CLEARED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    AUDIT_APPEND_FAILED = "AUDIT_APPEND_FAILED"
    VELOCITY_LIMIT = "VELOCITY_LIMIT"
    VELOCITY_CAP_EXCEEDED = "VELOCITY_CAP_EXCEEDED"
    INVALID_INPUT = "INVALID_INPUT"
    POLICY_DENY = "POLICY_DENY"
    POLICY_REQUIRES_HUMAN = "POLICY_REQUIRES_HUMAN"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    HUMAN_VETOED = "HUMAN_VETOED"
    REVIEW_NOT_FOUND = "REVIEW_NOT_FOUND"
    REVIEW_EXPIRED = "REVIEW_EXPIRED"
    REVIEW_CAPACITY_REACHED = "REVIEW_CAPACITY_REACHED"


@dataclass(frozen=True, slots=True)
class CallerContext:
    caller_id: str
    caller_roles: frozenset[str]
    authenticated_at: datetime

    def __post_init__(self) -> None:
        caller_id = self.caller_id.strip()

        if not caller_id:
            raise ValueError(
                "caller_id must not be empty"
            )

        object.__setattr__(
            self,
            "caller_id",
            caller_id,
        )

        object.__setattr__(
            self,
            "caller_roles",
            frozenset(
                role.strip().lower()
                for role in self.caller_roles
                if role.strip()
            ),
        )

        if self.authenticated_at.tzinfo is None:
            raise ValueError(
                "authenticated_at must be timezone-aware"
            )


@dataclass(frozen=True, slots=True)
class TransactionContext:
    user_id: str
    amount: Decimal
    timestamp: datetime
    location: str
    device_id: str
    metadata: Mapping[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if not self.user_id.strip():
            raise ValueError(
                "user_id must not be empty"
            )

        if not self.amount.is_finite():
            raise ValueError(
                "amount must be finite"
            )

        if self.timestamp.tzinfo is None:
            raise ValueError(
                "timestamp must be timezone-aware"
            )

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(
                dict(self.metadata)
            ),
        )


@dataclass(frozen=True, slots=True)
class Decision:
    status: DecisionStatus
    score: Decimal | None
    reason: ReasonCode
    decision_id: str = ""


@dataclass(frozen=True, slots=True)
class PendingReview:
    decision_id: str
    user_id: str
    caller_id: str
    score: Decimal | None
    effective_mode: GovernanceMode
    created_at: datetime
    expires_at: datetime
    transaction_context: TransactionContext
    policy: Mapping[str, Any]


class AuditWriter(Protocol):
    def append(
        self,
        payload: dict[str, Any],
    ) -> Any:
        ...


class MonitoringSink(Protocol):
    def analyze_event(
        self,
        event: dict[str, Any],
    ) -> Any:
        ...


class SystemOrchestrator:
    """Human-governed policy orchestration with authoritative audit."""

    def __init__(
        self,
        *,
        audit_store: AuditWriter,
        velocity_guard: VelocityGuard,
        environment: str,
        default_mode: GovernanceMode | str = GovernanceMode.HUMAN_GATED,
        authorizer: Callable[
            [CallerContext, str],
            bool,
        ] | None = None,
        hash_device_ids: bool = False,
        monitoring_manager: MonitoringSink | None = None,
        review_ttl_seconds: int = DEFAULT_REVIEW_TTL_SECONDS,
        max_pending_reviews: int = MAX_PENDING_REVIEWS,
    ) -> None:
        self.audit_store = audit_store
        self.velocity_guard = velocity_guard
        self.environment = (
            environment
            or "production"
        ).strip().lower()

        self.default_mode = self._normalize_mode(
            default_mode
        )

        self.authorizer = (
            authorizer
            or self._default_authorizer
        )

        self.hash_device_ids = bool(
            hash_device_ids
        )

        self._monitoring_manager = (
            monitoring_manager
        )

        if not 60 <= review_ttl_seconds <= 86_400:
            raise ValueError(
                "review_ttl_seconds must be between 60 and 86400"
            )

        if not 1 <= max_pending_reviews <= 100_000:
            raise ValueError(
                "max_pending_reviews must be between 1 and 100000"
            )

        self.review_ttl_seconds = (
            review_ttl_seconds
        )

        self.max_pending_reviews = (
            max_pending_reviews
        )

        self._pending_reviews: dict[
            str,
            PendingReview,
        ] = {}

        self._pending_reviews_lock = (
            threading.RLock()
        )

    @staticmethod
    def _normalize_mode(
        mode: GovernanceMode | str,
    ) -> GovernanceMode:
        if isinstance(
            mode,
            GovernanceMode,
        ):
            return mode

        normalized = str(
            mode
        ).strip().upper()

        try:
            return GovernanceMode(
                normalized
            )
        except ValueError as exc:
            raise ValueError(
                "governance mode must be SHADOW or HUMAN_GATED"
            ) from exc

    @staticmethod
    def _default_authorizer(
        caller: CallerContext,
        target_user_id: str,
    ) -> bool:
        return (
            caller.caller_id
            == target_user_id
            or "admin"
            in caller.caller_roles
        )

    @staticmethod
    def _is_privileged(
        caller: CallerContext,
    ) -> bool:
        return (
            "admin"
            in caller.caller_roles
        )

    def _resolve_mode(
        self,
        caller: CallerContext,
        requested_mode: str | None,
    ) -> GovernanceMode:
        if requested_mode is None:
            return self.default_mode

        requested = self._normalize_mode(
            requested_mode
        )

        if (
            requested
            != self.default_mode
            and not self._is_privileged(
                caller
            )
        ):
            return self.default_mode

        return requested

    def _notify_monitoring(
        self,
        event: dict[str, Any],
    ) -> None:
        manager = self._monitoring_manager

        if manager is None:
            return

        try:
            manager.analyze_event(
                event
            )
        except Exception:
            logger.debug(
                "Monitoring notification failed",
                exc_info=True,
            )

    def _append_audit(
        self,
        payload: dict[str, Any],
    ) -> None:
        try:
            self.audit_store.append(
                payload
            )
        except Exception:
            logger.error(
                "Authoritative governance audit append failed",
                exc_info=True,
            )

            self._notify_monitoring(
                {
                    "kind": "security",
                    "event_category": "governance_audit_failure",
                    "decision": payload.get(
                        "decision"
                    ),
                }
            )

            raise

    def _filter_metadata(
        self,
        metadata: Mapping[str, Any],
    ) -> dict[str, Any]:
        allowed_keys = {
            "location",
            "device_id",
            "txn_type",
            "channel",
            "risk_flags",
            "tenant_id",
        }

        return {
            key: metadata[key]
            for key in allowed_keys
            if key in metadata
        }

    def _maybe_hash_device_id(
        self,
        device_id: str,
    ) -> str:
        if not self.hash_device_ids:
            return device_id

        digest = hashlib.sha256(
            device_id.encode(
                "utf-8"
            )
        ).hexdigest()

        return (
            f"sha256:{digest}"
        )

    def _audit_record(
        self,
        *,
        context: TransactionContext | None,
        user_id: str,
        decision: DecisionStatus | str,
        reason_code: ReasonCode,
        score: Decimal | None,
        caller_id: str | None = None,
        decision_id: str | None = None,
        operator_id: str | None = None,
        resolution_reason: str | None = None,
        policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "user_id": user_id,
            "decision": (
                decision.value
                if isinstance(
                    decision,
                    DecisionStatus,
                )
                else str(
                    decision
                )
            ),
            "reason_code": reason_code.value,
            "score": (
                str(score)
                if score is not None
                else None
            ),
        }

        if caller_id is not None:
            record[
                "caller_id"
            ] = caller_id

        if decision_id is not None:
            record[
                "decision_id"
            ] = decision_id

        if operator_id is not None:
            record[
                "operator_id"
            ] = operator_id

        if resolution_reason:
            record[
                "resolution_reason"
            ] = resolution_reason

        if policy is not None:
            record[
                "policy"
            ] = dict(
                policy
            )

        if context is not None:
            filtered = self._filter_metadata(
                context.metadata
            )

            if "device_id" in filtered:
                filtered[
                    "device_id"
                ] = self._maybe_hash_device_id(
                    str(
                        filtered[
                            "device_id"
                        ]
                    )
                )

            record.update(
                {
                    "amount": str(
                        context.amount
                    ),
                    "location": context.location,
                    "device_id": self._maybe_hash_device_id(
                        context.device_id
                    ),
                    "transaction_time": context.timestamp.isoformat(),
                    "filtered_meta": filtered,
                }
            )

        return record

    def _purge_expired_reviews_locked(
        self,
        *,
        now: datetime,
    ) -> int:
        expired = [
            decision_id
            for decision_id, review
            in self._pending_reviews.items()
            if review.expires_at
            <= now
        ]

        for decision_id in expired:
            del self._pending_reviews[
                decision_id
            ]

        return len(
            expired
        )

    def process_transaction(
        self,
        *,
        caller: CallerContext,
        user_id: str,
        amount_str: str,
        metadata: Mapping[str, Any] | None = None,
        mode: str | None = None,
        risk_score: Decimal | str | None = None,
    ) -> Decision:
        metadata = dict(
            metadata
            or {}
        )

        if not self.authorizer(
            caller,
            user_id,
        ):
            record = self._audit_record(
                context=None,
                user_id=user_id,
                decision=DecisionStatus.BLOCKED,
                reason_code=ReasonCode.AUTHORIZATION_FAILED,
                score=None,
                caller_id=caller.caller_id,
            )

            try:
                self._append_audit(
                    record
                )
            except Exception:
                return Decision(
                    status=DecisionStatus.BLOCKED,
                    score=None,
                    reason=ReasonCode.AUDIT_APPEND_FAILED,
                )

            self._notify_monitoring(
                {
                    "kind": "security",
                    "event_category": "governance_authz_failure",
                    "caller_id": caller.caller_id,
                }
            )

            return Decision(
                status=DecisionStatus.BLOCKED,
                score=None,
                reason=ReasonCode.AUTHORIZATION_FAILED,
            )

        try:
            amount = Decimal(
                amount_str
            )
        except (
            InvalidOperation,
            ValueError,
            TypeError,
        ):
            return Decision(
                status=DecisionStatus.BLOCKED,
                score=None,
                reason=ReasonCode.INVALID_INPUT,
            )

        if (
            not amount.is_finite()
            or abs(
                amount
            )
            > MAX_TRANSACTION_AMOUNT
        ):
            return Decision(
                status=DecisionStatus.BLOCKED,
                score=None,
                reason=ReasonCode.INVALID_INPUT,
            )

        score: Decimal | None

        if risk_score is None:
            score = None
        else:
            try:
                score = Decimal(
                    str(
                        risk_score
                    )
                )
            except (
                InvalidOperation,
                ValueError,
                TypeError,
            ):
                return Decision(
                    status=DecisionStatus.BLOCKED,
                    score=None,
                    reason=ReasonCode.INVALID_INPUT,
                )

            if (
                not score.is_finite()
                or score < 0
                or score > 100
            ):
                return Decision(
                    status=DecisionStatus.BLOCKED,
                    score=None,
                    reason=ReasonCode.INVALID_INPUT,
                )

        now = _utc_now()

        allowed, velocity_reason = (
            self.velocity_guard.allow(
                user_id,
                now,
            )
        )

        if not allowed:
            reason = (
                ReasonCode.VELOCITY_LIMIT
                if velocity_reason
                == "VELOCITY_LIMIT"
                else ReasonCode.VELOCITY_CAP_EXCEEDED
            )

            record = self._audit_record(
                context=None,
                user_id=user_id,
                decision=DecisionStatus.BLOCKED,
                reason_code=reason,
                score=score,
                caller_id=caller.caller_id,
            )

            try:
                self._append_audit(
                    record
                )
            except Exception:
                return Decision(
                    status=DecisionStatus.BLOCKED,
                    score=score,
                    reason=ReasonCode.AUDIT_APPEND_FAILED,
                )

            return Decision(
                status=DecisionStatus.BLOCKED,
                score=score,
                reason=reason,
            )

        context = TransactionContext(
            user_id=user_id,
            amount=amount,
            timestamp=now,
            location=str(
                metadata.get(
                    "location",
                    "UNKNOWN",
                )
            ),
            device_id=str(
                metadata.get(
                    "device_id",
                    "UNKNOWN",
                )
            ),
            metadata=metadata,
        )

        effective_mode = self._resolve_mode(
            caller,
            mode,
        )

        policy_context = PolicyContext(
            action="write",
            actor_id=caller.caller_id,
            tenant_id=str(
                metadata.get(
                    "tenant_id",
                    "default",
                )
            ),
            resource=f"txn:{user_id}",
            mode=effective_mode.value,
            metadata={
                "amount": str(
                    amount
                ),
                "requested_mode": mode,
                "effective_mode": effective_mode.value,
                **metadata,
            },
        )

        policy_decision = evaluate(
            policy_context
        )

        policy_payload = (
            policy_decision.to_dict()
        )

        if not policy_decision.allowed:
            if (
                policy_decision.status
                == "REQUIRES_HUMAN"
            ):
                if (
                    effective_mode
                    is GovernanceMode.SHADOW
                ):
                    record = self._audit_record(
                        context=context,
                        user_id=user_id,
                        decision=DecisionStatus.REVIEW,
                        reason_code=ReasonCode.POLICY_REQUIRES_HUMAN,
                        score=score,
                        caller_id=caller.caller_id,
                        policy=policy_payload,
                    )

                    try:
                        self._append_audit(
                            record
                        )
                    except Exception:
                        return Decision(
                            status=DecisionStatus.BLOCKED,
                            score=score,
                            reason=ReasonCode.AUDIT_APPEND_FAILED,
                        )

                    return Decision(
                        status=DecisionStatus.REVIEW,
                        score=score,
                        reason=ReasonCode.POLICY_REQUIRES_HUMAN,
                    )

                decision_id = str(
                    uuid4()
                )

                expires_at = (
                    now
                    + timedelta(
                        seconds=self.review_ttl_seconds
                    )
                )

                review = PendingReview(
                    decision_id=decision_id,
                    user_id=user_id,
                    caller_id=caller.caller_id,
                    score=score,
                    effective_mode=effective_mode,
                    created_at=now,
                    expires_at=expires_at,
                    transaction_context=context,
                    policy=MappingProxyType(
                        dict(
                            policy_payload
                        )
                    ),
                )

                with self._pending_reviews_lock:
                    self._purge_expired_reviews_locked(
                        now=now
                    )

                    if (
                        len(
                            self._pending_reviews
                        )
                        >= self.max_pending_reviews
                    ):
                        return Decision(
                            status=DecisionStatus.BLOCKED,
                            score=score,
                            reason=ReasonCode.REVIEW_CAPACITY_REACHED,
                        )

                    self._pending_reviews[
                        decision_id
                    ] = review

                record = self._audit_record(
                    context=context,
                    user_id=user_id,
                    decision=DecisionStatus.REVIEW,
                    reason_code=ReasonCode.POLICY_REQUIRES_HUMAN,
                    score=score,
                    caller_id=caller.caller_id,
                    decision_id=decision_id,
                    policy=policy_payload,
                )

                try:
                    self._append_audit(
                        record
                    )
                except Exception:
                    with self._pending_reviews_lock:
                        self._pending_reviews.pop(
                            decision_id,
                            None,
                        )

                    return Decision(
                        status=DecisionStatus.BLOCKED,
                        score=score,
                        reason=ReasonCode.AUDIT_APPEND_FAILED,
                    )

                self._notify_monitoring(
                    {
                        "kind": "security",
                        "event_category": "governance_human_review_pending",
                        "decision_id": decision_id,
                        "user_id": user_id,
                    }
                )

                return Decision(
                    status=DecisionStatus.REVIEW,
                    score=score,
                    reason=ReasonCode.POLICY_REQUIRES_HUMAN,
                    decision_id=decision_id,
                )

            record = self._audit_record(
                context=context,
                user_id=user_id,
                decision=DecisionStatus.BLOCKED,
                reason_code=ReasonCode.POLICY_DENY,
                score=score,
                caller_id=caller.caller_id,
                policy=policy_payload,
            )

            try:
                self._append_audit(
                    record
                )
            except Exception:
                return Decision(
                    status=DecisionStatus.BLOCKED,
                    score=score,
                    reason=ReasonCode.AUDIT_APPEND_FAILED,
                )

            return Decision(
                status=DecisionStatus.BLOCKED,
                score=score,
                reason=ReasonCode.POLICY_DENY,
            )

        record = self._audit_record(
            context=context,
            user_id=user_id,
            decision=DecisionStatus.APPROVED,
            reason_code=ReasonCode.CLEARED,
            score=score,
            caller_id=caller.caller_id,
            policy=policy_payload,
        )

        try:
            self._append_audit(
                record
            )
        except Exception:
            return Decision(
                status=DecisionStatus.BLOCKED,
                score=score,
                reason=ReasonCode.AUDIT_APPEND_FAILED,
            )

        return Decision(
            status=DecisionStatus.APPROVED,
            score=score,
            reason=ReasonCode.CLEARED,
        )

    def resolve_human_decision(
        self,
        decision_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str = "",
    ) -> dict[str, Any]:
        decision_id = decision_id.strip()
        operator_id = operator_id.strip()

        if not decision_id:
            raise ValueError(
                "decision_id must not be empty"
            )

        if not operator_id:
            raise ValueError(
                "operator_id must not be empty"
            )

        now = _utc_now()

        with self._pending_reviews_lock:
            self._purge_expired_reviews_locked(
                now=now
            )

            review = self._pending_reviews.get(
                decision_id
            )

            if review is None:
                raise KeyError(
                    decision_id
                )

            if review.expires_at <= now:
                del self._pending_reviews[
                    decision_id
                ]
                raise TimeoutError(
                    decision_id
                )

        outcome = (
            DecisionStatus.APPROVED
            if approved
            else "VETOED"
        )

        reason_code = (
            ReasonCode.HUMAN_APPROVED
            if approved
            else ReasonCode.HUMAN_VETOED
        )

        audit_record = self._audit_record(
            context=review.transaction_context,
            user_id=review.user_id,
            decision=outcome,
            reason_code=reason_code,
            score=review.score,
            caller_id=review.caller_id,
            decision_id=decision_id,
            operator_id=operator_id,
            resolution_reason=reason,
            policy=review.policy,
        )

        self._append_audit(
            audit_record
        )

        with self._pending_reviews_lock:
            removed = self._pending_reviews.pop(
                decision_id,
                None,
            )

            if removed is None:
                raise RuntimeError(
                    "pending review disappeared during resolution"
                )

        self._notify_monitoring(
            {
                "kind": "security",
                "event_category": "governance_human_decision_resolved",
                "decision_id": decision_id,
                "outcome": (
                    "APPROVED"
                    if approved
                    else "VETOED"
                ),
                "operator_id": operator_id,
            }
        )

        return {
            "decision_id": decision_id,
            "outcome": (
                "APPROVED"
                if approved
                else "VETOED"
            ),
            "operator_id": operator_id,
            "resolved_at": now.isoformat(),
            "user_id": review.user_id,
            "original_caller_id": review.caller_id,
        }

    def list_pending_reviews(
        self,
    ) -> list[dict[str, Any]]:
        now = _utc_now()

        with self._pending_reviews_lock:
            self._purge_expired_reviews_locked(
                now=now
            )

            return [
                {
                    "decision_id": review.decision_id,
                    "user_id": review.user_id,
                    "caller_id": review.caller_id,
                    "score": (
                        str(
                            review.score
                        )
                        if review.score is not None
                        else None
                    ),
                    "effective_mode": review.effective_mode.value,
                    "created_at": review.created_at.isoformat(),
                    "expires_at": review.expires_at.isoformat(),
                }
                for review
                in self._pending_reviews.values()
            ]


__all__ = [
    "CallerContext",
    "Decision",
    "DecisionStatus",
    "GovernanceMode",
    "PendingReview",
    "ReasonCode",
    "SystemOrchestrator",
    "TransactionContext",
]
