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
from core.policy_gate import (
    STATUS_ALLOW,
    STATUS_OBSERVE,
    STATUS_REQUIRES_HUMAN,
    PolicyContext,
    evaluate,
    is_action_known,
)
from core.sentinel43_core_db import ActionStatus, PendingAction


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
    # SHADOW-mode observation: the action was evaluated and recorded, not
    # enforced. Distinct from CLEARED so the audit trail never conflates an
    # observed action with a genuinely allowed one.
    POLICY_OBSERVED = "POLICY_OBSERVED"
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


# =============================================================================
# Threat-recommendation governance
#
# SystemOrchestrator governs two kinds of consequential decision through one
# authority. The transaction adapter above (process_transaction /
# resolve_human_decision / list_pending_reviews) keeps its own in-memory review
# queue and TTL, unchanged. Threat recommendations reuse the orchestration
# responsibilities -- policy, authorization, staging, resolution and audit --
# but DELEGATE durable pending state to the single SentinelCoreStore attached
# below: there is no second queue, and nothing here expires a pending
# recommendation.
# =============================================================================

#: Audit lookup key for recommendation records. Restart recovery finds a
#: recommendation's history by (component, correlation_id), so this must not
#: change without migrating existing records.
RECOMMENDATION_COMPONENT: Final[str] = "heart"

#: Recorded as ``authority`` on every record this layer writes, so the ledger
#: itself shows which component made the decision.
RECOMMENDATION_AUTHORITY: Final[str] = "system_orchestrator"

#: The durable ``primary_action`` written by recommendation builds that
#: predate explicit operations. No operation was ever recorded for them.
LEGACY_REVIEW_ACTION: Final[str] = "human_review"


@dataclass(frozen=True, slots=True)
class DecisionPrincipal:
    """Who the SERVER decided the caller is, not who the caller says.

    ``is_human`` and ``identity_type`` are copied from the identity the
    request pipeline recorded when it verified the credential, so a
    human-looking ``operator_id`` in a request body cannot stand in for an
    authenticated human. ``subject`` must equal the operator_id the decision
    is recorded under.
    """

    subject: str
    identity_type: str
    is_human: bool


class UnauthorizedDecision(PermissionError):
    """A human decision was attempted by an identity the authority rejects."""


class PolicyRefused(RuntimeError):
    """The policy authority did not permit the operation.

    A RuntimeError so the API maps it like any other "cannot be decided now"
    outcome (409) and it is not mistaken for a health fault.
    """


class RecommendationAuthorityUnavailable(RuntimeError):
    """No durable recommendation store is attached to the orchestrator."""


@dataclass(frozen=True, slots=True)
class ProposedOperation:
    """The exact operation a human is asked to authorize, and its target.

    Only operations in the established policy vocabulary can be expressed. An
    operation the vocabulary cannot describe is not relabeled as something
    it can: the recommendation carries ``operation=None`` and is recorded as
    explicitly unsupported instead.
    """

    action: str
    target_type: str
    target: str

    def __post_init__(self) -> None:
        if not is_action_known(self.action):
            raise ValueError(
                f"{self.action!r} is not an operation the policy authority knows"
            )
        if not self.target_type.strip() or not self.target.strip():
            raise ValueError("an operation needs a target_type and a target")

    @property
    def resource(self) -> str:
        return f"{self.target_type}:{self.target}"

    def to_dict(self) -> dict[str, str]:
        return {
            "action": self.action,
            "target_type": self.target_type,
            "target": self.target,
        }


@dataclass(frozen=True, slots=True)
class ThreatRecommendation:
    """A detection-layer recommendation submitted for governance."""

    subject_key: str
    kind: str
    severity: str
    source_kind: str
    score: float
    reason: str
    operation: ProposedOperation | None
    evidence: Mapping[str, Any]
    requested_mode: GovernanceMode
    created_at: float


@dataclass(frozen=True, slots=True)
class RecommendationOutcome:
    status: str
    reason: str
    action_id: str | None = None
    policy: Mapping[str, Any] | None = None


def _operation_from_row(row: Mapping[str, Any]) -> ProposedOperation | None:
    """Rebuild the recorded operation from its durable row, if it has one."""
    action = str(row["primary_action"] or "")
    if not is_action_known(action):
        return None
    _identity, _sep, source_ip = str(row["target_value"]).rpartition("|")
    return ProposedOperation(
        action=action,
        target_type="source_ip",
        target=source_ip,
    )


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

        # Threat-recommendation governance: nothing attached, nothing
        # authorized, until the composition root binds the durable store.
        self._recommendation_store: Any | None = None
        self._recommendation_lock = threading.RLock()
        self._operator_authenticator: Callable[[DecisionPrincipal], bool] = (
            lambda _principal: False
        )
        self._max_pending_recommendations = 500

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

            if (
                policy_decision.status
                == STATUS_OBSERVE
            ):
                # SHADOW is observational, not enforcing. PolicyDecision.allowed
                # is `status == ALLOW`, so OBSERVE arrives here alongside real
                # denials -- and used to fall through to POLICY_DENY, blocking
                # every known action in SHADOW mode. Observation is recorded
                # under its own reason code so the audit trail keeps OBSERVE
                # distinguishable from a genuine ALLOW; the transaction then
                # continues without any enforcement or external action.
                record = self._audit_record(
                    context=context,
                    user_id=user_id,
                    decision=DecisionStatus.APPROVED,
                    reason_code=ReasonCode.POLICY_OBSERVED,
                    score=score,
                    caller_id=caller.caller_id,
                    policy=policy_payload,
                )

                try:
                    self._append_audit(
                        record
                    )
                except Exception:
                    # Observation that cannot be recorded is not observation.
                    return Decision(
                        status=DecisionStatus.BLOCKED,
                        score=score,
                        reason=ReasonCode.AUDIT_APPEND_FAILED,
                    )

                self._notify_monitoring(
                    {
                        "kind": "security",
                        "event_category": "governance_shadow_observed",
                        "caller_id": caller.caller_id,
                        "user_id": user_id,
                    }
                )

                return Decision(
                    status=DecisionStatus.APPROVED,
                    score=score,
                    reason=ReasonCode.POLICY_OBSERVED,
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

    # ------------------------------------------------------------------
    # Threat-recommendation governance (see module section above)
    # ------------------------------------------------------------------

    def attach_recommendation_store(
        self,
        store: Any,
        *,
        operator_authenticator: Callable[[DecisionPrincipal], bool] | None,
        max_pending_actions: int,
    ) -> None:
        """Bind the ONE durable store recommendation decisions live in.

        ``operator_authenticator`` fails closed when absent: an orchestrator
        with no authenticator authorizes no recommendation decision.
        """
        if not 1 <= int(max_pending_actions) <= 100_000:
            raise ValueError("max_pending_actions must be between 1 and 100000")
        with self._recommendation_lock:
            self._recommendation_store = store
            self._operator_authenticator = (
                operator_authenticator
                if operator_authenticator is not None
                else (lambda _principal: False)
            )
            self._max_pending_recommendations = int(max_pending_actions)

    def record_denied_decision(
        self,
        decision_id: str,
        *,
        operator_id: str,
        reason_code: str,
        identity_type: str,
    ) -> None:
        """Audit a transaction decision refused before it reached review.

        The transaction adapter has no identity awareness of its own, so the
        composition root checks the caller first; the refusal is still
        recorded here, by the authority, before it is reported.
        """
        self._append_audit(
            {
                "component": "governance",
                "correlation_id": decision_id or None,
                "authority": RECOMMENDATION_AUTHORITY,
                "decision_id": decision_id or None,
                "decision": "DENIED",
                "reason_code": reason_code,
                "operator_id": operator_id,
                "identity_type": identity_type,
            }
        )

    def detach_recommendation_store(self) -> None:
        with self._recommendation_lock:
            self._recommendation_store = None
            self._operator_authenticator = lambda _principal: False

    @property
    def recommendation_store_attached(self) -> bool:
        return self._recommendation_store is not None

    def _require_recommendation_store(self) -> Any:
        store = self._recommendation_store
        if store is None:
            raise RecommendationAuthorityUnavailable(
                "no durable recommendation store is attached to the orchestrator"
            )
        return store

    def _effective_recommendation_mode(
        self,
        requested: GovernanceMode,
    ) -> GovernanceMode:
        # The orchestrator's mode is a ceiling: a SHADOW orchestrator holds
        # every recommendation in observation, whatever the producer asked.
        if GovernanceMode.SHADOW in (requested, self.default_mode):
            return GovernanceMode.SHADOW
        return GovernanceMode.HUMAN_GATED

    @staticmethod
    def _operation_policy(
        *,
        operation: ProposedOperation,
        actor_id: str,
        mode: GovernanceMode,
        human_approved: bool,
        correlation_id: str | None = None,
    ) -> Any:
        return evaluate(
            PolicyContext(
                action=operation.action,
                actor_id=actor_id,
                tenant_id="default",
                resource=operation.resource,
                mode=mode.value,
                human_approved=human_approved,
                correlation_id=correlation_id,
            )
        )

    def _recommendation_record(
        self,
        recommendation: ThreatRecommendation,
        *,
        decision: str,
        reason_code: str,
        extra: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = dict(recommendation.evidence)
        record.update(
            {
                "subsystem": RECOMMENDATION_COMPONENT,
                "component": RECOMMENDATION_COMPONENT,
                "authority": RECOMMENDATION_AUTHORITY,
                "decision": decision,
                "reason_code": reason_code,
                "operation": (
                    recommendation.operation.to_dict()
                    if recommendation.operation is not None
                    else None
                ),
            }
        )
        if extra:
            record.update(extra)
        return record

    def stage_recommendation(
        self,
        recommendation: ThreatRecommendation,
    ) -> RecommendationOutcome:
        """Decide, record and (if permitted) durably stage one recommendation.

        Every branch writes an authoritative audit record before returning,
        and nothing is staged unless the policy authority's answer matches
        the effective mode exactly. Count-then-insert is serialized so
        concurrent submissions cannot collectively overshoot the ceiling.
        """
        store = self._require_recommendation_store()
        operation = recommendation.operation

        if operation is None:
            self._append_audit(
                self._recommendation_record(
                    recommendation,
                    decision="OBSERVED",
                    reason_code="UNSUPPORTED_OPERATION",
                )
            )
            return RecommendationOutcome(
                status="OBSERVED", reason="UNSUPPORTED_OPERATION"
            )

        mode = self._effective_recommendation_mode(
            recommendation.requested_mode
        )
        policy = self._operation_policy(
            operation=operation,
            actor_id=RECOMMENDATION_COMPONENT,
            mode=mode,
            human_approved=False,
        )
        policy_payload = policy.to_dict()
        expected = (
            STATUS_OBSERVE if mode is GovernanceMode.SHADOW else STATUS_REQUIRES_HUMAN
        )

        if policy.status != expected:
            self._append_audit(
                self._recommendation_record(
                    recommendation,
                    decision="OBSERVED",
                    reason_code="POLICY_REFUSED",
                    extra={"policy": policy_payload},
                )
            )
            logger.error(
                "Recommendation refused by policy: status=%s (expected %s for "
                "mode %s, operation %s)",
                policy.status,
                expected,
                mode.value,
                operation.action,
            )
            return RecommendationOutcome(
                status="OBSERVED", reason="POLICY_REFUSED", policy=policy_payload
            )

        if mode is GovernanceMode.SHADOW:
            self._append_audit(
                self._recommendation_record(
                    recommendation,
                    decision="OBSERVED",
                    reason_code="POLICY_OBSERVED",
                    extra={"policy": policy_payload},
                )
            )
            return RecommendationOutcome(
                status="OBSERVED", reason="POLICY_OBSERVED", policy=policy_payload
            )

        with self._recommendation_lock:
            pending = store.count_actions(status=ActionStatus.PENDING)
            if pending >= self._max_pending_recommendations:
                self._append_audit(
                    self._recommendation_record(
                        recommendation,
                        decision="OBSERVED",
                        reason_code="BACKPRESSURE_LIMIT",
                        extra={
                            "pending_actions": pending,
                            "pending_limit": self._max_pending_recommendations,
                        },
                    )
                )
                logger.error(
                    "Recommendation not staged: %d pending at the limit of %d; "
                    "resolve pending decisions to resume staging",
                    pending,
                    self._max_pending_recommendations,
                )
                return RecommendationOutcome(
                    status="OBSERVED", reason="BACKPRESSURE_LIMIT"
                )

            # Must satisfy the canonical action store's ACTION_ID_RE. The same
            # id keys the durable row, the audit history and the dashboard.
            action_id = f"HEART-{uuid4().hex.upper()}"
            store.insert_pending(
                PendingAction(
                    action_id=action_id,
                    created_at_ms=int(recommendation.created_at * 1000),
                    status=ActionStatus.PENDING,
                    target_type="identity_source_ip",
                    target_value=recommendation.subject_key,
                    primary_action=operation.action,
                    actions=(operation.action,),
                    severity=recommendation.severity,
                    kind=recommendation.kind,
                    source_kind=recommendation.source_kind,
                    score=float(recommendation.score),
                    reason=recommendation.reason,
                    system_id=RECOMMENDATION_COMPONENT,
                )
            )

            try:
                self._append_audit(
                    self._recommendation_record(
                        recommendation,
                        decision="STAGED",
                        reason_code="STAGED_FOR_HUMAN_REVIEW",
                        extra={
                            "decision_id": action_id,
                            "correlation_id": action_id,
                            "policy": policy_payload,
                        },
                    )
                )
            except Exception:
                # No consequential staging without durable audit: compensate
                # the row rather than leave an unaudited, decidable action.
                try:
                    store.transition_status(
                        action_id,
                        expected=ActionStatus.PENDING,
                        new_status=ActionStatus.EXPIRED,
                        operator_reason="audit_append_failed_at_stage_time",
                    )
                except Exception:
                    logger.error(
                        "Failed to compensate unaudited staged recommendation "
                        "%s -- it remains PENDING without a STAGED record",
                        action_id,
                        exc_info=True,
                    )
                raise

        return RecommendationOutcome(
            status="STAGED",
            reason="STAGED_FOR_HUMAN_REVIEW",
            action_id=action_id,
            policy=policy_payload,
        )

    def _staged_operation(self, action_id: str) -> tuple[bool, dict[str, Any] | None]:
        """(found, operation) from the authenticated STAGED record."""
        records = self.audit_store.get_records(
            component=RECOMMENDATION_COMPONENT,
            correlation_id=action_id,
            limit=500,
        )
        staged = [
            record
            for record in records
            if record.get("decision") == "STAGED"
            and record.get("decision_id") == action_id
        ]
        if len(staged) != 1:
            return False, None
        operation = staged[0].get("operation")
        return True, operation if isinstance(operation, dict) else None

    def _deny_recommendation_decision(
        self,
        action_id: str,
        *,
        operator_id: str,
        reason_code: str,
        identity_type: str,
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "subsystem": RECOMMENDATION_COMPONENT,
            "component": RECOMMENDATION_COMPONENT,
            "authority": RECOMMENDATION_AUTHORITY,
            "correlation_id": action_id,
            "decision_id": action_id,
            "decision": "DENIED",
            "reason_code": reason_code,
            "operator_id": operator_id,
            "identity_type": identity_type,
        }
        if extra:
            record.update(extra)
        self._append_audit(record)

    def resolve_recommendation(
        self,
        action_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str = "",
        principal: DecisionPrincipal | None = None,
    ) -> dict[str, Any]:
        """The one path by which a recommendation becomes APPROVED/VETOED.

        Order: authenticated human authority, then (for an approval) the
        operation actually recorded at staging, then the policy authority for
        that operation and its target, then an atomic durable transition,
        then durable audit (with compensation). Every refusal is audited
        before it is raised.
        """
        store = self._require_recommendation_store()
        action_id = action_id.strip()
        operator_id = operator_id.strip()
        if not action_id:
            raise ValueError("action_id must not be empty")
        if not operator_id:
            raise ValueError("operator_id must not be empty")

        identity_type = principal.identity_type if principal else "none"
        denial: str | None = None
        if principal is None:
            denial = "NO_AUTHENTICATION_CONTEXT"
        elif principal.subject.strip() != operator_id:
            denial = "OPERATOR_ID_DOES_NOT_MATCH_AUTHENTICATED_SUBJECT"
        elif not self._operator_authenticator(principal):
            denial = "UNAUTHORIZED_DECISION_ATTEMPT"
        if denial is not None:
            self._deny_recommendation_decision(
                action_id,
                operator_id=operator_id,
                reason_code=denial,
                identity_type=identity_type,
            )
            raise UnauthorizedDecision(
                "operator is not authorized to resolve this recommendation"
            )

        row = store.get_action(action_id)
        if row is None:
            raise KeyError(action_id)

        policy_payload: dict[str, Any] | None = None
        operation = _operation_from_row(row)
        if approved:
            found, staged_operation = self._staged_operation(action_id)
            if operation is None or staged_operation is None:
                # Nothing was ever recorded for a human to authorize. Approving
                # would bind consent to an operation nobody proposed.
                self._deny_recommendation_decision(
                    action_id,
                    operator_id=operator_id,
                    reason_code="UNSUPPORTED_OPERATION",
                    identity_type=identity_type,
                    extra={"primary_action": str(row["primary_action"])},
                )
                raise PolicyRefused(
                    "this recommendation records no supported operation to approve"
                )
            if not found or staged_operation != operation.to_dict():
                self._deny_recommendation_decision(
                    action_id,
                    operator_id=operator_id,
                    reason_code="OPERATION_DOES_NOT_MATCH_STAGING_RECORD",
                    identity_type=identity_type,
                    extra={
                        "operation": operation.to_dict(),
                        "staged_operation": staged_operation,
                    },
                )
                raise PolicyRefused(
                    "the durable operation does not match what was staged"
                )

            policy = self._operation_policy(
                operation=operation,
                actor_id=operator_id,
                mode=GovernanceMode.HUMAN_GATED,
                human_approved=True,
                correlation_id=action_id,
            )
            policy_payload = policy.to_dict()
            if policy.status != STATUS_ALLOW:
                self._deny_recommendation_decision(
                    action_id,
                    operator_id=operator_id,
                    reason_code="POLICY_REFUSED",
                    identity_type=identity_type,
                    extra={
                        "operation": operation.to_dict(),
                        "policy": policy_payload,
                    },
                )
                raise PolicyRefused(
                    f"policy did not permit approval (status={policy.status})"
                )

        new_status = ActionStatus.APPROVED if approved else ActionStatus.VETOED
        if not store.transition_status(
            action_id,
            expected=ActionStatus.PENDING,
            new_status=new_status,
            operator_id=operator_id,
            operator_reason=reason,
        ):
            current = store.get_status(action_id)
            if current is None:
                raise KeyError(action_id)
            raise RuntimeError(
                f"recommendation {action_id!r} is not awaiting a human decision "
                f"(current status={current.value})"
            )

        try:
            self._append_audit(
                {
                    "subsystem": RECOMMENDATION_COMPONENT,
                    "component": RECOMMENDATION_COMPONENT,
                    "authority": RECOMMENDATION_AUTHORITY,
                    "correlation_id": action_id,
                    "decision_id": action_id,
                    "decision": new_status.value,
                    "reason_code": (
                        "HUMAN_APPROVED" if approved else "HUMAN_VETOED"
                    ),
                    "operator_id": operator_id,
                    "identity_type": identity_type,
                    "resolution_reason": reason,
                    "operation": (
                        operation.to_dict() if operation is not None else None
                    ),
                    **({"policy": policy_payload} if policy_payload else {}),
                }
            )
        except Exception:
            # A decision that cannot be recorded must not be reported as made.
            try:
                store.transition_status(
                    action_id,
                    expected=new_status,
                    new_status=ActionStatus.PENDING,
                    operator_reason="reverted_unaudited_decision",
                )
            except Exception:
                logger.error(
                    "Failed to revert unaudited decision for recommendation "
                    "%s -- it remains %s without an audit record",
                    action_id,
                    new_status.value,
                    exc_info=True,
                )
            raise

        return {
            "decision_id": action_id,
            "outcome": new_status.value,
            "operator_id": operator_id,
            "operation": operation.to_dict() if operation is not None else None,
            "resolved_at": _utc_now().isoformat(),
        }

    def list_pending_recommendations(self, limit: int = 200) -> tuple[Any, ...]:
        return self._require_recommendation_store().list_actions(
            status=ActionStatus.PENDING, limit=limit
        )

    def count_pending_recommendations(self) -> int:
        return self._require_recommendation_store().count_actions(
            status=ActionStatus.PENDING
        )

    def expire_unverifiable_recommendation(self, action_id: str, *, problem: str) -> bool:
        """Take a pending row that cannot be verified out of reach of any
        decision. No audit record is fabricated for it."""
        return self._require_recommendation_store().transition_status(
            action_id,
            expected=ActionStatus.PENDING,
            new_status=ActionStatus.EXPIRED,
            operator_reason=f"quarantined_at_recovery:{problem}",
        )


__all__ = [
    "CallerContext",
    "Decision",
    "DecisionStatus",
    "GovernanceMode",
    "PendingReview",
    "ReasonCode",
    "SystemOrchestrator",
    "TransactionContext",
    "DecisionPrincipal",
    "LEGACY_REVIEW_ACTION",
    "PolicyRefused",
    "ProposedOperation",
    "RECOMMENDATION_AUTHORITY",
    "RECOMMENDATION_COMPONENT",
    "RecommendationAuthorityUnavailable",
    "RecommendationOutcome",
    "ThreatRecommendation",
    "UnauthorizedDecision",
]
