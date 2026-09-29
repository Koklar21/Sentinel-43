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
    GovernanceAction,
    PolicyContext,
    evaluate,
    is_action_known,
)
from core.sentinel43_core_db import ActionStatus, PendingAction


logger = logging.getLogger("sentinel43.governance")


MAX_TRANSACTION_AMOUNT: Final[Decimal] = Decimal("1e15")
MAX_PENDING_REVIEWS: Final[int] = 10_000
DEFAULT_REVIEW_TTL_SECONDS: Final[int] = 30 * 60


def _oversight_int(name: str, default: int) -> int:
    """One of the original oversight limits, read from the environment name
    the original design uses, so an existing deployment's configuration keeps
    meaning what it meant."""
    import os

    try:
        value = int(str(os.getenv(name, "")).strip() or default)
    except ValueError:
        return default
    return value if value > 0 else default


#: The original oversight action budget (Shadow_mode.py's OversightEngine):
#: how many actions may be recorded against ONE target inside one window
#: before further recommendations for it are held as observations. It bounds
#: how often a single subject is acted on, which the dedupe window (seconds)
#: and the pending ceiling (depth) do not.
OVERSIGHT_BUDGET_WINDOW_SECONDS: Final[int] = _oversight_int(
    "SENTINEL_OVERSIGHT_BUDGET_WINDOW_SECONDS", 300
)
OVERSIGHT_BUDGET_MAX_PER_TARGET: Final[int] = _oversight_int(
    "SENTINEL_OVERSIGHT_BUDGET_MAX_PER_TARGET", 5
)


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
RECOMMENDATION_AUTHORITY: Final[str] = "sentinel43_runtime_authority"

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
class ThreatRecommendation:
    """A detection-layer finding reported to the orchestration core.

    It carries the assessment and the Heart's evidence only. What response
    the finding warrants, and whether anything is staged, is decided by the
    owner-designated engine inside the orchestrator -- not by the reporter.
    """

    subject_key: str
    assessment: Any
    evidence: Mapping[str, Any]
    requested_mode: GovernanceMode
    created_at: float


@dataclass(frozen=True, slots=True)
class RecommendationOutcome:
    status: str
    reason: str
    action_id: str | None = None
    policy: Any = None
    operations: tuple[Mapping[str, str], ...] = ()
    engine_plan: Mapping[str, Any] | None = None
    recommendation: Mapping[str, Any] | None = None


#: Recorded on every approval: a human decision was made and audited, and any
#: incident record it authorized was opened in this system's own store. No
#: effect outside Sentinel-43 is produced, because no executor exists.
APPROVAL_ENFORCEMENT_NOTE: Final[str] = (
    "not_performed: approval records an audited human decision and opens any "
    "internal incident record it authorized; no external enforcement exists"
)

#: The one approvable operation that writes something beyond the decision
#: record itself -- and it writes only inside this system.
INCIDENT_OPEN_ACTION: Final[str] = GovernanceAction.INCIDENT_OPEN.value


def _operation_key(operation: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(operation.get("action")),
        str(operation.get("target_type")),
        str(operation.get("target")),
        str(operation.get("engine_action") or ""),
    )


def _is_single_operation_row(row: Mapping[str, Any]) -> bool:
    """Rows written by the pre-engine orchestrator: system_id "heart" and a
    single policy action, recorded in the policy vocabulary's own spelling.

    Engine rows carry the engine's system_id AND name their actions in the
    engine's upper-case spelling, so an engine action can never take this
    path -- not by editing primary_action, and not because the policy
    vocabulary has since grown an operation of the same name (rate_limit,
    step_up_auth, ...), which is_action_known matches case-insensitively.
    """
    primary = str(row["primary_action"] or "")
    return (
        str(row.get("system_id") or "") == RECOMMENDATION_COMPONENT
        and primary == primary.lower()
        and is_action_known(primary)
    )


def _engine_row_consistent(row: Mapping[str, Any]) -> bool:
    """The engine always records its primary action as its first action."""
    actions = [str(a) for a in (row.get("actions") or ())]
    return bool(actions) and actions[0] == str(row["primary_action"] or "")


def operations_for_row(row: Mapping[str, Any]) -> list[dict[str, str]] | None:
    """The authorizable operations a durable row proposes; None if it
    predates recorded operations (a legacy review row)."""
    primary = str(row["primary_action"] or "")
    if primary == LEGACY_REVIEW_ACTION:
        return None
    subject_key = str(row["target_value"])
    if _is_single_operation_row(row):
        # A single explicit operation (recorded before the engine ran).
        _identity, _sep, source_ip = subject_key.rpartition("|")
        return [{"action": primary, "target_type": "source_ip", "target": source_ip}]
    from .sentinel43_engine import engine_operations

    operations, _unsupported = engine_operations(
        tuple(row.get("actions") or ()),
        subject_key=subject_key,
        principal=str(row.get("principal_id") or ""),
    )
    return operations


def recommendation_for_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """The approval assessment for a durable row, derived only from what the
    row records (so it is identical at staging, decision and recovery)."""
    primary = str(row["primary_action"] or "")
    if primary == LEGACY_REVIEW_ACTION:
        return {
            "items": [],
            "operations": [],
            "approval": {
                "available": False,
                "reasons": [
                    "Staged before operations were recorded: there is no "
                    "recorded operation to approve."
                ],
                "blocking_actions": [],
            },
        }
    if _is_single_operation_row(row):
        operations = operations_for_row(row) or []
        return {
            "items": [],
            "operations": operations,
            "approval": {"available": True, "reasons": [], "blocking_actions": []},
        }
    from .sentinel43_engine import assess_actions

    assessed = assess_actions(
        tuple(row.get("actions") or ()),
        subject_key=str(row["target_value"]),
        principal=str(row.get("principal_id") or ""),
    )
    if not _engine_row_consistent(row):
        assessed["approval"] = {
            "available": False,
            "reasons": ["The durable row is internally inconsistent."],
            "blocking_actions": [],
        }
    return assessed


def staging_record_matches_row(
    record: Mapping[str, Any],
    row: Mapping[str, Any],
) -> bool:
    """Does the authenticated STAGED record bind exactly what the row
    proposes? Engine records bind the engine's full action list, so no action
    can be added, dropped, reordered or swapped (temporary for hard) later."""
    plan = record.get("engine_plan")
    if isinstance(plan, Mapping) and isinstance(plan.get("actions"), list):
        return (
            not _is_single_operation_row(row)
            and _engine_row_consistent(row)
            and str(plan.get("primary_action") or "") == str(row["primary_action"])
            and [str(a) for a in plan["actions"]]
            == [str(a) for a in (row.get("actions") or ())]
            # The account an account action would act on is part of what was
            # reviewed: a row whose principal_id has since changed proposes a
            # different target and cannot be approved on this record.
            and str(record.get("principal") or "")
            == str(row.get("principal_id") or "")
        )
    return same_operations(staged_operations_of(record), operations_for_row(row))


def staged_operations_of(record: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    """The operations an authenticated STAGED record bound; None if the
    record predates recorded operations."""
    if "operations" in record:
        value = record.get("operations")
        return list(value) if isinstance(value, list) else []
    if "operation" in record:
        value = record.get("operation")
        return [value] if isinstance(value, dict) else []
    return None


def same_operations(
    left: list[Mapping[str, Any]] | None,
    right: list[Mapping[str, Any]] | None,
) -> bool:
    if left is None or right is None:
        return left is None and right is None
    return sorted(map(_operation_key, left)) == sorted(map(_operation_key, right))

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
        self._budget_window_seconds = OVERSIGHT_BUDGET_WINDOW_SECONDS
        self._budget_max_per_target = OVERSIGHT_BUDGET_MAX_PER_TARGET
        self._engine: Any | None = None

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

    def append_authoritative_audit(
        self,
        payload: dict[str, Any],
    ) -> None:
        """Public audit sink for the owning Sentinel-43 runtime authority.

        The authority owns composition; this subordinate service still owns
        the established fail-closed audit mechanics.
        """
        self._append_audit(payload)

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
    # Threat-recommendation governance: the owner-designated engine decides
    # ------------------------------------------------------------------

    def bind_recommendation_runtime(
        self,
        store: Any,
        *,
        engine: Any,
        operator_authenticator: Callable[[DecisionPrincipal], bool] | None,
        max_pending_actions: int,
    ) -> None:
        """Bind runtime pieces owned by :class:`Sentinel43RuntimeAuthority`.

        This service deliberately does NOT construct the owner-designated
        engine.  Sentinel-43's top-level runtime authority owns that lifecycle
        and injects the single engine instance here for existing governance
        mechanics to use.
        """
        if store is None:
            raise ValueError("recommendation store is required")
        if engine is None:
            raise ValueError("owner engine is required")
        if not 1 <= int(max_pending_actions) <= 100_000:
            raise ValueError("max_pending_actions must be between 1 and 100000")

        authenticator = (
            operator_authenticator
            if operator_authenticator is not None
            else (lambda _principal: False)
        )
        with self._recommendation_lock:
            previous = self._engine
            self._recommendation_store = store
            self._operator_authenticator = authenticator
            self._max_pending_recommendations = int(max_pending_actions)
            self._engine = engine
        if previous is not None and previous is not engine:
            previous.shutdown()

    def record_denied_decision(
        self,
        decision_id: str,
        *,
        operator_id: str,
        reason_code: str,
        identity_type: str,
    ) -> None:
        """Audit a transaction decision refused before it reached review."""
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
            engine = self._engine
            self._recommendation_store = None
            self._engine = None
            self._operator_authenticator = lambda _principal: False
        if engine is not None:
            engine.shutdown()

    @property
    def recommendation_store_attached(self) -> bool:
        return self._recommendation_store is not None and self._engine is not None

    def list_incidents(self, limit: int = 200) -> tuple[Mapping[str, Any], ...]:
        """Incident records opened by approved decisions.

        The authority exposes the READ, not the store: handing out the store
        object would hand out its raw transition_status, which has no
        principal check of its own -- that check lives in the engine's store
        adapter, on the one path a decision may take.
        """
        return self._require_recommendation_store().list_incidents(limit=limit)

    @property
    def engine_identity(self) -> dict[str, str] | None:
        engine = self._engine
        return engine.identity.to_dict() if engine is not None else None

    def _require_recommendation_store(self) -> Any:
        store = self._recommendation_store
        if store is None or self._engine is None:
            raise RecommendationAuthorityUnavailable(
                "no orchestration engine and durable store are attached"
            )
        return store

    def _effective_recommendation_mode(
        self,
        requested: GovernanceMode,
    ) -> GovernanceMode:
        # The orchestrator's mode is a ceiling: a SHADOW orchestrator holds
        # every recommendation in observation, whatever the reporter asked.
        if GovernanceMode.SHADOW in (requested, self.default_mode):
            return GovernanceMode.SHADOW
        return GovernanceMode.HUMAN_GATED

    @staticmethod
    def _operation_policy(
        *,
        operation: Mapping[str, Any],
        actor_id: str,
        mode: GovernanceMode,
        human_approved: bool,
        correlation_id: str | None = None,
    ) -> Any:
        return evaluate(
            PolicyContext(
                action=str(operation["action"]),
                actor_id=actor_id,
                tenant_id="default",
                resource=f"{operation['target_type']}:{operation['target']}",
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
                "engine": self.engine_identity,
                "decision": decision,
                "reason_code": reason_code,
            }
        )
        if extra:
            record.update(extra)
        return record

    def stage_recommendation(
        self,
        recommendation: ThreatRecommendation,
    ) -> RecommendationOutcome:
        """The engine plans the response; the policy authority must agree for
        every authorizable operation; the engine then stages it into the one
        durable store. Every branch is audited before returning."""
        store = self._require_recommendation_store()
        engine = self._engine
        mode = self._effective_recommendation_mode(recommendation.requested_mode)
        assessment = recommendation.assessment

        from .sentinel43_engine import (
            BLOCKING_STATUSES,
            assess_actions,
            principal_of_assessment,
            validated_subject_key,
        )

        try:
            subject_ok = (
                validated_subject_key(assessment.identity, assessment.source_ip)
                == recommendation.subject_key
            )
        except ValueError:
            subject_ok = False
        if not subject_ok:
            # The subject is the target every operation acts on; a malformed
            # or ambiguous one must never reach the engine.
            self._append_audit(
                self._recommendation_record(
                    recommendation,
                    decision="OBSERVED",
                    reason_code="INVALID_SUBJECT",
                )
            )
            return RecommendationOutcome(status="OBSERVED", reason="INVALID_SUBJECT")

        principal = principal_of_assessment(assessment)
        plan = engine.plan(assessment)
        assessed = assess_actions(
            plan["actions"],
            subject_key=recommendation.subject_key,
            principal=principal,
        )
        operations = assessed["operations"]
        unsupported = [
            item["engine_action"]
            for item in assessed["items"]
            if item["status"] in BLOCKING_STATUSES
        ]
        decision_context = {
            "engine_plan": plan["summary"],
            "operations": operations,
            "unsupported_actions": unsupported,
            "principal": principal,
            "recommendation": {
                "items": assessed["items"],
                "approval": assessed["approval"],
            },
        }

        if plan["actions"] == ["LOG_ONLY"]:
            self._append_audit(
                self._recommendation_record(
                    recommendation,
                    decision="OBSERVED",
                    reason_code="ENGINE_LOG_ONLY",
                    extra=decision_context,
                )
            )
            return RecommendationOutcome(
                status="OBSERVED", reason="ENGINE_LOG_ONLY", engine_plan=plan["summary"]
            )

        expected = (
            STATUS_OBSERVE if mode is GovernanceMode.SHADOW else STATUS_REQUIRES_HUMAN
        )
        policies = [
            self._operation_policy(
                operation=operation,
                actor_id=RECOMMENDATION_COMPONENT,
                mode=mode,
                human_approved=False,
            ).to_dict()
            for operation in operations
        ]
        decision_context["policy"] = policies

        refused = [p for p in policies if p["status"] != expected]
        if refused:
            self._append_audit(
                self._recommendation_record(
                    recommendation,
                    decision="OBSERVED",
                    reason_code="POLICY_REFUSED",
                    extra=decision_context,
                )
            )
            logger.error(
                "Engine recommendation refused by policy: %s (expected %s, mode %s)",
                [p["status"] for p in refused],
                expected,
                mode.value,
            )
            return RecommendationOutcome(
                status="OBSERVED",
                reason="POLICY_REFUSED",
                policy=policies,
                engine_plan=plan["summary"],
            )

        stage_kwargs = {
            "mode_value": mode.value,
            "subject_key": recommendation.subject_key,
            "kind": assessment.threat_kind.value,
            "severity": assessment.severity.value,
            "source_kind": assessment.source_kind.value,
            "score": float(assessment.score),
            "principal": principal,
        }

        with self._recommendation_lock:
            if mode is GovernanceMode.HUMAN_GATED:
                pending = store.count_actions(status=ActionStatus.PENDING)
                if pending >= self._max_pending_recommendations:
                    self._append_audit(
                        self._recommendation_record(
                            recommendation,
                            decision="OBSERVED",
                            reason_code="BACKPRESSURE_LIMIT",
                            extra={
                                **decision_context,
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

                # The original oversight budget, in its original position:
                # after back-pressure, before anything durable is staged. A
                # target already acted on this often stays under observation
                # rather than producing another decision for a human.
                since_ms = int(
                    (_utc_now().timestamp() - self._budget_window_seconds) * 1000
                )
                recent = store.count_actions_for_target(
                    target_value=recommendation.subject_key, since_ms=since_ms
                )
                if recent >= self._budget_max_per_target:
                    self._append_audit(
                        self._recommendation_record(
                            recommendation,
                            decision="OBSERVED",
                            reason_code="BUDGET_EXCEEDED",
                            extra={
                                **decision_context,
                                "budget_target": recommendation.subject_key,
                                "budget_recent_actions": recent,
                                "budget_limit": self._budget_max_per_target,
                                "budget_window_seconds": self._budget_window_seconds,
                            },
                        )
                    )
                    logger.warning(
                        "Recommendation not staged: %d actions already recorded "
                        "for %s within %ds (limit %d)",
                        recent,
                        recommendation.subject_key,
                        self._budget_window_seconds,
                        self._budget_max_per_target,
                    )
                    return RecommendationOutcome(
                        status="OBSERVED", reason="BUDGET_EXCEEDED"
                    )

            staged = engine.stage(plan["directive"], **stage_kwargs)

            if staged is None:
                self._append_audit(
                    self._recommendation_record(
                        recommendation,
                        decision="OBSERVED",
                        reason_code="ENGINE_SUPPRESSED",
                        extra=decision_context,
                    )
                )
                return RecommendationOutcome(
                    status="OBSERVED",
                    reason="ENGINE_SUPPRESSED",
                    engine_plan=plan["summary"],
                )

            action_id = str(staged.action_id)

            if mode is GovernanceMode.SHADOW:
                self._append_audit(
                    self._recommendation_record(
                        recommendation,
                        decision="OBSERVED",
                        reason_code="POLICY_OBSERVED",
                        extra={**decision_context, "shadow_record_id": action_id},
                    )
                )
                return RecommendationOutcome(
                    status="OBSERVED",
                    reason="POLICY_OBSERVED",
                    policy=policies,
                    operations=tuple(operations),
                    engine_plan=plan["summary"],
                )

            try:
                self._append_audit(
                    self._recommendation_record(
                        recommendation,
                        decision="STAGED",
                        reason_code="STAGED_FOR_HUMAN_REVIEW",
                        extra={
                            **decision_context,
                            "decision_id": action_id,
                            "correlation_id": action_id,
                        },
                    )
                )
            except Exception:
                # No consequential staging without durable audit.
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
            policy=policies,
            operations=tuple(operations),
            engine_plan=plan["summary"],
            recommendation=decision_context["recommendation"],
        )

    def _staged_record(self, action_id: str) -> Mapping[str, Any] | None:
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
        return staged[0] if len(staged) == 1 else None

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
            "engine": self.engine_identity,
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
        """The one path by which a recommendation is approved or vetoed.

        Server-verified human authority first; for an approval, the operations
        recorded at staging and the policy authority for each of them; then
        the ENGINE's own approve_action/veto_action (its authenticator bound
        to this principal) performs the transition; then durable audit.
        """
        store = self._require_recommendation_store()
        engine = self._engine
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

        assessed = recommendation_for_row(row)
        operations = assessed["operations"]
        policies: list[dict[str, Any]] = []
        if approved:
            staged_record = self._staged_record(action_id)
            if staged_record is None or not staging_record_matches_row(
                staged_record, row
            ) or (
                f"{staged_record.get('identity')}|{staged_record.get('source_ip')}"
                != str(row["target_value"])
            ):
                staged_ops = (
                    staged_operations_of(staged_record) if staged_record else None
                )
                self._deny_recommendation_decision(
                    action_id,
                    operator_id=operator_id,
                    reason_code="OPERATION_DOES_NOT_MATCH_STAGING_RECORD",
                    identity_type=identity_type,
                    extra={"operations": operations, "staged_operations": staged_ops},
                )
                raise PolicyRefused(
                    "the durable operations do not match what was staged"
                )
            if not assessed["approval"]["available"]:
                # The recommendation is approved as a whole or not at all:
                # approving only its supported part would authorize a
                # different set than the human reviewed.
                self._deny_recommendation_decision(
                    action_id,
                    operator_id=operator_id,
                    reason_code="APPROVAL_UNAVAILABLE",
                    identity_type=identity_type,
                    extra={
                        "actions": list(row.get("actions") or ()),
                        "approval": assessed["approval"],
                    },
                )
                raise PolicyRefused(
                    "approval is unavailable for this recommendation: "
                    + "; ".join(assessed["approval"]["reasons"])
                )
            policies = [
                self._operation_policy(
                    operation=operation,
                    actor_id=operator_id,
                    mode=GovernanceMode.HUMAN_GATED,
                    human_approved=True,
                    correlation_id=action_id,
                ).to_dict()
                for operation in operations
            ]
            if any(p["status"] != STATUS_ALLOW for p in policies):
                self._deny_recommendation_decision(
                    action_id,
                    operator_id=operator_id,
                    reason_code="POLICY_REFUSED",
                    identity_type=identity_type,
                    extra={"operations": operations, "policy": policies},
                )
                raise PolicyRefused("policy did not permit approval")

        decide = engine.approve if approved else engine.veto
        if not decide(action_id, operator_id=operator_id, reason=reason, principal=principal):
            current = store.get_status(action_id)
            if current is None:
                raise KeyError(action_id)
            if current is not ActionStatus.PENDING:
                raise RuntimeError(
                    f"recommendation {action_id!r} is not awaiting a human decision "
                    f"(current status={current.value})"
                )
            self._deny_recommendation_decision(
                action_id,
                operator_id=operator_id,
                reason_code="ENGINE_REFUSED",
                identity_type=identity_type,
            )
            raise UnauthorizedDecision("the orchestration engine refused this decision")

        new_status = ActionStatus.APPROVED if approved else ActionStatus.VETOED
        incident_id: str | None = None
        try:
            if approved and any(
                str(operation.get("action")) == INCIDENT_OPEN_ACTION
                for operation in operations
            ):
                # The one authorized operation with an effect, and it is
                # internal: a durable follow-up record in this system's own
                # store. Nothing outside Sentinel-43 is touched.
                incident_id = store.open_incident(
                    action_id=action_id,
                    severity=str(row.get("severity") or ""),
                    kind=str(row.get("kind") or ""),
                    subject_type=str(row.get("target_type") or ""),
                    subject_value=str(row.get("target_value") or ""),
                    summary=str(row.get("reason") or ""),
                    engine_actions=tuple(
                        str(name) for name in (row.get("actions") or ())
                    ),
                    opened_by=operator_id,
                    operator_reason=reason,
                )
            self._append_audit(
                {
                    "subsystem": RECOMMENDATION_COMPONENT,
                    "component": RECOMMENDATION_COMPONENT,
                    "authority": RECOMMENDATION_AUTHORITY,
                    "engine": self.engine_identity,
                    "decided_by": "Sentinel43ResponseEngine."
                    + ("approve_action" if approved else "veto_action"),
                    "correlation_id": action_id,
                    "decision_id": action_id,
                    "decision": new_status.value,
                    "reason_code": (
                        "HUMAN_APPROVED" if approved else "HUMAN_VETOED"
                    ),
                    "operator_id": operator_id,
                    "identity_type": identity_type,
                    "resolution_reason": reason,
                    "operations": operations,
                    "actions": list(row.get("actions") or ()),
                    "enforcement": APPROVAL_ENFORCEMENT_NOTE if approved else None,
                    **({"incident_id": incident_id} if incident_id else {}),
                    **({"policy": policies} if policies else {}),
                }
            )
        except Exception:
            # A decision that cannot be recorded must not be reported as made.
            if incident_id is not None:
                try:
                    store.retract_incident(
                        incident_id, reason="reverted_unaudited_decision"
                    )
                except Exception:
                    logger.error(
                        "Failed to retract incident %s for a reverted decision",
                        incident_id,
                        exc_info=True,
                    )
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
            "operations": operations,
            "enforcement": APPROVAL_ENFORCEMENT_NOTE if approved else None,
            "incident_id": incident_id,
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
    "RECOMMENDATION_AUTHORITY",
    "RECOMMENDATION_COMPONENT",
    "RecommendationAuthorityUnavailable",
    "RecommendationOutcome",
    "ThreatRecommendation",
    "UnauthorizedDecision",
    "APPROVAL_ENFORCEMENT_NOTE",
    "operations_for_row",
    "recommendation_for_row",
    "same_operations",
    "staging_record_matches_row",
    "staged_operations_of",
]
