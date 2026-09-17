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

"""Sentinel-43 "Heart" -- human-governed threat-assessment staging.

Reconnects Fenrir/detection-layer threat assessments to the same
human-governed pattern :class:`core.governance.orchestrator.SystemOrchestrator`
already applies to financial transactions: dedupe, corroboration, an
authoritative audit trail, and staging for an explicit human decision.

State machine, and nothing beyond it:

    OBSERVE -> ASSESS -> RECOMMEND -> STAGE -> WAIT FOR HUMAN DECISION

Responsibilities:
    - dedupe/replay-protection for repeated identical findings
    - two-signal corroboration before staging a HIGH/CRITICAL finding
    - rate limiting per target
    - create HUMAN_GATED staged actions for explicit human approval/veto
    - append authoritative audit records for every step, including
      SHADOW-mode observation and corroboration-pending states

Non-responsibilities (by design, not by omission):
    - autonomous enforcement
    - any consequential action beyond APPROVED/VETOED bookkeeping -- no
      executor exists here. The historical IntegrationHub.execute() was
      always a logging-only stub in every prior implementation; building a
      real enforcement integration is separate work requiring its own
      security review, not something this module does implicitly.
    - background/timer-driven state transitions
    - storage backend selection beyond the stores it is given
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
from uuid import uuid4

from core.detection.sentinel_threat_types import ThreatAssessment, ThreatSeverity
from core.guards.velocity import VelocityGuard
from core.sentinel43_core_db import ActionStatus, PendingAction, SentinelCoreStore

from .orchestrator import GovernanceMode


logger = logging.getLogger("sentinel43.heart")


_CORROBORATION_REQUIRED_SEVERITIES = frozenset(
    {ThreatSeverity.HIGH, ThreatSeverity.CRITICAL}
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditWriter(Protocol):
    def append(self, payload: dict[str, Any]) -> Any: ...


class MonitoringSink(Protocol):
    def analyze_event(self, event: dict[str, Any]) -> Any: ...


@dataclass(frozen=True, slots=True)
class HeartConfig:
    dedupe_ttl_seconds: int = 300
    corroboration_window_seconds: int = 300
    corroboration_min_signals_for_high: int = 2
    max_tracked_targets: int = 10_000
    velocity_window_seconds: float = 60.0
    velocity_limit: int = 30

    def __post_init__(self) -> None:
        if not 1 <= self.dedupe_ttl_seconds <= 86_400 * 30:
            raise ValueError(
                "dedupe_ttl_seconds must be between 1 and 2592000"
            )
        if not 1 <= self.corroboration_window_seconds <= 86_400:
            raise ValueError(
                "corroboration_window_seconds must be between 1 and 86400"
            )
        if not 1 <= self.corroboration_min_signals_for_high <= 100:
            raise ValueError(
                "corroboration_min_signals_for_high must be between 1 and 100"
            )
        if not 1 <= self.max_tracked_targets <= 1_000_000:
            raise ValueError(
                "max_tracked_targets must be between 1 and 1000000"
            )


@dataclass(frozen=True, slots=True)
class HeartDecision:
    status: str
    reason: str
    action_id: str | None = None


class ThreatGovernor:
    """Human-governed staging for detection-layer threat assessments."""

    def __init__(
        self,
        *,
        audit_store: AuditWriter,
        velocity_guard: VelocityGuard,
        core_store: SentinelCoreStore,
        default_mode: GovernanceMode | str = GovernanceMode.HUMAN_GATED,
        config: HeartConfig | None = None,
        monitoring_manager: MonitoringSink | None = None,
    ) -> None:
        self.audit_store = audit_store
        self.velocity_guard = velocity_guard
        self.core_store = core_store
        self.default_mode = self._normalize_mode(default_mode)
        self.config = config or HeartConfig()
        self._monitoring_manager = monitoring_manager

        self._lock = threading.RLock()
        self._corroboration: OrderedDict[
            tuple[str, str], deque[float]
        ] = OrderedDict()

    @staticmethod
    def _normalize_mode(mode: GovernanceMode | str) -> GovernanceMode:
        if isinstance(mode, GovernanceMode):
            return mode
        normalized = str(mode).strip().upper()
        try:
            return GovernanceMode(normalized)
        except ValueError as exc:
            raise ValueError(
                "heart mode must be SHADOW or HUMAN_GATED"
            ) from exc

    def _notify_monitoring(self, event: dict[str, Any]) -> None:
        manager = self._monitoring_manager
        if manager is None:
            return
        try:
            manager.analyze_event(event)
        except Exception:
            logger.debug("Heart monitoring notification failed", exc_info=True)

    def _append_audit(self, payload: dict[str, Any]) -> None:
        try:
            self.audit_store.append(payload)
        except Exception:
            logger.error(
                "Authoritative Heart audit append failed", exc_info=True
            )
            self._notify_monitoring(
                {
                    "kind": "security",
                    "event_category": "heart_audit_failure",
                    "decision": payload.get("decision"),
                }
            )
            raise

    def _audit_record(
        self,
        assessment: ThreatAssessment,
        *,
        decision: str,
        reason_code: str,
        decision_id: str | None = None,
        operator_id: str | None = None,
        resolution_reason: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "subsystem": "heart",
            "identity": assessment.identity,
            "source_ip": assessment.source_ip,
            "threat_kind": assessment.threat_kind.value,
            "severity": assessment.severity.value,
            "source_kind": assessment.source_kind.value,
            "score": assessment.score,
            "supporting_tags": list(assessment.supporting_tags),
            "indicators": dict(assessment.indicators),
            "decision": decision,
            "reason_code": reason_code,
        }
        if decision_id is not None:
            record["decision_id"] = decision_id
        if operator_id is not None:
            record["operator_id"] = operator_id
        if resolution_reason:
            record["resolution_reason"] = resolution_reason
        if extra:
            record.update(extra)
        return record

    def _record_signal_locked(
        self,
        target_key: str,
        kind: str,
        *,
        now: float,
    ) -> tuple[int, bool]:
        key = (target_key, kind)

        with self._lock:
            if key not in self._corroboration and (
                len(self._corroboration) >= self.config.max_tracked_targets
            ):
                self._corroboration.popitem(last=False)

            signals = self._corroboration.get(key)
            if signals is None:
                signals = deque()
                self._corroboration[key] = signals
            else:
                self._corroboration.move_to_end(key)

            cutoff = now - self.config.corroboration_window_seconds
            while signals and signals[0] < cutoff:
                signals.popleft()

            signals.append(now)
            count = len(signals)

            corroborated = (
                count >= self.config.corroboration_min_signals_for_high
            )

            # Deliberately not cleared on success: once corroborated, every
            # further signal within the window must keep re-corroborating
            # (cheaply -- it's an in-memory count) and fall through to the
            # stage-dedupe check below, which is the actual anti-flood guard.
            # Clearing here would drop the count back under threshold and
            # strand a real, still-ongoing burst in AWAITING_CORROBORATION
            # forever instead of recognizing it as an already-staged repeat.
            return count, corroborated

    def observe(
        self,
        assessment: ThreatAssessment,
        *,
        mode: GovernanceMode | str | None = None,
    ) -> HeartDecision:
        """OBSERVE -> ASSESS -> RECOMMEND -> STAGE for one threat assessment.

        Never raises for an ordinary policy outcome. Only a durable-audit
        failure propagates -- a decision that cannot be recorded must not be
        reported as having happened (mirrors SystemOrchestrator).
        """
        effective_mode = (
            self._normalize_mode(mode) if mode is not None else self.default_mode
        )

        target_key = f"{assessment.identity}|{assessment.source_ip}"
        kind = assessment.threat_kind.value
        now = time.time()

        allowed_velocity, velocity_reason = self.velocity_guard.allow(target_key)
        if not allowed_velocity:
            self._append_audit(
                self._audit_record(
                    assessment,
                    decision="OBSERVED",
                    reason_code=velocity_reason,
                )
            )
            return HeartDecision(status="OBSERVED", reason=velocity_reason)

        # Corroboration counting is never gated by dedupe -- every qualifying
        # signal must be counted, or a HIGH+ finding could never accumulate
        # enough independent signals to be staged in the first place. Dedupe
        # (below) only gates the final stage/observe decision, once made.
        if assessment.severity in _CORROBORATION_REQUIRED_SEVERITIES:
            signal_count, corroborated = self._record_signal_locked(
                target_key, kind, now=now
            )
            if not corroborated:
                self._append_audit(
                    self._audit_record(
                        assessment,
                        decision="OBSERVED",
                        reason_code="AWAITING_CORROBORATION",
                        extra={
                            "signal_count": signal_count,
                            "signals_required": (
                                self.config.corroboration_min_signals_for_high
                            ),
                        },
                    )
                )
                return HeartDecision(
                    status="OBSERVED", reason="AWAITING_CORROBORATION"
                )

        stage_dedupe_key = f"heart:stage:{target_key}:{kind}"
        already_staged_recently = not self.core_store.dedupe_allow(
            stage_dedupe_key, ttl_seconds=self.config.dedupe_ttl_seconds
        )
        if already_staged_recently:
            self._append_audit(
                self._audit_record(
                    assessment,
                    decision="OBSERVED",
                    reason_code="DUPLICATE_SUPPRESSED",
                )
            )
            return HeartDecision(status="OBSERVED", reason="DUPLICATE_SUPPRESSED")

        if effective_mode is GovernanceMode.SHADOW:
            self._append_audit(
                self._audit_record(
                    assessment,
                    decision="OBSERVED",
                    reason_code="POLICY_OBSERVED",
                )
            )
            self._notify_monitoring(
                {
                    "kind": "security",
                    "event_category": "heart_shadow_observed",
                    "identity": assessment.identity,
                    "source_ip": assessment.source_ip,
                }
            )
            return HeartDecision(status="OBSERVED", reason="POLICY_OBSERVED")

        action_id = str(uuid4())

        action = PendingAction(
            action_id=action_id,
            created_at_ms=int(now * 1000),
            status=ActionStatus.PENDING,
            target_type="identity_source_ip",
            target_value=target_key,
            primary_action="human_review",
            actions=("review", "escalate"),
            severity=assessment.severity.value,
            kind=kind,
            source_kind=assessment.source_kind.value,
            score=float(assessment.score),
            reason=(
                f"{kind} from {assessment.source_ip} "
                f"(score={assessment.score:.1f}, "
                f"tags={','.join(assessment.supporting_tags) or 'none'})"
            ),
            system_id="heart",
        )

        self.core_store.insert_pending(action)

        try:
            self._append_audit(
                self._audit_record(
                    assessment,
                    decision="STAGED",
                    reason_code="STAGED_FOR_HUMAN_REVIEW",
                    decision_id=action_id,
                )
            )
        except Exception:
            # The staged row still exists; a human can still see and resolve
            # it via list_pending()/resolve_human_decision() even though this
            # particular STAGED audit line failed to append. Do not attempt
            # to roll back the insert -- vanishing a staged action would be
            # worse than a delayed/missing STAGED audit line, since the
            # underlying finding is still real and still awaits a decision.
            return HeartDecision(
                status="STAGED", reason="AUDIT_APPEND_FAILED", action_id=action_id
            )

        self._notify_monitoring(
            {
                "kind": "security",
                "event_category": "heart_staged_for_review",
                "decision_id": action_id,
                "identity": assessment.identity,
                "source_ip": assessment.source_ip,
                "severity": assessment.severity.value,
            }
        )

        return HeartDecision(
            status="STAGED", reason="STAGED_FOR_HUMAN_REVIEW", action_id=action_id
        )

    def resolve_human_decision(
        self,
        action_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str = "",
    ) -> dict[str, Any]:
        action_id = action_id.strip()
        operator_id = operator_id.strip()

        if not action_id:
            raise ValueError("action_id must not be empty")
        if not operator_id:
            raise ValueError("operator_id must not be empty")

        new_status = ActionStatus.APPROVED if approved else ActionStatus.VETOED

        transitioned = self.core_store.transition_status(
            action_id,
            expected=ActionStatus.PENDING,
            new_status=new_status,
            operator_id=operator_id,
            operator_reason=reason,
        )

        if not transitioned:
            current = self.core_store.get_status(action_id)
            if current is None:
                raise KeyError(action_id)
            raise RuntimeError(
                f"action {action_id!r} is not awaiting human decision "
                f"(current status={current.value})"
            )

        self._append_audit(
            {
                "subsystem": "heart",
                "decision_id": action_id,
                "decision": new_status.value,
                "reason_code": (
                    "HUMAN_APPROVED" if approved else "HUMAN_VETOED"
                ),
                "operator_id": operator_id,
                "resolution_reason": reason,
            }
        )

        self._notify_monitoring(
            {
                "kind": "security",
                "event_category": "heart_human_decision_resolved",
                "decision_id": action_id,
                "outcome": new_status.value,
                "operator_id": operator_id,
            }
        )

        return {
            "decision_id": action_id,
            "outcome": new_status.value,
            "operator_id": operator_id,
            "resolved_at": _utc_now_iso(),
        }

    def list_pending(self, limit: int = 200) -> tuple[Any, ...]:
        return self.core_store.list_actions(status=ActionStatus.PENDING, limit=limit)


__all__ = [
    "HeartConfig",
    "HeartDecision",
    "ThreatGovernor",
]
