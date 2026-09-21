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

    OBSERVE -> ASSESS -> DEDUPLICATE -> CORROBORATE -> APPLY BUDGET/RATE LIMIT
    -> RECORD DURABLE AUDIT -> STAGE RECOMMENDATION -> NOTIFY EXISTING
    CONSUMERS -> WAIT FOR AUTHENTICATED HUMAN APPROVAL OR VETO

A staged recommendation is mirrored into the application's own canonical
action/dashboard system via an injected :class:`ActionSink` -- there is
deliberately no separate Heart-only queue. ``SentinelCoreStore`` remains the
durable source of truth (it survives a restart; the in-memory canonical
action store does not), and the sink is a best-effort mirror of that source
of truth into the existing operator-facing surface, not a second one.

Responsibilities:
    - dedupe/replay-protection for repeated identical findings
    - two-signal corroboration before staging a HIGH/CRITICAL finding
    - rate limiting per target
    - create HUMAN_GATED staged actions for explicit human approval/veto
    - append authoritative audit records for every step, including
      SHADOW-mode observation and corroboration-pending states
    - report its own health truthfully via an injected callback, so a
      composition root can fail /ready closed without a second health
      framework

Non-responsibilities (by design, not by omission):
    - autonomous enforcement
    - any consequential action beyond APPROVED/VETOED bookkeeping -- no
      executor exists here. The historical IntegrationHub.execute() was
      always a logging-only stub in every prior implementation; building a
      real enforcement integration is separate work requiring its own
      security review, not something this module does implicitly.
    - background/timer-driven state transitions
    - storage backend selection beyond the stores it is given

Invariant enforced structurally, not just documented: a recommendation is
never reported as successfully staged unless the durable audit record for
that exact stage was accepted first. If audit acceptance fails after the
durable row was written, the row is compensated (transitioned to EXPIRED)
and the call raises -- it does not return a soft "staged anyway" result.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
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


class ActionSink(Protocol):
    """Mirrors a Heart-originated recommendation into the canonical,
    already-existing action/dashboard system (see module docstring).

    Implementations must be synchronously callable from a worker thread --
    the composition root is expected to bridge back to its own event loop
    internally (e.g. via ``asyncio.run_coroutine_threadsafe``) rather than
    require the Heart to know anything about asyncio.
    """

    def stage(self, record: dict[str, Any]) -> None: ...


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
        action_sink: ActionSink | None = None,
        on_health_change: Callable[[bool, str], None] | None = None,
    ) -> None:
        self.audit_store = audit_store
        self.velocity_guard = velocity_guard
        self.core_store = core_store
        self.default_mode = self._normalize_mode(default_mode)
        self.config = config or HeartConfig()
        self._monitoring_manager = monitoring_manager
        self._action_sink = action_sink
        self._on_health_change = on_health_change

        self._lock = threading.RLock()
        self._corroboration: OrderedDict[
            tuple[str, str], deque[float]
        ] = OrderedDict()
        # Highest detector evidence sequence already counted per key. A
        # signal only counts if it carries strictly newer evidence.
        self._last_evidence_seq: dict[tuple[str, str], int] = {}

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

    def _report_health(self, healthy: bool, detail: str) -> None:
        callback = self._on_health_change
        if callback is None:
            return
        try:
            callback(healthy, detail)
        except Exception:
            logger.debug("Heart health-change callback failed", exc_info=True)

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
            # Lookup keys for AuditStore.get_records(); lets recovery confirm
            # a durable row really has an authenticated STAGED audit record.
            "component": "heart",
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
            record["correlation_id"] = decision_id
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
        evidence_seq: int | None,
    ) -> tuple[int, bool]:
        key = (target_key, kind)

        with self._lock:
            if key not in self._corroboration and (
                len(self._corroboration) >= self.config.max_tracked_targets
            ):
                evicted_key, _ = self._corroboration.popitem(last=False)
                self._last_evidence_seq.pop(evicted_key, None)

            signals = self._corroboration.get(key)
            if signals is None:
                signals = deque()
                self._corroboration[key] = signals
            else:
                self._corroboration.move_to_end(key)

            cutoff = now - self.config.corroboration_window_seconds
            while signals and signals[0] < cutoff:
                signals.popleft()

            # An observation is independent only if the detector saw new
            # evidence since the last one counted. Rescanning an unchanged
            # window, or a retried event, must not manufacture corroboration.
            # Without evidence provenance nothing is counted, so the finding
            # stays pending instead of the threshold being lowered.
            last_seq = self._last_evidence_seq.get(key, 0)
            if evidence_seq is not None and evidence_seq > last_seq:
                signals.append(now)
                self._last_evidence_seq[key] = evidence_seq
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
        """OBSERVE -> ASSESS -> DEDUPLICATE -> CORROBORATE -> BUDGET/RATE
        LIMIT -> DURABLE AUDIT -> STAGE, for one threat assessment.

        Raises on any infrastructure failure (audit, dedupe store, velocity
        guard) rather than returning a decision that misrepresents what
        actually happened -- callers must not treat a normal return value as
        proof the Heart is healthy if they never call this at all, but they
        may treat an exception as proof it is not.
        """
        effective_mode = (
            self._normalize_mode(mode) if mode is not None else self.default_mode
        )

        target_key = f"{assessment.identity}|{assessment.source_ip}"
        kind = assessment.threat_kind.value
        now = time.time()

        try:
            decision = self._observe_unguarded(
                assessment,
                effective_mode=effective_mode,
                target_key=target_key,
                kind=kind,
                now=now,
            )
        except Exception:
            self._report_health(False, "observe_failed")
            raise

        self._report_health(True, "observe_ok")
        return decision

    def _observe_unguarded(
        self,
        assessment: ThreatAssessment,
        *,
        effective_mode: GovernanceMode,
        target_key: str,
        kind: str,
        now: float,
    ) -> HeartDecision:
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
            raw_seq = assessment.indicators.get("evidence_seq")
            evidence_seq = (
                raw_seq
                if isinstance(raw_seq, int) and not isinstance(raw_seq, bool)
                else None
            )
            signal_count, corroborated = self._record_signal_locked(
                target_key, kind, now=now, evidence_seq=evidence_seq
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

        # Deduplicate: this exact target+kind combination must not flood the
        # human-decision queue with repeats of a recommendation already
        # staged (or already decided) within the configured window.
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

        return self._stage(assessment, target_key=target_key, kind=kind, now=now)

    def _stage(
        self,
        assessment: ThreatAssessment,
        *,
        target_key: str,
        kind: str,
        now: float,
    ) -> HeartDecision:
        # Must satisfy the canonical action store's ACTION_ID_RE
        # (^[A-Z0-9_-]{1,64}$, core/api/main.py) -- this same id is used as
        # both the SentinelCoreStore key and the canonical action_store
        # key, deliberately, so there is one id per recommendation, not a
        # separate id-mapping to keep in sync between two stores.
        action_id = f"HEART-{uuid4().hex.upper()}"

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

        # Durable staging happens first, but a successful *response* requires
        # the audit record too (see below) -- this ordering only ever
        # produces an unaudited row transiently, inside this one function,
        # never as something reported to a caller as a successful stage.
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
            # Heart invariant: no consequential staging without durable
            # audit. Compensate the row rather than leave a silent,
            # unaudited PENDING action a human could still approve/veto
            # without any audit trail of it ever having been staged, then
            # propagate -- this call must not return a success.
            try:
                self.core_store.transition_status(
                    action_id,
                    expected=ActionStatus.PENDING,
                    new_status=ActionStatus.EXPIRED,
                    operator_reason="audit_append_failed_at_stage_time",
                )
            except Exception:
                logger.error(
                    "Failed to compensate unaudited staged action %s "
                    "after an audit append failure -- it remains PENDING "
                    "in SentinelCoreStore without a STAGED audit record",
                    action_id,
                    exc_info=True,
                )
            raise

        record = {
            "id": action_id,
            # Deliberately NOT "THREAT_ACTION" -- that string is already
            # the pre-existing generic default action_type for synthetic/
            # dashboard-created actions that go through the regular
            # SystemOrchestrator governance path (see
            # core/api/main.py::_create_synthetic_action and
            # dashboard/assets/js/dashboard.js). Colliding with it would
            # silently misroute those actions' approve/veto calls into the
            # Heart instead. This value is unique to Heart-originated
            # recommendations.
            "action_type": "HEART_RECOMMENDATION",
            "status": "STAGED",
            "created_at": _utc_now_iso(),
            "decision_reason": "",
            "operator": "",
            "payload": {
                "source": "heart",
                "identity": assessment.identity,
                "source_ip": assessment.source_ip,
                "ip": assessment.source_ip,
                "threat_kind": kind,
                "severity": assessment.severity.value,
                "source_kind": assessment.source_kind.value,
                "score": assessment.score,
                "indicators": dict(assessment.indicators),
                "supporting_tags": list(assessment.supporting_tags),
            },
        }

        sink = self._action_sink
        if sink is not None:
            try:
                sink.stage(record)
            except Exception:
                # The durable stage + audit already succeeded above -- this
                # is a lesser, recoverable failure (the action will not
                # appear in the dashboard's action list until reconciled)
                # and must not be reported as a failed stage. Logged loudly,
                # not swallowed at debug level, so it is actually observable.
                logger.error(
                    "Heart action_sink.stage failed for %s -- it is durably "
                    "staged and audited in SentinelCoreStore but will not "
                    "appear in the canonical action list until reconciled",
                    action_id,
                    exc_info=True,
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
        """WAIT FOR AUTHENTICATED HUMAN APPROVAL OR VETO's terminus.

        The caller (the API composition root) is solely responsible for
        proving ``operator_id`` is an authenticated, authorized human
        session -- this method has no notion of identity and will act on
        whatever operator_id it is given, exactly like
        :meth:`core.governance.orchestrator.SystemOrchestrator.resolve_human_decision`.
        A service credential or environment-derived identity must never
        reach this method as ``operator_id``.
        """
        action_id = action_id.strip()
        operator_id = operator_id.strip()

        if not action_id:
            raise ValueError("action_id must not be empty")
        if not operator_id:
            raise ValueError("operator_id must not be empty")

        try:
            result = self._resolve_unguarded(
                action_id,
                approved=approved,
                operator_id=operator_id,
                reason=reason,
            )
        except (KeyError, RuntimeError):
            # Expected business outcomes (action missing / already
            # resolved) -- not a Heart health problem, so not reported as
            # one; the caller maps these to 404/409 the same way governance
            # already does.
            raise
        except Exception:
            self._report_health(False, "resolve_failed")
            raise

        self._report_health(True, "resolve_ok")
        return result

    def _resolve_unguarded(
        self,
        action_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str,
    ) -> dict[str, Any]:
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

        try:
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
        except Exception:
            # Same invariant as staging: a decision that cannot be recorded
            # must not be reported as having happened. Best-effort revert to
            # PENDING so a human can retry the decision once audit recovers,
            # rather than leaving an unaudited terminal state that a second
            # approve/veto attempt would then find already resolved.
            try:
                self.core_store.transition_status(
                    action_id,
                    expected=new_status,
                    new_status=ActionStatus.PENDING,
                    operator_reason="reverted_unaudited_decision",
                )
            except Exception:
                logger.error(
                    "Failed to revert unaudited decision for action %s -- "
                    "it remains %s without an audit record of this decision",
                    action_id,
                    new_status.value,
                    exc_info=True,
                )
            raise

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
        """Read-only introspection against the durable source of truth.

        Not exposed as its own API surface (see module docstring) -- kept
        for internal reconciliation/diagnostics and direct testing.
        """
        return self.core_store.list_actions(status=ActionStatus.PENDING, limit=limit)


__all__ = [
    "ActionSink",
    "HeartConfig",
    "HeartDecision",
    "ThreatGovernor",
]
