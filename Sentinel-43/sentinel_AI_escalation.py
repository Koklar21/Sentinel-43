# =============================================================================
# Sentinel-43
#
# Copyright (c) 2025-2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 AI escalation contract for the current runtime.

This owner-designated source originally contained another complete response
engine, another SQLite action store, another audit path, an executor thread,
its own approval/veto logic, and ACTIVE auto-execution.

That is not the current Sentinel-43 architecture.

AI/detection may produce assessments, but escalation does not own response
authority. Escalation is an intake/translation boundary that reports governed
recommendations into Sentinel43RuntimeAuthority. Response planning remains the
responsibility of the one owner-designated engine loaded from Shadow_mode.py.

Current flow:

    AI / detector assessment
            |
            v
    escalation contract
            |
            v
      ThreatRecommendation
            |
            v
  Sentinel43RuntimeAuthority
            |
            +--> owner response engine
            +--> SystemOrchestrator
            +--> policy / human gate / durable state / audit

Supported governance modes are SHADOW and HUMAN_GATED only. ACTIVE,
AUTONOMOUS_VETO and delayed auto-execution are explicitly unsupported.

This module owns no database, background thread, approval queue, executor or
external integration.
"""

from __future__ import annotations

import enum
import hashlib
import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from core.governance.orchestrator import (
    DecisionPrincipal,
    ThreatRecommendation,
)
from core.governance.runtime_authority import Sentinel43RuntimeAuthority


logger = logging.getLogger(__name__)
SYSTEM_ID = "SENTINEL-43-AI-ESCALATION-01"


# =============================================================================
# Modes
# =============================================================================


class SentinelMode(str, enum.Enum):
    SHADOW = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"


UNSUPPORTED_AUTONOMOUS_MODES: frozenset[str] = frozenset(
    {"ACTIVE", "AUTONOMOUS", "AUTONOMOUS_VETO", "DELAYED_EXECUTE"}
)


# =============================================================================
# Assessment contract
# =============================================================================


class ThreatKind(str, enum.Enum):
    GENERIC_INTRUSION = "GENERIC_INTRUSION"
    MALWARE_DELIVERY = "MALWARE_DELIVERY"
    SPYWARE_ACTIVITY = "SPYWARE_ACTIVITY"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    UNKNOWN = "UNKNOWN"


class ThreatSourceKind(str, enum.Enum):
    HUMAN_LIKELY = "HUMAN_LIKELY"
    AI_AUTOMATION_LIKELY = "AI_AUTOMATION_LIKELY"
    MIXED_OR_UNKNOWN = "MIXED_OR_UNKNOWN"


class ThreatSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    """Typed escalation input.

    This is evidence. It does not authorize a response, choose an action, or
    mutate state.
    """

    identity: str
    source_ip: str
    threat_kind: ThreatKind
    severity: ThreatSeverity
    source_kind: ThreatSourceKind
    score: float
    indicators: Mapping[str, Any] = field(default_factory=dict)
    supporting_tags: tuple[str, ...] = ()
    window_size: int = 0
    generated_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        identity = str(self.identity or "").strip()
        source_ip = normalize_ip(self.source_ip)
        score = float(self.score)
        window_size = int(self.window_size)

        if not identity:
            raise ValueError("identity is required")
        if len(identity) > 256:
            raise ValueError("identity too long")
        if not source_ip:
            raise ValueError("source_ip is required")
        if not 0.0 <= score <= 100.0:
            raise ValueError("score must be within [0.0, 100.0]")
        if window_size < 0:
            raise ValueError("window_size must be >= 0")

        indicators = dict(self.indicators or {})
        if len(_json_dumps(indicators).encode("utf-8")) > 20_000:
            raise ValueError("indicators are too large")

        tags = tuple(
            str(tag).strip()[:128]
            for tag in self.supporting_tags
            if str(tag).strip()
        )

        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "source_ip", source_ip)
        object.__setattr__(self, "score", score)
        object.__setattr__(self, "window_size", window_size)
        object.__setattr__(self, "indicators", MappingProxyType(indicators))
        object.__setattr__(self, "supporting_tags", tags)
        object.__setattr__(self, "generated_at", float(self.generated_at))


# =============================================================================
# Response vocabulary
# =============================================================================


class ResponseAction(str, enum.Enum):
    """Original response vocabulary retained as data, not authority."""

    LOG_ONLY = "LOG_ONLY"
    FLAG_SUSPICIOUS = "FLAG_SUSPICIOUS"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    RATE_LIMIT = "RATE_LIMIT"
    TEMP_BLOCK_IDENTITY = "TEMP_BLOCK_IDENTITY"
    TEMP_BLOCK_IP = "TEMP_BLOCK_IP"
    HARD_BLOCK_IDENTITY = "HARD_BLOCK_IDENTITY"
    HARD_BLOCK_IP = "HARD_BLOCK_IP"
    QUARANTINE_SESSION = "QUARANTINE_SESSION"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
    OPEN_INCIDENT = "OPEN_INCIDENT"


@dataclass(frozen=True, slots=True)
class ResponsePolicy:
    """Historical planning thresholds retained for reference/config migration.

    The current owner response engine is authoritative for actual planning.
    This object is not evaluated by this module.
    """

    medium_threshold: float = 40.0
    high_threshold: float = 65.0
    critical_threshold: float = 85.0
    automation_medium_bonus: float = 5.0
    automation_high_bonus: float = 10.0
    temp_block_seconds: int = 900
    hard_block_seconds: int = 3600 * 6
    require_human_review_on_high: bool = True
    open_incident_on_critical: bool = True


@dataclass(frozen=True, slots=True)
class EscalationEnvelope:
    assessment: ThreatAssessment
    requested_mode: SentinelMode
    evidence: Mapping[str, Any]
    subject_key: str
    fingerprint: str
    created_at: float


@dataclass(frozen=True, slots=True)
class EscalationStatus:
    system_id: str
    mode: str
    recommendation_store_attached: bool
    engine_identity: Mapping[str, str] | None
    owns_response_planning: bool = False
    autonomous_execution_supported: bool = False
    local_executor_active: bool = False
    local_action_store_active: bool = False


@dataclass(slots=True)
class Metrics:
    assessments_built: int = 0
    envelopes_built: int = 0
    recommendations_submitted: int = 0
    recommendations_resolved: int = 0
    submission_failures: int = 0
    resolution_failures: int = 0

    def snapshot(self) -> dict[str, int]:
        return {
            name: int(getattr(self, name))
            for name in self.__dataclass_fields__
        }


# =============================================================================
# Helpers
# =============================================================================


def normalize_ip(value: str) -> str:
    raw = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw


def sanitize_key_component(value: str, *, max_len: int = 200) -> str:
    text = str(value or "").strip()
    allowed = "".join(
        ch for ch in text
        if ch.isalnum() or ch in ".:_-@|"
    )
    return allowed[:max_len]


def _json_dumps(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def stable_assessment_fingerprint(assessment: ThreatAssessment) -> str:
    payload = {
        "identity": assessment.identity,
        "source_ip": assessment.source_ip,
        "threat_kind": assessment.threat_kind.value,
        "severity": assessment.severity.value,
        "source_kind": assessment.source_kind.value,
        "score": assessment.score,
        "indicators": dict(assessment.indicators),
        "supporting_tags": list(assessment.supporting_tags),
        "window_size": assessment.window_size,
    }
    return hashlib.sha256(
        _json_dumps(payload).encode("utf-8")
    ).hexdigest()


# =============================================================================
# Escalation facade
# =============================================================================


class SentinelAIEscalation:
    """Current AI/detection escalation facade.

    It validates evidence and submits an already-governed recommendation into
    Sentinel-43. It never chooses the final response action itself.
    """

    def __init__(
        self,
        *,
        authority: Sentinel43RuntimeAuthority,
    ) -> None:
        if not isinstance(authority, Sentinel43RuntimeAuthority):
            raise TypeError(
                "SentinelAIEscalation requires the live "
                "Sentinel43RuntimeAuthority"
            )
        self._authority = authority
        self.metrics = Metrics()

    @property
    def authority(self) -> Sentinel43RuntimeAuthority:
        return self._authority

    @property
    def mode(self) -> SentinelMode:
        value = self._authority.governance_mode
        return SentinelMode(value.strip().upper())

    def build_assessment(
        self,
        *,
        identity: str,
        source_ip: str,
        threat_kind: ThreatKind,
        severity: ThreatSeverity,
        source_kind: ThreatSourceKind,
        score: float,
        indicators: Mapping[str, Any] | None = None,
        supporting_tags: Sequence[str] = (),
        window_size: int = 0,
        generated_at: float | None = None,
    ) -> ThreatAssessment:
        assessment = ThreatAssessment(
            identity=identity,
            source_ip=source_ip,
            threat_kind=threat_kind,
            severity=severity,
            source_kind=source_kind,
            score=score,
            indicators=indicators or {},
            supporting_tags=tuple(supporting_tags),
            window_size=window_size,
            generated_at=(
                time.time() if generated_at is None else float(generated_at)
            ),
        )
        self.metrics.assessments_built += 1
        return assessment

    def build_envelope(
        self,
        assessment: ThreatAssessment,
        *,
        requested_mode: SentinelMode | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> EscalationEnvelope:
        if not isinstance(assessment, ThreatAssessment):
            raise TypeError("assessment must be ThreatAssessment")

        mode = requested_mode or self.mode
        if mode not in (SentinelMode.SHADOW, SentinelMode.HUMAN_GATED):
            raise ValueError("mode must be SHADOW or HUMAN_GATED")

        subject_key = (
            f"{sanitize_key_component(assessment.identity, max_len=200)}|"
            f"{sanitize_key_component(assessment.source_ip, max_len=200)}"
        )
        if "|" == subject_key or subject_key.startswith("|") or subject_key.endswith("|"):
            raise ValueError("assessment does not contain a valid governed subject")

        envelope = EscalationEnvelope(
            assessment=assessment,
            requested_mode=mode,
            evidence=MappingProxyType(dict(evidence or {})),
            subject_key=subject_key,
            fingerprint=stable_assessment_fingerprint(assessment),
            created_at=time.time(),
        )
        self.metrics.envelopes_built += 1
        return envelope

    def submit_recommendation(
        self,
        recommendation: ThreatRecommendation,
    ) -> Any:
        """Submit through the one Sentinel-43 authority.

        Conversion into the canonical ThreatRecommendation remains owned by
        the live Heart/governance path. This method will not invent a second
        recommendation model or response planner.
        """

        if not isinstance(recommendation, ThreatRecommendation):
            raise TypeError(
                "submit_recommendation requires the canonical "
                "ThreatRecommendation"
            )

        try:
            result = self._authority.stage_recommendation(recommendation)
        except Exception:
            self.metrics.submission_failures += 1
            raise

        self.metrics.recommendations_submitted += 1
        return result

    def resolve_recommendation(
        self,
        action_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str = "",
        principal: DecisionPrincipal | None = None,
    ) -> dict[str, Any]:
        try:
            result = self._authority.resolve_recommendation(
                action_id,
                approved=approved,
                operator_id=operator_id,
                reason=reason,
                principal=principal,
            )
        except Exception:
            self.metrics.resolution_failures += 1
            raise

        self.metrics.recommendations_resolved += 1
        return result

    def plan_response(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError(
            "AI escalation does not own response planning; the owner-designated "
            "Sentinel43ResponseEngine loaded from Shadow_mode.py is authoritative"
        )

    def execute(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError(
            "AI escalation cannot execute external effects; route approved "
            "operations through the governed Sentinel-43 integration boundary"
        )

    def set_mode(self, mode: SentinelMode | str) -> None:
        value = (
            mode.value
            if isinstance(mode, SentinelMode)
            else str(mode).strip().upper()
        )
        if value in UNSUPPORTED_AUTONOMOUS_MODES:
            raise ValueError(
                "autonomous/ACTIVE governance is not supported"
            )

        try:
            requested = SentinelMode(value)
        except ValueError as exc:
            raise ValueError("mode must be SHADOW or HUMAN_GATED") from exc

        if requested is self.mode:
            return

        raise RuntimeError(
            "runtime mode changes are controlled by Sentinel-43 composition "
            "configuration"
        )

    def status(self) -> EscalationStatus:
        return EscalationStatus(
            system_id=SYSTEM_ID,
            mode=self.mode.value,
            recommendation_store_attached=(
                self._authority.recommendation_store_attached
            ),
            engine_identity=self._authority.engine_identity,
        )


# =============================================================================
# Original responsibility map
# =============================================================================


ESCALATION_RESPONSIBILITY_MAP: Mapping[str, str] = MappingProxyType(
    {
        "assessment_contract": "SentinelAIEscalation / detection models",
        "ai_detection": "outside escalation; current detection pipeline",
        "recommendation_entry": "Sentinel43RuntimeAuthority",
        "response_planning": "owner Sentinel43ResponseEngine from Shadow_mode.py",
        "policy_evaluation": "SystemOrchestrator + policy_gate",
        "human_gating": "Sentinel43RuntimeAuthority -> SystemOrchestrator",
        "durable_pending_state": "SentinelCoreStore",
        "authoritative_audit": "AuditStore via SystemOrchestrator",
        "response_action_vocabulary": "owner response engine / governance mapping",
        "local_sqlite_action_store": "INTENTIONALLY_NOT_USED",
        "local_audit_chain": "INTENTIONALLY_NOT_USED",
        "local_executor_thread": "INTENTIONALLY_NOT_USED",
        "local_approval_path": "INTENTIONALLY_NOT_USED",
        "autonomous_active_mode": "INTENTIONALLY_UNSUPPORTED",
        "direct_external_execution": "INTENTIONALLY_UNSUPPORTED",
    }
)


__all__ = [
    "ESCALATION_RESPONSIBILITY_MAP",
    "EscalationEnvelope",
    "EscalationStatus",
    "Metrics",
    "ResponseAction",
    "ResponsePolicy",
    "SYSTEM_ID",
    "SentinelAIEscalation",
    "SentinelMode",
    "ThreatAssessment",
    "ThreatKind",
    "ThreatSeverity",
    "ThreatSourceKind",
    "UNSUPPORTED_AUTONOMOUS_MODES",
    "normalize_ip",
    "sanitize_key_component",
    "stable_assessment_fingerprint",
]
