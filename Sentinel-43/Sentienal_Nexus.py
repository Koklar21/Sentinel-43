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

"""Sentinel-43 Nexus: current top-level orchestration contract.

This file is one of the owner-designated Sentinel-43 orchestration sources.
Its responsibility is CURRENT: the Nexus is the top-level orchestration
boundary through which governed threat/recommendation decisions enter the
Sentinel-43 brain.

The 2025 standalone implementation carried its own SQLite store, scheduler,
approval queues, audit chain and direct effect callbacks. Those mechanics
must not run beside the current runtime because doing so would create a second
authority, second durable state path and second approval/execution path.

The live implementation of the Nexus responsibility is composed through
core.governance.runtime_authority.Sentinel43RuntimeAuthority:

    evidence / Heart / governed callers
                  |
                  v
           SentinelNexus
                  |
                  v
      Sentinel43RuntimeAuthority
          |       |       |
          |       |       +-- authoritative audit / durable state
          |       +---------- SystemOrchestrator governance
          +------------------ owner-designated response engine

Supported operating modes are SHADOW and HUMAN_GATED only. Autonomous
execution (the old ACTIVE/AUTONOMOUS_VETO scheduler path) is explicitly
unsupported. No external effect may be executed directly from this module.

Original Nexus responsibilities retained here:
- typed threat/evidence intake contract
- stable fingerprinting
- top-level authority ownership contract
- policy/governance delegation
- dedupe/budget/corroboration/back-pressure responsibility mapping
- human-gated decision delegation
- durable state/audit responsibility mapping
- controlled IntegrationHub effect boundary
- lifecycle/status/metrics surface

The current durable implementations live beneath Sentinel43RuntimeAuthority;
this module does not duplicate them.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from core.governance.orchestrator import (
    DecisionPrincipal,
    ThreatRecommendation,
)
from core.governance.runtime_authority import Sentinel43RuntimeAuthority


SYSTEM_ID = "SENTINEL-43-NEXUS-01"
logger = logging.getLogger(__name__)


# =============================================================================
# Operating contract
# =============================================================================


class OpMode(str, Enum):
    """Owner-supported Sentinel-43 operating modes."""

    SHADOW = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"


UNSUPPORTED_AUTONOMOUS_MODES: frozenset[str] = frozenset(
    {"ACTIVE", "AUTONOMOUS_VETO", "DELAYED_EXECUTE"}
)


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReasonCode(str, Enum):
    UNKNOWN = "UNKNOWN"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    MALWARE_BEACON = "MALWARE_BEACON"
    C2_TRAFFIC = "C2_TRAFFIC"
    AUTH_ABUSE = "AUTH_ABUSE"
    DOS_PATTERN = "DOS_PATTERN"
    SUSPICIOUS_ASN = "SUSPICIOUS_ASN"
    GEO_ANOMALY = "GEO_ANOMALY"


class DecisionType(str, Enum):
    """Decision classes that can exist in the supported runtime."""

    NONE = "NONE"
    OBSERVE = "OBSERVE"
    REQUIRES_HUMAN = "REQUIRES_HUMAN"


@dataclass(frozen=True, slots=True)
class Evidence:
    """Typed Nexus evidence envelope."""

    system: str
    sensor: str
    observed_at: int
    confidence: float
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        system = str(self.system or "").strip()
        sensor = str(self.sensor or "").strip()
        confidence = float(self.confidence)

        if not system:
            raise ValueError("evidence.system is required")
        if not sensor:
            raise ValueError("evidence.sensor is required")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("evidence.confidence must be within [0.0, 1.0]")

        details = dict(self.details or {})
        encoded = _json_dumps(details)
        if len(encoded.encode("utf-8")) > 20_000:
            raise ValueError("evidence.details is too large")

        object.__setattr__(self, "system", system[:128])
        object.__setattr__(self, "sensor", sensor[:128])
        object.__setattr__(self, "observed_at", int(self.observed_at))
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "details", MappingProxyType(details))


@dataclass(frozen=True, slots=True)
class ThreatEvent:
    """Typed threat intake contract retained from the original Nexus."""

    target: str
    threat_type: str
    reason_code: ReasonCode
    severity: Severity
    evidence: Evidence

    def __post_init__(self) -> None:
        target = str(self.target or "").strip()
        threat_type = str(self.threat_type or "").strip() or "UNKNOWN"

        if not target:
            raise ValueError("target is required")
        if len(target) > 256:
            raise ValueError("target too long")

        object.__setattr__(self, "target", target)
        object.__setattr__(self, "threat_type", threat_type[:120])


@dataclass(frozen=True, slots=True)
class NexusStatus:
    system_id: str
    mode: str
    recommendation_store_attached: bool
    engine_identity: Mapping[str, str] | None
    autonomous_execution_supported: bool = False


@dataclass(slots=True)
class Metrics:
    """Nexus-entry metrics only.

    Governance/Heart/store metrics remain owned by their live implementations;
    this object deliberately does not create a competing metrics authority.
    """

    threat_events_built: int = 0
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
# Stable intake helpers
# =============================================================================


def _json_dumps(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def stable_fingerprint(
    *,
    target: str,
    threat_type: str,
    reason_code: ReasonCode,
    reason: str,
    extra: Mapping[str, Any] | None = None,
) -> str:
    """Stable Nexus fingerprint contract retained for evidence correlation."""

    payload = {
        "target": str(target),
        "threat_type": str(threat_type),
        "reason_code": reason_code.value,
        "reason": str(reason),
        "extra": dict(extra or {}),
    }
    return hashlib.sha256(_json_dumps(payload).encode("utf-8")).hexdigest()


# =============================================================================
# Integration boundary
# =============================================================================


class IntegrationHub:
    """Controlled effect boundary.

    The original standalone Nexus performed direct firewall callbacks here.
    The supported runtime does not permit this module to execute external
    effects. Any future integration must be explicitly bound beneath the
    Sentinel-43 authority and policy/human-approval chain.

    Keeping this boundary explicit preserves the original architectural rule:
    effects must terminate at an integration boundary rather than being
    scattered through detectors, Heart, API handlers or dashboard code.
    """

    @staticmethod
    def execute_external_effect(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError(
            "direct external execution is not supported; route the operation "
            "through Sentinel43RuntimeAuthority and an explicitly governed "
            "integration adapter"
        )

    @staticmethod
    def describe_boundary() -> dict[str, Any]:
        return {
            "system": SYSTEM_ID,
            "external_execution": False,
            "requires_authority": "Sentinel43RuntimeAuthority",
            "requires_human_gate": True,
        }


# =============================================================================
# Nexus facade
# =============================================================================


class SentinelNexus:
    """Current Nexus facade over the one Sentinel-43 runtime authority.

    This class owns no store, scheduler, approval queue, audit database or
    executor. It is the explicit Nexus entry surface and delegates governed
    decisions into Sentinel43RuntimeAuthority.
    """

    def __init__(
        self,
        *,
        authority: Sentinel43RuntimeAuthority,
    ) -> None:
        if not isinstance(authority, Sentinel43RuntimeAuthority):
            raise TypeError(
                "SentinelNexus requires the live Sentinel43RuntimeAuthority"
            )

        self._authority = authority
        self._integration = IntegrationHub()
        self.metrics = Metrics()
        logger.info(
            "[%s] Nexus bound to Sentinel43RuntimeAuthority",
            SYSTEM_ID,
        )

    @property
    def authority(self) -> Sentinel43RuntimeAuthority:
        return self._authority

    def describe_integration_boundary(self) -> dict[str, Any]:
        """Read-only description of the live fail-closed effect boundary."""
        return self._integration.describe_boundary()

    def execute_external_effect(self, *_args: Any, **_kwargs: Any) -> None:
        """Keep every external effect fail-closed at the Nexus boundary."""
        return self._integration.execute_external_effect(*_args, **_kwargs)

    def get_mode(self) -> OpMode:
        value = self._authority.governance_mode
        return OpMode(value.strip().upper())

    def set_mode(self, mode: OpMode | str) -> None:
        """Refuse hidden runtime mode mutation.

        Mode is deployment/composition configuration in the current runtime.
        A caller must not be able to switch the system into another authority
        posture through an incidental Nexus method.
        """

        value = mode.value if isinstance(mode, OpMode) else str(mode).strip().upper()
        if value in UNSUPPORTED_AUTONOMOUS_MODES:
            raise ValueError(
                "autonomous/ACTIVE governance is not supported"
            )
        try:
            requested = OpMode(value)
        except ValueError as exc:
            raise ValueError("mode must be SHADOW or HUMAN_GATED") from exc

        if requested is self.get_mode():
            return

        raise RuntimeError(
            "runtime mode changes are controlled by Sentinel-43 composition "
            "configuration; restart with the requested supported mode"
        )

    def build_threat(
        self,
        *,
        target: str,
        threat_type: str,
        severity: Severity = Severity.MEDIUM,
        reason_code: ReasonCode = ReasonCode.UNKNOWN,
        sensor: str = "manual",
        confidence: float = 0.65,
        details: Mapping[str, Any] | None = None,
        observed_at: int | None = None,
    ) -> ThreatEvent:
        event = ThreatEvent(
            target=target,
            threat_type=threat_type,
            reason_code=reason_code,
            severity=severity,
            evidence=Evidence(
                system=SYSTEM_ID,
                sensor=sensor,
                observed_at=int(time.time()) if observed_at is None else int(observed_at),
                confidence=confidence,
                details=details or {},
            ),
        )
        self.metrics.threat_events_built += 1
        return event

    def submit_recommendation(
        self,
        recommendation: ThreatRecommendation,
    ) -> Any:
        """Enter the live recommendation path through Sentinel-43 authority."""

        if not isinstance(recommendation, ThreatRecommendation):
            raise TypeError(
                "submit_recommendation requires ThreatRecommendation; "
                "detectors/Heart own conversion from evidence into a governed "
                "recommendation"
            )

        try:
            result = self._authority._stage_recommendation_from_nexus(
                recommendation
            )
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
        """Resolve only through the live Sentinel-43 human-decision path."""

        try:
            result = self._authority._resolve_recommendation_from_nexus(
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

    def list_pending_recommendations(
        self,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        return self._authority.list_pending_recommendations(limit)

    def list_pending_reviews(self) -> list[dict[str, Any]]:
        return self._authority.list_pending_reviews()

    def list_incidents(
        self,
        limit: int = 200,
    ) -> tuple[Mapping[str, Any], ...]:
        return self._authority.list_incidents(limit=limit)

    def status(self) -> NexusStatus:
        return NexusStatus(
            system_id=SYSTEM_ID,
            mode=self.get_mode().value,
            recommendation_store_attached=(
                self._authority.recommendation_store_attached
            ),
            engine_identity=self._authority.engine_identity,
        )


# =============================================================================
# Responsibility map
# =============================================================================


NEXUS_RESPONSIBILITY_MAP: Mapping[str, str] = MappingProxyType(
    {
        "top_level_orchestration": "Sentinel43RuntimeAuthority",
        "typed_threat_intake": "SentinelNexus/Heart",
        "policy_evaluation": "SystemOrchestrator + policy_gate",
        "response_planning": "owner-designated response engine",
        "dedupe": "owner engine / Heart governed path",
        "corroboration": "Heart",
        "backpressure": "SystemOrchestrator/Heart governed path",
        "per_target_budget": "SystemOrchestrator governed path",
        "human_gating": "Sentinel43RuntimeAuthority -> SystemOrchestrator",
        "durable_pending_state": "SentinelCoreStore",
        "authoritative_audit": "AuditStore via SystemOrchestrator",
        "integration_boundary": "IntegrationHub contract",
        "autonomous_execution": "INTENTIONALLY_UNSUPPORTED",
        "standalone_scheduler": "INTENTIONALLY_NOT_USED",
        "standalone_state_store": "INTENTIONALLY_NOT_USED",
    }
)


__all__ = [
    "DecisionType",
    "Evidence",
    "IntegrationHub",
    "Metrics",
    "NEXUS_RESPONSIBILITY_MAP",
    "NexusStatus",
    "OpMode",
    "ReasonCode",
    "SYSTEM_ID",
    "SentinelNexus",
    "Severity",
    "ThreatEvent",
    "UNSUPPORTED_AUTONOMOUS_MODES",
    "stable_fingerprint",
]
