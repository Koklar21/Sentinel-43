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

"""Sentinel-43 node/core contract for the current runtime.

This owner-designated source originally implemented a complete standalone
node: local SQLite audit/state, replay suppression, action budgets,
corroboration, a worker queue, a scheduler, synthetic Watchtower modules,
human-gated staging, autonomous-veto execution and direct quarantine actions.

Those responsibilities remain part of the Sentinel-43 design, but their
current implementations now live beneath the single
Sentinel43RuntimeAuthority. Recreating the 2025 standalone machinery here
would create duplicate authority, state, queues, audit, monitoring and
execution paths.

This file therefore defines the current node/core facade and typed contracts.
It owns no independent store, worker, scheduler, Watchtower, approval queue or
executor.

Current responsibility flow:

    monitoring / Watchtower / detectors
                |
                v
        evidence / recommendation
                |
                v
          SentinelNode
                |
                v
      Sentinel43RuntimeAuthority
          |              |
          v              v
   SystemOrchestrator   owner response engine
          |
          v
   durable state + authoritative audit + human gate

Supported governance modes are SHADOW and HUMAN_GATED only. Autonomous veto
or delayed execution is intentionally unsupported.

The original synthetic Watchtower random-event generator is intentionally not
preserved as a live mechanism. The current monitoring/Watchtower stack owns
real observations and reports them toward Sentinel-43.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from core.governance.orchestrator import (
    DecisionPrincipal,
    ThreatRecommendation,
)
from core.governance.runtime_authority import Sentinel43RuntimeAuthority


logger = logging.getLogger(__name__)
SYSTEM_ID = "SENTINEL-43-NODE-01"


# =============================================================================
# Supported node contracts
# =============================================================================


class DeploymentMode(str, Enum):
    SHADOW = "SHADOW"
    HUMAN_GATED = "HUMAN_GATED"


UNSUPPORTED_AUTONOMOUS_MODES: frozenset[str] = frozenset(
    {"ACTIVE", "AUTONOMOUS", "AUTONOMOUS_VETO", "DELAYED_EXECUTE"}
)


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    SYSTEM = "SYSTEM"
    ALERT = "ALERT"
    ACTION_STAGE = "ACTION_STAGE"
    ACTION_DECISION = "ACTION_DECISION"
    ACTION_VETO = "ACTION_VETO"
    CONFIG = "CONFIG"
    ERROR = "ERROR"
    DROP = "DROP"
    REPLAY = "REPLAY"
    BUDGET = "BUDGET"
    CORROBORATE = "CORROBORATE"


@dataclass(frozen=True, slots=True)
class AnomalyRecord:
    """Typed node-level observation contract.

    This object is evidence only. Constructing an anomaly does not authorize
    or stage an action.
    """

    module_id: str
    description: str
    severity: RiskLevel
    detected_at: dt.datetime
    metadata: Mapping[str, Any] = field(default_factory=dict)
    event_id: str = ""

    def __post_init__(self) -> None:
        module_id = str(self.module_id or "").strip()
        description = str(self.description or "").strip()

        if not module_id or len(module_id) > 128:
            raise ValueError("module_id must be 1..128 characters")
        if not description or len(description) > 1000:
            raise ValueError("description must be 1..1000 characters")
        if not isinstance(self.detected_at, dt.datetime):
            raise TypeError("detected_at must be a datetime")
        if self.detected_at.tzinfo is None:
            raise ValueError("detected_at must be timezone-aware")

        metadata = dict(self.metadata or {})
        encoded = _canonical_json(metadata)
        if len(encoded.encode("utf-8")) > 20_000:
            raise ValueError("metadata is too large")

        event_id = str(self.event_id or "").strip()
        if not event_id:
            event_id = _default_event_id(
                module_id,
                self.detected_at,
                description,
                metadata,
            )
        if len(event_id) > 256:
            raise ValueError("event_id too long")

        object.__setattr__(self, "module_id", module_id)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "metadata", MappingProxyType(metadata))
        object.__setattr__(self, "event_id", event_id)


@dataclass(frozen=True, slots=True)
class PendingAction:
    """Read-only reference to a governed action.

    The old core stored executable callables in PendingAction. The current
    contract stores no executable payload here; execution authority does not
    belong to this node facade.
    """

    action_id: str
    description: str
    created_at: dt.datetime
    risk_level: RiskLevel
    principal_id: str
    status: str


@dataclass(frozen=True, slots=True)
class NodeStatus:
    system_id: str
    mode: str
    recommendation_store_attached: bool
    engine_identity: Mapping[str, str] | None
    autonomous_execution_supported: bool
    local_scheduler_active: bool
    local_audit_store_active: bool
    synthetic_watchtower_active: bool


@dataclass(slots=True)
class Metrics:
    """Entry-point metrics only.

    Subsystem-owned metrics remain in the live monitoring, Heart, governance,
    store and audit implementations rather than being duplicated here.
    """

    anomalies_validated: int = 0
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
# Stable observation helpers
# =============================================================================


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )


def _hash_str(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _default_event_id(
    module_id: str,
    detected_at: dt.datetime,
    description: str,
    metadata: Mapping[str, Any],
) -> str:
    payload = {
        "module_id": module_id,
        "detected_at": detected_at.astimezone(dt.timezone.utc).isoformat(),
        "description": description,
        "metadata": dict(metadata),
    }
    return _hash_str(_canonical_json(payload))


# =============================================================================
# Sentinel node facade
# =============================================================================


class SentinelNode:
    """Current node/core facade over Sentinel43RuntimeAuthority.

    The node is an intake and visibility surface. It is not an independent
    decision authority and cannot execute an external response.
    """

    def __init__(
        self,
        *,
        authority: Sentinel43RuntimeAuthority,
    ) -> None:
        if not isinstance(authority, Sentinel43RuntimeAuthority):
            raise TypeError(
                "SentinelNode requires the live Sentinel43RuntimeAuthority"
            )

        self._authority = authority
        self.metrics = Metrics()
        logger.info(
            "[%s] Node bound to Sentinel43RuntimeAuthority",
            SYSTEM_ID,
        )

    @property
    def authority(self) -> Sentinel43RuntimeAuthority:
        return self._authority

    @property
    def mode(self) -> DeploymentMode:
        value = self._authority.governance_mode
        return DeploymentMode(value.strip().upper())

    def set_mode(self, mode: DeploymentMode | str) -> None:
        """Refuse hidden runtime mode mutation.

        Governance posture is established by the Sentinel-43 composition
        configuration, not by a node-local setter.
        """

        value = (
            mode.value
            if isinstance(mode, DeploymentMode)
            else str(mode).strip().upper()
        )
        if value in UNSUPPORTED_AUTONOMOUS_MODES:
            raise ValueError(
                "autonomous/ACTIVE governance is not supported"
            )

        try:
            requested = DeploymentMode(value)
        except ValueError as exc:
            raise ValueError("mode must be SHADOW or HUMAN_GATED") from exc

        if requested is self.mode:
            return

        raise RuntimeError(
            "runtime mode changes are controlled by Sentinel-43 composition "
            "configuration; restart with the requested supported mode"
        )

    def validate_anomaly(self, anomaly: AnomalyRecord) -> AnomalyRecord:
        """Accept a typed observation without turning evidence into authority."""

        if not isinstance(anomaly, AnomalyRecord):
            raise TypeError("anomaly must be an AnomalyRecord")

        self.metrics.anomalies_validated += 1
        return anomaly

    def submit_recommendation(
        self,
        recommendation: ThreatRecommendation,
    ) -> Any:
        """Submit a governed recommendation through Sentinel-43."""

        if not isinstance(recommendation, ThreatRecommendation):
            raise TypeError(
                "submit_recommendation requires ThreatRecommendation"
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
        """Resolve only through the authoritative human-decision path."""

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

    def get_metrics(self) -> dict[str, int]:
        return self.metrics.snapshot()

    def status(self) -> NodeStatus:
        return NodeStatus(
            system_id=SYSTEM_ID,
            mode=self.mode.value,
            recommendation_store_attached=(
                self._authority.recommendation_store_attached
            ),
            engine_identity=self._authority.engine_identity,
            autonomous_execution_supported=False,
            local_scheduler_active=False,
            local_audit_store_active=False,
            synthetic_watchtower_active=False,
        )

    # ------------------------------------------------------------------
    # Explicitly retired standalone mechanisms
    # ------------------------------------------------------------------

    def run_watchtower_cycle(self) -> None:
        raise RuntimeError(
            "synthetic node-local Watchtower is not supported; use the "
            "current monitoring/Watchtower runtime and report its evidence "
            "through Sentinel-43"
        )

    def trigger_response(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError(
            "SentinelNode cannot execute or independently stage a response; "
            "build/report a ThreatRecommendation through "
            "Sentinel43RuntimeAuthority"
        )

    def approve_staged_action(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError(
            "node-local approval is not supported; resolve the governed "
            "recommendation through Sentinel43RuntimeAuthority with a "
            "server-verified DecisionPrincipal"
        )

    def veto_action(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError(
            "node-local veto is not supported; resolve the governed "
            "recommendation through Sentinel43RuntimeAuthority with a "
            "server-verified DecisionPrincipal"
        )

    def shutdown(self) -> None:
        """No-op by design.

        This facade owns no worker, scheduler, store or audit resource.
        Sentinel43RuntimeAuthority owns the lifecycle of its real runtime.
        """

        logger.info("[%s] Node facade released", SYSTEM_ID)


# =============================================================================
# Original responsibility map
# =============================================================================


CORE_RESPONSIBILITY_MAP: Mapping[str, str] = MappingProxyType(
    {
        "node_orchestration": "Sentinel43RuntimeAuthority",
        "typed_anomaly_contract": "SentinelNode / monitoring evidence models",
        "event_replay_protection": "current monitoring/detection pipeline",
        "ingest_backpressure": "current monitoring/detection pipeline",
        "action_budget": "SystemOrchestrator governed path",
        "corroboration": "Heart",
        "human_gated_staging": "Sentinel43RuntimeAuthority -> SystemOrchestrator",
        "response_planning": "owner-designated response engine",
        "durable_pending_state": "SentinelCoreStore",
        "authoritative_audit": "AuditStore via SystemOrchestrator",
        "watchtower": "current Watchtower/monitoring runtime",
        "synthetic_random_watchtower": "INTENTIONALLY_NOT_USED",
        "local_worker_queue": "INTENTIONALLY_NOT_USED",
        "local_scheduler": "INTENTIONALLY_NOT_USED",
        "local_sqlite_audit": "INTENTIONALLY_NOT_USED",
        "autonomous_veto_execution": "INTENTIONALLY_UNSUPPORTED",
        "direct_quarantine_execution": "INTENTIONALLY_UNSUPPORTED",
    }
)


__all__ = [
    "AnomalyRecord",
    "CORE_RESPONSIBILITY_MAP",
    "DeploymentMode",
    "EventType",
    "Metrics",
    "NodeStatus",
    "PendingAction",
    "RiskLevel",
    "SYSTEM_ID",
    "SentinelNode",
    "UNSUPPORTED_AUTONOMOUS_MODES",
]
