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

"""Top-level runtime authority for the Sentinel-43 orchestration brain.

This object establishes the ownership boundary that the rest of the runtime
must respect: Sentinel-43 owns governance composition.  SystemOrchestrator is
a subordinate governance service; the owner-designated response engine is
created here and injected into that service rather than being constructed by
it.

The owner-designated Nexus, node/core, and AI-escalation sources are loaded
and owned here as live runtime components. The shared monitoring/evidence
manager and identity/session mutation service are also owned here. Watchtower
transport, remaining detection lifecycle, and the dashboard are integrated
through this same boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .orchestrator import DecisionPrincipal, SystemOrchestrator


class Sentinel43RuntimeAuthority:
    """Own the live Sentinel-43 governance stack.

    There is exactly one authority object at the composition boundary.  It
    owns the SystemOrchestrator and the owner-designated engine lifecycle,
    while delegating existing governance behaviour to those mature
    implementations.
    """

    def __init__(
        self,
        orchestrator: SystemOrchestrator,
        *,
        monitoring_manager: Any | None = None,
    ) -> None:
        if orchestrator is None:
            raise ValueError("Sentinel43RuntimeAuthority requires an orchestrator")
        self._orchestrator = orchestrator
        self._engine: Any | None = None
        self._monitoring_manager = monitoring_manager
        self._heart: Any | None = None

        from .identity import IdentityGovernanceService

        self._identity = IdentityGovernanceService(
            audit_sink=self._orchestrator.append_authoritative_audit
        )

        # The owner source directory is part of the live runtime, not a
        # historical appendix. Load the three non-engine owner components
        # exactly once and bind all of them to this same authority.
        from .owner_components import load_owner_runtime_components

        self._owner_components = load_owner_runtime_components(self)

    @property
    def governance_mode(self) -> str:
        """Effective governance posture exposed by the authority itself.

        Callers do not receive the subordinate SystemOrchestrator object.
        """
        mode = self._orchestrator.default_mode
        return str(getattr(mode, "value", mode)).strip().upper()

    @property
    def threat_ingress_available(self) -> bool:
        """Whether a Heart is attached behind the authority boundary."""
        return self._heart is not None

    def attach_heart(self, heart: Any) -> None:
        if heart is None:
            raise ValueError("Sentinel43RuntimeAuthority requires a Heart instance")
        if self._heart is not None and self._heart is not heart:
            raise RuntimeError("a different Heart is already attached")
        self._heart = heart

    def detach_heart(self) -> None:
        self._heart = None

    def observe_threat(self, assessment: Any) -> Any:
        """Detection ingress through the owner AI-escalation contract.

        Fenrir reports to Sentinel-43. The owner escalation component validates
        the canonical assessment, governed subject and requested mode before
        the same assessment reaches Heart. Escalation owns no response plan or
        staging authority.
        """
        heart = self._heart
        if heart is None:
            raise RuntimeError("Sentinel-43 Heart is not attached")

        envelope = self._owner_components.ai_escalation.build_envelope(
            assessment
        )
        return heart.observe(
            envelope.assessment,
            mode=envelope.requested_mode.value,
        )

    @property
    def monitoring_manager(self) -> Any | None:
        """The one monitoring/evidence manager owned by this runtime."""
        return self._monitoring_manager

    @property
    def identity(self) -> Any:
        """Governed account/session mutation service."""
        return self._identity

    @property
    def nexus(self) -> Any:
        """The live owner-designated Nexus entry component."""
        return self._owner_components.nexus

    @property
    def node(self) -> Any:
        """The live owner-designated node/core component."""
        return self._owner_components.node

    @property
    def ai_escalation(self) -> Any:
        """The live owner-designated AI-escalation component."""
        return self._owner_components.ai_escalation

    @property
    def owner_component_identities(self) -> dict[str, dict[str, str]]:
        """Source provenance for the three loaded owner components."""
        return self._owner_components.identity_map()

    def authority_snapshot(self) -> dict[str, Any]:
        """Read-only proof of the live Sentinel-43 authority composition.

        The snapshot exposes identities and state, never subordinate service
        objects, stores, queues, authenticators, or mutation capabilities.
        """
        mode = self._orchestrator.default_mode
        return {
            "authority": type(self).__name__,
            "mode": str(getattr(mode, "value", mode)).strip().upper(),
            "owner_components": self.owner_component_identities,
            "owner_engine": self.engine_identity,
            "recommendation_store_attached": self.recommendation_store_attached,
            "runtime_reporting_available": self._monitoring_manager is not None,
            "external_execution_supported": False,
        }

    def report_runtime_observation(self, observation: Any) -> Any:
        """Public runtime/deployment reporting entry through SentinelNode."""
        return self._owner_components.node.report_runtime_observation(
            observation
        )

    def _report_runtime_observation_from_node(
        self,
        observation: Any,
    ) -> Any:
        """Node-only handoff into the authority-owned monitoring pipeline."""
        manager = self._monitoring_manager
        if manager is None:
            raise RuntimeError(
                "Sentinel-43 monitoring manager is unavailable"
            )

        to_event = getattr(observation, "to_monitoring_event", None)
        if not callable(to_event):
            raise TypeError(
                "runtime observation must expose to_monitoring_event()"
            )

        event = to_event()
        return manager.analyze_event(
            event,
            source_ip=str(event.get("pod_ip") or "").strip() or None,
            source_identity=str(
                event.get("source_identity") or ""
            ).strip() or None,
            trusted_producer=None,
        )

    @property
    def recommendation_store_attached(self) -> bool:
        return self._orchestrator.recommendation_store_attached

    @property
    def engine_identity(self) -> dict[str, str] | None:
        return self._orchestrator.engine_identity

    def attach_recommendation_store(
        self,
        store: Any,
        *,
        operator_authenticator: Callable[[DecisionPrincipal], bool] | None,
        max_pending_actions: int,
    ) -> None:
        """Create the ONE owner engine and bind it beneath this authority."""
        from .sentinel43_engine import GovernedEngine

        authenticator = (
            operator_authenticator
            if operator_authenticator is not None
            else (lambda _principal: False)
        )
        engine = GovernedEngine(
            store,
            human_authenticator=authenticator,
            audit_sink=self._orchestrator.append_authoritative_audit,
        )

        try:
            self._orchestrator.bind_recommendation_runtime(
                store,
                engine=engine,
                operator_authenticator=authenticator,
                max_pending_actions=max_pending_actions,
            )
        except Exception:
            engine.shutdown()
            raise

        # bind_recommendation_runtime owns replacement cleanup for the
        # previously-bound engine.  Keep our reference aligned without
        # shutting the same engine down twice.
        self._engine = engine

    def detach_recommendation_store(self) -> None:
        """Detach and stop the owned recommendation engine exactly once."""
        engine = self._engine
        self._engine = None
        self._orchestrator.detach_recommendation_store()
        # detach_recommendation_store() shuts the engine bound into the
        # orchestrator.  Do not call shutdown again here.
        if engine is not None and self._orchestrator.recommendation_store_attached:
            # Defensive invariant: a detached authority may never retain an
            # attached subordinate runtime.
            raise RuntimeError("recommendation runtime remained attached")

    def shutdown(self) -> None:
        """Stop resources owned by the Sentinel-43 runtime authority."""
        monitoring = self._monitoring_manager
        self._monitoring_manager = None
        try:
            if monitoring is not None:
                monitoring.stop()
                try:
                    from core.monitoring import set_monitoring_manager

                    set_monitoring_manager(None)
                except Exception:
                    # Registry cleanup is best-effort; the owned instance is
                    # already stopped and detached from this authority.
                    pass
        finally:
            self.detach_heart()
            self.detach_recommendation_store()

    # ------------------------------------------------------------------
    # Authority surface used by Heart/API.
    # These calls enter Sentinel-43 first; the subordinate orchestrator
    # performs the existing governance mechanics.
    # ------------------------------------------------------------------

    def stage_recommendation(self, recommendation: Any) -> Any:
        """Public governed entry: every recommendation crosses the Nexus."""
        return self._owner_components.nexus.submit_recommendation(recommendation)

    def _stage_recommendation_from_nexus(self, recommendation: Any) -> Any:
        """Nexus-only handoff into the subordinate governance service."""
        return self._orchestrator.stage_recommendation(recommendation)

    def resolve_recommendation(
        self,
        action_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str = "",
        principal: DecisionPrincipal | None = None,
    ) -> dict[str, Any]:
        """Public governed decision entry: resolution crosses the Nexus."""
        return self._owner_components.nexus.resolve_recommendation(
            action_id,
            approved=approved,
            operator_id=operator_id,
            reason=reason,
            principal=principal,
        )

    def _resolve_recommendation_from_nexus(
        self,
        action_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str = "",
        principal: DecisionPrincipal | None = None,
    ) -> dict[str, Any]:
        """Nexus-only handoff into the subordinate governance service."""
        return self._orchestrator.resolve_recommendation(
            action_id,
            approved=approved,
            operator_id=operator_id,
            reason=reason,
            principal=principal,
        )

    def count_pending_recommendations(self) -> int:
        return self._orchestrator.count_pending_recommendations()

    def list_pending_recommendations(self, limit: int = 500) -> list[dict[str, Any]]:
        return self._orchestrator.list_pending_recommendations(limit)

    def list_pending_reviews(self) -> list[dict[str, Any]]:
        return self._orchestrator.list_pending_reviews()

    def record_denied_decision(
        self,
        decision_id: str,
        *,
        operator_id: str,
        reason_code: str,
        identity_type: str,
    ) -> None:
        self._orchestrator.record_denied_decision(
            decision_id,
            operator_id=operator_id,
            reason_code=reason_code,
            identity_type=identity_type,
        )

    def resolve_human_decision(
        self,
        decision_id: str,
        *,
        approved: bool,
        operator_id: str,
        reason: str,
    ) -> Any:
        return self._orchestrator.resolve_human_decision(
            decision_id,
            approved=approved,
            operator_id=operator_id,
            reason=reason,
        )

    def expire_unverifiable_recommendation(
        self,
        action_id: str,
        *,
        reason: str,
    ) -> bool:
        return self._orchestrator.expire_unverifiable_recommendation(
            action_id,
            reason=reason,
        )

    def list_incidents(self, limit: int = 200) -> tuple[Mapping[str, Any], ...]:
        return self._orchestrator.list_incidents(limit=limit)


__all__ = ["Sentinel43RuntimeAuthority"]
