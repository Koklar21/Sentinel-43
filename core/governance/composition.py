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

"""Governance composition.

Assembles a :class:`SystemOrchestrator` from an already-validated settings
object supplied by the API composition root.

This module performs:
    - no environment reads
    - no filesystem/network I/O
    - no background thread creation
    - no global/singleton state

The authoritative audit writer is injected explicitly. Governance is
non-autonomous: only SHADOW and HUMAN_GATED modes exist and the orchestrator
has no timer-driven or background execution path.
"""

from __future__ import annotations

from typing import Any

from core.guards.velocity import VelocityConfig, VelocityGuard
from core.sentinel43_core_db import SentinelCoreStore

from .heart import HeartConfig, ThreatGovernor
from .orchestrator import (
    DEFAULT_REVIEW_TTL_SECONDS,
    MAX_PENDING_REVIEWS,
    AuditWriter,
    GovernanceMode,
    SystemOrchestrator,
)

_SUPPORTED_MODES: frozenset[str] = frozenset(
    mode.value for mode in GovernanceMode
)


def _get(settings: Any, name: str, default: Any) -> Any:
    value = getattr(settings, name, default)
    return default if value is None else value


def _validate_mode(raw: Any) -> GovernanceMode:
    normalized = str(raw or "").strip().upper()
    if normalized not in _SUPPORTED_MODES:
        raise ValueError(
            f"governance default_mode must be one of {sorted(_SUPPORTED_MODES)}; "
            f"got {raw!r}. Autonomous/ACTIVE governance is not supported."
        )
    return GovernanceMode(normalized)


def build_orchestrator_from_settings(
    settings: Any,
    *,
    audit_store: AuditWriter,
    monitoring_manager: Any | None = None,
) -> SystemOrchestrator:
    """Build a SystemOrchestrator from a validated settings object.

    ``settings`` is duck-typed; the composition root owns all environment
    parsing and passes concrete values here. ``audit_store`` must be an
    initialized authoritative audit writer — the orchestrator fails a
    resolution (rather than reporting success) if an audit append raises.
    """
    if audit_store is None:
        raise ValueError(
            "build_orchestrator_from_settings requires an explicit, "
            "initialized authoritative audit_store"
        )

    default_mode = _validate_mode(_get(settings, "default_mode", "HUMAN_GATED"))

    velocity_guard = VelocityGuard(
        VelocityConfig(
            window_seconds=float(
                _get(settings, "velocity_window_seconds", 60.0)
            ),
            limit=int(_get(settings, "velocity_limit", 10)),
            gc_interval_seconds=float(
                _get(settings, "velocity_gc_interval_seconds", 300.0)
            ),
            max_tracked_users=int(
                _get(settings, "velocity_max_tracked_users", 10_000)
            ),
        )
    )

    return SystemOrchestrator(
        audit_store=audit_store,
        velocity_guard=velocity_guard,
        environment=str(_get(settings, "environment", "production")),
        default_mode=default_mode,
        hash_device_ids=bool(_get(settings, "hash_device_ids", False)),
        monitoring_manager=monitoring_manager,
        review_ttl_seconds=int(
            _get(settings, "review_ttl_seconds", DEFAULT_REVIEW_TTL_SECONDS)
        ),
        max_pending_reviews=int(
            _get(settings, "max_pending_reviews", MAX_PENDING_REVIEWS)
        ),
    )


def build_heart_from_settings(
    settings: Any,
    *,
    audit_store: AuditWriter,
    core_store: SentinelCoreStore,
    monitoring_manager: Any | None = None,
    action_sink: Any | None = None,
    on_health_change: Any | None = None,
) -> ThreatGovernor:
    """Build a ThreatGovernor (the "Heart") from a validated settings object.

    Mirrors :func:`build_orchestrator_from_settings`: ``settings`` is
    duck-typed and owned by the API composition root, which does all
    environment parsing. ``audit_store`` and ``core_store`` must already be
    initialized -- this function performs no filesystem/network I/O.
    """
    if audit_store is None:
        raise ValueError(
            "build_heart_from_settings requires an explicit, initialized "
            "authoritative audit_store"
        )

    if core_store is None:
        raise ValueError(
            "build_heart_from_settings requires an explicit, initialized "
            "SentinelCoreStore"
        )

    default_mode = _validate_mode(_get(settings, "default_mode", "HUMAN_GATED"))

    velocity_guard = VelocityGuard(
        VelocityConfig(
            window_seconds=float(
                _get(settings, "velocity_window_seconds", 60.0)
            ),
            limit=int(_get(settings, "velocity_limit", 30)),
        )
    )

    heart_config = HeartConfig(
        dedupe_ttl_seconds=int(_get(settings, "dedupe_ttl_seconds", 300)),
        corroboration_window_seconds=int(
            _get(settings, "corroboration_window_seconds", 300)
        ),
        corroboration_min_signals_for_high=int(
            _get(settings, "corroboration_min_signals_for_high", 2)
        ),
    )

    return ThreatGovernor(
        audit_store=audit_store,
        velocity_guard=velocity_guard,
        core_store=core_store,
        default_mode=default_mode,
        config=heart_config,
        monitoring_manager=monitoring_manager,
        action_sink=action_sink,
        on_health_change=on_health_change,
    )


__all__ = ["build_heart_from_settings", "build_orchestrator_from_settings"]
