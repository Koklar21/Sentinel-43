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

"""Subsystem lifecycle states and startup configuration validation.

Two jobs, both deliberately small:

1. A single vocabulary for "what is this subsystem doing right now"
   (:class:`SubsystemState`), recorded in a thread-safe
   :class:`SubsystemRegistry` that the composition root owns and the
   health/readiness endpoints read.

2. A pure check for "was this subsystem given the configuration it needs"
   (:func:`missing_settings`), so an enabled-but-unconfigured subsystem is
   refused at startup with an explicit reason instead of starting half-alive
   and discarding its work at runtime.

This module is intentionally inert:
    - no environment reads (the composition root owns those and passes values in)
    - no network, filesystem, or logging side effects
    - no background threads or timers
    - no global singleton registry

SECRET SAFETY
    ``missing_settings`` accepts values only to test emptiness and returns
    **names only** -- never a value, never a prefix, never a length.
    :class:`SubsystemStatus` has no field that is permitted to hold credential
    material: ``reason`` is a fixed code from ``Reason`` and ``detail`` is
    operator-facing prose. Callers must not place secrets in either; nothing
    here will redact for you.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Final


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SubsystemState(StrEnum):
    """Lifecycle state of one optional or required subsystem.

    DISABLED     turned off by configuration; not a fault
    STARTING     initialization in progress
    ACTIVE       running and able to do its job
    DEGRADED     running, but not at full capability
    UNAVAILABLE  enabled but cannot run -- typically not configured
    FAILED       was running or tried to run, and broke
    STOPPING     orderly shutdown in progress
    STOPPED      shut down cleanly; not a fault

    UNAVAILABLE and FAILED are both faults but answer different operator
    questions: "you did not give it what it needs" versus "it broke". Mirrors
    the STOPPED/FAILED split on WatchtowerState.
    """

    DISABLED = "DISABLED"
    STARTING = "STARTING"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class Reason(StrEnum):
    """Stable, machine-readable explanation for a subsystem's state.

    These are codes, not messages: operators and probes match on them, so
    they must never be reworded to include contextual or secret detail.
    """

    NONE = ""
    DISABLED = "disabled"
    STARTING = "starting"
    MISSING_TOKEN = "missing_token"
    MISSING_CONFIG = "missing_config"
    INVALID_CONFIG = "invalid_config"
    START_FAILED = "start_failed"
    DEPENDENCY_UNREACHABLE = "dependency_unreachable"
    STOPPED = "stopped"


#: States in which a subsystem is doing its job.
_HEALTHY_STATES: Final[frozenset[SubsystemState]] = frozenset(
    {SubsystemState.ACTIVE}
)

#: States that are not faults -- a subsystem here is behaving as configured.
_NON_FAULT_STATES: Final[frozenset[SubsystemState]] = frozenset(
    {SubsystemState.DISABLED, SubsystemState.ACTIVE, SubsystemState.STOPPED}
)


def missing_settings(
    settings: Mapping[str, str | None],
) -> tuple[str, ...]:
    """Return the names of settings that are unset, empty, or whitespace.

    Values are inspected only for emptiness and are never returned, logged,
    or retained. Order follows the mapping so the caller's declaration order
    is preserved in the reported result.
    """
    return tuple(
        name
        for name, value in settings.items()
        if value is None or not str(value).strip()
    )


@dataclass(frozen=True, slots=True)
class SubsystemStatus:
    """Immutable status record for one subsystem.

    ``configured`` answers "was it given what it needs", which is distinct
    from ``state``: a subsystem can be correctly configured and still
    UNAVAILABLE because starting it failed.
    """

    name: str
    state: SubsystemState = SubsystemState.DISABLED
    configured: bool = False
    required: bool = False
    reason: Reason = Reason.NONE
    #: Operator-facing prose. Never put credential material here.
    detail: str = ""
    #: Names only -- see module docstring on secret safety.
    missing: tuple[str, ...] = ()
    updated_at: str = ""

    def __post_init__(self) -> None:
        name = str(self.name).strip()
        if not name:
            raise ValueError("subsystem name must not be empty")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "detail", str(self.detail).strip())
        object.__setattr__(self, "missing", tuple(self.missing))
        if not self.updated_at:
            object.__setattr__(self, "updated_at", _utc_now())

    @property
    def healthy(self) -> bool:
        return self.state in _HEALTHY_STATES

    @property
    def faulted(self) -> bool:
        """True when the subsystem is in a state it should not be in."""
        return self.state not in _NON_FAULT_STATES

    @property
    def blocks_readiness(self) -> bool:
        """A required subsystem that is not ACTIVE blocks readiness."""
        return self.required and not self.healthy

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "configured": self.configured,
            "required": self.required,
            "reason": self.reason.value,
            "detail": self.detail,
            "missing": list(self.missing),
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    ready: bool
    blocking: tuple[str, ...]
    degraded: tuple[str, ...]
    subsystems: tuple[SubsystemStatus, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "blocking": list(self.blocking),
            "degraded": list(self.degraded),
            "subsystems": [item.to_dict() for item in self.subsystems],
        }


class SubsystemRegistry:
    """Thread-safe record of subsystem lifecycle state.

    Owned by the composition root. Readers (health, readiness, status routes)
    only ever receive immutable snapshots.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: dict[str, SubsystemStatus] = {}

    def declare(
        self,
        name: str,
        *,
        required: bool = False,
    ) -> SubsystemStatus:
        """Register a subsystem before startup begins.

        Declaring up front means a subsystem that never reports is still
        visible, rather than silently absent from the status surface.
        """
        with self._lock:
            status = SubsystemStatus(
                name=name,
                state=SubsystemState.DISABLED,
                configured=False,
                required=required,
                reason=Reason.DISABLED,
            )
            self._items[status.name] = status
            return status

    def set(
        self,
        name: str,
        state: SubsystemState,
        *,
        configured: bool | None = None,
        required: bool | None = None,
        reason: Reason | None = None,
        detail: str | None = None,
        missing: Iterable[str] | None = None,
    ) -> SubsystemStatus:
        """Update a subsystem's state, carrying forward unspecified fields."""
        with self._lock:
            current = self._items.get(name)
            if current is None:
                current = SubsystemStatus(name=name)

            updated = replace(
                current,
                state=state,
                configured=(
                    current.configured if configured is None else configured
                ),
                required=(
                    current.required if required is None else required
                ),
                reason=(current.reason if reason is None else reason),
                detail=(current.detail if detail is None else detail),
                missing=(
                    current.missing if missing is None else tuple(missing)
                ),
                updated_at=_utc_now(),
            )
            self._items[updated.name] = updated
            return updated

    def mark_disabled(self, name: str) -> SubsystemStatus:
        return self.set(
            name,
            SubsystemState.DISABLED,
            configured=False,
            reason=Reason.DISABLED,
            detail="Disabled by configuration.",
            missing=(),
        )

    def mark_unconfigured(
        self,
        name: str,
        missing: Iterable[str],
        *,
        reason: Reason = Reason.MISSING_CONFIG,
    ) -> SubsystemStatus:
        """Record that an ENABLED subsystem was not given what it needs.

        The subsystem must not then be started: a half-started component that
        cannot do its job is worse than one that is plainly unavailable.
        """
        names = tuple(missing)
        return self.set(
            name,
            SubsystemState.UNAVAILABLE,
            configured=False,
            reason=reason,
            detail=(
                "Enabled but not configured; required settings are unset: "
                + ", ".join(names)
                if names
                else "Enabled but not configured."
            ),
            missing=names,
        )

    def mark_starting(self, name: str) -> SubsystemStatus:
        return self.set(
            name,
            SubsystemState.STARTING,
            configured=True,
            reason=Reason.STARTING,
            detail="Initializing.",
            missing=(),
        )

    def mark_active(self, name: str, detail: str = "") -> SubsystemStatus:
        return self.set(
            name,
            SubsystemState.ACTIVE,
            configured=True,
            reason=Reason.NONE,
            detail=detail,
            missing=(),
        )

    def mark_degraded(
        self,
        name: str,
        reason: Reason,
        detail: str = "",
    ) -> SubsystemStatus:
        return self.set(
            name,
            SubsystemState.DEGRADED,
            reason=reason,
            detail=detail,
        )

    def mark_failed(
        self,
        name: str,
        detail: str = "",
        *,
        reason: Reason = Reason.START_FAILED,
    ) -> SubsystemStatus:
        """It broke. Distinct from UNAVAILABLE, which means it was never
        given what it needs to run."""
        return self.set(
            name,
            SubsystemState.FAILED,
            reason=reason,
            detail=detail,
        )

    def mark_stopping(self, name: str) -> SubsystemStatus:
        return self.set(
            name,
            SubsystemState.STOPPING,
            reason=Reason.STOPPED,
            detail="Shutting down.",
        )

    def mark_stopped(self, name: str) -> SubsystemStatus:
        return self.set(
            name,
            SubsystemState.STOPPED,
            reason=Reason.STOPPED,
            detail="Shut down cleanly.",
            missing=(),
        )

    def get(self, name: str) -> SubsystemStatus | None:
        with self._lock:
            return self._items.get(name)

    def snapshot(self) -> tuple[SubsystemStatus, ...]:
        with self._lock:
            return tuple(
                self._items[key] for key in sorted(self._items)
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            item.name: item.to_dict() for item in self.snapshot()
        }

    def readiness(self) -> ReadinessReport:
        """Can this service actually do its job?

        A required subsystem that is not ACTIVE blocks readiness. An optional
        subsystem that is DISABLED is not a problem at all; one that is
        faulted makes the service degraded but still ready to serve.
        """
        items = self.snapshot()
        blocking = tuple(
            item.name for item in items if item.blocks_readiness
        )
        degraded = tuple(
            item.name
            for item in items
            if item.faulted and not item.blocks_readiness
        )
        return ReadinessReport(
            ready=not blocking,
            blocking=blocking,
            degraded=degraded,
            subsystems=items,
        )

    def reset(self) -> None:
        with self._lock:
            self._items.clear()


__all__ = [
    "ReadinessReport",
    "Reason",
    "SubsystemRegistry",
    "SubsystemState",
    "SubsystemStatus",
    "missing_settings",
]
