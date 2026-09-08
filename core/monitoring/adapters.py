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

"""Adapters that convert runtime signals into monitoring event models."""

from __future__ import annotations

from .event_types import (
    DependencyEvent,
    ExpectationEvent,
    RequestEvent,
    ResourceEvent,
    RuntimeEvent,
    SecurityEvent,
)


def request_event(
    status_code: int,
    latency_ms: int,
) -> RequestEvent:
    return RequestEvent(
        status_code=status_code,
        latency_ms=latency_ms,
    )


def expectation_event(
    status: str,
    failed_checks: int = 0,
) -> ExpectationEvent:
    return ExpectationEvent(
        expectation_status=status,
        failed_checks=failed_checks,
    )


def runtime_event(
    error_rate_percent: int | float,
    crash_loop: bool = False,
) -> RuntimeEvent:
    return RuntimeEvent(
        error_rate_percent=error_rate_percent,
        crash_loop=crash_loop,
    )


def dependency_event(
    status: str,
    version_mismatch: bool = False,
) -> DependencyEvent:
    return DependencyEvent(
        dependency_status=status,
        version_mismatch=version_mismatch,
    )


def resource_event(
    cpu_percent: int | float,
    memory_percent: int | float,
    disk_percent: int | float,
) -> ResourceEvent:
    return ResourceEvent(
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        disk_percent=disk_percent,
    )


def security_event(
    unsigned_artifact: bool = False,
    secrets_exposed: bool = False,
    debug_mode_enabled: bool = False,
) -> SecurityEvent:
    return SecurityEvent(
        unsigned_artifact=unsigned_artifact,
        secrets_exposed=secrets_exposed,
        debug_mode_enabled=debug_mode_enabled,
    )


__all__ = [
    "dependency_event",
    "expectation_event",
    "request_event",
    "resource_event",
    "runtime_event",
    "security_event",
]
