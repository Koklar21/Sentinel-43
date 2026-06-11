# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

from __future__ import annotations

from typing import Any, Dict

from .event_types import (
    RequestEvent,
    ExpectationEvent,
    RuntimeEvent,
    DependencyEvent,
    ResourceEvent,
    SecurityEvent,
)


# ============================================================
# API / Request Monitoring
# ============================================================

def request_event(status_code: int, latency_ms: int) -> RequestEvent:
    """
    Convert API request metrics into a monitoring event.
    """
    return RequestEvent(
        status_code=status_code,
        latency_ms=latency_ms,
    )


# ============================================================
# Expectation Monitoring
# ============================================================

def expectation_event(status: str, failed_checks: int = 0) -> ExpectationEvent:
    """
    Convert expectation validation results into a monitoring event.
    """
    return ExpectationEvent(
        expectation_status=status,
        failed_checks=failed_checks,
    )


# ============================================================
# Runtime Health Monitoring
# ============================================================

def runtime_event(error_rate_percent: int, crash_loop: bool = False) -> RuntimeEvent:
    """
    Convert runtime health metrics into a monitoring event.
    """
    return RuntimeEvent(
        error_rate_percent=error_rate_percent,
        crash_loop=crash_loop,
    )


# ============================================================
# Dependency Monitoring
# ============================================================

def dependency_event(status: str, version_mismatch: bool = False) -> DependencyEvent:
    """
    Convert dependency health data into a monitoring event.
    """
    return DependencyEvent(
        dependency_status=status,
        version_mismatch=version_mismatch,
    )


# ============================================================
# Resource Monitoring
# ============================================================

def resource_event(cpu: int, memory: int, disk: int) -> ResourceEvent:
    """
    Convert system resource metrics into a monitoring event.
    """
    return ResourceEvent(
        cpu_percent=cpu,
        memory_percent=memory,
        disk_percent=disk,
    )


# ============================================================
# Security Monitoring
# ============================================================

def security_event(
    unsigned_artifact: bool = False,
    secrets_exposed: bool = False,
    debug_mode_enabled: bool = False,
) -> SecurityEvent:
    """
    Convert security signals into a monitoring event.
    """
    return SecurityEvent(
        unsigned_artifact=unsigned_artifact,
        secrets_exposed=secrets_exposed,
        debug_mode_enabled=debug_mode_enabled,
    )
