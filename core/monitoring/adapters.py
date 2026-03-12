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