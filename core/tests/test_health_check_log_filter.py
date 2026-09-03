# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# core/tests/test_health_check_log_filter.py
#
# Tests for core/logging/health_check_filter.py -- the mechanism that
# quiets successful (2xx) uvicorn access-log lines for known health/ready
# endpoints without touching the health checks themselves, Watchtower's
# evaluation of them, or logging for any other route.
#
# Constructs logging.LogRecord objects with the exact args shape uvicorn's
# access logger actually uses (see uvicorn.protocols.http.h11_impl /
# httptools_impl):
#
#   access_logger.info(
#       '%s - "%s %s HTTP/%s" %d',
#       client_addr, method, path_with_query, http_version, status,
#   )
#
# i.e. record.args == (client_addr, method, path, http_version, status).
# =============================================================================

from __future__ import annotations

import logging
import os

import pytest

from core.logging.health_check_filter import (
    HealthCheckAccessFilter,
    install_health_check_access_filter,
)

UVICORN_ACCESS_MSG = '%s - "%s %s HTTP/%s" %d'

HEALTH_PATHS = frozenset({"/health", "/ready", "/watchtower/health"})


def _access_record(method: str, path: str, status: int) -> logging.LogRecord:
    return logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=UVICORN_ACCESS_MSG,
        args=("127.0.0.1:12345", method, path, "1.1", status),
        exc_info=None,
    )


@pytest.fixture
def filt() -> HealthCheckAccessFilter:
    return HealthCheckAccessFilter(HEALTH_PATHS)


# ---------------------------------------------------------------------------
# Requirement: successful health requests are filtered
# ---------------------------------------------------------------------------

def test_successful_health_check_is_suppressed(filt: HealthCheckAccessFilter):
    record = _access_record("GET", "/health", 200)

    assert filt.filter(record) is False


def test_repeated_successful_health_checks_stay_suppressed(filt: HealthCheckAccessFilter):
    for _ in range(5):
        assert filt.filter(_access_record("GET", "/health", 200)) is False


def test_health_check_path_with_query_string_is_matched(filt: HealthCheckAccessFilter):
    """uvicorn logs the path with any query string attached; matching must
    strip it rather than fail to recognize the path."""
    record = _access_record("GET", "/health?probe=1", 200)

    assert filt.filter(record) is False


# ---------------------------------------------------------------------------
# Requirement: failed health requests remain visible
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [400, 401, 403, 404, 500, 502, 503, 504])
def test_failed_health_check_is_never_suppressed(filt: HealthCheckAccessFilter, status: int):
    record = _access_record("GET", "/health", status)

    assert filt.filter(record) is True


def test_repeated_failures_all_remain_visible(filt: HealthCheckAccessFilter):
    """No existing log-deduplication mechanism exists in this codebase to
    hook into (see health_check_filter.py's module docstring / the PR
    description) -- every failure must still print."""
    for _ in range(5):
        assert filt.filter(_access_record("GET", "/watchtower/health", 503)) is True


# ---------------------------------------------------------------------------
# Requirement: successful non-health API requests remain unaffected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path",
    ["/api/status", "/v1/status", "/api/version", "/rules/status", "/config/status", "/metrics"],
)
def test_non_health_success_is_never_suppressed(filt: HealthCheckAccessFilter, path: str):
    record = _access_record("GET", path, 200)

    assert filt.filter(record) is True


def test_non_health_failure_is_never_suppressed(filt: HealthCheckAccessFilter):
    record = _access_record("POST", "/v1/assess", 401)

    assert filt.filter(record) is True


# ---------------------------------------------------------------------------
# Requirement: state-change logging -- recovery shown once, then quiet again
# ---------------------------------------------------------------------------

def test_recovery_after_failure_is_shown_exactly_once(filt: HealthCheckAccessFilter):
    # Healthy from the start: no prior failure, so nothing to "recover" from.
    assert filt.filter(_access_record("GET", "/health", 200)) is False
    assert filt.filter(_access_record("GET", "/health", 200)) is False

    # Goes unhealthy -- always visible.
    assert filt.filter(_access_record("GET", "/health", 503)) is True
    assert filt.filter(_access_record("GET", "/health", 503)) is True

    # First success after the failure run: shown once (the recovery).
    assert filt.filter(_access_record("GET", "/health", 200)) is True

    # Back to quiet for subsequent successes.
    assert filt.filter(_access_record("GET", "/health", 200)) is False
    assert filt.filter(_access_record("GET", "/health", 200)) is False


def test_state_is_tracked_independently_per_path(filt: HealthCheckAccessFilter):
    filt.filter(_access_record("GET", "/health", 503))

    # A different health path was never seen failing -- still quiet.
    assert filt.filter(_access_record("GET", "/ready", 200)) is False

    # /health itself still owes a visible recovery.
    assert filt.filter(_access_record("GET", "/health", 200)) is True


# ---------------------------------------------------------------------------
# Requirement: malformed / non-uvicorn-shaped records are never touched
# ---------------------------------------------------------------------------

def test_non_access_log_record_shape_passes_through(filt: HealthCheckAccessFilter):
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Started server process [%d]",
        args=(1234,),
        exc_info=None,
    )

    assert filt.filter(record) is True


# ---------------------------------------------------------------------------
# Requirement: installation is idempotent and targets the real access logger
# ---------------------------------------------------------------------------

def test_install_is_idempotent():
    # "uvicorn.access" is a process-wide singleton logger: other already-run
    # test modules that imported core.api.main or core.monitoring.watchtower
    # may have legitimately installed a filter on it before this test runs,
    # and other tests running later rely on it staying installed. Don't
    # reset that shared state -- just confirm repeated install calls never
    # grow the filter count, whatever it started at.
    logger = logging.getLogger("uvicorn.access")

    def _count() -> int:
        return sum(1 for f in logger.filters if isinstance(f, HealthCheckAccessFilter))

    baseline = _count()

    install_health_check_access_filter(HEALTH_PATHS)
    assert _count() == max(baseline, 1)

    install_health_check_access_filter(HEALTH_PATHS)
    assert _count() == max(baseline, 1)


# ---------------------------------------------------------------------------
# Requirement: importing the real apps wires the filter onto uvicorn.access,
# and the health-check routes themselves keep returning real status codes --
# i.e. this is display-only, health checks are not disabled.
# ---------------------------------------------------------------------------

def test_main_app_installs_filter_and_health_routes_still_work(monkeypatch: pytest.MonkeyPatch):
    # core.api.main reads S43_JWT_SECRET/_ALGORITHM and S43_WS_REQUIRE_AUTH as
    # module-level constants frozen at import time (see test_v1_auth.py's
    # identical note) -- only matters if this is the first test in the
    # process to import core.api.main; setdefault so an already-configured
    # environment (e.g. another test module imported first) wins instead.
    monkeypatch.setenv("SENTINEL_ENV", "test")
    for key, value in {
        "S43_JWT_SECRET": "test-secret-for-health-filter-tests",
        "S43_JWT_ALGORITHM": "HS256",
    }.items():
        if not os.environ.get(key):
            monkeypatch.setenv(key, value)

    import core.api.main as main_module

    access_logger = logging.getLogger("uvicorn.access")
    assert any(
        isinstance(f, HealthCheckAccessFilter) for f in access_logger.filters
    ), "core.api.main must install the health-check access filter on import"

    from fastapi.testclient import TestClient

    with TestClient(main_module.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

        response = client.get("/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"


def test_watchtower_app_installs_filter_and_health_routes_still_work():
    import core.monitoring.watchtower as watchtower_module

    app = watchtower_module.app  # triggers lazy singleton creation

    access_logger = logging.getLogger("uvicorn.access")
    assert any(
        isinstance(f, HealthCheckAccessFilter) for f in access_logger.filters
    ), "core.monitoring.watchtower must install the health-check access filter"

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        response = client.get("/watchtower/health")
        # Real status code from the real health check -- ACTIVE -> 200,
        # anything else (initializing/degraded/failed) -> 503. Either way,
        # this proves the route executed for real, not a stub.
        assert response.status_code in (200, 503)

        response = client.get("/watchtower/ready")
        assert response.status_code in (200, 503)


__all__: list[str] = []
