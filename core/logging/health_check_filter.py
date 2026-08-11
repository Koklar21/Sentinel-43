# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# core/logging/health_check_filter.py
#
# Suppresses successful (2xx) uvicorn access-log noise for a fixed set of
# health/readiness/liveness endpoints, without touching:
#   - the health-check routes themselves (still run, still return real codes)
#   - Watchtower's evaluation of those results
#   - Docker/container healthcheck behavior
#   - any other endpoint's logging
#
# Origin of the noise: uvicorn's own "uvicorn.access" logger, configured by
# uvicorn itself at server startup and never touched by this project's
# app-startup path (core.api.main has no configure_logging()/init_logging()
# call — see core/logging/setup.py and core/logging_init.py, neither of
# which core.api.main imports). That access logger fires once per request,
# at INFO level, for every route including health/ready/liveness endpoints
# hit every few seconds by Docker healthchecks, Watchtower, and the
# dashboard — hence the flood.
#
# Both uvicorn.protocols.http.h11_impl and .httptools_impl call the access
# logger the same way:
#
#   access_logger.info(
#       '%s - "%s %s HTTP/%s" %d',
#       get_client_addr(scope), method, path_with_query, http_version, status,
#   )
#
# record.args is therefore always a 5-tuple (client_addr, method, path,
# http_version, status_code). Reading those positional args directly is the
# closest thing to structured filtering this unstructured third-party
# logger offers -- far more reliable than regex-matching the formatted
# message string, and stable across both uvicorn HTTP implementations.
# =============================================================================

from __future__ import annotations

import logging
import threading

__all__ = ["HealthCheckAccessFilter", "install_health_check_access_filter"]


class HealthCheckAccessFilter(logging.Filter):
    """
    Hide successful (2xx) uvicorn access-log lines for a fixed set of
    health/readiness/liveness paths. Everything else always passes through
    untouched:

      - non-2xx results for those same paths (failures stay visible)
      - every request to any other path, whatever its status

    State-change aware per path: the first 2xx logged for a path *after*
    that path was last seen failing is NOT suppressed, so recovery is
    surfaced exactly once. The next 2xx after that goes quiet again. A path
    never seen failing starts in the "healthy" state, so routine successful
    polling is quiet from the first request — there's no failure to recover
    from yet.
    """

    def __init__(self, health_paths: frozenset[str]) -> None:
        super().__init__()
        self._health_paths = health_paths
        self._lock = threading.Lock()
        self._was_failing: dict[str, bool] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if not isinstance(args, tuple) or len(args) != 5:
            return True  # not uvicorn's access-log record shape; never touch it

        _client_addr, _method, raw_path, _http_version, status_code = args

        path = str(raw_path).split("?", 1)[0]
        if path not in self._health_paths:
            return True

        try:
            status_int = int(status_code)
        except (TypeError, ValueError):
            return True

        is_success = 200 <= status_int < 300

        with self._lock:
            was_failing = self._was_failing.get(path, False)
            self._was_failing[path] = not is_success

        if not is_success:
            return True  # failures (4xx/5xx/etc.) are always visible

        return was_failing  # show only the first success after a failure


def install_health_check_access_filter(health_paths: frozenset[str]) -> None:
    """
    Attach a HealthCheckAccessFilter to uvicorn's access logger.

    Idempotent: safe to call more than once in the same process (e.g. an app
    module re-imported across test files) -- only ever attaches one filter
    instance per logger, so requests aren't evaluated twice.
    """
    access_logger = logging.getLogger("uvicorn.access")

    for existing in access_logger.filters:
        if isinstance(existing, HealthCheckAccessFilter):
            return

    access_logger.addFilter(HealthCheckAccessFilter(health_paths))
