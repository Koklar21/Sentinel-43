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

"""Suppress routine successful Uvicorn access logs for health endpoints."""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable


class HealthCheckAccessFilter(logging.Filter):
    """Suppress healthy polling while preserving failures and recovery."""

    def __init__(
        self,
        health_paths: Iterable[str],
    ) -> None:
        super().__init__()

        normalized = frozenset(
            path.strip()
            for path in health_paths
            if isinstance(path, str)
            and path.strip().startswith("/")
        )

        if not normalized:
            raise ValueError(
                "health_paths must contain at least one absolute path"
            )

        self._health_paths = normalized
        self._lock = threading.Lock()
        self._was_failing: dict[str, bool] = {}

    @property
    def health_paths(self) -> frozenset[str]:
        return self._health_paths

    def filter(
        self,
        record: logging.LogRecord,
    ) -> bool:
        args = record.args

        if (
            not isinstance(args, tuple)
            or len(args) != 5
        ):
            return True

        (
            _client_addr,
            _method,
            raw_path,
            _http_version,
            status_code,
        ) = args

        path = str(
            raw_path
        ).split(
            "?",
            1,
        )[0]

        if path not in self._health_paths:
            return True

        try:
            status = int(
                status_code
            )
        except (
            TypeError,
            ValueError,
        ):
            return True

        success = (
            200
            <= status
            < 300
        )

        with self._lock:
            was_failing = self._was_failing.get(
                path,
                False,
            )

            self._was_failing[
                path
            ] = not success

        if not success:
            return True

        return was_failing


def install_health_check_access_filter(
    health_paths: Iterable[str],
) -> None:
    """Install or replace Sentinel-43's Uvicorn health access filter."""
    access_logger = logging.getLogger(
        "uvicorn.access"
    )

    replacement = HealthCheckAccessFilter(
        health_paths
    )

    for existing in list(
        access_logger.filters
    ):
        if isinstance(
            existing,
            HealthCheckAccessFilter,
        ):
            if (
                existing.health_paths
                == replacement.health_paths
            ):
                return

            access_logger.removeFilter(
                existing
            )

    access_logger.addFilter(
        replacement
    )


__all__ = [
    "HealthCheckAccessFilter",
    "install_health_check_access_filter",
]
