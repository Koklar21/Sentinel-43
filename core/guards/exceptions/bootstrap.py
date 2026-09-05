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

"""
Expectations bootstrap for the Sentinel-43 guards system.

File:
    core/guards/expectations/bootstrap.py

CORRECTION: a previous revision of this docstring listed the path as
core/guards/exceptions/bootstrap.py — that was stale/wrong. The relative
import below (`from .expectations import ...`) confirms this file lives
in core/guards/expectations/, not core/guards/exceptions/. Fix the docstring
whenever this file moves; don't let it drift again.

NAMING NOTE: there is a second, unrelated module also named bootstrap.py at
core/bootstrap.py (production startup-config validation: JWT secrets, WS
auth enforcement, etc). They do different jobs and are not interchangeable.
If both are ever imported in the same file, alias at least one explicitly —
do not rely on import order to keep them apart.

Changes from previous version:
  - Fix (CRITICAL): expectation generators were consumed by
    register_expectations() and then re-iterated by len(tuple(...)),
    returning 0 for all counts. Converted to list() immediately at
    assignment so both register and count use the same materialized data.
  - Fix (HIGH): module-level constants were evaluated at import time,
    meaning Docker env vars injected after module load were silently
    ignored. Also float() on an invalid timeout string raised ValueError
    at import. Now lazy via @lru_cache.
  - Fix (HIGH): _register_bootstrap_with_watchtower() was called inside
    _report_bootstrap_status(), which fired on every status call.
    bootstrap_expectations() calls _report_bootstrap_status twice minimum
    (start + success/failure), causing 2+ redundant re-registrations per
    startup. Registration now happens once at the top of
    bootstrap_expectations() before any status reporting.
  - Fix (LOW): response.read() had no size cap. Now bounded at 64 KB.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from ...monitoring.watchtower_client import watchtower_request
from .expectations import (
    get_basic_expectations,
    get_hardened_expectations,
    get_sentinel43_expectations,
)
from .registry import list_expectations, register_expectations


_VALID_BOOTSTRAP_PROFILES = frozenset({"basic", "hardened", "sentinel43"})
_MAX_RESPONSE_BYTES = 64 * 1024  # 64 KB cap on Watchtower response bodies


# =============================================================================
# Lazy config  (Fix HIGH: not evaluated at import time)
# =============================================================================

@lru_cache(maxsize=1)
def _get_config() -> dict[str, Any]:
    """
    Read bootstrap configuration from environment on first call.
    lru_cache means Docker env vars set before first use are picked up
    correctly, and the config is stable after that.
    """
    raw_timeout = os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0").strip()
    try:
        timeout = float(raw_timeout)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
    except ValueError:
        timeout = 2.0

    return {
        "module_id":  (os.getenv("S43_BOOTSTRAP_MODULE_ID", "sentinel43-bootstrap").strip()
                       or "sentinel43-bootstrap"),
        "version":    (os.getenv("SENTINEL_VERSION", "0.1.0").strip() or "0.1.0"),
        "wt_url":     os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/"),
        "wt_timeout": timeout,
    }


def _cfg(key: str) -> Any:
    return _get_config()[key]


# =============================================================================
# Helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # DEFECT_INVENTORY.md D-16: this used to build the request without the
    # internal service token, so every call here 401'd against Watchtower.
    # Delegates to the canonical client (which reads S43_WATCHTOWER_URL /
    # _TIMEOUT itself); the bounded read (Fix LOW, previously 64 KB here) is
    # preserved via max_response_bytes.
    return watchtower_request(
        method, path, payload,
        timeout=_cfg("wt_timeout"),
        max_response_bytes=_MAX_RESPONSE_BYTES,
    )


def _register_bootstrap_with_watchtower() -> dict[str, Any]:
    return _watchtower_request(
        "POST",
        "/watchtower/modules/register",
        {
            "module_id":   _cfg("module_id"),
            "module_type": "bootstrap",
            "version":     _cfg("version"),
            "endpoint":    None,
            "capabilities": [
                "expectation_bootstrap",
                "profile_loading",
                "startup_validation",
                "bootstrap_failure_reporting",
            ],
            "metadata": {
                "watchtower_url": _cfg("wt_url"),
                "timestamp":      utc_now(),
            },
        },
    )


def _report_bootstrap_status(
    status: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Fix (HIGH): registration removed from here. It was called on every
    # status report, causing 2+ redundant POSTs to /modules/register per
    # bootstrap run. Registration is now done once in bootstrap_expectations().
    return _watchtower_request(
        "POST",
        "/watchtower/dependencies/report",
        {
            "name":    _cfg("module_id"),
            "status":  status,
            "version": _cfg("version"),
            "details": {
                "event":     event,
                "timestamp": utc_now(),
                **(details or {}),
            },
        },
    )


def _report_bootstrap_event(
    kind: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _watchtower_request(
        "POST",
        "/watchtower/analyze",
        {
            "event": {
                "kind":   kind,
                "source": _cfg("module_id"),
                "status": status,
                "details": {
                    "timestamp": utc_now(),
                    **(details or {}),
                },
            }
        },
    )


# =============================================================================
# Public API
# =============================================================================

def bootstrap_expectations(profile: str = "sentinel43") -> None:
    """
    Register expectations for the selected bootstrap profile.

    Supported profiles:
        basic      — core health and reachability expectations
        hardened   — basic + elevated security expectations
        sentinel43 — hardened + full Sentinel-43 monitoring expectations
    """
    normalized = profile.strip().lower()

    # Fix (HIGH): register once here rather than inside every status call.
    _register_bootstrap_with_watchtower()

    _report_bootstrap_status(
        status="online",
        event="bootstrap_started",
        details={"profile": normalized},
    )

    try:
        if normalized not in _VALID_BOOTSTRAP_PROFILES:
            raise ValueError(
                f"Unknown expectation bootstrap profile: {profile!r}. "
                f"Expected one of: {sorted(_VALID_BOOTSTRAP_PROFILES)}"
            )

        # Fix (CRITICAL): materialize as list immediately so register_expectations()
        # and the subsequent len() count use the same data. If get_*_expectations()
        # returns a generator, the original code consumed it in register_expectations()
        # and then re-iterated an exhausted iterator, giving count=0 for every profile.
        basic_list = list(get_basic_expectations())
        register_expectations(basic_list)

        loaded_profiles = ["basic"]
        loaded_counts = {
            "basic":     len(basic_list),
            "hardened":  0,
            "sentinel43": 0,
        }

        if normalized in {"hardened", "sentinel43"}:
            hardened_list = list(get_hardened_expectations())
            register_expectations(hardened_list)
            loaded_profiles.append("hardened")
            loaded_counts["hardened"] = len(hardened_list)

        if normalized == "sentinel43":
            sentinel43_list = list(get_sentinel43_expectations())
            register_expectations(sentinel43_list)
            loaded_profiles.append("sentinel43")
            loaded_counts["sentinel43"] = len(sentinel43_list)

        expectation_count = len(list_expectations())

        _report_bootstrap_status(
            status="online",
            event="bootstrap_completed",
            details={
                "profile":              normalized,
                "loaded_profiles":      loaded_profiles,
                "loaded_counts":        loaded_counts,
                "total_expectations":   expectation_count,
            },
        )

        _report_bootstrap_event(
            kind="expectation",
            status="bootstrap_completed",
            details={
                "profile":            normalized,
                "total_expectations": expectation_count,
            },
        )

    except Exception as exc:
        _report_bootstrap_status(
            status="failed",
            event="bootstrap_failed",
            details={"profile": normalized, "error": str(exc)},
        )
        _report_bootstrap_event(
            kind="expectation",
            status="bootstrap_failed",
            details={"profile": normalized, "error": str(exc)},
        )
        raise
