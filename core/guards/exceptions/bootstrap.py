# Sentinel-43
# Copyright (c) 2026 Justin
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from .expectations import (
    get_basic_expectations,
    get_hardened_expectations,
    get_sentinel43_expectations,
)
from .registry import list_expectations, register_expectations


_VALID_BOOTSTRAP_PROFILES = {"basic", "hardened", "sentinel43"}

BOOTSTRAP_MODULE_ID = os.getenv("S43_BOOTSTRAP_MODULE_ID", "sentinel43-bootstrap")
BOOTSTRAP_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")
WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{WATCHTOWER_URL}{path}"
    data = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            if not body:
                return {"status_code": response.status}

            parsed = json.loads(body)
            if isinstance(parsed, dict):
                parsed.setdefault("status_code", response.status)
                return parsed

            return {
                "status_code": response.status,
                "body": parsed,
            }

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)

        return {
            "error": "watchtower_http_error",
            "status_code": exc.code,
            "detail": detail,
        }

    except Exception as exc:
        return {
            "error": "watchtower_unreachable",
            "detail": str(exc),
        }


def _register_bootstrap_with_watchtower() -> dict[str, Any]:
    payload = {
        "module_id": BOOTSTRAP_MODULE_ID,
        "module_type": "bootstrap",
        "version": BOOTSTRAP_VERSION,
        "endpoint": None,
        "capabilities": [
            "expectation_bootstrap",
            "profile_loading",
            "startup_validation",
            "bootstrap_failure_reporting",
        ],
        "metadata": {
            "watchtower_url": WATCHTOWER_URL,
            "timestamp": utc_now(),
        },
    }

    return _watchtower_request("POST", "/watchtower/modules/register", payload)


def _report_bootstrap_status(
    status: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _register_bootstrap_with_watchtower()

    payload = {
        "name": BOOTSTRAP_MODULE_ID,
        "status": status,
        "version": BOOTSTRAP_VERSION,
        "details": {
            "event": event,
            "timestamp": utc_now(),
            **(details or {}),
        },
    }

    return _watchtower_request("POST", "/watchtower/dependencies/report", payload)


def _report_bootstrap_event(
    kind: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "event": {
            "kind": kind,
            "source": BOOTSTRAP_MODULE_ID,
            "status": status,
            "details": {
                "timestamp": utc_now(),
                **(details or {}),
            },
        }
    }

    return _watchtower_request("POST", "/watchtower/analyze", payload)


def bootstrap_expectations(profile: str = "sentinel43") -> None:
    """
    Register expectations for the selected bootstrap profile.

    Supported profiles:
        - basic
        - hardened
        - sentinel43
    """

    normalized = profile.strip().lower()

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

        basic_expectations = get_basic_expectations()
        register_expectations(basic_expectations)

        loaded_profiles = ["basic"]
        loaded_counts = {
            "basic": len(tuple(basic_expectations)),
            "hardened": 0,
            "sentinel43": 0,
        }

        if normalized in {"hardened", "sentinel43"}:
            hardened_expectations = get_hardened_expectations()
            register_expectations(hardened_expectations)
            loaded_profiles.append("hardened")
            loaded_counts["hardened"] = len(tuple(hardened_expectations))

        if normalized == "sentinel43":
            sentinel43_expectations = get_sentinel43_expectations()
            register_expectations(sentinel43_expectations)
            loaded_profiles.append("sentinel43")
            loaded_counts["sentinel43"] = len(tuple(sentinel43_expectations))

        expectation_count = len(list_expectations())

        _report_bootstrap_status(
            status="online",
            event="bootstrap_completed",
            details={
                "profile": normalized,
                "loaded_profiles": loaded_profiles,
                "loaded_counts": loaded_counts,
                "total_expectations": expectation_count,
            },
        )

        _report_bootstrap_event(
            kind="expectation",
            status="bootstrap_completed",
            details={
                "profile": normalized,
                "total_expectations": expectation_count,
            },
        )

    except Exception as exc:
        _report_bootstrap_status(
            status="failed",
            event="bootstrap_failed",
            details={
                "profile": normalized,
                "error": str(exc),
            },
        )

        _report_bootstrap_event(
            kind="expectation",
            status="bootstrap_failed",
            details={
                "profile": normalized,
                "error": str(exc),
            },
        )

        raise