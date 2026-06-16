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
# 1. GNU Affero General Public License (AGPL v3.0)
# for open-source use, modification, and distribution.
#
# 2. Commercial License
# for proprietary, enterprise, government, or other commercial use
# not permitted under the AGPL v3.0.
#
# Use, modification, redistribution, and commercial use are governed by
# the terms of the applicable license. Any use outside those terms is
# prohibited.
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

import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Tuple

from .contracts import ExpectationCategory, ExpectationContract


WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
REGISTRY_MODULE_ID = os.getenv("S43_EXPECTATION_REGISTRY_ID", "sentinel-43-expectation-registry")
REGISTRY_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")


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

            return {"status_code": response.status, "body": parsed}

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


class ExpectationRegistry:
    """
    Central registry for Sentinel-43 expectations.

    Responsibilities:
    - Register expectations
    - Retrieve expectations by name or category
    - Provide ordered iteration of expectations
    - Report registry lifecycle/failures to Watchtower
    """

    def __init__(self) -> None:
        self._by_name: Dict[str, ExpectationContract] = {}
        self._by_category: Dict[ExpectationCategory, Dict[str, ExpectationContract]] = {}
        self._lock = threading.RLock()
        self._registered_with_watchtower = False
        self._last_watchtower_error: dict[str, Any] | None = None

    # -----------------------------
    # Watchtower intercom
    # -----------------------------

    def _register_with_watchtower_if_needed(self) -> None:
        with self._lock:
            if self._registered_with_watchtower:
                return

        payload = {
            "module_id": REGISTRY_MODULE_ID,
            "module_type": "expectation-registry",
            "version": REGISTRY_VERSION,
            "endpoint": None,
            "capabilities": [
                "expectation_registration",
                "expectation_lookup",
                "expectation_category_index",
                "contract_registry",
                "duplicate_detection",
            ],
            "metadata": {
                "timestamp": utc_now(),
            },
        }

        result = _watchtower_request("POST", "/watchtower/modules/register", payload)

        with self._lock:
            self._registered_with_watchtower = "error" not in result
            self._last_watchtower_error = result if "error" in result else None

    def _report_dependency(
        self,
        status: str,
        details: dict[str, Any],
    ) -> None:
        self._register_with_watchtower_if_needed()

        payload = {
            "name": REGISTRY_MODULE_ID,
            "status": status,
            "version": REGISTRY_VERSION,
            "details": {
                "timestamp": utc_now(),
                **details,
            },
        }

        result = _watchtower_request("POST", "/watchtower/dependencies/report", payload)

        with self._lock:
            self._last_watchtower_error = result if "error" in result else None

    def _report_event(
        self,
        kind: str,
        status: str,
        details: dict[str, Any],
    ) -> None:
        self._register_with_watchtower_if_needed()

        payload = {
            "event": {
                "kind": kind,
                "source": REGISTRY_MODULE_ID,
                "status": status,
                "details": {
                    "timestamp": utc_now(),
                    **details,
                },
            }
        }

        result = _watchtower_request("POST", "/watchtower/analyze", payload)

        with self._lock:
            self._last_watchtower_error = result if "error" in result else None

    # -----------------------------
    # Registration
    # -----------------------------

    def register(self, expectation: ExpectationContract) -> None:
        name = expectation.name

        with self._lock:
            if name in self._by_name:
                self._report_dependency(
                    status="degraded",
                    details={
                        "event": "duplicate_expectation_registration",
                        "expectation": name,
                        "category": getattr(expectation.category, "value", str(expectation.category)),
                    },
                )
                raise ValueError(f"Expectation '{name}' is already registered.")

            self._by_name[name] = expectation

            category_map = self._by_category.setdefault(expectation.category, {})
            category_map[name] = expectation

            total = len(self._by_name)

        self._report_event(
            kind="expectation",
            status="registered",
            details={
                "event": "expectation_registered",
                "expectation": name,
                "category": getattr(expectation.category, "value", str(expectation.category)),
                "total_expectations": total,
            },
        )

    def register_many(self, expectations: Iterable[ExpectationContract]) -> None:
        registered = 0

        for expectation in expectations:
            self.register(expectation)
            registered += 1

        self._report_dependency(
            status="online",
            details={
                "event": "expectation_batch_registered",
                "registered_count": registered,
                "total_expectations": len(self),
            },
        )

    # -----------------------------
    # Retrieval
    # -----------------------------

    def get(self, name: str) -> ExpectationContract:
        with self._lock:
            try:
                return self._by_name[name]
            except KeyError as exc:
                self._report_dependency(
                    status="degraded",
                    details={
                        "event": "expectation_lookup_missing",
                        "expectation": name,
                    },
                )
                raise KeyError(f"Expectation '{name}' is not registered.") from exc

    def all(self) -> Tuple[ExpectationContract, ...]:
        with self._lock:
            return tuple(self._by_name.values())

    def by_category(
        self,
        category: ExpectationCategory,
    ) -> Tuple[ExpectationContract, ...]:
        with self._lock:
            return tuple(self._by_category.get(category, {}).values())

    # -----------------------------
    # Status / Utilities
    # -----------------------------

    def status(self) -> dict[str, Any]:
        with self._lock:
            categories = {
                getattr(category, "value", str(category)): len(items)
                for category, items in self._by_category.items()
            }

            return {
                "module_id": REGISTRY_MODULE_ID,
                "version": REGISTRY_VERSION,
                "expectation_count": len(self._by_name),
                "categories": categories,
                "watchtower_url": WATCHTOWER_URL,
                "registered_with_watchtower": self._registered_with_watchtower,
                "last_watchtower_error": self._last_watchtower_error,
                "timestamp": utc_now(),
            }

    def clear(self) -> None:
        with self._lock:
            prior_count = len(self._by_name)
            self._by_name.clear()
            self._by_category.clear()

        self._report_dependency(
            status="degraded",
            details={
                "event": "expectation_registry_cleared",
                "prior_count": prior_count,
            },
        )

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_name)

    def __contains__(self, name: str) -> bool:
        with self._lock:
            return name in self._by_name


# -------------------------------------------------
# Global registry instance
# -------------------------------------------------

_registry = ExpectationRegistry()


def get_registry() -> ExpectationRegistry:
    return _registry


def register_expectation(expectation: ExpectationContract) -> None:
    _registry.register(expectation)


def register_expectations(expectations: Iterable[ExpectationContract]) -> None:
    _registry.register_many(expectations)


def get_expectation(name: str) -> ExpectationContract:
    return _registry.get(name)


def list_expectations() -> Tuple[ExpectationContract, ...]:
    return _registry.all()


def list_expectations_by_category(
    category: ExpectationCategory,
) -> Tuple[ExpectationContract, ...]:
    return _registry.by_category(category)


def registry_status() -> dict[str, Any]:
    return _registry.status()
