"""
dashboard/services/api_client.py

Sentinel-43 Dashboard API client.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests


LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10

API_BASE_URL = os.getenv(
    "SENTINEL_API_URL",
    "http://localhost:8000",
)


class APIClient:
    """
    Simple API client for Sentinel-43 backend communication.
    """

    def __init__(
        self,
        base_url: str = API_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Perform HTTP request.
        """

        url = f"{self.base_url}{endpoint}"

        try:
            response = requests.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs,
            )

            response.raise_for_status()

            if response.content:
                return response.json()

            return {}

        except requests.RequestException as exc:
            LOGGER.error(
                "API request failed: %s %s (%s)",
                method,
                url,
                exc,
            )

            return {
                "success": False,
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Core Endpoints
    # ------------------------------------------------------------------

    def get_health(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "/health",
        )

    def get_ready(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "/ready",
        )

    def get_root(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "/",
        )

    # ------------------------------------------------------------------
    # Watchtower
    # ------------------------------------------------------------------

    def get_watchtower_status(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "/watchtower/status",
        )

    # ------------------------------------------------------------------
    # Remote Operations
    # ------------------------------------------------------------------

    def get_remote_operations(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "/remote-operations",
        )

    def submit_remote_event(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/remote-operations",
            json=payload,
        )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def get_audit_logs(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "/audit",
        )

    # ------------------------------------------------------------------
    # Node Status
    # ------------------------------------------------------------------

    def get_node_status(self) -> dict[str, Any]:
        return self._request(
            "GET",
            "/nodes",
        )


api_client = APIClient()
