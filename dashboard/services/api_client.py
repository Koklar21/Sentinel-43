"""
Sentinel-43 Dashboard Service
API Client

Shared HTTP client helpers for dashboard service modules.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


DEFAULT_API_BASE_URL = os.getenv("SENTINEL_DASHBOARD_API_URL", "http://localhost:8000")
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("SENTINEL_DASHBOARD_API_TIMEOUT", "5.0"))


@dataclass(slots=True)
class ApiResponse:
    ok: bool
    status_code: int | None
    data: Any = None
    error: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status_code": self.status_code,
            "data": self.data,
            "error": self.error,
            "headers": self.headers,
        }


class ApiClient:
    """
    Lightweight dashboard API client.

    Uses urllib from the Python standard library.
    No requests/httpx dependency needed. Tiny miracle, really.
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_API_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        token: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.token = token or os.getenv("SENTINEL_DASHBOARD_API_TOKEN")

    def get(self, path: str) -> ApiResponse:
        return self.request("GET", path)

    def post(self, path: str, payload: dict[str, Any] | None = None) -> ApiResponse:
        return self.request("POST", path, payload=payload)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> ApiResponse:
        url = self._build_url(path)
        body = None

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        if extra_headers:
            headers.update(extra_headers)

        if payload is not None:
            body = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url=url,
            data=body,
            headers=headers,
            method=method.upper(),
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                raw = response.read().decode("utf-8")
                data = self._parse_response_body(raw)

                return ApiResponse(
                    ok=200 <= response.status < 300,
                    status_code=response.status,
                    data=data,
                    error=None,
                    headers=dict(response.headers.items()),
                )

        except urllib.error.HTTPError as exc:
            raw_error = self._safe_read_error(exc)
            parsed_error = self._parse_response_body(raw_error)

            return ApiResponse(
                ok=False,
                status_code=exc.code,
                data=parsed_error,
                error=self._extract_error_message(parsed_error, fallback=str(exc)),
                headers=dict(exc.headers.items()) if exc.headers else {},
            )

        except urllib.error.URLError as exc:
            return ApiResponse(
                ok=False,
                status_code=None,
                data=None,
                error=f"API unreachable: {exc.reason}",
                headers={},
            )

        except TimeoutError:
            return ApiResponse(
                ok=False,
                status_code=None,
                data=None,
                error="API request timed out.",
                headers={},
            )

        except Exception as exc:
            return ApiResponse(
                ok=False,
                status_code=None,
                data=None,
                error=f"API request failed: {exc.__class__.__name__}: {exc}",
                headers={},
            )

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path

        cleaned_path = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}{cleaned_path}"

    @staticmethod
    def _parse_response_body(raw: str) -> Any:
        if not raw:
            return None

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

    @staticmethod
    def _safe_read_error(exc: urllib.error.HTTPError) -> str:
        try:
            return exc.read().decode("utf-8")
        except Exception:
            return str(exc)

    @staticmethod
    def _extract_error_message(parsed: Any, *, fallback: str) -> str:
        if isinstance(parsed, dict):
            detail = parsed.get("detail")
            error = parsed.get("error")
            message = parsed.get("message")

            if isinstance(detail, str):
                return detail

            if isinstance(error, str):
                return error

            if isinstance(message, str):
                return message

        return fallback


api_client = ApiClient()


def api_get(path: str) -> dict[str, Any]:
    response = api_client.get(path)
    return response.to_dict()


def api_post(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    response = api_client.post(path, payload)
    return response.to_dict()
