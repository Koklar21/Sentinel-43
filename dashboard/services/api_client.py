"""
Sentinel-43 Dashboard Service
API Client

Shared HTTP client helpers for dashboard service modules.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


LOCAL_DEV_ALLOWED_HTTP_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "s43-api",
    "sentinel-api",
})

ALLOWED_METHODS = frozenset({
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
})

PROTECTED_HEADERS = frozenset({
    "accept",
    "authorization",
    "content-type",
})

SAFE_RESPONSE_HEADERS = frozenset({
    "x-request-id",
    "x-correlation-id",
    "retry-after",
})

MAX_PAYLOAD_BYTES = 1 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ApiResponse:
    ok: bool
    status_code: int | None
    data: Any = None
    error: str | None = None
    headers: dict[str, str] | None = None
    is_json: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status_code": self.status_code,
            "data": self.data,
            "error": self.error,
            "headers": dict(self.headers or {}),
            "is_json": self.is_json,
        }


def _parse_timeout(raw: str | None, default: float = 5.0) -> float:
    if raw is None:
        return default

    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default

    if value <= 0:
        return default

    return value


def _default_base_url() -> str:
    raw = os.getenv("SENTINEL_DASHBOARD_API_URL", "").strip()

    if not raw:
        return "http://localhost:8000"

    return raw


class ApiClient:
    """
    Lightweight dashboard API client.

    Uses urllib from the Python standard library.
    No requests/httpx dependency needed. Humanity endures.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        token: str | None = None,
        allow_insecure_local_http: bool = True,
    ) -> None:
        self.base_url = self._validate_base_url(
            base_url or _default_base_url(),
            allow_insecure_local_http=allow_insecure_local_http,
        )
        self.timeout_seconds = self._validate_timeout(
            timeout_seconds
            if timeout_seconds is not None
            else _parse_timeout(os.getenv("SENTINEL_DASHBOARD_API_TIMEOUT"))
        )
        self.token = token or os.getenv("SENTINEL_DASHBOARD_API_TOKEN")

    def get(self, path: str) -> ApiResponse:
        return self.request("GET", path)

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> ApiResponse:
        return self.request("POST", path, payload=payload)

    def put(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> ApiResponse:
        return self.request("PUT", path, payload=payload)

    def patch(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> ApiResponse:
        return self.request("PATCH", path, payload=payload)

    def delete(self, path: str) -> ApiResponse:
        return self.request("DELETE", path)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> ApiResponse:
        try:
            normalized_method = self._validate_method(method)
            url = self._build_url(path)
            headers = self._build_headers(extra_headers)
            body = self._encode_payload(payload)

            request = urllib.request.Request(
                url=url,
                data=body,
                headers=headers,
                method=normalized_method,
            )

            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                raw = response.read().decode("utf-8")
                data, is_json = self._parse_response_body(raw)

                return ApiResponse(
                    ok=200 <= response.status < 300,
                    status_code=response.status,
                    data=data,
                    error=None if is_json else "API returned non-JSON response.",
                    headers=self._safe_headers(dict(response.headers.items())),
                    is_json=is_json,
                )

        except urllib.error.HTTPError as exc:
            raw_error = self._safe_read_error(exc)
            parsed_error, is_json = self._parse_response_body(raw_error)
            fallback = f"HTTP error {exc.code}"

            return ApiResponse(
                ok=False,
                status_code=exc.code,
                data=parsed_error if is_json else None,
                error=self._extract_error_message(
                    parsed_error,
                    fallback=fallback,
                ),
                headers=self._safe_headers(
                    dict(exc.headers.items()) if exc.headers else {}
                ),
                is_json=is_json,
            )

        except socket.timeout:
            return ApiResponse(
                ok=False,
                status_code=None,
                data=None,
                error="API request timed out.",
                headers={},
                is_json=True,
            )

        except urllib.error.URLError as exc:
            reason = exc.reason.__class__.__name__

            return ApiResponse(
                ok=False,
                status_code=None,
                data=None,
                error=f"API unreachable: {reason}",
                headers={},
                is_json=True,
            )

        except ValueError as exc:
            return ApiResponse(
                ok=False,
                status_code=None,
                data=None,
                error=str(exc),
                headers={},
                is_json=True,
            )

        except Exception as exc:
            return ApiResponse(
                ok=False,
                status_code=None,
                data=None,
                error=f"API request failed: {exc.__class__.__name__}",
                headers={},
                is_json=True,
            )

    def _build_url(self, path: str) -> str:
        if not isinstance(path, str) or not path.strip():
            raise ValueError("path must be a non-empty relative path")

        cleaned_path = path.strip()

        if cleaned_path.startswith(("http://", "https://")):
            raise ValueError("absolute URLs are not permitted in path")

        if "\r" in cleaned_path or "\n" in cleaned_path:
            raise ValueError("path must not contain CRLF characters")

        if not cleaned_path.startswith("/"):
            cleaned_path = f"/{cleaned_path}"

        return f"{self.base_url}{cleaned_path}"

    def _build_headers(
        self,
        extra_headers: dict[str, str] | None,
    ) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        if not extra_headers:
            return headers

        for key, value in extra_headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("extra_headers must contain string keys and values")

            normalized_key = key.lower().strip()

            if normalized_key in PROTECTED_HEADERS:
                raise ValueError(f"Cannot override protected header: {key!r}")

            if any(char in key for char in ("\r", "\n")):
                raise ValueError(f"Header name contains CRLF: {key!r}")

            if any(char in value for char in ("\r", "\n")):
                raise ValueError(f"Header value contains CRLF for: {key!r}")

            headers[key.strip()] = value.strip()

        return headers

    @staticmethod
    def _encode_payload(payload: dict[str, Any] | None) -> bytes | None:
        if payload is None:
            return None

        if not isinstance(payload, dict):
            raise ValueError("payload must be a dictionary")

        try:
            body = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("payload must be JSON serializable") from exc

        if len(body) > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Request payload too large: {len(body)} bytes"
            )

        return body

    @staticmethod
    def _validate_method(method: str) -> str:
        if not isinstance(method, str):
            raise ValueError("method must be a string")

        normalized = method.upper().strip()

        if normalized not in ALLOWED_METHODS:
            raise ValueError(f"Disallowed HTTP method: {method!r}")

        return normalized

    @staticmethod
    def _validate_timeout(timeout_seconds: float) -> float:
        try:
            value = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout_seconds must be a positive number") from exc

        if value <= 0:
            raise ValueError("timeout_seconds must be greater than 0")

        return value

    @staticmethod
    def _validate_base_url(
        base_url: str,
        *,
        allow_insecure_local_http: bool,
    ) -> str:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty string")

        cleaned = base_url.strip().rstrip("/")

        if "\r" in cleaned or "\n" in cleaned:
            raise ValueError("base_url must not contain CRLF characters")

        parsed = urllib.parse.urlparse(cleaned)

        if parsed.scheme not in {"http", "https"}:
            raise ValueError("base_url must use http or https")

        if not parsed.netloc:
            raise ValueError("base_url must include a host")

        if parsed.scheme == "http":
            host = parsed.hostname or ""

            if not allow_insecure_local_http or host not in LOCAL_DEV_ALLOWED_HTTP_HOSTS:
                raise ValueError(
                    "insecure HTTP base_url is only allowed for local development hosts"
                )

        return cleaned

    @staticmethod
    def _parse_response_body(raw: str) -> tuple[Any, bool]:
        if not raw:
            return None, True

        try:
            return json.loads(raw), True
        except json.JSONDecodeError:
            return None, False

    @staticmethod
    def _safe_read_error(exc: urllib.error.HTTPError) -> str:
        try:
            return exc.read().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return ""

    @staticmethod
    def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
        safe: dict[str, str] = {}

        for key, value in headers.items():
            normalized = key.lower()

            if normalized in SAFE_RESPONSE_HEADERS:
                safe[key] = value

        return safe

    @staticmethod
    def _extract_error_message(parsed: Any, *, fallback: str) -> str:
        if isinstance(parsed, dict):
            for key in ("detail", "error", "message"):
                value = parsed.get(key)

                if isinstance(value, str) and value.strip():
                    return value.strip()

        return fallback
