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

"""Canonical Watchtower HTTP client.

Configuration is injected explicitly. This module performs no environment
reads and no import-time network/configuration side effects.
"""

from __future__ import annotations

import json
import logging
import math
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Final


logger = logging.getLogger(__name__)


_DEFAULT_MAX_RESPONSE_BYTES: Final[int] = 1024 * 1024
_MAX_ALLOWED_RESPONSE_BYTES: Final[int] = 64 * 1024 * 1024
_MAX_ALLOWED_TIMEOUT_SECONDS: Final[float] = 300.0
_DEFAULT_LOG_SUPPRESS_SECONDS: Final[float] = 60.0


@dataclass(frozen=True, slots=True)
class WatchtowerClientConfig:
    base_url: str
    service_token: str
    timeout_seconds: float = 2.0
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES
    log_suppress_seconds: float = _DEFAULT_LOG_SUPPRESS_SECONDS

    def __post_init__(self) -> None:
        base_url = self.base_url.strip().rstrip("/")
        token = self.service_token.strip()

        if not base_url:
            raise ValueError(
                "base_url must not be empty"
            )

        if not token:
            raise ValueError(
                "service_token must not be empty"
            )

        if not math.isfinite(
            self.timeout_seconds
        ) or not (
            0.0
            < self.timeout_seconds
            <= _MAX_ALLOWED_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "timeout_seconds is outside the supported range"
            )

        if not (
            1
            <= self.max_response_bytes
            <= _MAX_ALLOWED_RESPONSE_BYTES
        ):
            raise ValueError(
                "max_response_bytes is outside the supported range"
            )

        if not math.isfinite(
            self.log_suppress_seconds
        ) or self.log_suppress_seconds < 0:
            raise ValueError(
                "log_suppress_seconds must be finite and >= 0"
            )

        object.__setattr__(
            self,
            "base_url",
            base_url,
        )

        object.__setattr__(
            self,
            "service_token",
            token,
        )


@dataclass(frozen=True, slots=True)
class WatchtowerResponse:
    ok: bool
    status_code: int | None
    body: dict[str, Any] | list[Any] | None = None
    error: str | None = None

    def to_dict(
        self,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": self.ok,
            "status_code": self.status_code,
        }

        if self.body is not None:
            result["body"] = self.body

        if self.error is not None:
            result["error"] = self.error

        return result


def _bounded_read(
    read_fn: Callable[[int], bytes],
    get_header_fn: Callable[[str], str | None],
    max_response_bytes: int,
) -> tuple[bytes, bool]:
    declared_length: int | None = None

    try:
        raw_length = get_header_fn(
            "Content-Length"
        )
    except Exception:
        raw_length = None

    if raw_length is not None:
        try:
            declared_length = int(
                str(
                    raw_length
                ).strip()
            )
        except ValueError:
            declared_length = None

    if (
        declared_length is not None
        and declared_length
        > max_response_bytes
    ):
        return b"", True

    chunk = read_fn(
        max_response_bytes + 1
    )

    if len(
        chunk
    ) > max_response_bytes:
        return (
            chunk[
                :max_response_bytes
            ],
            True,
        )

    return chunk, False


class WatchtowerClient:
    """Synchronous internal HTTP client for authenticated Watchtower calls."""

    def __init__(
        self,
        config: WatchtowerClientConfig,
    ) -> None:
        self._config = config
        self._last_logged: dict[
            tuple[str, str],
            float,
        ] = {}

        self._log_lock = threading.Lock()

    def _should_log(
        self,
        key: tuple[str, str],
    ) -> bool:
        suppress_seconds = (
            self._config.log_suppress_seconds
        )

        if suppress_seconds <= 0:
            return True

        now = time.monotonic()

        with self._log_lock:
            last = self._last_logged.get(
                key,
                0.0,
            )

            if (
                now - last
                < suppress_seconds
            ):
                return False

            self._last_logged[
                key
            ] = now

            return True

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> WatchtowerResponse:
        clean_method = str(
            method
        ).strip().upper()

        clean_path = str(
            path
        ).strip()

        if clean_method not in {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            raise ValueError(
                f"unsupported HTTP method {clean_method!r}"
            )

        if (
            not clean_path
            or not clean_path.startswith(
                "/"
            )
        ):
            raise ValueError(
                "path must be an absolute path beginning with '/'"
            )

        data: bytes | None = None

        if payload is not None:
            try:
                data = json.dumps(
                    payload,
                    allow_nan=False,
                    separators=(
                        ",",
                        ":",
                    ),
                ).encode(
                    "utf-8"
                )
            except (
                TypeError,
                ValueError,
                UnicodeEncodeError,
            ) as exc:
                raise ValueError(
                    "payload is not valid JSON"
                ) from exc

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": (
                "Bearer "
                + self._config.service_token
            ),
        }

        request = urllib.request.Request(
            url=(
                self._config.base_url
                + clean_path
            ),
            data=data,
            headers=headers,
            method=clean_method,
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self._config.timeout_seconds,
            ) as response:
                body_bytes, oversized = _bounded_read(
                    response.read,
                    response.getheader,
                    self._config.max_response_bytes,
                )

                if oversized:
                    if self._should_log(
                        (
                            clean_path,
                            "oversized_response",
                        )
                    ):
                        logger.warning(
                            "Watchtower response exceeded size cap: %s %s",
                            clean_method,
                            clean_path,
                        )

                    return WatchtowerResponse(
                        ok=False,
                        status_code=response.status,
                        error="response_too_large",
                    )

                if not body_bytes:
                    return WatchtowerResponse(
                        ok=(
                            200
                            <= response.status
                            < 300
                        ),
                        status_code=response.status,
                    )

                try:
                    parsed = json.loads(
                        body_bytes.decode(
                            "utf-8"
                        )
                    )
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ):
                    if self._should_log(
                        (
                            clean_path,
                            "malformed_response",
                        )
                    ):
                        logger.warning(
                            "Watchtower returned malformed JSON: %s %s",
                            clean_method,
                            clean_path,
                        )

                    return WatchtowerResponse(
                        ok=False,
                        status_code=response.status,
                        error="malformed_response",
                    )

                return WatchtowerResponse(
                    ok=(
                        200
                        <= response.status
                        < 300
                    ),
                    status_code=response.status,
                    body=parsed,
                )

        except urllib.error.HTTPError as exc:
            _, oversized = _bounded_read(
                exc.read,
                (
                    lambda name: (
                        exc.headers.get(
                            name
                        )
                        if exc.headers
                        is not None
                        else None
                    )
                ),
                self._config.max_response_bytes,
            )

            error_kind = (
                "http_error_body_too_large"
                if oversized
                else "http_error"
            )

            if self._should_log(
                (
                    clean_path,
                    error_kind,
                )
            ):
                logger.warning(
                    "Watchtower HTTP failure: %s %s -> %s",
                    clean_method,
                    clean_path,
                    exc.code,
                )

            return WatchtowerResponse(
                ok=False,
                status_code=exc.code,
                error=error_kind,
            )

        except TimeoutError:
            if self._should_log(
                (
                    clean_path,
                    "timeout",
                )
            ):
                logger.warning(
                    "Watchtower request timed out: %s %s",
                    clean_method,
                    clean_path,
                )

            return WatchtowerResponse(
                ok=False,
                status_code=None,
                error="timeout",
            )

        except urllib.error.URLError as exc:
            if isinstance(
                exc.reason,
                TimeoutError,
            ):
                error_kind = "timeout"
            else:
                error_kind = "unreachable"

            if self._should_log(
                (
                    clean_path,
                    error_kind,
                )
            ):
                logger.warning(
                    "Watchtower request failed: %s %s (%s)",
                    clean_method,
                    clean_path,
                    error_kind,
                )

            return WatchtowerResponse(
                ok=False,
                status_code=None,
                error=error_kind,
            )


_default_client_lock = threading.Lock()
_default_client: WatchtowerClient | None = None


def configure_default_watchtower_client(
    config: WatchtowerClientConfig,
) -> None:
    """Install the process-wide default client during explicit startup."""
    global _default_client

    with _default_client_lock:
        _default_client = WatchtowerClient(
            config
        )


def get_default_watchtower_client(
) -> WatchtowerClient:
    with _default_client_lock:
        client = _default_client

    if client is None:
        raise RuntimeError(
            "default Watchtower client is not configured"
        )

    return client


def watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compatibility wrapper around the explicitly configured default client."""
    return get_default_watchtower_client().request(
        method,
        path,
        payload,
    ).to_dict()


__all__ = [
    "WatchtowerClient",
    "WatchtowerClientConfig",
    "WatchtowerResponse",
    "configure_default_watchtower_client",
    "get_default_watchtower_client",
    "watchtower_request",
]
