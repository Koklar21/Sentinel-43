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

"""Global request-context ASGI middleware.

Responsibilities:
    - guarantee every HTTP request has a request ID
    - accept an inbound X-Request-ID only when it is valid and bounded
    - expose the request ID through scope["state"]["request_id"]
    - echo the request ID on every HTTP response started by the application
    - avoid import-time side effects
"""

from __future__ import annotations

import re
import uuid
from typing import Final

from starlette.types import ASGIApp, Message, Receive, Scope, Send


X_REQUEST_ID: Final[str] = "X-Request-ID"
_X_REQUEST_ID_BYTES: Final[bytes] = b"x-request-id"

_MAX_REQUEST_ID_LENGTH: Final[int] = 128

_REQUEST_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$"
)


def _new_request_id() -> str:
    return str(
        uuid.uuid4()
    )


def _normalize_request_id(
    value: str | None,
) -> str:
    if value is None:
        return _new_request_id()

    candidate = value.strip()

    if not candidate:
        return _new_request_id()

    if len(candidate) > _MAX_REQUEST_ID_LENGTH:
        return _new_request_id()

    if not _REQUEST_ID_PATTERN.fullmatch(
        candidate
    ):
        return _new_request_id()

    return candidate


def _request_header(
    scope: Scope,
    name: bytes,
) -> str | None:
    for key, value in scope.get(
        "headers",
        (),
    ):
        if key.lower() == name:
            try:
                return value.decode(
                    "ascii"
                )
            except UnicodeDecodeError:
                return None

    return None


class RequestContextMiddleware:
    """Attach a bounded request ID to HTTP request state and response headers."""

    def __init__(
        self,
        app: ASGIApp,
    ) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        request_id = _normalize_request_id(
            _request_header(
                scope,
                _X_REQUEST_ID_BYTES,
            )
        )

        state = scope.setdefault(
            "state",
            {},
        )

        state[
            "request_id"
        ] = request_id

        request_id_header = (
            X_REQUEST_ID.encode(
                "ascii"
            ),
            request_id.encode(
                "ascii"
            ),
        )

        async def send_with_request_id(
            message: Message,
        ) -> None:
            if message["type"] == "http.response.start":
                headers = list(
                    message.get(
                        "headers",
                        [],
                    )
                )

                headers = [
                    (
                        key,
                        value,
                    )
                    for key, value in headers
                    if key.lower()
                    != _X_REQUEST_ID_BYTES
                ]

                headers.append(
                    request_id_header
                )

                message[
                    "headers"
                ] = headers

            await send(
                message
            )

        await self.app(
            scope,
            receive,
            send_with_request_id,
        )


__all__ = [
    "RequestContextMiddleware",
    "X_REQUEST_ID",
]
