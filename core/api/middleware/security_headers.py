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

"""Sentinel-43 transport and response security middleware.

SecurityHeadersMiddleware:
    - Adds static browser hardening headers.
    - Emits HSTS only for non-local HTTPS requests, unless explicitly forced.
    - Trusts X-Forwarded-Proto only from configured trusted proxy CIDRs.
    - Optionally emits an operator-supplied Content-Security-Policy.

TrustedHostGuard:
    - Enforces an explicit Host allow-list.
    - Supports exact hosts and leading-dot suffix patterns.
    - Correctly parses host:port and bracketed IPv6 authorities.
    - Exempts only explicitly listed coarse probe paths.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from typing import Final, Iterable

from starlette.types import ASGIApp, Message, Receive, Scope, Send


_LOCAL_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "dev", "local", "test"}
)

_HOST_CHECK_EXEMPT_PATHS: Final[frozenset[str]] = frozenset(
    {
        "/health",
        "/ready",
        "/watchtower/health",
        "/watchtower/ready",
        "/api/ready",
        "/api/watchtower/health",
        "/api/watchtower/ready",
    }
)

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on"}
)

_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off"}
)

_DEFAULT_HSTS_MAX_AGE: Final[int] = 15_552_000  # 180 days

_STATIC_HEADERS: Final[tuple[tuple[bytes, bytes], ...]] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-site"),
    (
        b"permissions-policy",
        b"geolocation=(), microphone=(), camera=()",
    ),
)


def _environment() -> str:
    return os.getenv("SENTINEL_ENV", "production").strip().lower()


def _is_local_environment() -> bool:
    return _environment() in _LOCAL_ENVIRONMENTS


def _env_bool(
    name: str,
    *,
    default: bool | None = None,
) -> bool | None:
    raw = os.getenv(name)

    if raw is None:
        return default

    normalized = raw.strip().lower()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    raise RuntimeError(
        f"{name} must be boolean; got {raw!r}"
    )


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name)

    if raw is None:
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError as exc:
            raise RuntimeError(
                f"{name} must be an integer; got {raw!r}"
            ) from exc

    if not minimum <= value <= maximum:
        raise RuntimeError(
            f"{name} must be between {minimum} and {maximum}; got {value}"
        )

    return value


@lru_cache(maxsize=32)
def _parse_proxy_networks(raw: str) -> tuple[
    ipaddress.IPv4Network | ipaddress.IPv6Network,
    ...,
]:
    networks: list[
        ipaddress.IPv4Network | ipaddress.IPv6Network
    ] = []

    for part in raw.split(","):
        item = part.strip()
        if not item:
            continue

        try:
            networks.append(
                ipaddress.ip_network(item, strict=False)
            )
        except ValueError as exc:
            raise RuntimeError(
                f"Invalid CIDR {item!r} in S43_TRUSTED_PROXIES"
            ) from exc

    return tuple(networks)


def _trusted_proxy_networks() -> tuple[
    ipaddress.IPv4Network | ipaddress.IPv6Network,
    ...,
]:
    return _parse_proxy_networks(
        os.getenv("S43_TRUSTED_PROXIES", "").strip()
    )


def _peer_is_trusted_proxy(scope: Scope) -> bool:
    networks = _trusted_proxy_networks()

    if not networks:
        return False

    client = scope.get("client")
    if not (
        isinstance(client, (list, tuple))
        and client
        and client[0] is not None
    ):
        return False

    try:
        address = ipaddress.ip_address(str(client[0]).strip())
    except ValueError:
        return False

    return any(
        address.version == network.version
        and address in network
        for network in networks
    )


def _header_values(
    headers: Iterable[tuple[bytes, bytes]],
    name: bytes,
) -> list[bytes]:
    return [
        value
        for key, value in headers
        if key.lower() == name
    ]


def _effective_scheme(scope: Scope) -> str:
    scheme = str(scope.get("scheme") or "http").strip().lower()

    if not _peer_is_trusted_proxy(scope):
        return scheme

    forwarded = _header_values(
        scope.get("headers") or [],
        b"x-forwarded-proto",
    )

    # Multiple X-Forwarded-Proto headers are ambiguous. Ignore them rather
    # than guessing which proxy/client value deserves trust.
    if len(forwarded) != 1:
        return scheme

    first = (
        forwarded[0]
        .decode("latin-1")
        .split(",", 1)[0]
        .strip()
        .lower()
    )

    if first in {"http", "https"}:
        return first

    return scheme


def _merge_headers(
    existing: Iterable[tuple[bytes, bytes]],
    additions: Iterable[tuple[bytes, bytes]],
) -> list[tuple[bytes, bytes]]:
    headers = list(existing)
    present = {name.lower() for name, _ in headers}

    for name, value in additions:
        if name.lower() not in present:
            headers.append((name, value))
            present.add(name.lower())

    return headers


def _parse_host_authority(value: str) -> str:
    """Extract the hostname from an HTTP Host authority.

    Handles:
        example.com
        example.com:8000
        [2001:db8::1]
        [2001:db8::1]:8000
    """
    authority = value.strip().lower()

    if not authority:
        return ""

    if authority.startswith("["):
        closing = authority.find("]")
        if closing == -1:
            return ""
        return authority[1:closing]

    # A normal DNS/IPv4 authority has at most one colon separating a port.
    if authority.count(":") == 1:
        host, possible_port = authority.rsplit(":", 1)
        if possible_port.isdigit():
            return host

    # Unbracketed IPv6 in Host is invalid HTTP authority syntax, but returning
    # it unchanged ensures it does not accidentally match a valid allow-list.
    return authority


def _trusted_host_patterns() -> tuple[str, ...]:
    raw = os.getenv("S43_TRUSTED_HOSTS", "")

    patterns = tuple(
        item.strip().lower()
        for item in raw.split(",")
        if item.strip()
    )

    if "*" in patterns and not _is_local_environment():
        raise RuntimeError(
            "S43_TRUSTED_HOSTS='*' is not permitted outside local/test"
        )

    return patterns


def _host_matches(host: str, pattern: str) -> bool:
    if pattern == "*":
        return True

    if pattern.startswith("."):
        suffix = pattern[1:]
        return host == suffix or host.endswith(f".{suffix}")

    return host == pattern


class SecurityHeadersMiddleware:
    """Add transport-security and browser-hardening response headers."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        secure = _effective_scheme(scope) == "https"
        local = _is_local_environment()

        force_hsts = _env_bool(
            "S43_HSTS_FORCE",
            default=False,
        )
        disable_hsts = _env_bool(
            "S43_HSTS_DISABLE",
            default=False,
        )

        emit_hsts = bool(
            not disable_hsts
            and not local
            and (secure or force_hsts)
        )

        max_age = _env_int(
            "S43_HSTS_MAX_AGE",
            _DEFAULT_HSTS_MAX_AGE,
            minimum=0,
            maximum=63_072_000,  # 2 years
        )

        csp = os.getenv(
            "S43_CONTENT_SECURITY_POLICY",
            "",
        ).strip()

        async def wrapped_send(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers = _merge_headers(
                    message.get("headers") or [],
                    _STATIC_HEADERS,
                )

                dynamic: list[tuple[bytes, bytes]] = []

                if emit_hsts:
                    dynamic.append(
                        (
                            b"strict-transport-security",
                            (
                                f"max-age={max_age}; includeSubDomains"
                            ).encode("ascii"),
                        )
                    )

                if csp:
                    try:
                        encoded_csp = csp.encode("latin-1")
                    except UnicodeEncodeError as exc:
                        raise RuntimeError(
                            "S43_CONTENT_SECURITY_POLICY must be latin-1 encodable"
                        ) from exc

                    dynamic.append(
                        (
                            b"content-security-policy",
                            encoded_csp,
                        )
                    )

                message["headers"] = _merge_headers(
                    headers,
                    dynamic,
                )

            await send(message)

        await self.app(scope, receive, wrapped_send)


class TrustedHostGuard:
    """Enforce an explicit HTTP Host allow-list."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        allowed = _trusted_host_patterns()
        path = str(scope.get("path") or "")

        if not allowed or path in _HOST_CHECK_EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        host_values = _header_values(
            scope.get("headers") or [],
            b"host",
        )

        # HTTP/1.1 requires exactly one Host header. Reject ambiguity instead
        # of quietly accepting the first value and hoping every upstream proxy
        # made the same choice.
        if len(host_values) != 1:
            await self._reject(send)
            return

        host = _parse_host_authority(
            host_values[0].decode("latin-1")
        )

        if not host:
            await self._reject(send)
            return

        if not any(
            _host_matches(host, pattern)
            for pattern in allowed
        ):
            await self._reject(send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"error":"invalid_host"}'

        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json"),
                    (
                        b"content-length",
                        str(len(body)).encode("ascii"),
                    ),
                    (b"cache-control", b"no-store"),
                ],
            }
        )

        await send(
            {
                "type": "http.response.body",
                "body": body,
                "more_body": False,
            }
        )


__all__ = [
    "SecurityHeadersMiddleware",
    "TrustedHostGuard",
]
