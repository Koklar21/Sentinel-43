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

"""Sentinel-43 application-layer firewall middleware.

Pure ASGI middleware for HTTP/WebSocket pre-routing checks.

Responsibilities:
    - IP allow/block policy
    - trusted-proxy client IP resolution
    - request-path screening
    - header-budget enforcement
    - duplicate Content-Length rejection
    - Content-Length size checks when present
    - bounded in-memory request-rate limiting
    - firewall context injection into ASGI scope state
    - best-effort monitoring dispatch

This middleware does not enforce actual streamed-body size. The ASGI server or
trusted reverse proxy must also enforce maximum request-body/frame sizes.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import logging
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Final,
    Iterable,
    Mapping,
    MutableMapping,
    Sequence,
)
from urllib.parse import unquote

from ...security_context import (
    STATE_KEY as SC_STATE_KEY,
    UNKNOWN_CLIENT,
    IdentityType,
    SecurityContext,
    attach_security_context,
    new_id,
    sanitize_correlation_id,
)

logger = logging.getLogger(__name__)

ASGIApp = Callable[
    [
        dict[str, Any],
        Callable[[], Awaitable[dict[str, Any]]],
        Callable[[dict[str, Any]], Awaitable[None]],
    ],
    Awaitable[None],
]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_TRUE_VALUES: Final[frozenset[str]] = frozenset(
    {"1", "true", "yes", "on", "enabled"}
)
_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"0", "false", "no", "off", "disabled"}
)
_SAFE_METHOD_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{1,16}$")


class BlockReason(str, Enum):
    IP_INVALID = "ip_invalid"
    IP_BLOCKED = "ip_blocked"
    IP_NOT_ALLOWED = "ip_not_allowed"
    PATH_BLOCKED = "path_blocked"
    CONTENT_LENGTH_INVALID = "content_length_invalid"
    CONTENT_LENGTH_TOO_LARGE = "content_length_too_large"
    DUPLICATE_CONTENT_LENGTH = "duplicate_content_length"
    HEADER_BUDGET_EXCEEDED = "header_budget_exceeded"
    RATE_LIMITED = "rate_limited"
    WEBSOCKET_RATE_LIMITED = "websocket_rate_limited"
    INVALID_SCOPE = "invalid_scope"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False

    raise ValueError(f"{name} must be boolean; got {raw!r}")


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
            raise ValueError(f"{name} must be integer; got {raw!r}") from exc

    if not minimum <= value <= maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum}; got {value}"
        )

    return value


def _env_csv(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    return tuple(
        item.strip()
        for item in raw.split(",")
        if item.strip()
    )


class TrafficClass(str, Enum):
    """Rate-budget class for a request.

    The firewall runs before authentication, so it cannot key budgets on a
    verified identity. Route prefix is the honest proxy available at this
    layer, and it is sufficient for the property that matters: a malfunctioning
    internal producer burns only its own budget and cannot starve operators.
    """

    PUBLIC = "public"
    INTERNAL_FENRIR = "internal_fenrir"
    SPARTA_NODE = "sparta_node"
    REMOTE_GATEWAY = "remote_gateway"
    WEBSOCKET = "websocket"


#: Longest-prefix wins; order matters.
_TRAFFIC_CLASS_PREFIXES: Final[tuple[tuple[str, TrafficClass], ...]] = (
    ("/internal/", TrafficClass.INTERNAL_FENRIR),
    ("/watchtower/events", TrafficClass.INTERNAL_FENRIR),
    ("/node/", TrafficClass.SPARTA_NODE),
    ("/remote-gateway/", TrafficClass.REMOTE_GATEWAY),
)


@dataclass(frozen=True, slots=True)
class FirewallConfig:
    enabled: bool = True

    # IP / proxy handling
    trusted_proxy_cidrs: tuple[str, ...] = ()
    allowed_ip_cidrs: tuple[str, ...] = ()
    blocked_ip_cidrs: tuple[str, ...] = ()
    respect_x_forwarded_for: bool = True
    reject_unparseable_client_ip: bool = True

    # Request limits
    max_content_length_bytes: int = 10 * 1024 * 1024
    max_total_header_bytes: int = 32 * 1024

    # Path blocking
    blocked_path_prefixes: tuple[str, ...] = (
        "/.git",
        "/.env",
        "/wp-admin",
        "/wp-login",
        "/phpmyadmin",
        "/adminer",
        "/server-status",
        "/actuator",
        "/debug",
        "/vendor",
        "/node_modules",
    )
    blocked_path_contains: tuple[str, ...] = (
        "../",
        "..\\",
        "%2e%2e",
        "%252e%252e",
        ".env",
        "passwd",
        "shadow",
    )

    # Rate limiting
    http_rate_limit_requests: int = 300
    http_rate_limit_window_seconds: int = 60
    websocket_rate_limit_requests: int = 60
    websocket_rate_limit_window_seconds: int = 60
    rate_limit_max_keys: int = 10_000

    # Independent per-class budgets. Each class gets its own limiter, keyed
    # per client within that class, so exhausting one cannot deny another.
    # An internal producer in a retry storm degrades itself, not the operator.
    internal_rate_limit_requests: int = 600
    sparta_rate_limit_requests: int = 600
    remote_gateway_rate_limit_requests: int = 120

    # Response behavior
    block_status_code: int = 403
    rate_limit_status_code: int = 429
    include_block_reason: bool = False

    # Keep false when SecurityHeadersMiddleware is mounted separately.
    add_security_headers: bool = False

    # Monitoring
    monitoring_enabled: bool = True
    monitoring_source: str = "sentinel-firewall"
    monitoring_node: str = "s43-api"
    monitoring_timeout_seconds: float = 1.0

    @classmethod
    def from_env(cls) -> "FirewallConfig":
        config = cls(
            enabled=_env_bool("S43_FIREWALL_ENABLED", True),
            trusted_proxy_cidrs=_env_csv("S43_TRUSTED_PROXIES"),
            allowed_ip_cidrs=_env_csv("S43_FIREWALL_ALLOWED_IPS"),
            blocked_ip_cidrs=_env_csv("S43_FIREWALL_BLOCKED_IPS"),
            respect_x_forwarded_for=_env_bool(
                "S43_FIREWALL_RESPECT_X_FORWARDED_FOR",
                True,
            ),
            reject_unparseable_client_ip=_env_bool(
                "S43_FIREWALL_REJECT_INVALID_CLIENT_IP",
                True,
            ),
            max_content_length_bytes=_env_int(
                "S43_FIREWALL_MAX_CONTENT_LENGTH",
                10 * 1024 * 1024,
                minimum=1,
                maximum=1024 * 1024 * 1024,
            ),
            max_total_header_bytes=_env_int(
                "S43_FIREWALL_MAX_HEADER_BYTES",
                32 * 1024,
                minimum=1024,
                maximum=1024 * 1024,
            ),
            http_rate_limit_requests=_env_int(
                "S43_FIREWALL_HTTP_RATE_LIMIT",
                300,
                minimum=1,
                maximum=1_000_000,
            ),
            http_rate_limit_window_seconds=_env_int(
                "S43_FIREWALL_HTTP_RATE_WINDOW",
                60,
                minimum=1,
                maximum=86_400,
            ),
            websocket_rate_limit_requests=_env_int(
                "S43_FIREWALL_WS_RATE_LIMIT",
                60,
                minimum=1,
                maximum=1_000_000,
            ),
            websocket_rate_limit_window_seconds=_env_int(
                "S43_FIREWALL_WS_RATE_WINDOW",
                60,
                minimum=1,
                maximum=86_400,
            ),
            rate_limit_max_keys=_env_int(
                "S43_FIREWALL_RATE_LIMIT_MAX_KEYS",
                10_000,
                minimum=100,
                maximum=1_000_000,
            ),
            block_status_code=_env_int(
                "S43_FIREWALL_BLOCK_STATUS",
                403,
                minimum=400,
                maximum=599,
            ),
            rate_limit_status_code=_env_int(
                "S43_FIREWALL_RATE_LIMIT_STATUS",
                429,
                minimum=400,
                maximum=599,
            ),
            include_block_reason=_env_bool(
                "S43_FIREWALL_INCLUDE_BLOCK_REASON",
                False,
            ),
            add_security_headers=_env_bool(
                "S43_FIREWALL_ADD_SECURITY_HEADERS",
                False,
            ),
            monitoring_enabled=_env_bool(
                "S43_FIREWALL_MONITORING_ENABLED",
                True,
            ),
            monitoring_source=(
                os.getenv(
                    "S43_FIREWALL_MONITORING_SOURCE",
                    "sentinel-firewall",
                ).strip()
                or "sentinel-firewall"
            ),
            monitoring_node=(
                os.getenv(
                    "S43_FIREWALL_MONITORING_NODE",
                    "s43-api",
                ).strip()
                or "s43-api"
            ),
            monitoring_timeout_seconds=float(
                os.getenv(
                    "S43_FIREWALL_MONITORING_TIMEOUT",
                    "1.0",
                ).strip()
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if self.monitoring_timeout_seconds <= 0:
            raise ValueError(
                "monitoring_timeout_seconds must be greater than zero"
            )

        _parse_networks(
            self.trusted_proxy_cidrs,
            field_name="trusted_proxy_cidrs",
        )
        _parse_networks(
            self.allowed_ip_cidrs,
            field_name="allowed_ip_cidrs",
        )
        _parse_networks(
            self.blocked_ip_cidrs,
            field_name="blocked_ip_cidrs",
        )

        if not 400 <= self.block_status_code <= 599:
            raise ValueError("block_status_code must be an HTTP error status")

        if not 400 <= self.rate_limit_status_code <= 599:
            raise ValueError(
                "rate_limit_status_code must be an HTTP error status"
            )


@dataclass(frozen=True, slots=True)
class FirewallDecision:
    allowed: bool
    reason: BlockReason | None = None
    status_code: int = 403
    detail: str = "Forbidden"


class _RateLimiter:
    """Bounded in-memory sliding-window limiter."""

    def __init__(
        self,
        limit: int,
        window_seconds: int,
        *,
        max_keys: int,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys

        self._hits: dict[str, deque[float]] = {}
        self._last_seen: dict[str, float] = {}
        self._operations = 0

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds

        bucket = self._hits.get(key)
        if bucket is None:
            if len(self._hits) >= self.max_keys:
                self._evict_oldest()
            bucket = deque()
            self._hits[key] = bucket

        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        self._last_seen[key] = now
        self._operations += 1

        if self._operations % 256 == 0:
            self._prune(cutoff)

        if len(bucket) >= self.limit:
            return False

        bucket.append(now)
        return True

    def _prune(self, cutoff: float) -> None:
        stale = [
            key
            for key, last_seen in self._last_seen.items()
            if last_seen <= cutoff
        ]

        for key in stale:
            self._hits.pop(key, None)
            self._last_seen.pop(key, None)

    def _evict_oldest(self) -> None:
        if not self._last_seen:
            return

        oldest_key = min(
            self._last_seen,
            key=self._last_seen.__getitem__,
        )
        self._hits.pop(oldest_key, None)
        self._last_seen.pop(oldest_key, None)


def _headers_to_mapping(
    headers: Iterable[tuple[bytes, bytes]],
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}

    for raw_name, raw_value in headers:
        # ASGI headers are bytes and latin-1 round-trippable by convention.
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        result.setdefault(name, []).append(value)

    return result


def _header_total_size(
    headers: Iterable[tuple[bytes, bytes]],
) -> int:
    # Include separator overhead rather than undercounting every header.
    return sum(
        len(name) + len(value) + 4
        for name, value in headers
    )


def _first_header(
    headers: Mapping[str, list[str]],
    name: str,
) -> str | None:
    values = headers.get(name.lower())
    return values[0] if values else None


def _client_host_from_scope(scope: Mapping[str, Any]) -> str:
    client = scope.get("client")

    if (
        isinstance(client, (list, tuple))
        and client
        and client[0] is not None
    ):
        return str(client[0]).strip()

    return ""


def _parse_ip(value: str) -> IPAddress | None:
    if not value:
        return None

    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _parse_networks(
    values: Sequence[str],
    *,
    field_name: str,
) -> tuple[IPNetwork, ...]:
    networks: list[IPNetwork] = []

    for value in values:
        try:
            networks.append(
                ipaddress.ip_network(value, strict=False)
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"SentinelFirewall: invalid CIDR {value!r} in "
                f"{field_name}: {exc}"
            ) from exc

    return tuple(networks)


def _ip_in_networks(
    ip: IPAddress,
    networks: Sequence[IPNetwork],
) -> bool:
    return any(
        ip.version == network.version and ip in network
        for network in networks
    )


def _json_body(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _normalized_path_candidates(scope: Mapping[str, Any]) -> tuple[str, ...]:
    path = str(scope.get("path") or "/")

    raw_path = scope.get("raw_path")
    if isinstance(raw_path, bytes):
        raw = raw_path.decode("latin-1", errors="replace")
    else:
        raw = path

    candidates: list[str] = [path, raw]

    current = raw
    for _ in range(2):
        decoded = unquote(current)
        if decoded == current:
            break
        candidates.append(decoded)
        current = decoded

    return tuple(dict.fromkeys(candidate.lower() for candidate in candidates))


class SentinelFirewall:
    """Pure ASGI application-layer firewall."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: FirewallConfig | None = None,
        monitoring_manager: Any | None = None,
    ) -> None:
        self.app = app
        self.config = config or FirewallConfig()
        self.config.validate()

        self.monitoring_manager = monitoring_manager

        self._trusted_proxy_networks = _parse_networks(
            self.config.trusted_proxy_cidrs,
            field_name="trusted_proxy_cidrs",
        )
        self._allowed_networks = _parse_networks(
            self.config.allowed_ip_cidrs,
            field_name="allowed_ip_cidrs",
        )
        self._blocked_networks = _parse_networks(
            self.config.blocked_ip_cidrs,
            field_name="blocked_ip_cidrs",
        )

        self._http_limiter = _RateLimiter(
            self.config.http_rate_limit_requests,
            self.config.http_rate_limit_window_seconds,
            max_keys=self.config.rate_limit_max_keys,
        )
        self._ws_limiter = _RateLimiter(
            self.config.websocket_rate_limit_requests,
            self.config.websocket_rate_limit_window_seconds,
            max_keys=self.config.rate_limit_max_keys,
        )

        window = self.config.http_rate_limit_window_seconds
        max_keys = self.config.rate_limit_max_keys
        self._class_limiters: dict[TrafficClass, _RateLimiter] = {
            TrafficClass.PUBLIC: self._http_limiter,
            TrafficClass.WEBSOCKET: self._ws_limiter,
            TrafficClass.INTERNAL_FENRIR: _RateLimiter(
                self.config.internal_rate_limit_requests,
                window,
                max_keys=max_keys,
            ),
            TrafficClass.SPARTA_NODE: _RateLimiter(
                self.config.sparta_rate_limit_requests,
                window,
                max_keys=max_keys,
            ),
            TrafficClass.REMOTE_GATEWAY: _RateLimiter(
                self.config.remote_gateway_rate_limit_requests,
                window,
                max_keys=max_keys,
            ),
        }

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Receive,
        send: Send,
    ) -> None:
        if not self.config.enabled:
            await self.app(scope, receive, send)
            return

        scope_type = scope.get("type")

        if scope_type == "http":
            await self._handle_http(scope, receive, send)
            return

        if scope_type == "websocket":
            await self._handle_websocket(scope, receive, send)
            return

        # Lifespan and other valid ASGI scope types pass through untouched.
        await self.app(scope, receive, send)

    async def _handle_http(
        self,
        scope: dict[str, Any],
        receive: Receive,
        send: Send,
    ) -> None:
        decision = self._screen_scope(scope, websocket=False)
        self._attach_state(scope, decision)

        if not decision.allowed:
            self._dispatch_monitoring_background(scope, decision)
            await self._send_http_block(send, decision)
            return

        async def wrapped_send(message: dict[str, Any]) -> None:
            if (
                self.config.add_security_headers
                and message.get("type") == "http.response.start"
            ):
                message["headers"] = self._merge_security_headers(
                    message.get("headers") or []
                )

            await send(message)

        await self.app(scope, receive, wrapped_send)

    async def _handle_websocket(
        self,
        scope: dict[str, Any],
        receive: Receive,
        send: Send,
    ) -> None:
        decision = self._screen_scope(scope, websocket=True)
        self._attach_state(scope, decision)

        if not decision.allowed:
            self._dispatch_monitoring_background(scope, decision)
            await send(
                {
                    "type": "websocket.close",
                    "code": 1008,
                    "reason": (
                        decision.reason.value
                        if decision.reason
                        else "blocked"
                    ),
                }
            )
            return

        await self.app(scope, receive, send)

    def _screen_scope(
        self,
        scope: Mapping[str, Any],
        *,
        websocket: bool,
    ) -> FirewallDecision:
        scope_type = scope.get("type")

        if scope_type not in {"http", "websocket"}:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.INVALID_SCOPE,
                status_code=self.config.block_status_code,
                detail="Invalid ASGI scope",
            )

        try:
            headers = _headers_to_mapping(scope.get("headers") or [])
        except Exception:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.HEADER_BUDGET_EXCEEDED,
                status_code=400,
                detail="Malformed request headers",
            )

        client_ip_text = self._resolve_client_ip(scope, headers)
        client_ip = _parse_ip(client_ip_text)

        if client_ip is None and self.config.reject_unparseable_client_ip:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.IP_INVALID,
                status_code=400,
                detail="Invalid client address",
            )

        ip_decision = self._screen_ip(client_ip)
        if not ip_decision.allowed:
            return ip_decision

        path_decision = self._screen_path(scope)
        if not path_decision.allowed:
            return path_decision

        header_decision = self._screen_headers(scope, headers)
        if not header_decision.allowed:
            return header_decision

        if not websocket:
            content_decision = self._screen_content_length(headers)
            if not content_decision.allowed:
                return content_decision

        traffic_class = self._classify(scope, websocket=websocket)
        limiter = self._class_limiters[traffic_class]
        limiter_key = client_ip_text or "unknown"

        if not limiter.allow(limiter_key):
            return FirewallDecision(
                allowed=False,
                reason=(
                    BlockReason.WEBSOCKET_RATE_LIMITED
                    if websocket
                    else BlockReason.RATE_LIMITED
                ),
                status_code=self.config.rate_limit_status_code,
                detail="Rate limit exceeded",
            )

        return FirewallDecision(allowed=True)

    @staticmethod
    def _classify(
        scope: Mapping[str, Any],
        *,
        websocket: bool,
    ) -> TrafficClass:
        if websocket:
            return TrafficClass.WEBSOCKET

        raw_path = scope.get("path")
        path = raw_path if isinstance(raw_path, str) else ""

        for prefix, traffic_class in _TRAFFIC_CLASS_PREFIXES:
            if path.startswith(prefix):
                return traffic_class

        return TrafficClass.PUBLIC

    def _resolve_client_ip(
        self,
        scope: Mapping[str, Any],
        headers: Mapping[str, list[str]],
    ) -> str:
        direct_host = _client_host_from_scope(scope)
        direct_ip = _parse_ip(direct_host)

        if not self.config.respect_x_forwarded_for:
            return direct_host

        if direct_ip is None:
            return direct_host

        if not self._trusted_proxy_networks:
            return direct_host

        if not _ip_in_networks(
            direct_ip,
            self._trusted_proxy_networks,
        ):
            return direct_host

        xff = _first_header(headers, "x-forwarded-for")
        if not xff:
            return direct_host

        candidates = [
            part.strip()
            for part in xff.split(",")
            if part.strip()
        ]

        if not candidates:
            return direct_host

        for candidate in reversed(candidates):
            parsed = _parse_ip(candidate)
            if parsed is None:
                return direct_host

            if _ip_in_networks(
                parsed,
                self._trusted_proxy_networks,
            ):
                continue

            return str(parsed)

        return direct_host

    def _screen_ip(
        self,
        ip: IPAddress | None,
    ) -> FirewallDecision:
        if ip is None:
            return FirewallDecision(allowed=True)

        if (
            self._blocked_networks
            and _ip_in_networks(ip, self._blocked_networks)
        ):
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.IP_BLOCKED,
                status_code=self.config.block_status_code,
                detail="Client IP blocked",
            )

        if (
            self._allowed_networks
            and not _ip_in_networks(ip, self._allowed_networks)
        ):
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.IP_NOT_ALLOWED,
                status_code=self.config.block_status_code,
                detail="Client IP not allowed",
            )

        return FirewallDecision(allowed=True)

    def _screen_path(
        self,
        scope: Mapping[str, Any],
    ) -> FirewallDecision:
        candidates = _normalized_path_candidates(scope)

        for candidate in candidates:
            for prefix in self.config.blocked_path_prefixes:
                if candidate.startswith(prefix.lower()):
                    return FirewallDecision(
                        allowed=False,
                        reason=BlockReason.PATH_BLOCKED,
                        status_code=self.config.block_status_code,
                        detail="Path blocked",
                    )

            for token in self.config.blocked_path_contains:
                if token.lower() in candidate:
                    return FirewallDecision(
                        allowed=False,
                        reason=BlockReason.PATH_BLOCKED,
                        status_code=self.config.block_status_code,
                        detail="Path blocked",
                    )

        return FirewallDecision(allowed=True)

    def _screen_headers(
        self,
        scope: Mapping[str, Any],
        headers: Mapping[str, list[str]],
    ) -> FirewallDecision:
        total = _header_total_size(scope.get("headers") or [])

        if total > self.config.max_total_header_bytes:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.HEADER_BUDGET_EXCEEDED,
                status_code=431,
                detail="Header budget exceeded",
            )

        # Reject every duplicate Content-Length. Identical duplicates may be
        # tolerated by some HTTP stacks, but rejecting them closes an entire
        # class of request-smuggling ambiguity at this boundary.
        content_length_values = headers.get("content-length") or []
        if len(content_length_values) > 1:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.DUPLICATE_CONTENT_LENGTH,
                status_code=400,
                detail="Duplicate Content-Length headers",
            )

        return FirewallDecision(allowed=True)

    def _screen_content_length(
        self,
        headers: Mapping[str, list[str]],
    ) -> FirewallDecision:
        content_length = _first_header(headers, "content-length")

        # Do not require Content-Length. HTTP/1.1 chunked transfer and HTTP/2+
        # can legitimately carry request bodies without this header. Actual
        # streamed-body limits belong at the ASGI server/reverse-proxy layer.
        if content_length is None:
            return FirewallDecision(allowed=True)

        stripped = content_length.strip()

        if not stripped.isdigit():
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.CONTENT_LENGTH_INVALID,
                status_code=400,
                detail="Invalid Content-Length",
            )

        length = int(stripped)

        if length > self.config.max_content_length_bytes:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.CONTENT_LENGTH_TOO_LARGE,
                status_code=413,
                detail="Payload too large",
            )

        return FirewallDecision(allowed=True)

    def _attach_state(
        self,
        scope: MutableMapping[str, Any],
        decision: FirewallDecision,
    ) -> None:
        try:
            headers = _headers_to_mapping(scope.get("headers") or [])
            client_ip = self._resolve_client_ip(scope, headers)
            via_trusted_proxy = self._came_via_trusted_proxy(scope)
            inbound_correlation = _first_header(headers, "x-request-id")
        except Exception:
            client_ip = ""
            via_trusted_proxy = False
            inbound_correlation = None

        state = scope.setdefault("state", {})

        if not isinstance(state, dict):
            state = {}
            scope["state"] = state

        state["s43_firewall_allowed"] = decision.allowed
        state["s43_firewall_reason"] = (
            decision.reason.value
            if decision.reason
            else None
        )

        # The single canonical security context for this request. Downstream
        # code reads this instead of re-deriving the client identity, so the
        # trusted-proxy decision has exactly one implementation.
        context = SecurityContext(
            request_id=new_id(),
            correlation_id=sanitize_correlation_id(inbound_correlation),
            client_ip=client_ip or UNKNOWN_CLIENT,
            via_trusted_proxy=via_trusted_proxy,
            firewall_allowed=decision.allowed,
            firewall_reason=(
                decision.reason.value if decision.reason else ""
            ),
        )
        attach_security_context(state, context)

    def _came_via_trusted_proxy(
        self,
        scope: Mapping[str, Any],
    ) -> bool:
        """True only when the immediate peer is a configured trusted proxy.

        This is the same predicate that gates whether X-Forwarded-For is
        honoured, surfaced so downstream code can record how the client
        identity was established without re-deriving it.
        """
        if not self._trusted_proxy_networks:
            return False
        direct_ip = _parse_ip(_client_host_from_scope(scope))
        if direct_ip is None:
            return False
        return _ip_in_networks(direct_ip, self._trusted_proxy_networks)

    @staticmethod
    def _security_headers() -> tuple[tuple[bytes, bytes], ...]:
        return (
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"x-sentinel-firewall", b"active"),
        )

    def _merge_security_headers(
        self,
        existing: Iterable[tuple[bytes, bytes]],
    ) -> list[tuple[bytes, bytes]]:
        headers = list(existing)
        existing_names = {
            name.lower()
            for name, _value in headers
        }

        for name, value in self._security_headers():
            if name not in existing_names:
                headers.append((name, value))

        return headers

    async def _send_http_block(
        self,
        send: Send,
        decision: FirewallDecision,
    ) -> None:
        body_payload: dict[str, Any] = {
            "error": "request_blocked",
            "detail": decision.detail,
        }

        if (
            self.config.include_block_reason
            and decision.reason is not None
        ):
            body_payload["reason"] = decision.reason.value

        body = _json_body(body_payload)

        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"x-sentinel-firewall", b"blocked"),
            (b"cache-control", b"no-store"),
        ]

        if self.config.add_security_headers:
            headers = self._merge_security_headers(headers)

        await send(
            {
                "type": "http.response.start",
                "status": decision.status_code,
                "headers": headers,
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
                "more_body": False,
            }
        )

    def _dispatch_monitoring_background(
        self,
        scope: Mapping[str, Any],
        decision: FirewallDecision,
    ) -> None:
        if not self.config.monitoring_enabled:
            return

        if self.monitoring_manager is None:
            return

        try:
            asyncio.create_task(
                self._dispatch_monitoring(scope, decision),
                name="sentinel43-firewall-monitoring",
            )
        except RuntimeError:
            # No running loop. This should be rare in normal ASGI execution;
            # the block itself must still succeed.
            logger.debug(
                "Firewall monitoring task could not be scheduled",
                exc_info=True,
            )

    async def _dispatch_monitoring(
        self,
        scope: Mapping[str, Any],
        decision: FirewallDecision,
    ) -> None:
        manager = self.monitoring_manager
        if manager is None:
            return

        reason = (
            decision.reason.value
            if decision.reason
            else "unknown"
        )

        try:
            headers = _headers_to_mapping(scope.get("headers") or [])
            client_ip = self._resolve_client_ip(scope, headers)
        except Exception:
            client_ip = ""

        # Provenance travels with the event: the firewall is the source, and
        # the request's correlation id lets this block be tied to everything
        # else that happened on the same request.
        state = scope.get("state") or {}
        context = (
            state.get(SC_STATE_KEY) if isinstance(state, dict) else None
        )

        event = {
            "kind": "security",
            "source": self.config.monitoring_source,
            "source_identity": (
                context.identity_type.value
                if context is not None
                else IdentityType.ANONYMOUS.value
            ),
            "correlation_id": (
                context.correlation_id if context is not None else ""
            ),
            "node": self.config.monitoring_node,
            "status": "blocked",
            "severity": "warning",
            "event_type": "firewall_block",
            "action": "block",
            "details": {
                "reason": reason,
                "path": scope.get("path"),
                "method": scope.get("method"),
                "scope_type": scope.get("type"),
                "client_ip": client_ip or None,
                "timestamp": time.time(),
            },
            "metadata": {
                "firewall": "SentinelFirewall",
                "reason": reason,
            },
        }

        async def invoke() -> None:
            try:
                accepted = inspect.signature(manager.analyze_event).parameters
                takes_any = any(
                    p.kind is inspect.Parameter.VAR_KEYWORD
                    for p in accepted.values()
                )
            except (TypeError, ValueError):
                accepted, takes_any = {}, False
            kwargs: dict[str, Any] = {}
            if takes_any or "source_ip" in accepted:
                kwargs["source_ip"] = client_ip or None
            if takes_any or "trusted_producer" in accepted:
                kwargs["trusted_producer"] = "firewall"
            result = manager.analyze_event(event, **kwargs)

            if inspect.isawaitable(result):
                await result

        try:
            await asyncio.wait_for(
                invoke(),
                timeout=self.config.monitoring_timeout_seconds,
            )
        except Exception:
            logger.debug(
                "Firewall monitoring dispatch failed",
                exc_info=True,
            )


__all__ = [
    "BlockReason",
    "TrafficClass",
    "FirewallConfig",
    "FirewallDecision",
    "SentinelFirewall",
]
