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
Sentinel-43 Application-Layer Firewall

File:
    core/middleware/sentinel_firewall.py

Purpose:
    Pure ASGI firewall middleware for FastAPI / Starlette.

Responsibilities:
    - Provide importable exports:
        BlockReason
        FirewallConfig
        SentinelFirewall

    - Screen HTTP and WebSocket scopes before application routing.
    - Apply basic IP allow/block checks.
    - Apply request path blocking.
    - Enforce Content-Length limits.
    - Reject duplicate Content-Length headers.
    - Enforce total header budget.
    - Apply simple in-memory rate limiting.
    - Attach firewall context to scope["state"].
    - Dispatch best-effort monitoring events.

Notes:
    This middleware is intentionally dependency-light. It does not require
    FastAPI imports at module import time. It is designed for:

        app.add_middleware(SentinelFirewall, config=FirewallConfig(...))

    Because apparently Python packages demand paperwork before protecting doors.
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple


logger = logging.getLogger("SentinelFirewall")


ASGIApp = Callable[[dict[str, Any], Callable[[], Awaitable[dict[str, Any]]], Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[None]]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


class BlockReason(str, Enum):
    """
    Firewall block reasons.
    """

    IP_BLOCKED = "ip_blocked"
    IP_NOT_ALLOWED = "ip_not_allowed"
    PATH_BLOCKED = "path_blocked"
    CONTENT_LENGTH_MISSING = "content_length_missing"
    CONTENT_LENGTH_INVALID = "content_length_invalid"
    CONTENT_LENGTH_TOO_LARGE = "content_length_too_large"
    DUPLICATE_CONTENT_LENGTH = "duplicate_content_length"
    HEADER_BUDGET_EXCEEDED = "header_budget_exceeded"
    RATE_LIMITED = "rate_limited"
    WEBSOCKET_RATE_LIMITED = "websocket_rate_limited"
    INVALID_SCOPE = "invalid_scope"


@dataclass(slots=True)
class FirewallConfig:
    """
    SentinelFirewall configuration.

    Safe beta defaults:
        - enabled=True
        - no IP allowlist by default
        - no blocklist by default
        - blocks common dangerous paths
        - rate limits are conservative but not absurd
    """

    enabled: bool = True

    # IP / proxy handling
    trusted_proxy_cidrs: Sequence[str] = field(default_factory=tuple)
    allowed_ip_cidrs: Sequence[str] = field(default_factory=tuple)
    blocked_ip_cidrs: Sequence[str] = field(default_factory=tuple)
    respect_x_forwarded_for: bool = True

    # Request limits
    max_content_length_bytes: int = 10 * 1024 * 1024
    require_content_length_for_methods: Sequence[str] = field(
        default_factory=lambda: ("POST", "PUT", "PATCH")
    )
    max_total_header_bytes: int = 32 * 1024

    # Path blocking
    blocked_path_prefixes: Sequence[str] = field(
        default_factory=lambda: (
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
    )
    blocked_path_contains: Sequence[str] = field(
        default_factory=lambda: (
            "../",
            "..\\",
            "%2e%2e",
            "%252e%252e",
            ".env",
            "passwd",
            "shadow",
        )
    )

    # Rate limits
    http_rate_limit_requests: int = 300
    http_rate_limit_window_seconds: int = 60
    websocket_rate_limit_requests: int = 60
    websocket_rate_limit_window_seconds: int = 60

    # Response behavior
    block_status_code: int = 403
    rate_limit_status_code: int = 429
    include_block_reason: bool = True
    add_security_headers: bool = True

    # Monitoring
    monitoring_enabled: bool = True
    monitoring_source: str = "sentinel-firewall"
    monitoring_node: str = "s43-api"


@dataclass(slots=True)
class FirewallDecision:
    allowed: bool
    reason: Optional[BlockReason] = None
    status_code: int = 403
    detail: str = "Forbidden"


class _RateLimiter:
    """
    Tiny in-memory sliding window limiter.

    This is good enough for local/private beta. For public beta behind multiple
    API workers, Redis-backed rate limiting is the grown-up answer. Naturally,
    we are doing the simple thing first because pain should arrive in stages.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self._hits: dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds

        bucket = self._hits[key]

        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self.limit:
            return False

        bucket.append(now)
        return True


def _headers_to_mapping(headers: Iterable[tuple[bytes, bytes]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)

    for raw_name, raw_value in headers:
        try:
            name = raw_name.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
        except Exception:
            continue

        result[name].append(value)

    return dict(result)


def _header_total_size(headers: Iterable[tuple[bytes, bytes]]) -> int:
    total = 0
    for name, value in headers:
        total += len(name) + len(value)
    return total


def _first_header(headers: Mapping[str, list[str]], name: str) -> Optional[str]:
    values = headers.get(name.lower())
    if not values:
        return None
    return values[0]


def _client_host_from_scope(scope: Mapping[str, Any]) -> str:
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client:
        return str(client[0])
    return "unknown"


def _parse_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(value.strip())
    except Exception:
        return None


def _parse_networks(
    values: Sequence[str], *, field: str
) -> tuple[ipaddress._BaseNetwork, ...]:
    """
    Parse a sequence of CIDR / IP strings into network objects.

    Fail closed: a malformed entry raises instead of being silently dropped.
    Silently discarding an invalid entry weakens security in every direction
    this config is used — an intended blocked_ip_cidrs entry stops blocking,
    an allowed_ip_cidrs list that loses all its entries stops allow-listing
    (everyone passes), a trusted_proxy_cidrs typo changes whose
    X-Forwarded-For is believed. The caller (SentinelFirewall.__init__) lets
    this propagate; core/api/main.py turns it into a fail-closed startup
    error outside local/test environments.
    """
    networks: list[ipaddress._BaseNetwork] = []

    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"SentinelFirewall: invalid CIDR {value!r} in firewall "
                f"config field {field!r}: {exc}"
            ) from exc

    return tuple(networks)


def _ip_in_networks(ip: ipaddress._BaseAddress, networks: Sequence[ipaddress._BaseNetwork]) -> bool:
    return any(ip in network for network in networks)


def _json_body(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class SentinelFirewall:
    """
    Pure ASGI application-layer firewall.

    Usage:

        from core.middleware.sentinel_firewall import FirewallConfig, SentinelFirewall

        app.add_middleware(
            SentinelFirewall,
            config=FirewallConfig(),
            monitoring_manager=monitoring_manager,
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: Optional[FirewallConfig] = None,
        monitoring_manager: Optional[Any] = None,
    ) -> None:
        self.app = app
        self.config = config or FirewallConfig()
        self.monitoring_manager = monitoring_manager

        self._trusted_proxy_networks = _parse_networks(
            self.config.trusted_proxy_cidrs, field="trusted_proxy_cidrs"
        )
        self._allowed_networks = _parse_networks(
            self.config.allowed_ip_cidrs, field="allowed_ip_cidrs"
        )
        self._blocked_networks = _parse_networks(
            self.config.blocked_ip_cidrs, field="blocked_ip_cidrs"
        )

        self._http_limiter = _RateLimiter(
            self.config.http_rate_limit_requests,
            self.config.http_rate_limit_window_seconds,
        )
        self._ws_limiter = _RateLimiter(
            self.config.websocket_rate_limit_requests,
            self.config.websocket_rate_limit_window_seconds,
        )

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
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

        await self.app(scope, receive, send)

    async def _handle_http(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        decision = self._screen_scope(scope, websocket=False)

        self._attach_state(scope, decision)

        if not decision.allowed:
            await self._dispatch_monitoring(scope, decision)
            await self._send_http_block(send, decision)
            return

        async def wrapped_send(message: dict[str, Any]) -> None:
            if (
                self.config.add_security_headers
                and message.get("type") == "http.response.start"
            ):
                headers = list(message.get("headers") or [])
                headers.extend(self._security_headers())
                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, wrapped_send)

    async def _handle_websocket(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        decision = self._screen_scope(scope, websocket=True)

        self._attach_state(scope, decision)

        if not decision.allowed:
            await self._dispatch_monitoring(scope, decision)
            await send(
                {
                    "type": "websocket.close",
                    "code": 1008,
                    "reason": decision.reason.value if decision.reason else "blocked",
                }
            )
            return

        await self.app(scope, receive, send)

    def _screen_scope(self, scope: Mapping[str, Any], *, websocket: bool) -> FirewallDecision:
        scope_type = scope.get("type")
        if scope_type not in {"http", "websocket"}:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.INVALID_SCOPE,
                status_code=self.config.block_status_code,
                detail="Invalid ASGI scope",
            )

        headers = _headers_to_mapping(scope.get("headers") or [])
        client_ip = self._resolve_client_ip(scope, headers)
        parsed_ip = _parse_ip(client_ip) if client_ip != "unknown" else None

        ip_decision = self._screen_ip(parsed_ip)
        if not ip_decision.allowed:
            return ip_decision

        path = str(scope.get("path") or "/")
        path_decision = self._screen_path(path)
        if not path_decision.allowed:
            return path_decision

        header_decision = self._screen_headers(scope, headers)
        if not header_decision.allowed:
            return header_decision

        if not websocket:
            content_decision = self._screen_content_length(scope, headers)
            if not content_decision.allowed:
                return content_decision

        limiter = self._ws_limiter if websocket else self._http_limiter
        limiter_key = f"{client_ip}:{scope_type}"

        if not limiter.allow(limiter_key):
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.WEBSOCKET_RATE_LIMITED if websocket else BlockReason.RATE_LIMITED,
                status_code=self.config.rate_limit_status_code,
                detail="Rate limit exceeded",
            )

        return FirewallDecision(allowed=True)

    def _resolve_client_ip(self, scope: Mapping[str, Any], headers: Mapping[str, list[str]]) -> str:
        direct_host = _client_host_from_scope(scope)
        direct_ip = _parse_ip(direct_host)

        if not self.config.respect_x_forwarded_for:
            return direct_host

        if direct_ip is None:
            return direct_host

        # No trusted proxies configured => never believe a forwarded header.
        # An empty trusted-proxy list means "trust nobody", NOT "trust
        # everybody": without this guard the block below would happily take
        # an X-Forwarded-For value from any direct caller and treat it as the
        # client IP for IP allow/block, the rate-limiter key, and the
        # monitoring source_ip. Every request is attributed to its direct
        # TCP peer until S43_TRUSTED_PROXIES is set to the real proxy CIDR.
        if not self._trusted_proxy_networks:
            return direct_host

        # The direct peer must itself be a configured trusted proxy before we
        # believe anything it forwarded.
        if not _ip_in_networks(direct_ip, self._trusted_proxy_networks):
            return direct_host

        xff = _first_header(headers, "x-forwarded-for")
        if not xff:
            return direct_host

        candidates = [part.strip() for part in xff.split(",") if part.strip()]
        if not candidates:
            return direct_host

        # Walk the chain right-to-left. The rightmost entry is what our
        # trusted direct peer observed; peel off further trusted-proxy hops;
        # the first address that is NOT a trusted proxy is the real client.
        # (Leftmost-wins is wrong for multi-hop / mixed chains: a client can
        # prepend arbitrary entries, and only the trusted segment on the
        # right is verifiable.)
        for candidate in reversed(candidates):
            parsed = _parse_ip(candidate)
            if parsed is None:
                # Malformed entry inside the segment we would otherwise
                # trust — bail to the direct peer rather than guess.
                return direct_host
            if _ip_in_networks(parsed, self._trusted_proxy_networks):
                continue
            return str(parsed)

        # Whole chain was trusted proxies; nothing identifies an external
        # client, so attribute to the direct peer.
        return direct_host

    def _screen_ip(self, ip: Optional[ipaddress._BaseAddress]) -> FirewallDecision:
        if ip is None:
            return FirewallDecision(allowed=True)

        if self._blocked_networks and _ip_in_networks(ip, self._blocked_networks):
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.IP_BLOCKED,
                status_code=self.config.block_status_code,
                detail="Client IP blocked",
            )

        if self._allowed_networks and not _ip_in_networks(ip, self._allowed_networks):
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.IP_NOT_ALLOWED,
                status_code=self.config.block_status_code,
                detail="Client IP not allowed",
            )

        return FirewallDecision(allowed=True)

    def _screen_path(self, path: str) -> FirewallDecision:
        lowered = path.lower()

        for prefix in self.config.blocked_path_prefixes:
            if lowered.startswith(prefix.lower()):
                return FirewallDecision(
                    allowed=False,
                    reason=BlockReason.PATH_BLOCKED,
                    status_code=self.config.block_status_code,
                    detail="Path blocked",
                )

        for token in self.config.blocked_path_contains:
            if token.lower() in lowered:
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
                status_code=self.config.block_status_code,
                detail="Header budget exceeded",
            )

        content_length_values = headers.get("content-length") or []
        if len(content_length_values) > 1:
            unique_values = {value.strip() for value in content_length_values}
            if len(unique_values) > 1:
                return FirewallDecision(
                    allowed=False,
                    reason=BlockReason.DUPLICATE_CONTENT_LENGTH,
                    status_code=400,
                    detail="Duplicate Content-Length headers",
                )

        return FirewallDecision(allowed=True)

    def _screen_content_length(
        self,
        scope: Mapping[str, Any],
        headers: Mapping[str, list[str]],
    ) -> FirewallDecision:
        method = str(scope.get("method") or "GET").upper()
        content_length = _first_header(headers, "content-length")

        if content_length is None:
            if method in {m.upper() for m in self.config.require_content_length_for_methods}:
                return FirewallDecision(
                    allowed=False,
                    reason=BlockReason.CONTENT_LENGTH_MISSING,
                    status_code=411,
                    detail="Content-Length required",
                )
            return FirewallDecision(allowed=True)

        try:
            length = int(content_length.strip())
        except Exception:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.CONTENT_LENGTH_INVALID,
                status_code=400,
                detail="Invalid Content-Length",
            )

        if length < 0:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.CONTENT_LENGTH_INVALID,
                status_code=400,
                detail="Invalid Content-Length",
            )

        if length > self.config.max_content_length_bytes:
            return FirewallDecision(
                allowed=False,
                reason=BlockReason.CONTENT_LENGTH_TOO_LARGE,
                status_code=413,
                detail="Payload too large",
            )

        return FirewallDecision(allowed=True)

    def _attach_state(self, scope: MutableMapping[str, Any], decision: FirewallDecision) -> None:
        headers = _headers_to_mapping(scope.get("headers") or [])
        client_ip = self._resolve_client_ip(scope, headers)

        state = scope.setdefault("state", {})
        if not isinstance(state, dict):
            state = {}
            scope["state"] = state

        state["s43_firewall_allowed"] = decision.allowed
        state["s43_firewall_reason"] = decision.reason.value if decision.reason else None
        state["s43_client_ip"] = client_ip

    def _security_headers(self) -> list[tuple[bytes, bytes]]:
        return [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"x-sentinel-firewall", b"active"),
        ]

    async def _send_http_block(self, send: Send, decision: FirewallDecision) -> None:
        body_payload: dict[str, Any] = {
            "error": "request_blocked",
            "detail": decision.detail,
        }

        if self.config.include_block_reason and decision.reason is not None:
            body_payload["reason"] = decision.reason.value

        body = _json_body(body_payload)

        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"x-sentinel-firewall", b"blocked"),
        ]

        if self.config.add_security_headers:
            headers.extend(self._security_headers())

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

    async def _dispatch_monitoring(
        self,
        scope: Mapping[str, Any],
        decision: FirewallDecision,
    ) -> None:
        if not self.config.monitoring_enabled:
            return

        manager = self.monitoring_manager
        if manager is None:
            return

        reason = decision.reason.value if decision.reason else "unknown"
        headers = _headers_to_mapping(scope.get("headers") or [])
        client_ip = self._resolve_client_ip(scope, headers)

        event = {
            "kind": "security",
            "source": self.config.monitoring_source,
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
                "client_ip": client_ip,
                "timestamp": time.time(),
            },
            "metadata": {
                "firewall": "SentinelFirewall",
                "reason": reason,
            },
        }

        try:
            result = manager.analyze_event(event, source_ip=client_ip)
            if inspect.isawaitable(result):
                await result
        except TypeError:
            try:
                result = manager.analyze_event(event)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.debug("Firewall monitoring dispatch failed", exc_info=True)
        except Exception:
            logger.debug("Firewall monitoring dispatch failed", exc_info=True)


__all__ = [
    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",
]
