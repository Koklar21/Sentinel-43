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
v1.2.0 — Pure ASGI Firewall + Hardened Reporting Path

FastAPI / Starlette middleware that sits in front of every HTTP route and enforces:

  - Pure ASGI request handling, avoiding BaseHTTPMiddleware overhead.
  - Exact IP and CIDR allowlist/blocklist with startup pre-compilation.
  - Trusted-proxy-only X-Forwarded-For handling.
  - Per-IP sliding-window rate limiting.
  - Request Content-Length limits before body read.
  - Optional rejection of body methods that omit Content-Length.
  - Header budget checks using raw ASGI header bytes.
  - Path length, exact path, and prefix path blocking.
  - Request scope state injection for downstream handlers.
  - Optional response header injection.
  - Bounded monitoring queue with a single worker thread.
  - Thread-safe operational counters.

Mounting on an existing S43 FastAPI app:

    from core.middleware.sentinel_firewall import SentinelFirewall, FirewallConfig

    firewall_cfg = FirewallConfig.from_env()
    app.add_middleware(
        SentinelFirewall,
        config=firewall_cfg,
        monitoring_manager=mm,
    )

The middleware runs before routing, so blocked requests never reach handlers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, MutableMapping, Optional, Sequence

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("SentinelFirewall")


# =============================================================================
# Utilities
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False

    logger.warning("Invalid bool for %s=%r, using default %s", name, raw, default)
    return default


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = int(raw.strip())
        if not lo <= value <= hi:
            raise ValueError(f"out of [{lo},{hi}]")
        return value
    except ValueError:
        logger.warning("Invalid int for %s=%r, using default %s", name, raw, default)
        return default


def _env_float(
    name: str,
    default: float,
    lo: float | None = None,
    hi: float | None = None,
) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = float(raw.strip())
        if lo is not None and value < lo:
            raise ValueError(f"below minimum {lo}")
        if hi is not None and value > hi:
            raise ValueError(f"above maximum {hi}")
        return value
    except ValueError:
        logger.warning("Invalid float for %s=%r, using default %s", name, raw, default)
        return default


def _env_set(name: str) -> frozenset[str]:
    """
    Parse a comma-separated env var into a frozenset of stripped strings.
    Empty input returns frozenset().
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return frozenset()

    return frozenset(item.strip() for item in raw.split(",") if item.strip())


def _safe_ip_address(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _compile_ip_entries(
    entries: Iterable[str],
    *,
    label: str,
) -> tuple[frozenset[ipaddress._BaseAddress], tuple[ipaddress._BaseNetwork, ...]]:
    """
    Compile exact IPs and CIDR ranges once at startup.

    Exact IPs become a frozenset for O(1) lookup. CIDRs become a tuple of
    network objects. We still scan CIDRs linearly because Python stdlib has no
    built-in prefix trie, and pulling one in for beta would be very on-brand for
    overengineering a toaster.
    """
    exact: set[ipaddress._BaseAddress] = set()
    networks: list[ipaddress._BaseNetwork] = []

    for raw_entry in entries:
        entry = raw_entry.strip()
        if not entry:
            continue

        try:
            if "/" in entry:
                networks.append(ipaddress.ip_network(entry, strict=False))
            else:
                exact.add(ipaddress.ip_address(entry))
        except ValueError:
            logger.warning("Invalid %s IP/CIDR entry ignored: %r", label, entry)

    return frozenset(exact), tuple(networks)


def _ip_matches_compiled(
    ip_value: str,
    exact_ips: frozenset[ipaddress._BaseAddress],
    networks: Sequence[ipaddress._BaseNetwork],
) -> bool:
    ip_obj = _safe_ip_address(ip_value)
    if ip_obj is None:
        return False

    if ip_obj in exact_ips:
        return True

    return any(ip_obj in network for network in networks)


def _get_header(headers: Sequence[tuple[bytes, bytes]], name: bytes) -> str:
    """
    Return the first matching HTTP header decoded as latin-1.

    ASGI headers are lowercase-preserving bytes. We compare lowercased bytes and
    decode only the one we need. This avoids building Starlette Request objects
    just to ask them the same question while pretending allocations are free.
    """
    wanted = name.lower()
    for key, value in headers:
        if key.lower() == wanted:
            return value.decode("latin-1", errors="ignore").strip()
    return ""


def _append_response_headers(message: Message, extra_headers: list[tuple[bytes, bytes]]) -> Message:
    if message.get("type") != "http.response.start":
        return message

    headers = list(message.get("headers", []))
    headers.extend(extra_headers)
    message["headers"] = headers
    return message


# =============================================================================
# Configuration
# =============================================================================

@dataclass(frozen=True)
class FirewallConfig:
    """
    Immutable firewall configuration.

    IP filtering:
      allowed_ips:
        If not None, only matching exact IPs/CIDRs are admitted.
        None means allow all unless blocked.

      blocked_ips:
        Always rejected, regardless of allowlist.

    Rate limiting:
      rate_limit_per_window:
        Max requests per client per sliding window.

      rate_window_seconds:
        Sliding window length.

      rate_limit_burst:
        Extra allowance above the base limit.

    Payload:
      max_request_bytes:
        Requests whose Content-Length exceeds this are rejected before body read.
        0 disables this limit.

      require_content_length_for_body:
        When true, POST/PUT/PATCH requests without Content-Length are rejected.
        This blocks chunked-body bypasses unless an upstream proxy already handles
        body-size enforcement.

    Header budget:
      max_header_bytes:
        Approximate max total request header bytes. 0 disables this limit.

    Paths:
      blocked_paths:
        Exact path matches rejected.

      blocked_prefixes:
        Prefix path matches rejected.

      max_path_length:
        Rejects absurdly long paths before routing.

    Proxy trust:
      trusted_proxies:
        Exact IPs/CIDRs allowed to supply X-Forwarded-For.

    Monitoring:
      monitoring_queue_size:
        Max queued block reports. When full, reports are dropped instead of
        blocking request handling.

    Response:
      inject_response_headers:
        Adds S43 firewall metadata to successful downstream responses.
    """

    allowed_ips: frozenset[str] | None = None
    blocked_ips: frozenset[str] = field(default_factory=frozenset)

    rate_limit_per_window: int = 200
    rate_window_seconds: float = 60.0
    rate_limit_burst: int = 0

    max_request_bytes: int = 65_536
    require_content_length_for_body: bool = True
    body_methods: frozenset[str] = field(default_factory=lambda: frozenset({"POST", "PUT", "PATCH"}))

    max_header_bytes: int = 32_768

    blocked_paths: frozenset[str] = field(default_factory=frozenset)
    blocked_prefixes: frozenset[str] = field(default_factory=frozenset)
    max_path_length: int = 2_048

    trusted_proxies: frozenset[str] = field(default_factory=frozenset)

    gc_every_n_requests: int = 500
    monitoring_queue_size: int = 1_000
    inject_response_headers: bool = False

    # Compiled fields are derived in __post_init__.
    _allowed_exact_ips: frozenset[ipaddress._BaseAddress] = field(init=False, repr=False)
    _allowed_networks: tuple[ipaddress._BaseNetwork, ...] = field(init=False, repr=False)
    _blocked_exact_ips: frozenset[ipaddress._BaseAddress] = field(init=False, repr=False)
    _blocked_networks: tuple[ipaddress._BaseNetwork, ...] = field(init=False, repr=False)
    _trusted_proxy_exact_ips: frozenset[ipaddress._BaseAddress] = field(init=False, repr=False)
    _trusted_proxy_networks: tuple[ipaddress._BaseNetwork, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.allowed_ips is not None:
            object.__setattr__(self, "allowed_ips", frozenset(self.allowed_ips))

        object.__setattr__(self, "blocked_ips", frozenset(self.blocked_ips))
        object.__setattr__(self, "blocked_paths", frozenset(self.blocked_paths))
        object.__setattr__(self, "blocked_prefixes", frozenset(self.blocked_prefixes))
        object.__setattr__(self, "trusted_proxies", frozenset(self.trusted_proxies))
        object.__setattr__(self, "body_methods", frozenset(m.upper() for m in self.body_methods))

        if self.rate_limit_per_window < 1:
            raise ValueError("rate_limit_per_window must be >= 1")

        if self.rate_window_seconds <= 0:
            raise ValueError("rate_window_seconds must be > 0")

        if self.rate_limit_burst < 0:
            raise ValueError("rate_limit_burst must be >= 0")

        if self.max_request_bytes < 0:
            raise ValueError("max_request_bytes must be >= 0")

        if self.max_header_bytes < 0:
            raise ValueError("max_header_bytes must be >= 0")

        if self.max_path_length < 1:
            raise ValueError("max_path_length must be >= 1")

        if self.gc_every_n_requests < 1:
            raise ValueError("gc_every_n_requests must be >= 1")

        if self.monitoring_queue_size < 1:
            raise ValueError("monitoring_queue_size must be >= 1")

        allowed_exact, allowed_networks = _compile_ip_entries(
            self.allowed_ips or frozenset(),
            label="allowed_ips",
        )
        blocked_exact, blocked_networks = _compile_ip_entries(
            self.blocked_ips,
            label="blocked_ips",
        )
        trusted_exact, trusted_networks = _compile_ip_entries(
            self.trusted_proxies,
            label="trusted_proxies",
        )

        object.__setattr__(self, "_allowed_exact_ips", allowed_exact)
        object.__setattr__(self, "_allowed_networks", allowed_networks)
        object.__setattr__(self, "_blocked_exact_ips", blocked_exact)
        object.__setattr__(self, "_blocked_networks", blocked_networks)
        object.__setattr__(self, "_trusted_proxy_exact_ips", trusted_exact)
        object.__setattr__(self, "_trusted_proxy_networks", trusted_networks)

    @classmethod
    def from_env(cls) -> "FirewallConfig":
        """
        Build a FirewallConfig from environment variables.

        S43_FIREWALL_ALLOWED_IPS
            Comma-separated exact IPs/CIDRs. Empty = allow all.

        S43_FIREWALL_BLOCKED_IPS
            Comma-separated exact IPs/CIDRs.

        S43_FIREWALL_RATE_LIMIT
            Requests per window. Default: 200.

        S43_FIREWALL_RATE_WINDOW
            Window seconds. Default: 60.

        S43_FIREWALL_RATE_BURST
            Additional burst allowance. Default: 0.

        S43_FIREWALL_MAX_BYTES
            Max Content-Length in bytes. Default: 65536. 0 disables.

        S43_FIREWALL_REQUIRE_CONTENT_LENGTH
            Reject body methods missing Content-Length. Default: true.

        S43_FIREWALL_MAX_HEADER_BYTES
            Approximate max total header bytes. Default: 32768. 0 disables.

        S43_FIREWALL_BLOCKED_PATHS
            Comma-separated exact path blocklist.

        S43_FIREWALL_BLOCKED_PREFIXES
            Comma-separated path prefix blocklist.

        S43_FIREWALL_MAX_PATH_LENGTH
            Maximum request path length. Default: 2048.

        S43_FIREWALL_TRUSTED_PROXIES
            Comma-separated exact IPs/CIDRs trusted for X-Forwarded-For.

        S43_FIREWALL_GC_EVERY
            Rate-limit GC interval. Default: 500.

        S43_FIREWALL_MONITORING_QUEUE_SIZE
            Max queued block reports. Default: 1000.

        S43_FIREWALL_INJECT_RESPONSE_HEADERS
            Adds S43 response headers on allowed requests. Default: false.
        """
        allowed_raw = _env_set("S43_FIREWALL_ALLOWED_IPS")

        return cls(
            allowed_ips=allowed_raw if allowed_raw else None,
            blocked_ips=_env_set("S43_FIREWALL_BLOCKED_IPS"),
            rate_limit_per_window=_env_int("S43_FIREWALL_RATE_LIMIT", 200, 1, 100_000),
            rate_window_seconds=_env_float("S43_FIREWALL_RATE_WINDOW", 60.0, lo=0.1, hi=86_400.0),
            rate_limit_burst=_env_int("S43_FIREWALL_RATE_BURST", 0, 0, 10_000),
            max_request_bytes=_env_int("S43_FIREWALL_MAX_BYTES", 65_536, 0, 100 * 1024 * 1024),
            require_content_length_for_body=_env_bool("S43_FIREWALL_REQUIRE_CONTENT_LENGTH", True),
            max_header_bytes=_env_int("S43_FIREWALL_MAX_HEADER_BYTES", 32_768, 0, 1024 * 1024),
            blocked_paths=_env_set("S43_FIREWALL_BLOCKED_PATHS"),
            blocked_prefixes=_env_set("S43_FIREWALL_BLOCKED_PREFIXES"),
            max_path_length=_env_int("S43_FIREWALL_MAX_PATH_LENGTH", 2_048, 128, 32_768),
            trusted_proxies=_env_set("S43_FIREWALL_TRUSTED_PROXIES"),
            gc_every_n_requests=_env_int("S43_FIREWALL_GC_EVERY", 500, 10, 100_000),
            monitoring_queue_size=_env_int("S43_FIREWALL_MONITORING_QUEUE_SIZE", 1_000, 1, 100_000),
            inject_response_headers=_env_bool("S43_FIREWALL_INJECT_RESPONSE_HEADERS", False),
        )


# =============================================================================
# Block reasons
# =============================================================================

class BlockReason:
    IP_BLOCKED = "ip_blocked"
    IP_NOT_ALLOWED = "ip_not_in_allowlist"
    RATE_LIMITED = "rate_limited"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    CONTENT_LENGTH_REQUIRED = "content_length_required"
    CONTENT_LENGTH_INVALID = "content_length_invalid"
    PATH_BLOCKED = "path_blocked"
    PATH_TOO_LONG = "path_too_long"
    HEADERS_TOO_LARGE = "headers_too_large"


# =============================================================================
# SentinelFirewall ASGI middleware
# =============================================================================

class SentinelFirewall:
    """
    Pure ASGI application-layer firewall for Sentinel-43.

    This intentionally avoids BaseHTTPMiddleware. It reads only the ASGI scope
    and headers before deciding whether to drop a request, so blocked requests
    never construct a Starlette Request and never hit route handlers.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: FirewallConfig,
        *,
        monitoring_manager: Optional[Any] = None,
    ) -> None:
        self.app = app
        self._config = config
        self._monitoring_manager = monitoring_manager

        self._rate_tracker: dict[str, deque[float]] = {}
        self._rate_lock = threading.Lock()

        self._stats_lock = threading.Lock()
        self._total_requests = 0
        self._blocked_count = 0
        self._gc_counter = 0
        self._dropped_report_count = 0
        self._reported_block_count = 0

        self._report_queue: queue.Queue[dict[str, Any] | None] = queue.Queue(
            maxsize=config.monitoring_queue_size
        )
        self._reporter_stop = threading.Event()
        self._reporter_thread: threading.Thread | None = None

        if monitoring_manager is not None:
            self._reporter_thread = threading.Thread(
                target=self._report_worker,
                name="s43-firewall-reporter",
                daemon=True,
            )
            self._reporter_thread.start()

        logger.info(
            "SentinelFirewall initialized: rate_limit=%d/%ss max_bytes=%d "
            "allowed_ips=%s blocked_ips=%d blocked_paths=%d trusted_proxies=%d "
            "monitoring_queue=%d pure_asgi=true",
            config.rate_limit_per_window,
            config.rate_window_seconds,
            config.max_request_bytes,
            "all" if config.allowed_ips is None else len(config.allowed_ips),
            len(config.blocked_ips),
            len(config.blocked_paths) + len(config.blocked_prefixes),
            len(config.trusted_proxies),
            config.monitoring_queue_size,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """
        Stop the reporting worker.

        Starlette does not automatically call middleware close hooks, so call
        this from app shutdown if you want a tidy local dev teardown. Daemon
        worker still exits with the process if humans forget, as tradition
        demands.
        """
        self._reporter_stop.set()
        if self._reporter_thread is not None:
            try:
                self._report_queue.put_nowait(None)
            except queue.Full:
                pass
            self._reporter_thread.join(timeout=2.0)

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    def _inc_total(self) -> None:
        with self._stats_lock:
            self._total_requests += 1

    def _inc_blocked(self) -> None:
        with self._stats_lock:
            self._blocked_count += 1

    def _inc_dropped_report(self) -> None:
        with self._stats_lock:
            self._dropped_report_count += 1

    def _inc_reported_block(self) -> None:
        with self._stats_lock:
            self._reported_block_count += 1

    # ------------------------------------------------------------------
    # IP extraction
    # ------------------------------------------------------------------

    def _peer_ip(self, scope: Scope) -> str:
        client = scope.get("client")
        if not client:
            return "unknown"

        try:
            return str(client[0] or "unknown")
        except Exception:
            return "unknown"

    def _is_trusted_proxy(self, immediate_ip: str) -> bool:
        return _ip_matches_compiled(
            immediate_ip,
            self._config._trusted_proxy_exact_ips,
            self._config._trusted_proxy_networks,
        )

    def _extract_client_ip(self, scope: Scope, headers: Sequence[tuple[bytes, bytes]]) -> str:
        """
        Extract the client IP from ASGI scope.

        X-Forwarded-For is trusted only when the immediate upstream peer is in
        trusted_proxies. Untrusted callers can type fake XFF headers all day.
        The firewall remains unimpressed.
        """
        immediate_ip = self._peer_ip(scope)
        forwarded_for = _get_header(headers, b"x-forwarded-for")

        if not forwarded_for:
            return immediate_ip

        if not self._is_trusted_proxy(immediate_ip):
            return immediate_ip

        first = forwarded_for.split(",")[0].strip()

        if _safe_ip_address(first) is None:
            logger.warning(
                "Firewall: invalid X-Forwarded-For from trusted proxy=%s value=%r",
                immediate_ip,
                forwarded_for[:200],
            )
            return immediate_ip

        return first

    # ------------------------------------------------------------------
    # IP filtering
    # ------------------------------------------------------------------

    def _is_blocked_ip(self, ip_value: str) -> bool:
        return _ip_matches_compiled(
            ip_value,
            self._config._blocked_exact_ips,
            self._config._blocked_networks,
        )

    def _is_allowed_ip(self, ip_value: str) -> bool:
        config = self._config

        if self._is_blocked_ip(ip_value):
            return False

        if config.allowed_ips is None:
            return True

        return _ip_matches_compiled(
            ip_value,
            config._allowed_exact_ips,
            config._allowed_networks,
        )

    def _ip_block_reason(self, ip_value: str) -> str:
        if self._is_blocked_ip(ip_value):
            return BlockReason.IP_BLOCKED
        return BlockReason.IP_NOT_ALLOWED

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _check_rate_limit(self, ip_value: str) -> bool:
        """
        Atomic check-and-record using a sliding window.
        """
        config = self._config
        now = time.monotonic()
        cutoff = now - config.rate_window_seconds
        limit = config.rate_limit_per_window + config.rate_limit_burst

        with self._rate_lock:
            window = self._rate_tracker.setdefault(ip_value, deque())

            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= limit:
                return False

            window.append(now)

            self._gc_counter += 1
            if self._gc_counter >= config.gc_every_n_requests:
                self._gc_counter = 0
                self._gc_rate_tracker_locked(cutoff)

            return True

    def _gc_rate_tracker_locked(self, cutoff: float) -> None:
        stale = [
            client_id
            for client_id, window in self._rate_tracker.items()
            if not window or window[-1] < cutoff
        ]

        for client_id in stale:
            self._rate_tracker.pop(client_id, None)

    # ------------------------------------------------------------------
    # Path filtering
    # ------------------------------------------------------------------

    def _is_path_too_long(self, path: str) -> bool:
        return len(path) > self._config.max_path_length

    def _is_path_blocked(self, path: str) -> bool:
        config = self._config

        if path in config.blocked_paths:
            return True

        return any(path.startswith(prefix) for prefix in config.blocked_prefixes)

    # ------------------------------------------------------------------
    # Header / payload checks
    # ------------------------------------------------------------------

    def _headers_too_large(self, headers: Sequence[tuple[bytes, bytes]]) -> bool:
        if self._config.max_header_bytes <= 0:
            return False

        total = 0
        for key, value in headers:
            total += len(key) + len(value)
            if total > self._config.max_header_bytes:
                return True

        return False

    def _payload_block_reason(
        self,
        method: str,
        headers: Sequence[tuple[bytes, bytes]],
    ) -> str | None:
        """
        Return a BlockReason if the payload should be blocked, else None.

        This uses Content-Length only. If chunked uploads are allowed directly to
        the app, enforce streaming body limits upstream. This middleware rejects
        body methods without Content-Length by default because letting unknown
        body sizes wander in is not security, it is hope with a badge.
        """
        config = self._config

        if config.max_request_bytes <= 0 and not config.require_content_length_for_body:
            return None

        method = method.upper()
        raw = _get_header(headers, b"content-length")

        if not raw:
            if config.require_content_length_for_body and method in config.body_methods:
                return BlockReason.CONTENT_LENGTH_REQUIRED
            return None

        try:
            value = int(raw)
        except ValueError:
            return BlockReason.CONTENT_LENGTH_INVALID

        if value < 0:
            return BlockReason.CONTENT_LENGTH_INVALID

        if config.max_request_bytes > 0 and value > config.max_request_bytes:
            return BlockReason.PAYLOAD_TOO_LARGE

        return None

    # ------------------------------------------------------------------
    # Monitoring integration
    # ------------------------------------------------------------------

    def _report_worker(self) -> None:
        manager = self._monitoring_manager
        if manager is None:
            return

        while not self._reporter_stop.is_set():
            try:
                event = self._report_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if event is None:
                self._report_queue.task_done()
                return

            try:
                manager.analyze_event(event)
                self._inc_reported_block()
            except Exception as exc:
                logger.debug("Firewall: MonitoringManager notification failed: %s", exc)
            finally:
                self._report_queue.task_done()

    def _report_block(
        self,
        reason: str,
        client_ip: str,
        path: str,
    ) -> None:
        """
        Queue a firewall block event for the monitoring pipeline.

        This never blocks the request path. If the queue is full, the event is
        dropped and counted. The firewall protects the application first; it is
        not here to lovingly journal every troll with a loop and a dream.
        """
        if self._monitoring_manager is None:
            return

        event: dict[str, Any] = {
            "kind": "security",
            "auth_failure": reason in {BlockReason.IP_BLOCKED, BlockReason.IP_NOT_ALLOWED},
            "rate_limited": reason == BlockReason.RATE_LIMITED,
            "firewall_block": reason,
            "source_ip": client_ip,
            "path": path,
            "timestamp": utc_now(),
        }

        try:
            self._report_queue.put_nowait(event)
        except queue.Full:
            self._inc_dropped_report()
            logger.debug(
                "Firewall: monitoring report queue full; dropped block report reason=%s ip=%s path=%s",
                reason,
                client_ip,
                path,
            )

    # ------------------------------------------------------------------
    # ASGI response helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _send_block_response(
        send: Send,
        http_status: int,
        reason: str,
        code: str,
        *,
        retry_after: int | None = None,
    ) -> None:
        body = json.dumps({"error": reason, "code": code}).encode("utf-8")

        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
            (b"x-s43-firewall", b"blocked"),
            (b"x-s43-block-code", code.encode("ascii", errors="ignore")),
        ]

        if retry_after is not None:
            headers.append((b"retry-after", str(max(1, retry_after)).encode("ascii")))

        await send(
            {
                "type": "http.response.start",
                "status": http_status,
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

    # ------------------------------------------------------------------
    # Middleware entrypoint
    # ------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        self._inc_total()

        headers: Sequence[tuple[bytes, bytes]] = scope.get("headers", [])
        method = str(scope.get("method", "GET")).upper()
        path = str(scope.get("path", "/"))
        client_ip = self._extract_client_ip(scope, headers)

        # ---- Path length check ----
        if self._is_path_too_long(path):
            self._inc_blocked()
            logger.warning("Firewall: path too long ip=%s path_len=%d", client_ip, len(path))
            self._report_block(BlockReason.PATH_TOO_LONG, client_ip, path)
            await self._send_block_response(send, 414, "URI Too Long", "PATH_TOO_LONG")
            return

        # ---- Header budget check ----
        if self._headers_too_large(headers):
            self._inc_blocked()
            logger.warning("Firewall: headers too large ip=%s path=%s", client_ip, path)
            self._report_block(BlockReason.HEADERS_TOO_LARGE, client_ip, path)
            await self._send_block_response(
                send,
                431,
                "Request Header Fields Too Large",
                "HEADERS_TOO_LARGE",
            )
            return

        # ---- IP check ----
        if not self._is_allowed_ip(client_ip):
            self._inc_blocked()
            reason = self._ip_block_reason(client_ip)
            logger.warning(
                "Firewall: IP blocked ip=%s path=%s reason=%s",
                client_ip,
                path,
                reason,
            )
            self._report_block(reason, client_ip, path)
            await self._send_block_response(send, 403, "Forbidden", reason.upper())
            return

        # ---- Path block check ----
        if self._is_path_blocked(path):
            self._inc_blocked()
            logger.warning("Firewall: path blocked ip=%s path=%s", client_ip, path)
            self._report_block(BlockReason.PATH_BLOCKED, client_ip, path)
            await self._send_block_response(send, 403, "Forbidden", "PATH_BLOCKED")
            return

        # ---- Payload check ----
        payload_reason = self._payload_block_reason(method, headers)
        if payload_reason is not None:
            self._inc_blocked()

            if payload_reason == BlockReason.PAYLOAD_TOO_LARGE:
                status_code = 413
                error = "Payload Too Large"
            elif payload_reason == BlockReason.CONTENT_LENGTH_REQUIRED:
                status_code = 411
                error = "Length Required"
            else:
                status_code = 400
                error = "Invalid Content-Length"

            logger.warning(
                "Firewall: payload blocked ip=%s path=%s reason=%s content-length=%s",
                client_ip,
                path,
                payload_reason,
                _get_header(headers, b"content-length"),
            )

            self._report_block(payload_reason, client_ip, path)
            await self._send_block_response(send, status_code, error, payload_reason.upper())
            return

        # ---- Rate limit ----
        if not self._check_rate_limit(client_ip):
            self._inc_blocked()
            retry_after = int(max(1.0, self._config.rate_window_seconds))
            logger.warning("Firewall: rate limited ip=%s path=%s", client_ip, path)
            self._report_block(BlockReason.RATE_LIMITED, client_ip, path)
            await self._send_block_response(
                send,
                429,
                "Too Many Requests",
                "RATE_LIMITED",
                retry_after=retry_after,
            )
            return

        # ---- Downstream state injection ----
        # Starlette Request.state is backed by scope["state"], so this remains
        # compatible with downstream handlers reading request.state.s43_client_ip.
        state = scope.setdefault("state", {})
        if isinstance(state, MutableMapping):
            state["s43_client_ip"] = client_ip
            state["s43_firewall_passed"] = True

        # ---- Optional response header injection ----
        if not self._config.inject_response_headers:
            await self.app(scope, receive, send)
            return

        extra_headers = [
            (b"x-s43-firewall", b"passed"),
            (b"x-s43-client-ip", client_ip.encode("latin-1", errors="ignore")),
        ]

        async def send_with_headers(message: Message) -> None:
            await send(_append_response_headers(message, extra_headers))

        await self.app(scope, receive, send_with_headers)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        with self._rate_lock:
            tracked_ips = len(self._rate_tracker)

        with self._stats_lock:
            total_requests = self._total_requests
            blocked_count = self._blocked_count
            dropped_report_count = self._dropped_report_count
            reported_block_count = self._reported_block_count

        return {
            "total_requests": total_requests,
            "blocked_count": blocked_count,
            "block_rate_percent": round(
                100 * blocked_count / max(1, total_requests),
                2,
            ),
            "tracked_ips": tracked_ips,
            "reported_block_count": reported_block_count,
            "dropped_report_count": dropped_report_count,
            "monitoring_queue_size": self._report_queue.qsize(),
            "config": {
                "rate_limit_per_window": self._config.rate_limit_per_window,
                "rate_window_seconds": self._config.rate_window_seconds,
                "rate_limit_burst": self._config.rate_limit_burst,
                "max_request_bytes": self._config.max_request_bytes,
                "require_content_length_for_body": self._config.require_content_length_for_body,
                "max_header_bytes": self._config.max_header_bytes,
                "max_path_length": self._config.max_path_length,
                "allowed_ips": (
                    list(self._config.allowed_ips)
                    if self._config.allowed_ips is not None
                    else "all"
                ),
                "blocked_ips_count": len(self._config.blocked_ips),
                "blocked_paths_count": (
                    len(self._config.blocked_paths)
                    + len(self._config.blocked_prefixes)
                ),
                "trusted_proxies_count": len(self._config.trusted_proxies),
                "monitoring_queue_capacity": self._config.monitoring_queue_size,
                "inject_response_headers": self._config.inject_response_headers,
                "pure_asgi": True,
            },
            "timestamp": utc_now(),
        }


__all__ = [
    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",
]
