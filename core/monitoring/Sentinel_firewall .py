```python id="yorzw1"
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
v1.1.0

FastAPI / Starlette middleware that sits in front of every route and enforces:

  - IP allowlist / blocklist with exact IP and CIDR support.
  - Trusted-proxy-only X-Forwarded-For handling.
  - Per-IP sliding-window rate limiting.
  - Request Content-Length limits before body read.
  - Optional rejection of body methods that omit Content-Length.
  - Header budget checks.
  - Path length, exact path, and prefix path blocking.
  - Request state injection for downstream handlers.
  - Optional response header injection.
  - Best-effort MonitoringManager security events.
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

import ipaddress
import json
import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

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


def _env_float(name: str, default: float, lo: float | None = None, hi: float | None = None) -> float:
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


def _entry_matches_ip(entry: str, ip_value: str) -> bool:
    """
    Match an IP against either:
      - exact IP string
      - CIDR network string

    Invalid entries do not match. This avoids DNS lookups and other nonsense
    humans eventually regret.
    """
    entry = entry.strip()
    if not entry:
        return False

    ip_obj = _safe_ip_address(ip_value)
    if ip_obj is None:
        return False

    try:
        if "/" in entry:
            return ip_obj in ipaddress.ip_network(entry, strict=False)
        return ip_obj == ipaddress.ip_address(entry)
    except ValueError:
        logger.warning("Invalid firewall IP/CIDR entry ignored: %r", entry)
        return False


def _any_entry_matches(entries: frozenset[str], ip_value: str) -> bool:
    return any(_entry_matches_ip(entry, ip_value) for entry in entries)


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
    inject_response_headers: bool = False

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
# SentinelFirewall middleware
# =============================================================================

class SentinelFirewall(BaseHTTPMiddleware):
    """
    Application-layer firewall middleware for Sentinel-43.
    """

    def __init__(
        self,
        app: ASGIApp,
        config: FirewallConfig,
        *,
        monitoring_manager: Optional[Any] = None,
    ) -> None:
        super().__init__(app)

        self._config = config
        self._monitoring_manager = monitoring_manager

        self._rate_tracker: dict[str, deque[float]] = {}
        self._rate_lock = threading.Lock()

        self._stats_lock = threading.Lock()
        self._total_requests = 0
        self._blocked_count = 0
        self._gc_counter = 0

        logger.info(
            "SentinelFirewall initialized: rate_limit=%d/%ss max_bytes=%d "
            "allowed_ips=%s blocked_ips=%d blocked_paths=%d trusted_proxies=%d",
            config.rate_limit_per_window,
            config.rate_window_seconds,
            config.max_request_bytes,
            "all" if config.allowed_ips is None else len(config.allowed_ips),
            len(config.blocked_ips),
            len(config.blocked_paths) + len(config.blocked_prefixes),
            len(config.trusted_proxies),
        )

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    def _inc_total(self) -> None:
        with self._stats_lock:
            self._total_requests += 1

    def _inc_blocked(self) -> None:
        with self._stats_lock:
            self._blocked_count += 1

    # ------------------------------------------------------------------
    # IP extraction
    # ------------------------------------------------------------------

    def _extract_client_ip(self, request: Request) -> str:
        """
        Extract the client IP.

        X-Forwarded-For is trusted only when the immediate upstream peer is in
        trusted_proxies. If the proxy is not trusted, forwarded headers are
        ignored. Because apparently anyone on the internet can type headers,
        which is shocking only if you just woke up from 1996.
        """
        if request.client is None:
            return "unknown"

        immediate_ip = request.client.host or "unknown"
        forwarded_for = request.headers.get("X-Forwarded-For", "").strip()

        if not forwarded_for:
            return immediate_ip

        if not _any_entry_matches(self._config.trusted_proxies, immediate_ip):
            return immediate_ip

        # RFC-style chain: first entry is original client.
        first = forwarded_for.split(",")[0].strip()

        # Reject garbage by falling back to immediate IP.
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

    def _is_ip_allowed(self, ip_value: str) -> bool:
        config = self._config

        if _any_entry_matches(config.blocked_ips, ip_value):
            return False

        if config.allowed_ips is not None and not _any_entry_matches(config.allowed_ips, ip_value):
            return False

        return True

    def _ip_block_reason(self, ip_value: str) -> str:
        if _any_entry_matches(self._config.blocked_ips, ip_value):
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

    def _headers_too_large(self, request: Request) -> bool:
        if self._config.max_header_bytes <= 0:
            return False

        total = 0
        for key, value in request.headers.items():
            total += len(key.encode("utf-8", errors="ignore"))
            total += len(value.encode("utf-8", errors="ignore"))

            if total > self._config.max_header_bytes:
                return True

        return False

    def _payload_block_reason(self, request: Request) -> str | None:
        """
        Return a BlockReason if the payload should be blocked, else None.

        This uses Content-Length only. If you allow chunked uploads directly to
        the app, enforce streaming body limits upstream or replace this with a
        lower-level ASGI receive wrapper. Pretending chunked bodies do not exist
        is how people accidentally host a landfill.
        """
        config = self._config

        if config.max_request_bytes <= 0 and not config.require_content_length_for_body:
            return None

        method = request.method.upper()
        raw = request.headers.get("content-length", "").strip()

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

    def _report_block(
        self,
        reason: str,
        client_ip: str,
        path: str,
    ) -> None:
        """
        Route a firewall block event to the monitoring pipeline.

        The try/except is inside the worker thread, not just around start(),
        because exceptions raised inside daemon threads do not get caught by the
        parent. Yes, another tiny Python bear trap.
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

        def _worker() -> None:
            try:
                self._monitoring_manager.analyze_event(event)
            except Exception as exc:
                logger.debug("Firewall: MonitoringManager notification failed: %s", exc)

        try:
            threading.Thread(target=_worker, daemon=True).start()
        except Exception as exc:
            logger.debug("Firewall: MonitoringManager thread start failed: %s", exc)

    # ------------------------------------------------------------------
    # Block response factory
    # ------------------------------------------------------------------

    @staticmethod
    def _block_response(
        http_status: int,
        reason: str,
        code: str,
        *,
        retry_after: int | None = None,
    ) -> Response:
        headers = {
            "Cache-Control": "no-store",
            "X-S43-Firewall": "blocked",
            "X-S43-Block-Code": code,
        }

        if retry_after is not None:
            headers["Retry-After"] = str(max(1, retry_after))

        return Response(
            content=json.dumps(
                {
                    "error": reason,
                    "code": code,
                }
            ),
            status_code=http_status,
            media_type="application/json",
            headers=headers,
        )

    # ------------------------------------------------------------------
    # Middleware dispatch
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        self._inc_total()

        client_ip = self._extract_client_ip(request)
        path = request.url.path

        # ---- Path length check ----
        if self._is_path_too_long(path):
            self._inc_blocked()
            logger.warning("Firewall: path too long ip=%s path_len=%d", client_ip, len(path))
            self._report_block(BlockReason.PATH_TOO_LONG, client_ip, path)
            return self._block_response(414, "URI Too Long", "PATH_TOO_LONG")

        # ---- Header budget check ----
        if self._headers_too_large(request):
            self._inc_blocked()
            logger.warning("Firewall: headers too large ip=%s path=%s", client_ip, path)
            self._report_block(BlockReason.HEADERS_TOO_LARGE, client_ip, path)
            return self._block_response(431, "Request Header Fields Too Large", "HEADERS_TOO_LARGE")

        # ---- IP check ----
        if not self._is_ip_allowed(client_ip):
            self._inc_blocked()
            reason = self._ip_block_reason(client_ip)
            logger.warning(
                "Firewall: IP blocked ip=%s path=%s reason=%s",
                client_ip,
                path,
                reason,
            )
            self._report_block(reason, client_ip, path)
            return self._block_response(403, "Forbidden", reason.upper())

        # ---- Path block check ----
        if self._is_path_blocked(path):
            self._inc_blocked()
            logger.warning("Firewall: path blocked ip=%s path=%s", client_ip, path)
            self._report_block(BlockReason.PATH_BLOCKED, client_ip, path)
            return self._block_response(403, "Forbidden", "PATH_BLOCKED")

        # ---- Payload check ----
        payload_reason = self._payload_block_reason(request)
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
                request.headers.get("content-length"),
            )

            self._report_block(payload_reason, client_ip, path)
            return self._block_response(status_code, error, payload_reason.upper())

        # ---- Rate limit ----
        if not self._check_rate_limit(client_ip):
            self._inc_blocked()
            retry_after = int(max(1.0, self._config.rate_window_seconds))
            logger.warning("Firewall: rate limited ip=%s path=%s", client_ip, path)
            self._report_block(BlockReason.RATE_LIMITED, client_ip, path)
            return self._block_response(
                429,
                "Too Many Requests",
                "RATE_LIMITED",
                retry_after=retry_after,
            )

        # ---- Downstream request state injection ----
        request.state.s43_client_ip = client_ip
        request.state.s43_firewall_passed = True

        response = await call_next(request)

        if self._config.inject_response_headers:
            response.headers["X-S43-Firewall"] = "passed"
            response.headers["X-S43-Client-IP"] = client_ip

        return response

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        with self._rate_lock:
            tracked_ips = len(self._rate_tracker)

        with self._stats_lock:
            total_requests = self._total_requests
            blocked_count = self._blocked_count

        return {
            "total_requests": total_requests,
            "blocked_count": blocked_count,
            "block_rate_percent": round(
                100 * blocked_count / max(1, total_requests),
                2,
            ),
            "tracked_ips": tracked_ips,
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
                "inject_response_headers": self._config.inject_response_headers,
            },
            "timestamp": utc_now(),
        }


__all__ = [
    "BlockReason",
    "FirewallConfig",
    "SentinelFirewall",
]
```
