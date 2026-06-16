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
v1.0.0

FastAPI / Starlette middleware that sits in front of every route and enforces:

  - IP allowlist / blocklist (configurable via env or at construction time)
  - Per-IP request rate limiting with sliding window + backoff tracking
  - Request size limits (Content-Length header inspection before body read)
  - Path-level blocking (exact and prefix match)
  - Optional header injection for downstream handlers (X-S43-Client-IP, etc.)

All blocked/rate-limited requests are reported, best-effort, to the S43
MonitoringManager (if wired) so they surface as SecurityEvents in the
Watchtower pipeline and accumulate in SentinelWindowStore for threat scoring.

Mounting on an existing S43 FastAPI app:

    from sentinel43.monitoring.sentinel_firewall import SentinelFirewall, FirewallConfig

    firewall_cfg = FirewallConfig.from_env()
    app.add_middleware(SentinelFirewall, config=firewall_cfg, monitoring_manager=mm)

The middleware runs before routing, so blocked requests never reach handlers.
"""

from __future__ import annotations

import asyncio
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


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(raw.strip())
        if not lo <= v <= hi:
            raise ValueError(f"out of [{lo},{hi}]")
        return v
    except ValueError:
        logger.warning("Invalid int for %s=%r, using default %s", name, raw, default)
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        logger.warning("Invalid float for %s=%r, using default %s", name, raw, default)
        return default


def _env_set(name: str) -> frozenset[str]:
    """Parse a comma-separated env var into a frozenset of stripped strings."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return frozenset()
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


# =============================================================================
# Configuration
# =============================================================================

@dataclass(frozen=True)
class FirewallConfig:
    """
    Immutable firewall configuration. Matches S43's frozen-dataclass pattern.

    IP filtering:
      allowed_ips: if not None, only listed IPs are admitted.
                   None = allow all (unless blocked).
      blocked_ips: always rejected, regardless of allowed_ips.

    Rate limiting:
      rate_limit_per_window: max requests per sliding window.
      rate_window_seconds: length of the sliding window.
      rate_limit_burst: additional one-time burst allowance above the limit.

    Payload:
      max_request_bytes: requests whose Content-Length exceeds this are
                         rejected before the body is read. 0 = no limit.

    Paths:
      blocked_paths: exact path matches that are always rejected.
      blocked_prefixes: path prefixes that are always rejected.

    Proxy trust:
      trusted_proxies: IPs from which X-Forwarded-For is trusted for
                       real-IP extraction (e.g. your load balancer).
    """
    # IP filtering
    allowed_ips: frozenset[str] | None = None
    blocked_ips: frozenset[str] = field(default_factory=frozenset)

    # Rate limiting
    rate_limit_per_window: int = 200
    rate_window_seconds: float = 60.0
    rate_limit_burst: int = 0

    # Payload limits
    max_request_bytes: int = 65_536

    # Path blocking
    blocked_paths: frozenset[str] = field(default_factory=frozenset)
    blocked_prefixes: frozenset[str] = field(default_factory=frozenset)

    # Proxy trust
    trusted_proxies: frozenset[str] = field(default_factory=frozenset)

    # GC: how often (in request count) to prune stale rate-limit entries
    gc_every_n_requests: int = 500

    def __post_init__(self) -> None:
        # Normalise all IP/path sets to frozenset regardless of what was passed
        if self.allowed_ips is not None:
            object.__setattr__(self, "allowed_ips", frozenset(self.allowed_ips))
        object.__setattr__(self, "blocked_ips", frozenset(self.blocked_ips))
        object.__setattr__(self, "blocked_paths", frozenset(self.blocked_paths))
        object.__setattr__(self, "blocked_prefixes", frozenset(self.blocked_prefixes))
        object.__setattr__(self, "trusted_proxies", frozenset(self.trusted_proxies))

        if self.rate_limit_per_window < 1:
            raise ValueError("rate_limit_per_window must be >= 1")
        if self.rate_window_seconds <= 0:
            raise ValueError("rate_window_seconds must be > 0")

    @classmethod
    def from_env(cls) -> "FirewallConfig":
        """
        Build a FirewallConfig from environment variables.

        S43_FIREWALL_ALLOWED_IPS   -- comma-separated IP allowlist (empty = allow all)
        S43_FIREWALL_BLOCKED_IPS   -- comma-separated IP blocklist
        S43_FIREWALL_RATE_LIMIT    -- requests per window (default 200)
        S43_FIREWALL_RATE_WINDOW   -- window in seconds (default 60)
        S43_FIREWALL_RATE_BURST    -- burst allowance (default 0)
        S43_FIREWALL_MAX_BYTES     -- max Content-Length in bytes (default 65536)
        S43_FIREWALL_BLOCKED_PATHS -- comma-separated exact path blocklist
        S43_FIREWALL_BLOCKED_PREFIXES -- comma-separated path prefix blocklist
        S43_FIREWALL_TRUSTED_PROXIES -- comma-separated trusted proxy IPs
        S43_FIREWALL_GC_EVERY      -- rate-limit GC interval (default 500)
        """
        allowed_raw = _env_set("S43_FIREWALL_ALLOWED_IPS")
        return cls(
            allowed_ips=allowed_raw if allowed_raw else None,
            blocked_ips=_env_set("S43_FIREWALL_BLOCKED_IPS"),
            rate_limit_per_window=_env_int("S43_FIREWALL_RATE_LIMIT", 200, 1, 100_000),
            rate_window_seconds=_env_float("S43_FIREWALL_RATE_WINDOW", 60.0),
            rate_limit_burst=_env_int("S43_FIREWALL_RATE_BURST", 0, 0, 10_000),
            max_request_bytes=_env_int("S43_FIREWALL_MAX_BYTES", 65_536, 0, 100 * 1024 * 1024),
            blocked_paths=_env_set("S43_FIREWALL_BLOCKED_PATHS"),
            blocked_prefixes=_env_set("S43_FIREWALL_BLOCKED_PREFIXES"),
            trusted_proxies=_env_set("S43_FIREWALL_TRUSTED_PROXIES"),
            gc_every_n_requests=_env_int("S43_FIREWALL_GC_EVERY", 500, 10, 100_000),
        )


# =============================================================================
# Block reasons
# =============================================================================

class BlockReason:
    IP_BLOCKED      = "ip_blocked"
    IP_NOT_ALLOWED  = "ip_not_in_allowlist"
    RATE_LIMITED    = "rate_limited"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    PATH_BLOCKED    = "path_blocked"


# =============================================================================
# SentinelFirewall middleware
# =============================================================================

class SentinelFirewall(BaseHTTPMiddleware):
    """
    Application-layer firewall middleware for Sentinel-43.

    Attach to any FastAPI / Starlette app with:
        app.add_middleware(
            SentinelFirewall,
            config=FirewallConfig.from_env(),
            monitoring_manager=mm,   # optional
        )

    All firewall decisions run before request bodies are read or handlers
    are dispatched, keeping the overhead minimal for blocked requests.
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

        # Rate limiting: ip -> deque of monotonic timestamps
        self._rate_tracker: dict[str, deque[float]] = {}
        self._rate_lock = threading.Lock()

        # Stats (non-critical -- no lock; counter drift under heavy concurrency
        # is acceptable for observability counters)
        self._total_requests = 0
        self._blocked_count = 0
        self._gc_counter = 0

        logger.info(
            "SentinelFirewall initialized: rate_limit=%d/%ds max_bytes=%d "
            "allowed_ips=%s blocked_ips=%d blocked_paths=%d",
            config.rate_limit_per_window,
            int(config.rate_window_seconds),
            config.max_request_bytes,
            "all" if config.allowed_ips is None else len(config.allowed_ips),
            len(config.blocked_ips),
            len(config.blocked_paths) + len(config.blocked_prefixes),
        )

    # ------------------------------------------------------------------
    # IP extraction
    # ------------------------------------------------------------------

    def _extract_client_ip(self, request: Request) -> str:
        """
        Extract the real client IP. Trusts X-Forwarded-For only when the
        immediate upstream (request.client.host) is a configured trusted proxy.
        This prevents untrusted callers from spoofing their IP by injecting
        X-Forwarded-For headers.
        """
        if request.client is None:
            return "unknown"

        immediate_ip = request.client.host

        forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
        if forwarded_for and immediate_ip in self._config.trusted_proxies:
            # First entry is the original client IP per RFC 7239
            return forwarded_for.split(",")[0].strip()

        return immediate_ip

    # ------------------------------------------------------------------
    # IP filtering
    # ------------------------------------------------------------------

    def _is_ip_allowed(self, ip: str) -> bool:
        config = self._config

        if ip in config.blocked_ips:
            return False

        if config.allowed_ips is not None and ip not in config.allowed_ips:
            return False

        return True

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _check_rate_limit(self, ip: str) -> bool:
        """
        Atomic check-and-record using a sliding window.
        Returns True if the request is within the rate limit.
        Includes periodic GC to prevent unbounded dict growth under IP churn
        (same issue fixed in remote_gateway.py _AUTH_FAILURES).
        """
        config = self._config
        now = time.monotonic()
        cutoff = now - config.rate_window_seconds
        limit = config.rate_limit_per_window + config.rate_limit_burst

        with self._rate_lock:
            window = self._rate_tracker.setdefault(ip, deque())

            # Prune expired entries
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= limit:
                return False

            window.append(now)

            # Periodic GC: remove clients with all-expired windows to
            # prevent unbounded dict growth when many distinct IPs appear
            # briefly and never return.
            self._gc_counter += 1
            if self._gc_counter >= self._config.gc_every_n_requests:
                self._gc_counter = 0
                stale = [
                    cid for cid, w in self._rate_tracker.items()
                    if not w or w[-1] < cutoff
                ]
                for cid in stale:
                    self._rate_tracker.pop(cid, None)

            return True

    # ------------------------------------------------------------------
    # Path filtering
    # ------------------------------------------------------------------

    def _is_path_blocked(self, path: str) -> bool:
        config = self._config

        if path in config.blocked_paths:
            return True

        for prefix in config.blocked_prefixes:
            if path.startswith(prefix):
                return True

        return False

    # ------------------------------------------------------------------
    # Payload size check
    # ------------------------------------------------------------------

    def _is_payload_too_large(self, request: Request) -> bool:
        if self._config.max_request_bytes <= 0:
            return False

        raw = request.headers.get("content-length", "").strip()
        if not raw:
            return False

        try:
            return int(raw) > self._config.max_request_bytes
        except ValueError:
            return False

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
        Runs on a daemon thread to avoid blocking the async request path.
        Best-effort: any exception is silently logged.
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
            import threading as _t
            _t.Thread(
                target=self._monitoring_manager.analyze_event,
                args=(event,),
                kwargs={"source_ip": client_ip},
                daemon=True,
            ).start()
        except Exception as exc:
            logger.debug("Firewall: MonitoringManager notification failed: %s", exc)

    # ------------------------------------------------------------------
    # Block response factory
    # ------------------------------------------------------------------

    @staticmethod
    def _block_response(http_status: int, reason: str, code: str) -> Response:
        return Response(
            content=json.dumps({"error": reason, "code": code}),
            status_code=http_status,
            media_type="application/json",
        )

    # ------------------------------------------------------------------
    # Middleware dispatch
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        self._total_requests += 1
        client_ip = self._extract_client_ip(request)
        path = request.url.path

        # ---- IP check ----
        if not self._is_ip_allowed(client_ip):
            self._blocked_count += 1
            reason = (
                BlockReason.IP_BLOCKED
                if client_ip in self._config.blocked_ips
                else BlockReason.IP_NOT_ALLOWED
            )
            logger.warning("Firewall: IP blocked ip=%s path=%s reason=%s", client_ip, path, reason)
            self._report_block(reason, client_ip, path)
            return self._block_response(403, "Forbidden", reason.upper())

        # ---- Path check ----
        if self._is_path_blocked(path):
            self._blocked_count += 1
            logger.warning("Firewall: path blocked ip=%s path=%s", client_ip, path)
            self._report_block(BlockReason.PATH_BLOCKED, client_ip, path)
            return self._block_response(403, "Forbidden", "PATH_BLOCKED")

        # ---- Payload size check ----
        if self._is_payload_too_large(request):
            self._blocked_count += 1
            logger.warning(
                "Firewall: payload too large ip=%s path=%s content-length=%s",
                client_ip, path, request.headers.get("content-length"),
            )
            self._report_block(BlockReason.PAYLOAD_TOO_LARGE, client_ip, path)
            return self._block_response(413, "Payload Too Large", "PAYLOAD_TOO_LARGE")

        # ---- Rate limit ----
        if not self._check_rate_limit(client_ip):
            self._blocked_count += 1
            logger.warning("Firewall: rate limited ip=%s path=%s", client_ip, path)
            self._report_block(BlockReason.RATE_LIMITED, client_ip, path)
            return self._block_response(429, "Too Many Requests", "RATE_LIMITED")

        # ---- Inject S43 headers for downstream handlers ----
        # These are added to the request scope (not the response) so handlers
        # can read the resolved client IP without re-parsing proxy headers.
        request.state.s43_client_ip = client_ip
        request.state.s43_firewall_passed = True

        return await call_next(request)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        with self._rate_lock:
            tracked_ips = len(self._rate_tracker)

        return {
            "total_requests": self._total_requests,
            "blocked_count": self._blocked_count,
            "block_rate_percent": round(
                100 * self._blocked_count / max(1, self._total_requests), 2
            ),
            "tracked_ips": tracked_ips,
            "config": {
                "rate_limit_per_window": self._config.rate_limit_per_window,
                "rate_window_seconds": self._config.rate_window_seconds,
                "max_request_bytes": self._config.max_request_bytes,
                "allowed_ips": (
                    list(self._config.allowed_ips)
                    if self._config.allowed_ips is not None else "all"
                ),
                "blocked_ips_count": len(self._config.blocked_ips),
                "blocked_paths_count": (
                    len(self._config.blocked_paths) + len(self._config.blocked_prefixes)
                ),
            },
            "timestamp": utc_now(),
        }
