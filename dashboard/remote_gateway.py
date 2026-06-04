# =============================================================================
# Sentinel-43 Remote Gateway
#
# Purpose:
#   Handles outbound/inbound remote-node gateway communication only.
#
# This is NOT the frontend gateway.
# This is NOT the WebSocket UI layer.
# This is NOT the gRPC-Web bridge.
# =============================================================================

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field


logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _env_float(name: str, default: float) -> float:
    value = _env(name)
    if value is None:
        return default

    try:
        return float(value)
    except ValueError:
        logger.warning("Invalid float for %s=%r; using default %s", name, value, default)
        return default


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        logger.warning("Invalid integer for %s=%r; using default %s", name, value, default)
        return default


@dataclass(frozen=True)
class RemoteGatewayConfig:
    enabled: bool
    default_timeout_seconds: float
    max_retries: int
    retry_backoff_seconds: float
    max_payload_bytes: int
    gateway_name: str


def load_remote_gateway_config() -> RemoteGatewayConfig:
    enabled_raw = (_env("SENTINEL_REMOTE_GATEWAY_ENABLED", "true") or "true").lower()

    return RemoteGatewayConfig(
        enabled=enabled_raw in {"1", "true", "yes", "on"},
        default_timeout_seconds=_env_float("SENTINEL_REMOTE_TIMEOUT_SECONDS", 10.0),
        max_retries=_env_int("SENTINEL_REMOTE_MAX_RETRIES", 2),
        retry_backoff_seconds=_env_float("SENTINEL_REMOTE_RETRY_BACKOFF_SECONDS", 0.25),
        max_payload_bytes=_env_int("SENTINEL_REMOTE_MAX_PAYLOAD_BYTES", 1_048_576),
        gateway_name=_env("SENTINEL_REMOTE_GATEWAY_NAME", "sentinel-43-remote-gateway")
        or "sentinel-43-remote-gateway",
    )


CONFIG = load_remote_gateway_config()


# =============================================================================
# Models
# =============================================================================

class RemoteGatewayState(str, Enum):
    ONLINE = "online"
    DISABLED = "disabled"
    DEGRADED = "degraded"
    ERROR = "error"


class RemoteRequestMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class RemoteForwardRequest(BaseModel):
    url: str = Field(..., min_length=8)
    method: RemoteRequestMethod = RemoteRequestMethod.GET
    headers: dict[str, str] = Field(default_factory=dict)
    payload: dict[str, Any] | list[Any] | str | None = None
    timeout_seconds: float | None = None


class RemoteForwardResponse(BaseModel):
    ok: bool
    status_code: int
    elapsed_ms: float
    url: str
    method: str
    response: Any | None = None
    error: str | None = None


class RemoteHealthResponse(BaseModel):
    gateway: str
    state: RemoteGatewayState
    enabled: bool
    timeout_seconds: float
    max_retries: int
    retry_backoff_seconds: float
    max_payload_bytes: int


# =============================================================================
# Router
# =============================================================================

router = APIRouter(prefix="/remote", tags=["remote-gateway"])


@router.get("/health", response_model=RemoteHealthResponse)
async def remote_gateway_health() -> RemoteHealthResponse:
    state = RemoteGatewayState.ONLINE if CONFIG.enabled else RemoteGatewayState.DISABLED

    return RemoteHealthResponse(
        gateway=CONFIG.gateway_name,
        state=state,
        enabled=CONFIG.enabled,
        timeout_seconds=CONFIG.default_timeout_seconds,
        max_retries=CONFIG.max_retries,
        retry_backoff_seconds=CONFIG.retry_backoff_seconds,
        max_payload_bytes=CONFIG.max_payload_bytes,
    )


@router.get("/status", response_model=RemoteHealthResponse)
async def remote_gateway_status() -> RemoteHealthResponse:
    return await remote_gateway_health()


@router.post("/forward", response_model=RemoteForwardResponse)
async def forward_remote_request(
    body: RemoteForwardRequest,
    request: Request,
) -> RemoteForwardResponse:
    if not CONFIG.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Remote gateway is disabled.",
        )

    _validate_remote_url(body.url)
    _validate_payload_size(body.payload)

    timeout = body.timeout_seconds or CONFIG.default_timeout_seconds

    return await _send_with_retries(
        url=body.url,
        method=body.method.value,
        headers=_sanitize_headers(body.headers, request),
        payload=body.payload,
        timeout_seconds=timeout,
    )


# =============================================================================
# Internal Helpers
# =============================================================================

def _validate_remote_url(url: str) -> None:
    lowered = url.lower()

    if not lowered.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Remote URL must start with http:// or https://.",
        )

    blocked_hosts = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    }

    for blocked in blocked_hosts:
        if blocked in lowered:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Remote URL points to a blocked local address.",
            )


def _validate_payload_size(payload: Any | None) -> None:
    if payload is None:
        return

    raw = str(payload).encode("utf-8")

    if len(raw) > CONFIG.max_payload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Remote payload exceeds configured size limit.",
        )


def _sanitize_headers(
    headers: dict[str, str],
    request: Request,
) -> dict[str, str]:
    blocked = {
        "host",
        "content-length",
        "connection",
        "transfer-encoding",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    }

    clean_headers: dict[str, str] = {}

    for key, value in headers.items():
        normalized = key.lower().strip()

        if normalized in blocked:
            continue

        clean_headers[key] = value

    request_id = request.headers.get("x-request-id")

    if request_id:
        clean_headers["x-request-id"] = request_id

    clean_headers.setdefault("x-sentinel-gateway", CONFIG.gateway_name)

    return clean_headers


async def _send_with_retries(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    payload: Any | None,
    timeout_seconds: float,
) -> RemoteForwardResponse:
    last_error: str | None = None
    started = time.perf_counter()

    for attempt in range(CONFIG.max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=payload if method != "GET" else None,
                )

            elapsed_ms = (time.perf_counter() - started) * 1000

            parsed_response: Any
            try:
                parsed_response = response.json()
            except ValueError:
                parsed_response = response.text

            return RemoteForwardResponse(
                ok=200 <= response.status_code < 300,
                status_code=response.status_code,
                elapsed_ms=round(elapsed_ms, 3),
                url=url,
                method=method,
                response=parsed_response,
                error=None,
            )

        except httpx.TimeoutException:
            last_error = "Remote request timed out."
            logger.warning(
                "Remote request timeout attempt=%s url=%s",
                attempt + 1,
                url,
            )

        except httpx.RequestError as exc:
            last_error = f"Remote request failed: {exc.__class__.__name__}"
            logger.warning(
                "Remote request error attempt=%s url=%s error=%s",
                attempt + 1,
                url,
                exc,
            )

        if attempt < CONFIG.max_retries:
            await asyncio.sleep(CONFIG.retry_backoff_seconds * (attempt + 1))

    elapsed_ms = (time.perf_counter() - started) * 1000

    return RemoteForwardResponse(
        ok=False,
        status_code=502,
        elapsed_ms=round(elapsed_ms, 3),
        url=url,
        method=method,
        response=None,
        error=last_error or "Remote request failed.",
    )


# =============================================================================
# Optional App Factory
# =============================================================================

def get_remote_gateway_router() -> APIRouter:
    return router