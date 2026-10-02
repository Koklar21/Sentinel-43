# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from core.api import origin_policy


REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"


def _request(*, origin: str | None = None, referer: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = [(b"host", b"localhost")]
    if origin is not None:
        headers.append((b"origin", origin.encode("ascii")))
    if referer is not None:
        headers.append((b"referer", referer.encode("ascii")))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/auth/login",
            "raw_path": b"/auth/login",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 50000),
            "server": ("localhost", 443),
        }
    )


def _set_environment(monkeypatch, value: str) -> None:
    monkeypatch.setenv("SENTINEL_ENV", value)
    monkeypatch.setenv("S43_ENV", value)


def test_local_defaults_include_compose_https_origins(monkeypatch):
    _set_environment(monkeypatch, "development")
    monkeypatch.delenv("S43_ALLOWED_ORIGINS", raising=False)

    origins = origin_policy.configured_allowed_origins()

    assert "https://localhost" in origins
    assert "https://127.0.0.1" in origins


def test_nonlocal_missing_origin_configuration_fails_closed(monkeypatch):
    _set_environment(monkeypatch, "production")
    monkeypatch.delenv("S43_ALLOWED_ORIGINS", raising=False)

    with pytest.raises(HTTPException) as exc_info:
        origin_policy.require_state_change_origin(
            _request(origin="https://localhost")
        )

    assert exc_info.value.status_code == 503
    assert "Allowed origins are not configured" in str(exc_info.value.detail)


def test_nonlocal_exact_origin_is_required(monkeypatch):
    _set_environment(monkeypatch, "production")
    monkeypatch.setenv(
        "S43_ALLOWED_ORIGINS",
        "https://beta.example.test",
    )

    origin_policy.require_state_change_origin(
        _request(origin="https://beta.example.test")
    )

    with pytest.raises(HTTPException) as exc_info:
        origin_policy.require_state_change_origin(
            _request(origin="https://beta.example.test.attacker.invalid")
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Origin not allowed."


def test_nonlocal_missing_browser_origin_is_rejected(monkeypatch):
    _set_environment(monkeypatch, "production")
    monkeypatch.setenv(
        "S43_ALLOWED_ORIGINS",
        "https://beta.example.test",
    )

    with pytest.raises(HTTPException) as exc_info:
        origin_policy.require_state_change_origin(_request())

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Origin validation required."


def test_compose_default_matches_canonical_local_origin_set():
    source = COMPOSE_FILE.read_text(encoding="utf-8")

    for origin in origin_policy.DEFAULT_LOCAL_ALLOWED_ORIGINS:
        assert origin in source
