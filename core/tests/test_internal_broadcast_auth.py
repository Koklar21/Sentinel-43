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
# =============================================================================
#
# core/tests/test_internal_broadcast_auth.py
#
# POST /internal/events/broadcast used to be gated with _require_operator()
# (dashboard operator JWT + X-S43-Password), even though its only real
# caller — FenrirHunter (core/detection/fenrir_hunter.py) — sends
# `Authorization: Bearer <S43_FENRIR_API_TOKEN>` and never a password
# header. That meant every real call from Fenrir was silently rejected
# with 401 before the token was ever inspected. The route now checks
# S43_FENRIR_API_TOKEN directly via _require_fenrir_service_token(); this
# file proves the fix and guards against the route drifting back onto the
# operator auth model (which would silently break Fenrir's dashboard
# broadcast again without any test noticing).
# =============================================================================

from __future__ import annotations

import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-for-internal-broadcast-tests")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

from core.api.main import app  # noqa: E402

BROADCAST_URL = "/internal/events/broadcast"
SERVICE_TOKEN = "test-fenrir-service-token-value"


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


def _broadcast_body() -> dict:
    # The route restricts the Fenrir service token to its own "fenrir.*"
    # event namespace (core.api.main.internal_broadcast_event).
    return {"event_type": "fenrir.finding", "channel": "security", "data": {"score": 91}}


def test_rejects_missing_authorization_header(client: TestClient, monkeypatch):
    monkeypatch.setenv("S43_FENRIR_API_TOKEN", SERVICE_TOKEN)

    response = client.post(BROADCAST_URL, json=_broadcast_body())

    assert response.status_code == 401


def test_rejects_wrong_token(client: TestClient, monkeypatch):
    monkeypatch.setenv("S43_FENRIR_API_TOKEN", SERVICE_TOKEN)

    response = client.post(
        BROADCAST_URL,
        json=_broadcast_body(),
        headers={"Authorization": "Bearer not-the-configured-token"},
    )

    assert response.status_code == 401


def test_rejects_when_service_token_not_configured(client: TestClient, monkeypatch):
    """
    An unconfigured S43_FENRIR_API_TOKEN must fail closed (503), not accept
    all callers or reject with a misleading 401 that looks like a client
    credential mistake rather than a server misconfiguration.
    """
    monkeypatch.delenv("S43_FENRIR_API_TOKEN", raising=False)

    response = client.post(
        BROADCAST_URL,
        json=_broadcast_body(),
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
    )

    assert response.status_code == 503


def test_operator_jwt_alone_is_not_accepted(client: TestClient, monkeypatch):
    """
    Guards against regressing back to _require_operator(): a syntactically
    Bearer-shaped value that is not the configured service token (e.g. an
    operator JWT) must not be accepted just because it looks like a token.
    """
    monkeypatch.setenv("S43_FENRIR_API_TOKEN", SERVICE_TOKEN)

    response = client.post(
        BROADCAST_URL,
        json=_broadcast_body(),
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.fake.jwt"},
    )

    assert response.status_code == 401


def test_accepts_correct_service_token(client: TestClient, monkeypatch):
    monkeypatch.setenv("S43_FENRIR_API_TOKEN", SERVICE_TOKEN)

    response = client.post(
        BROADCAST_URL,
        json=_broadcast_body(),
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["event_type"] == "fenrir.finding"


__all__: list[str] = []
