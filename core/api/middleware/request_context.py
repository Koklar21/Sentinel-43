# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
#
# See LICENSE.md and COMMERCIAL_LICENSE.md at the repository root.
# =============================================================================

"""Global request context middleware.

File: api/middleware/request_context.py

Responsibilities:
- Guarantee every request has a request_id
- Respect incoming X-Request-ID header if provided
- Attach request_id to request.state.request_id
- Echo request_id on every response (including 404s)

Import-safe when FastAPI/Starlette are not installed.
"""

from __future__ import annotations

import uuid
from typing import Optional, Any


X_REQUEST_ID = "X-Request-ID"


def _normalize_request_id(value: Optional[str]) -> str:
    if value and str(value).strip():
        return str(value).strip()
    return str(uuid.uuid4())


def _import_starlette():
    try:
        from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint  # type: ignore
        from starlette.requests import Request  # type: ignore
        from starlette.responses import Response  # type: ignore
        return BaseHTTPMiddleware, RequestResponseEndpoint, Request, Response
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Starlette/FastAPI is required for request context middleware. Install fastapi."
        ) from e


def create_request_context_middleware():
    BaseHTTPMiddleware, RequestResponseEndpoint, Request, Response = _import_starlette()

    class RequestContextMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
            request_id = _normalize_request_id(request.headers.get(X_REQUEST_ID))
            request.state.request_id = request_id

            response = await call_next(request)
            response.headers[X_REQUEST_ID] = request_id
            return response

    return RequestContextMiddleware


# -----------------------------------------------------------------------------
# Minimal tests
# -----------------------------------------------------------------------------


def _run_self_tests() -> None:  # pragma: no cover
    import unittest

    try:
        from fastapi import FastAPI  # type: ignore
        from fastapi.testclient import TestClient  # type: ignore
    except Exception:
        FastAPI = None  # type: ignore
        TestClient = None  # type: ignore

    class MiddlewareTests(unittest.TestCase):
        def setUp(self) -> None:
            if FastAPI is None or TestClient is None:
                self.skipTest("fastapi[test] is not installed in this environment")

        def test_generates_request_id(self):
            app = FastAPI()
            app.add_middleware(create_request_context_middleware())

            @app.get("/ping")
            def ping():
                return {"ok": True}

            client = TestClient(app)
            r = client.get("/ping")
            self.assertEqual(r.status_code, 200)
            self.assertTrue(X_REQUEST_ID in r.headers)
            self.assertTrue(len(r.headers[X_REQUEST_ID]) > 0)

        def test_echoes_request_id(self):
            app = FastAPI()
            app.add_middleware(create_request_context_middleware())

            @app.get("/ping")
            def ping():
                return {"ok": True}

            client = TestClient(app)
            r = client.get("/ping", headers={X_REQUEST_ID: "abc-123"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers[X_REQUEST_ID], "abc-123")

        def test_applies_to_404(self):
            app = FastAPI()
            app.add_middleware(create_request_context_middleware())
            client = TestClient(app)
            r = client.get("/missing")
            self.assertEqual(r.status_code, 404)
            self.assertTrue(X_REQUEST_ID in r.headers)

    unittest.main(argv=["request_context.py"], exit=False)


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
