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

"""Shared pytest configuration for the Sentinel-43 core test suite.

## Why this file exists

`core.api.main` registers `SentinelFirewall` in its middleware stack. The
firewall's first check resolves the client address from the ASGI
`scope["client"]` and, with `reject_unparseable_client_ip=True` (the
production default), rejects any request whose client address is not a
parseable IP.

Starlette's `TestClient` defaults `scope["client"]` to `("testclient", 50000)`
-- the literal string `"testclient"`, which is not an IP. Every route test in
this suite constructs `TestClient(app)` without overriding that, so once the
firewall is active every such request is blocked with
`{"error": "request_blocked", "detail": "Invalid client address"}` (HTTP 400)
before it reaches the route under test.

## What this does -- and does NOT do

It changes ONLY the synthetic default client address the `TestClient`
presents, from the non-IP string `"testclient"` to loopback `127.0.0.1` --
which is what a real local client looks like. It does not:

  * disable or reconfigure SentinelFirewall
  * change any FirewallConfig default
  * add a "testing mode" bypass to production code
  * touch the app, its middleware, or any environment variable

A test that deliberately exercises a blocked / spoofed / proxied address
still passes an explicit `client=(...)` to `TestClient`, and that explicit
value is respected -- the default is only filled in when the caller gave
none. Firewall config tests (`test_firewall_config_hardening.py`) exercise
`FirewallConfig.from_env()` directly and are unaffected.
"""

from __future__ import annotations

import starlette.testclient as _testclient

# Loopback is a legitimate client address (not in any default block list and,
# with an empty allow-list, permitted). This is the address a real local
# caller would present.
_TEST_CLIENT_ADDR: tuple[str, int] = ("127.0.0.1", 50000)

_original_testclient_init = _testclient.TestClient.__init__


def _testclient_init_with_ip(self, *args, **kwargs):  # type: ignore[no-untyped-def]
    # Only supply the default when the caller did not specify one, so tests
    # that intentionally use a different / blocked address keep control.
    kwargs.setdefault("client", _TEST_CLIENT_ADDR)
    return _original_testclient_init(self, *args, **kwargs)


# Guard against double-application (pytest may import conftest more than once
# in some layouts).
if getattr(_testclient.TestClient.__init__, "__name__", "") != "_testclient_init_with_ip":
    _testclient.TestClient.__init__ = _testclient_init_with_ip  # type: ignore[assignment]
