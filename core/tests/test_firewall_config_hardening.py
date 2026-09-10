# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is distributed under a dual-license model:
#   1. GNU Affero General Public License (AGPL v3.0)
#   2. Commercial License
# =============================================================================
#
# core/tests/test_firewall_config_hardening.py
#
# Pass 2 — firewall configuration defaults + fail-closed configuration/startup.
#
#   * A present-but-malformed security value (bad bool / int / CIDR) is a hard
#     error, not a silent fall-back to a default.
#   * blocked_path_prefixes / blocked_path_contains are NOT env-configurable
#     via FirewallConfig.from_env() -- they are always the built-in
#     dangerous-path lists, so an operator can never accidentally wipe them.
#   * SentinelFirewall is a required control: a failure to import / configure /
#     register it fails startup closed outside development/local/test.
#
# from_env() here is the canonical FirewallConfig.from_env() classmethod that
# core.api.main uses (via `from core.middleware import FirewallConfig`).
# Registration behavior is exercised in a subprocess because the try/except
# runs once at core.api.main import time.
# =============================================================================

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import textwrap
from typing import Any

import pytest

from core.middleware.sentinel_firewall import FirewallConfig
from core.api.middleware.sentinel_firewall_middleware import SentinelFirewall

_FW_ENV_VARS = (
    "S43_FIREWALL_ENABLED",
    "S43_FIREWALL_MAX_CONTENT_LENGTH",
    "S43_FIREWALL_MAX_HEADER_BYTES",
    "S43_FIREWALL_ALLOWED_IPS",
    "S43_FIREWALL_BLOCKED_IPS",
    "S43_TRUSTED_PROXIES",
)


@pytest.fixture(autouse=True)
def _clean_fw_env(monkeypatch):
    for name in _FW_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    yield


# Snapshot the dataclass's own defaults (no env applied).
_DEFAULTS = FirewallConfig()


# ---------------------------------------------------------------------------
# blocked_path_prefixes / blocked_path_contains are NOT env-configurable via
# from_env() -- always the built-in dangerous-path lists.
# ---------------------------------------------------------------------------

def test_blocked_path_prefixes_are_the_builtin_default():
    cfg = FirewallConfig.from_env()
    assert tuple(cfg.blocked_path_prefixes) == tuple(_DEFAULTS.blocked_path_prefixes)
    assert "/.git" in cfg.blocked_path_prefixes
    assert "/wp-admin" in cfg.blocked_path_prefixes
    assert len(cfg.blocked_path_prefixes) >= 10


def test_blocked_path_contains_is_the_builtin_default():
    # Not env-configurable at all -> always the built-in traversal/secret list.
    cfg = FirewallConfig.from_env()
    assert tuple(cfg.blocked_path_contains) == tuple(_DEFAULTS.blocked_path_contains)
    assert "../" in cfg.blocked_path_contains


# ---------------------------------------------------------------------------
# Other env-backed fields: absent -> dataclass default; present -> applied
# ---------------------------------------------------------------------------

def test_all_defaults_when_no_env():
    cfg = FirewallConfig.from_env()
    assert cfg.enabled is True
    assert cfg.max_content_length_bytes == _DEFAULTS.max_content_length_bytes
    assert cfg.max_total_header_bytes == _DEFAULTS.max_total_header_bytes
    assert tuple(cfg.allowed_ip_cidrs) == ()
    assert tuple(cfg.blocked_ip_cidrs) == ()
    assert tuple(cfg.trusted_proxy_cidrs) == ()
    assert cfg.respect_x_forwarded_for is True


def test_present_values_are_applied(monkeypatch):
    monkeypatch.setenv("S43_FIREWALL_ENABLED", "false")
    monkeypatch.setenv("S43_FIREWALL_MAX_CONTENT_LENGTH", "2048")
    monkeypatch.setenv("S43_FIREWALL_MAX_HEADER_BYTES", "4096")
    monkeypatch.setenv("S43_FIREWALL_ALLOWED_IPS", "10.0.0.0/8")
    monkeypatch.setenv("S43_FIREWALL_BLOCKED_IPS", "6.6.6.6/32,7.7.7.0/24")
    monkeypatch.setenv("S43_TRUSTED_PROXIES", "192.168.0.0/16")
    cfg = FirewallConfig.from_env()
    assert cfg.enabled is False
    assert cfg.max_content_length_bytes == 2048
    assert cfg.max_total_header_bytes == 4096
    assert tuple(cfg.allowed_ip_cidrs) == ("10.0.0.0/8",)
    assert tuple(cfg.blocked_ip_cidrs) == ("6.6.6.6/32", "7.7.7.0/24")
    assert tuple(cfg.trusted_proxy_cidrs) == ("192.168.0.0/16",)


def test_enabled_true_variants(monkeypatch):
    for v in ("1", "true", "YES", "on", "enabled"):
        monkeypatch.setenv("S43_FIREWALL_ENABLED", v)
        assert FirewallConfig.from_env().enabled is True
    for v in ("0", "false", "No", "off", "disabled"):
        monkeypatch.setenv("S43_FIREWALL_ENABLED", v)
        assert FirewallConfig.from_env().enabled is False


# ---------------------------------------------------------------------------
# Malformed security config -> hard error (no silent fall-back)
# ---------------------------------------------------------------------------

def test_malformed_enabled_raises(monkeypatch):
    monkeypatch.setenv("S43_FIREWALL_ENABLED", "maybe")
    with pytest.raises(ValueError, match="must be boolean"):
        FirewallConfig.from_env()


def test_malformed_int_raises(monkeypatch):
    monkeypatch.setenv("S43_FIREWALL_MAX_CONTENT_LENGTH", "10MB")
    with pytest.raises(ValueError, match="must be integer"):
        FirewallConfig.from_env()


@pytest.mark.parametrize("var,bad", [
    ("S43_TRUSTED_PROXIES", "not-a-cidr"),
    ("S43_TRUSTED_PROXIES", "10.0.0.0/99"),
    ("S43_FIREWALL_BLOCKED_IPS", "999.1.1.1"),
    ("S43_FIREWALL_ALLOWED_IPS", "10.0.0.0/8,garbage"),
])
def test_invalid_cidr_in_env_fails_from_env(monkeypatch, var, bad):
    # from_env() runs config.validate(), which parses every CIDR list.
    monkeypatch.setenv(var, bad)
    with pytest.raises(ValueError, match="invalid CIDR"):
        FirewallConfig.from_env()


def test_directly_constructed_bad_cidr_still_rejected():
    # Defense in depth: a caller bypassing from_env() and building
    # FirewallConfig by hand still can't smuggle a bad CIDR past the middleware.
    cfg = FirewallConfig(trusted_proxy_cidrs=("garbage",))
    with pytest.raises(ValueError, match="invalid CIDR"):
        SentinelFirewall(app=lambda s, r, se: None, config=cfg)


def test_valid_cidrs_construct_cleanly(monkeypatch):
    monkeypatch.setenv("S43_TRUSTED_PROXIES", "10.0.0.0/8, 2001:db8::/32, 127.0.0.1")
    cfg = FirewallConfig.from_env()
    fw = SentinelFirewall(app=lambda s, r, se: None, config=cfg)
    assert len(fw._trusted_proxy_networks) == 3


# ---------------------------------------------------------------------------
# Fail-closed firewall registration in core/api/main.py (subprocess)
# ---------------------------------------------------------------------------

def _import_main(env_overrides: dict[str, str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    for name in _FW_ENV_VARS:
        env.pop(name, None)
    env.update({
        "S43_JWT_SECRET": "x",
        "S43_JWT_ALGORITHM": "HS256",
        "S43_WS_REQUIRE_AUTH": "true",
        "S43_WATCHTOWER_URL": "http://127.0.0.1:59999",
        "S43_WATCHTOWER_TIMEOUT": "0.2",
        "PYTHONPATH": os.getcwd(),
    })
    env.update(env_overrides)
    code = textwrap.dedent("""
        import core.api.main as m
        names = [mw.cls.__name__ for mw in m.app.user_middleware]
        print("FIREWALL_PRESENT=" + str("SentinelFirewall" in names))
    """)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, env=env, timeout=120,
    )


def test_registration_failure_is_fatal_outside_local():
    # A malformed S43_FIREWALL_ENABLED makes FirewallConfig.from_env() raise.
    r = _import_main({"SENTINEL_ENV": "production", "S43_FIREWALL_ENABLED": "not-a-bool"})
    assert r.returncode != 0, r.stdout + r.stderr
    combined = r.stdout + r.stderr
    assert "SentinelFirewall is required" in combined
    assert "FIREWALL_PRESENT=True" not in combined


def test_registration_failure_degrades_in_local_env():
    r = _import_main({"SENTINEL_ENV": "test", "S43_FIREWALL_ENABLED": "not-a-bool"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "FIREWALL_PRESENT=False" in r.stdout


def test_registration_succeeds_by_default():
    r = _import_main({"SENTINEL_ENV": "production"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "FIREWALL_PRESENT=True" in r.stdout


def test_invalid_cidr_is_fatal_startup_outside_local():
    r = _import_main({"SENTINEL_ENV": "production", "S43_TRUSTED_PROXIES": "nonsense"})
    assert r.returncode != 0, r.stdout + r.stderr
    assert "SentinelFirewall is required" in (r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# Server-level (uvicorn) proxy handling must not undermine the app control
# ---------------------------------------------------------------------------

def test_uvicorn_proxy_pin_beats_forwarded_allow_ips_env(monkeypatch):
    import uvicorn

    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    cfg = uvicorn.Config("core.api.main:app", forwarded_allow_ips="127.0.0.1")
    assert cfg.forwarded_allow_ips == "127.0.0.1"


def test_uvicorn_proxyheaders_does_not_rewrite_non_loopback_peer():
    import asyncio

    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    seen: dict[str, Any] = {}

    async def app(scope, receive, send):
        seen["client"] = scope.get("client")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1")
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"9.9.9.9")],
        "client": ("172.18.0.7", 5555),
        "scheme": "http",
    }

    async def receive():
        return {"type": "http.request"}

    async def send(_m):
        return None

    asyncio.run(mw(scope, receive, send))
    assert seen["client"] == ("172.18.0.7", 5555)


@pytest.mark.parametrize("path", [
    "core/api/Dockerfile",
    "docker-compose.yml",
    "deploy/kubernetes/base/s43-api-deployment.yaml",
])
def test_deployment_files_pin_forwarded_allow_ips(path):
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    text = (repo_root / path).read_text(encoding="utf-8")
    assert "--forwarded-allow-ips" in text, f"{path} lost the uvicorn proxy pin"
    tail = text.split("--forwarded-allow-ips", 1)[1][:40]
    assert "127.0.0.1" in tail


__all__: list[str] = []
