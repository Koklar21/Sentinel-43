# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_tls_posture.py
#
# Beta-execution Phase 2 (F-TLS-1) -- _validate_security_config() refuses to
# start a non-local API with a plaintext, non-loopback browser origin; the
# Compose reverse proxy is wired as the single TLS terminator.
# =============================================================================

from __future__ import annotations

import pathlib

import pytest

import core.api.main as m

_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _cfg(monkeypatch, *, env, origins, insecure=None):
    monkeypatch.setattr(m, "SENTINEL_ENV", env)
    monkeypatch.setattr(m, "JWT_SECRET", "x" * 16)
    monkeypatch.setattr(m, "WS_REQUIRE_AUTH", True)
    monkeypatch.setattr(m, "_ALLOWED_ORIGINS", frozenset(origins))
    if insecure is None:
        monkeypatch.delenv("S43_ALLOW_INSECURE_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("S43_ALLOW_INSECURE_ORIGINS", insecure)


def test_nonlocal_plaintext_origin_refuses_startup(monkeypatch):
    _cfg(monkeypatch, env="production", origins={"http://beta.example.com"})
    with pytest.raises(RuntimeError, match="HTTPS origins"):
        m._validate_security_config()


def test_nonlocal_https_origin_is_fine(monkeypatch):
    _cfg(monkeypatch, env="production", origins={"https://beta.example.com"})
    m._validate_security_config()  # no raise


def test_loopback_http_origin_is_exempt(monkeypatch):
    _cfg(
        monkeypatch,
        env="production",
        origins={"http://localhost:5500", "http://127.0.0.1:8000"},
    )
    m._validate_security_config()  # loopback is a browser "secure context"


def test_insecure_origins_opt_out(monkeypatch):
    _cfg(
        monkeypatch,
        env="production",
        origins={"http://proxy.internal"},
        insecure="true",
    )
    m._validate_security_config()  # no raise -- private-network proxy case


def test_local_env_never_checks_origins(monkeypatch):
    _cfg(monkeypatch, env="development", origins={"http://anything.example"})
    m._validate_security_config()  # no raise


# ---------------------------------------------------------------------------
# Compose reverse proxy wiring
# ---------------------------------------------------------------------------

def test_compose_backend_is_not_host_published():
    yaml = pytest.importorskip("yaml")
    compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    api = compose["services"]["s43-api"]
    assert "ports" not in api, "s43-api must not be host-published; only s43-proxy is"
    proxy = compose["services"]["s43-proxy"]
    published = {str(p).split(":")[0] for p in proxy["ports"]}
    assert {"80", "443"} <= published


def test_compose_proxy_has_fixed_ip_the_api_trusts():
    yaml = pytest.importorskip("yaml")
    compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    proxy_ip = compose["services"]["s43-proxy"]["networks"]["s43_net"]["ipv4_address"]
    trusted = compose["services"]["s43-api"]["environment"]["S43_TRUSTED_PROXIES"]
    assert proxy_ip in str(trusted)


def test_proxy_nginx_conf_terminates_tls_and_upgrades_websockets():
    conf = " ".join((_ROOT / "deploy/proxy/nginx.conf").read_text(encoding="utf-8").split())
    assert "listen 443 ssl" in conf
    assert "return 308 https://" in conf                 # http -> https
    assert "proxy_set_header X-Forwarded-Proto https" in conf
    assert "proxy_set_header Upgrade $http_upgrade" in conf
    assert "proxy_set_header Connection $connection_upgrade" in conf
    assert "Strict-Transport-Security" in conf
    assert "ssl_protocols" in conf and "TLSv1.2" in conf


def test_k8s_beta_ingress_still_forces_tls_redirect_and_adds_hsts():
    text = (_ROOT / "deploy/kubernetes/overlays/beta/ingress.yaml").read_text(encoding="utf-8")
    assert "ssl-redirect" in text and '"true"' in text
    assert "Strict-Transport-Security" in text  # added this pass
