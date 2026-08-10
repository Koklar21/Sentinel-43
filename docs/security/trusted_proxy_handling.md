# Sentinel-43 — Trusted Proxy / X-Forwarded-For Handling

## The bug (fixed)

`core/middleware/sentinel_firewall.py` is a compatibility shim that restores
`FirewallConfig.from_env()` on the relocated firewall implementation
(`core/api/middleware/sentinel_firewall_middleware.py`), which is the one
actually mounted in `core/api/main.py` (`app.add_middleware(SentinelFirewall,
config=FirewallConfig.from_env(), ...)`).

The shim's `_build_config_kwargs()` built a candidate kwarg named
`trusted_proxies`, but `FirewallConfig`'s real dataclass field is
`trusted_proxy_cidrs`. `_constructor_accepts()` only forwards kwargs whose
name matches an actual constructor parameter — the mismatch meant the
`S43_TRUSTED_PROXIES` env var was read correctly but then silently dropped,
and `trusted_proxy_cidrs` stayed permanently `()`.

`sentinel_firewall_middleware.py`'s `_resolve_client_ip()` only refuses to
trust `X-Forwarded-For` when `trusted_proxy_cidrs` is non-empty *and* the
direct TCP peer isn't in it. With `trusted_proxy_cidrs` always empty and
`respect_x_forwarded_for=True` (the default), the middleware trusted
`X-Forwarded-For` **unconditionally from any caller** — that value became
`client_ip` for firewall IP allow/block decisions, the rate-limiter bucket
key, and audit `client_ip` (flows further into `core/monitoring/manager.py`'s
threat-scoring `source_ip`). Any client could put an arbitrary IP in that
header and have it treated as authoritative.

This was live in Docker Compose already — not introduced by Kubernetes —
because nothing in the stack ever set `S43_TRUSTED_PROXIES` in a way that
would have worked even if an operator tried to.

**Fix**: the candidate key is now `trusted_proxy_cidrs` (matching the real
field), so `S43_TRUSTED_PROXIES` actually reaches `FirewallConfig`. See
`core/middleware/sentinel_firewall.py` and the regression test at
`core/tests/test_firewall_trusted_proxy_config.py`.

## Operational rule for every deployment (Compose and Kubernetes)

- **Unset `S43_TRUSTED_PROXIES` (the default) means the firewall trusts
  nobody's `X-Forwarded-For` header.** This is fail-safe, not broken: every
  request is attributed to its direct TCP peer instead. Behind a reverse
  proxy or ingress, that peer is the proxy itself, so every request will
  appear to come from the proxy's IP until this is configured correctly.
- **Set `S43_TRUSTED_PROXIES` to the real, narrow CIDR(s) of whatever
  terminates TLS/proxies in front of the API** — e.g. the ingress
  controller's pod CIDR or Service ClusterIP range in a Kubernetes
  deployment, or `127.0.0.1/32` for a same-host reverse proxy. Never set it
  to `0.0.0.0/0` or any CIDR broader than the actual trusted proxy's network
  — that recreates the exact spoofing gap this fix closes.
- In `deploy/kubernetes/`, `S43_TRUSTED_PROXIES` is left empty in the shared
  base and in the `dev` overlay (no ingress in dev — direct
  `kubectl port-forward` access, so there's no proxy to trust). The `beta`
  overlay, which adds an Ingress, sets it to the cluster's actual
  ingress-controller network — see
  `deploy/kubernetes/overlays/beta/kustomization.yaml` and
  `deploy/kubernetes/README.md`.

## What this fix does not change

Every deployment that never set `S43_TRUSTED_PROXIES` (which is every
deployment today, since setting it was previously a no-op) behaves
identically after this fix: `trusted_proxy_cidrs` was `()` before and is
still `()` unless the operator explicitly configures it. No default
behavior changed for existing callers.
