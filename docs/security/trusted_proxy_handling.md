# Sentinel-43 — Trusted Proxy / X-Forwarded-For Handling

## The bugs (fixed in two parts)

`core/middleware/sentinel_firewall.py` is a compatibility shim that restores
`FirewallConfig.from_env()` on the relocated firewall implementation
(`core/api/middleware/sentinel_firewall_middleware.py`), which is the one
actually mounted in `core/api/main.py` (`app.add_middleware(SentinelFirewall,
config=FirewallConfig.from_env(), ...)`).

**Part 1 — the env var never reached the config (commit `3f65ca1`).**
The shim's `_build_config_kwargs()` built a candidate kwarg named
`trusted_proxies`, but `FirewallConfig`'s real dataclass field is
`trusted_proxy_cidrs`. `_constructor_accepts()` only forwards kwargs whose
name matches an actual constructor parameter — the mismatch meant the
`S43_TRUSTED_PROXIES` env var was read correctly but then silently dropped,
and `trusted_proxy_cidrs` stayed permanently `()`. `3f65ca1` fixed the key
name so `S43_TRUSTED_PROXIES` actually reaches `FirewallConfig`.

**Part 2 — an empty trusted list still trusted everyone (commit `326bed8`, Pass 2).**
`3f65ca1` alone did **not** make the default safe.
`sentinel_firewall_middleware.py`'s `_resolve_client_ip()` had
`if self._trusted_proxy_networks and not _ip_in_networks(direct_ip, ...)` —
when `trusted_proxy_cidrs` is empty (the default, and what `S43_TRUSTED_PROXIES`
unset or `""` produces) the `and` short-circuits, the guard is skipped, and
the code takes `X-Forwarded-For`'s first entry as `client_ip` **from any
caller**. That value drives firewall IP allow/block, the rate-limiter bucket
key, and audit `client_ip` (→ `core/monitoring/manager.py` threat-scoring
`source_ip`). Any client could spoof it.

`326bed8` fixes `_resolve_client_ip()`:

- **No trusted proxies configured ⇒ every request is attributed to its
  direct TCP peer.** `X-Forwarded-For` and RFC 7239 `Forwarded` are ignored.
- **With trusted proxies set**, the `X-Forwarded-For` chain is walked
  right-to-left: peel off trusted-proxy hops; the first address that is not a
  trusted proxy is the client. (Leftmost-wins is wrong for multi-hop / mixed
  chains — a client can prepend arbitrary entries; only the trusted segment
  on the right is verifiable.) A malformed entry inside that segment ⇒ fall
  back to the direct peer.

Regression tests: `core/tests/test_firewall_trusted_proxy_config.py` (env →
field) and `core/tests/test_firewall_proxy_trust.py` (resolution behavior,
Pass 2).

## Server level — uvicorn (Pass 2, commit `52ea75d`)

uvicorn's `ProxyHeadersMiddleware` runs *before* SentinelFirewall and, by
default, rewrites `scope["client"]` from `X-Forwarded-For` when the direct
peer is in `--forwarded-allow-ips` / `$FORWARDED_ALLOW_IPS` (default
`127.0.0.1`). A `FORWARDED_ALLOW_IPS=*` — a common container copy-paste —
lets uvicorn believe `X-Forwarded-For` from any peer, defeating everything
above. The API uvicorn command now pins `--forwarded-allow-ips 127.0.0.1`
explicitly (Dockerfile, `docker-compose.yml`,
`deploy/kubernetes/base/s43-api-deployment.yaml`); an explicit CLI value
overrides the env var. `S43_TRUSTED_PROXIES` remains the single authoritative
proxy-trust control — a deployment behind a real reverse proxy sets **both**
`--forwarded-allow-ips` and `S43_TRUSTED_PROXIES` to that proxy's address.

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
  overlay, which adds an Ingress, ships `S43_TRUSTED_PROXIES: ""` (empty) in
  `deploy/kubernetes/overlays/beta/configmap-patch.yaml`, flagged
  `# CHANGEME` — it is **not** filled in with a real value, since
  ingress-controller pod CIDRs vary per cluster/CNI and can't be guessed
  generically. Empty fails closed safely: no peer is trusted, `X-Forwarded-For`
  is never honored, and every request is attributed to the ingress
  controller's own address until an operator sets the real, narrow CIDR.
  (An earlier revision shipped a non-CIDR placeholder string that made the API
  refuse to start; that was replaced by the empty value, and this document was
  corrected on 2026-09-19 to match the YAML, which is the source of truth.
  A non-empty value that is not a valid CIDR is still rejected at startup.)
  See `deploy/kubernetes/README.md`.

## What Pass 2 changed for existing deployments

Before Pass 2, a deployment that never set `S43_TRUSTED_PROXIES` (every
deployment) had `trusted_proxy_cidrs == ()` **and trusted `X-Forwarded-For`
from any caller**. After Pass 2 the same deployment attributes every request
to its direct TCP peer and ignores `X-Forwarded-For` entirely. If you are
running the API directly (no reverse proxy), this is strictly more correct
and nothing else changes. If you are already running behind a proxy **and
were relying on the old broken behavior** to see real client IPs, you must
now set `S43_TRUSTED_PROXIES` to that proxy's CIDR — the old behavior was a
spoofing vulnerability, not a feature.
