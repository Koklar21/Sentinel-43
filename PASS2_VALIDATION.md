# Sentinel-43 — Pass 2 Validation

Firewall defaults / proxy trust / fail-closed startup. Exact commands and
outcomes. Companion to `RELEASE_FINDINGS.md`, `PASS1_VALIDATION.md`.

## Starting state (verified before any change)

| Item | Value |
|---|---|
| Work clone | `C:\Users\heero\Sentinel-43-work` |
| Branch | `integration/beta-hardening-20260901` |
| HEAD at start | `4dbd4a9` (Pass 1 handoff); substantive Pass 1 state `49eba9f` |
| `git status` | clean |
| `git fsck --full` | 0 errors |
| merge-base with `origin/main` | `8d2b80f` (== `origin/main`) |
| `49eba9f` ancestor of HEAD | yes |
| Original OneDrive repo | HEAD `e859b61`, `## main...origin/main [ahead 1]`, unchanged |

## Firewall configuration architecture (as discovered — code is the evidence)

```
env (S43_FIREWALL_* / S43_TRUSTED_PROXIES)
  -> core/middleware/sentinel_firewall.py            (compat shim)
       imports FirewallConfig/SentinelFirewall/BlockReason from
       core/api/middleware/sentinel_firewall_middleware.py (the real impl)
       and monkey-patches FirewallConfig.from_env() onto it
  -> core/middleware/__init__.py                      (loader: prefers
       core.middleware.sentinel_firewall, falls back to the relocated path,
       asserts from_env() exists)
  -> core/api/main.py  app.add_middleware(SentinelFirewall,
       config=FirewallConfig.from_env(), monitoring_manager=...)
  -> SentinelFirewall.__init__  (instantiated lazily when the ASGI stack is
       built — NOT at add_middleware time): _parse_networks() x3
  -> per request: _screen_scope -> _resolve_client_ip / _screen_ip /
       _screen_path / _screen_headers / _screen_content_length / rate limit
```

Two physical `FirewallConfig`/`SentinelFirewall` definitions still exist
(`core/api/middleware/sentinel_firewall_middleware.py` = real;
`core/monitoring/Sentinel_firewall .py` = orphaned, finding A4). The runtime
path is unambiguously the first, via the `core.middleware` shim. Not
reconciled in Pass 2 (out of scope; A4 is a Pass-7 cleanup item).

## 3f65ca1 field-mapping audit (against the real `FirewallConfig` dataclass)

`@dataclass(slots=True) FirewallConfig` real fields and how the shim's
`_build_config_kwargs()` maps env to them (post-Pass-2):

| Constructor field | Type | Dataclass default | Env var | Shim kind | Empty-env behavior |
|---|---|---|---|---|---|
| `enabled` | bool | `True` | `S43_FIREWALL_ENABLED` | bool | unset ⇒ default; malformed ⇒ **error** |
| `trusted_proxy_cidrs` | Sequence[str] | `()` | `S43_TRUSTED_PROXIES` | cidr_csv | unset/`""` ⇒ `()` (== default); bad CIDR ⇒ **error** |
| `allowed_ip_cidrs` | Sequence[str] | `()` | `S43_FIREWALL_ALLOWED_IP_CIDRS` | cidr_csv | unset/`""` ⇒ `()`; bad CIDR ⇒ **error** |
| `blocked_ip_cidrs` | Sequence[str] | `()` | `S43_FIREWALL_BLOCKED_IPS` | cidr_csv | unset/`""` ⇒ `()`; bad CIDR ⇒ **error** |
| `respect_x_forwarded_for` | bool | `True` | — (not env-configurable) | — | always `True` |
| `max_content_length_bytes` | int | `10485760` | `S43_FIREWALL_MAX_BODY_BYTES` | int | unset ⇒ default; malformed ⇒ **error** |
| `max_total_header_bytes` | int | `32768` | `S43_FIREWALL_MAX_HEADER_BYTES` | int | unset ⇒ default; malformed ⇒ **error** |
| `require_content_length_for_methods` | Sequence[str] | `("POST","PUT","PATCH")` | — | — | not env-configurable |
| `blocked_path_prefixes` | Sequence[str] | **11 entries** (`/.git`, `/.env`, `/wp-admin`, `/wp-login`, `/phpmyadmin`, `/adminer`, `/server-status`, `/actuator`, `/debug`, `/vendor`, `/node_modules`) | `S43_FIREWALL_BLOCKED_PATHS` | csv (keep_default_when_blank) | **unset OR blank ⇒ the 11 defaults kept** (was: wiped to `()`); explicit value replaces |
| `blocked_path_contains` | Sequence[str] | `("../","..\\","%2e%2e","%252e%252e",".env","passwd","shadow")` | — | — | never env-configurable — always the default |
| rate limits, status codes, `include_block_reason`, `add_security_headers`, `monitoring_*` | int/bool/str | (see code) | — | — | not env-configurable |

`_constructor_accepts()` still guards each field name. `allowed_origins`
(a CORS setting) is correctly absent. **Every S43_FIREWALL_* env var maps to
a real constructor parameter with the intended type.** `3f65ca1`'s mapping
is correct; Pass 2 added: (a) unset ⇒ keep default (not override with a
blank), (b) blank `blocked_path_prefixes` ⇒ keep default + warn, (c) load-
time validation of every CIDR and every bool/int.

## Security defaults — the 5 configuration states, per field

| Field | A. absent | B. `""` | C. valid | D. malformed | E. boundary |
|---|---|---|---|---|---|
| `blocked_path_prefixes` | 11 built-ins | 11 built-ins (+warn) | replaces list | n/a (any csv is "valid") | `","` / ws ⇒ 11 built-ins |
| `enabled` | `True` | `""` ⇒ **error** ("not a valid boolean") | true/false spellings | `maybe` ⇒ **error** | — |
| `max_*_bytes` | dataclass default | `""` ⇒ **error** | int applied | `10MB` ⇒ **error** | — |
| `trusted_proxy_cidrs` etc. | `()` | `()` | CIDRs applied | `nonsense` / `10.0.0.0/99` ⇒ **error at from_env()** | `127.0.0.1` (host ⇒ /32) OK |

Evidence: `core/tests/test_firewall_config_hardening.py` — 27 items, all pass.

## Trusted-proxy model & hop selection (post-fix)

`_resolve_client_ip(scope, headers)`:

1. `direct_host` = `scope["client"][0]`; `direct_ip` = parsed or `None`.
2. `respect_x_forwarded_for` False ⇒ return `direct_host`.
3. `direct_ip` unparseable ⇒ return `direct_host`.
4. **`_trusted_proxy_networks` empty ⇒ return `direct_host`.** (the fix — was
   fall-through to trusting XFF)
5. direct peer not in `_trusted_proxy_networks` ⇒ return `direct_host`.
6. no `X-Forwarded-For` / empty ⇒ return `direct_host`.
7. **walk XFF right-to-left**: for each entry from the right — unparseable ⇒
   return `direct_host`; in a trusted network ⇒ continue; else ⇒ return it.
8. whole chain trusted ⇒ return `direct_host`.

`Forwarded` (RFC 7239) is not read anywhere ⇒ cannot influence client IP.

Evidence: `core/tests/test_firewall_proxy_trust.py` — 20 items exercising
crafted `http` scopes through `SentinelFirewall` and reading
`scope["state"]["s43_client_ip"]` + the allow/block decision. Covers: direct
/ untrusted XFF / untrusted `Forwarded` / peer-not-in-trusted / spoof-cannot-
evade-block / spoof-cannot-forge-allowlist / single hop / multi hop / mixed
(client-prepended) chain / whole-chain-trusted / malformed rightmost /
malformed only / empty XFF / respect=False / IPv4 / IPv6 / IPv4-mapped-IPv6 /
duplicate `X-Forwarded-For` headers / header casing + whitespace.

## Server-level (uvicorn) proxy behavior

- Dockerfile / docker-compose.yml / k8s launched `uvicorn ... --host 0.0.0.0
  --port 8000` with no proxy flags. uvicorn 0.52.4 default: `--proxy-headers`
  **on**, `--forwarded-allow-ips` = `127.0.0.1` (or `$FORWARDED_ALLOW_IPS`).
- Verified (`test_firewall_config_hardening.py`):
  - `ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1")` does **not**
    rewrite `scope["client"]` for a non-loopback peer (`172.18.0.7`). ⇒ the
    current containerized deployment is not actively exploitable — external
    peers are never `127.0.0.1`.
  - `uvicorn.Config(app, forwarded_allow_ips="127.0.0.1")` yields
    `forwarded_allow_ips == "127.0.0.1"` even with `FORWARDED_ALLOW_IPS=*` ⇒
    an explicit CLI value beats the env var.
- **Risk**: `FORWARDED_ALLOW_IPS=*` (common container copy-paste) ⇒ uvicorn
  rewrites `scope["client"]` from XFF for any peer, before SentinelFirewall.
- **Mitigation applied**: `--forwarded-allow-ips 127.0.0.1` pinned on the API
  command in all three deployment files (commit `52ea75d`). Behavior-
  preserving for the current deployment; neutralizes the env footgun. Guard
  test asserts the flag is present in each file. Full deploy-time validation
  (TLS scheme handling behind a real proxy) deferred to the deployment pass.

## Fail-closed configuration / startup

`core/api/main.py` used `except ImportError: warning / except Exception:
error` around firewall registration ⇒ boots unprotected on any failure.

Now (commit `9164f43`): a single `except Exception` ⇒ `RuntimeError` at
import time when `not _is_local_environment()`; a loud `logger.error` +
continue when `SENTINEL_ENV` ∈ {development, dev, local, test}.

Also fixed the pre-existing `core/api/__init__.py` circular import that this
change surfaced (`from .main import app` at package init ⇒ cycle through
`core.middleware.sentinel_firewall`). Now lazy via PEP 562 `__getattr__`.
Nothing imports `from core.api import app`; `uvicorn core.api.main:app` is
unaffected (reads `app` off the module).

Evidence (subprocess, `test_firewall_config_hardening.py`):
- `SENTINEL_ENV=production` + `S43_FIREWALL_ENABLED=not-a-bool` ⇒ non-zero
  exit, stderr contains "required security control", firewall absent.
- `SENTINEL_ENV=production` + `S43_TRUSTED_PROXIES=nonsense` ⇒ same.
- `SENTINEL_ENV=test` + broken config ⇒ exit 0, `FIREWALL_PRESENT=False`.
- default env ⇒ exit 0, `FIREWALL_PRESENT=True`.

## Pass 1 security invariants — regression check

| ID | Result |
|---|---|
| SI-1 `/v1` scope→role bypass closed | PASS (`test_v1_auth.py` 5; SI script 3/3) |
| SI-2 `require_admin` gates `/users` | PASS (`test_users_admin.py` 25; SI script 4/4) |
| SI-3 Watchtower bridge/service auth fail-closed | PASS (`test_watchtower_service_auth.py` 53, `test_watchtower_bridge_auth.py` 8; SI script 5/5) |
| SI-4 e859b61 divergent watchtower.py absent | PASS (blob unchanged this pass) |
| SI-5 `:9100` unexposed on host | PASS (`docker-compose.yml` — `s43-core` has no `ports:`; YAML re-parsed) |
| SI-6 firewall shim → real fields | PASS (`test_firewall_trusted_proxy_config.py` 2; + the audit above) |
| SI-7 `/users` mounted, auth-gated | PASS (SI script; `test_users_admin.py`) |

Pass 1 SI script: **13/13**. No Pass 1 invariant regressed.

## Full test suite

Same environment as Pass 1 (`.venv-pass1`, Python 3.13.5, pytest 9.1.1,
fastapi 0.141.1 / starlette 1.6.0 / …). Env:
`S43_WATCHTOWER_URL=http://127.0.0.1:59999`, `S43_WATCHTOWER_TIMEOUT=0.2`.

```
python -m pytest core/tests/ --ignore=core/tests/test_bootstrap.py \
  --ignore=core/tests/test_system_smoke.py -q
```

Tested commit: `f245cf3` (HEAD before the PASS2_VALIDATION.md / handoff
doc-only commits).

Collection: **253 items**, 15 files (2 ignored).
Result: **253 passed · 0 failed · 0 skipped · 0 xfail · 0 xpass · exit 0** ·
~67 s. 5 unique warning locations, unchanged from Pass 1 (the
`HTTP_422_UNPROCESSABLE_ENTITY` / testclient-httpx deprecations and the pre-
existing `core.monitoring.sparta_core` ImportWarning). No new warnings.

New/changed test files (standalone): `test_firewall_config_hardening.py` 27
· `test_firewall_proxy_trust.py` 20 · `test_firewall_trusted_proxy_config.py`
2 (unchanged). 206 (Pass 1) + 47 new = 253.

`test_bootstrap.py` / `test_system_smoke.py` still excluded (live HTTP to
`localhost:8000`; `requests` not in `requirements.txt`) — no-live-contact
constraint, same as Pass 1.

## Deferred / not done in Pass 2

- P2-3: parse RFC 7239 `Forwarded` — a feature, not a hardening (it is
  ignored, so inert). Deferred.
- F-P2-5 full validation: deploy behind a real proxy and check `X-Forwarded-
  Proto` scheme handling — needs a deployment, deferred to Pass 6.
- Reconcile the two physical `FirewallConfig` files / delete
  `core/monitoring/Sentinel_firewall .py` (A4) — Pass 7 cleanup.
- Carried from Pass 1 (unchanged, not this pass's scope): test-ordering env
  fragility, `/users` 500-vs-503 without `DATABASE_URL`,
  `HTTP_422_UNPROCESSABLE_ENTITY` deprecation, `require_admin`↔
  `require_operator` de-dup, `sparta_core` casing, `docker-compose.yml`
  `s43-setup` path.
