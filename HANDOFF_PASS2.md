# Sentinel-43 — Pass 2 Handoff

- Date: 2026-09-01
- Pass run: **Pass 2 only** — firewall defaults / proxy trust / fail-closed startup. Stopped here.
- Do NOT begin Pass 3 without explicit approval. No push. No deploy.

## Short outcome

Found and fixed four ways SentinelFirewall could silently run weaker than
intended, plus a related server-level gap and a circular import the fix
exposed. All exercised by 47 new tests. Full suite **253 passed / 0 failed /
0 skipped / exit 0**. All seven Pass 1 security invariants re-verified.
Original OneDrive repo, worktrees, running stack, `.env` — untouched.

---

## A. Exact starting state

| Item | Value |
|---|---|
| Work clone | `C:\Users\heero\Sentinel-43-work` (branch `integration/beta-hardening-20260901`) |
| HEAD at start | `4dbd4a9` (Pass 1 handoff commit); substantive Pass 1 code state `49eba9f` |
| `git status` | clean · `git fsck --full` 0 errors |
| merge-base with `origin/main` | `8d2b80f` (== `origin/main`) · `49eba9f` is an ancestor of HEAD |
| Original repo `C:\Users\…\OneDrive\…\Sentinel-43` | HEAD `e859b61`, `## main...origin/main [ahead 1]`, fsck clean — **unchanged**, re-verified at start and end |

## B. Exact ending commit

- Branch `integration/beta-hardening-20260901`
- **HEAD after this handoff commit: see `git rev-parse HEAD`** (this file is the last commit)
- Substantive/tested code state: **`f245cf3`** (docs+code); `d530462` adds `PASS2_VALIDATION.md`; the handoff commit adds this file. `git diff 4dbd4a9..f245cf3` = 11 files, +873 / −105.
- Local only. Not pushed. No PR.

## C. Firewall configuration architecture discovered

```
env  ->  core/middleware/sentinel_firewall.py  (compat shim: imports the real
         FirewallConfig/SentinelFirewall from
         core/api/middleware/sentinel_firewall_middleware.py and attaches
         FirewallConfig.from_env())
     ->  core/middleware/__init__.py  (loader; prefers the shim path, asserts from_env)
     ->  core/api/main.py  app.add_middleware(SentinelFirewall,
                                config=FirewallConfig.from_env(), ...)
     ->  SentinelFirewall.__init__  (instantiated when the ASGI stack builds,
                                NOT at add_middleware time) -> _parse_networks() x3
     ->  per request: _screen_scope -> _resolve_client_ip / _screen_ip /
                                _screen_path / _screen_headers / _screen_content_length / rate-limit
```

Note: `app.add_middleware()` only records `(cls, kwargs)`; the middleware
object (and its CIDR parsing) is built later, on ASGI-stack construction —
so config errors that live in `__init__` surface at app startup, and
`from_env()` errors surface at import. Pass 2 makes `from_env()` catch the
CIDR errors too, so they all fail at the same early, fail-closed point.

Two physical `FirewallConfig` definitions exist; the runtime one is
`core/api/middleware/sentinel_firewall_middleware.py`. The other
(`core/monitoring/Sentinel_firewall .py`, finding A4) is orphaned — not
reconciled (Pass 7 cleanup).

## D. 3f65ca1 field-mapping audit

Full table in `PASS2_VALIDATION.md`. Result: **every `S43_FIREWALL_*` /
`S43_TRUSTED_PROXIES` env var maps to a real `FirewallConfig` constructor
parameter with the intended type.** `3f65ca1`'s key rename was correct.
`allowed_origins` (CORS) is correctly not a firewall field. The gaps
3f65ca1 left (and Pass 2 closed): unset var overriding a default; blank
`blocked_path_prefixes` wiping the built-ins; no load-time validation of
CIDRs / bools / ints.

## E. Security-default findings

| ID | Finding | Fix | Test |
|---|---|---|---|
| **P2-1 (High)** | `blocked_path_prefixes` — the 11 built-in dangerous-path prefixes (`/.git`, `/.env`, `/wp-admin`, `/actuator`, `/debug`, `/vendor`, `/node_modules`, …) were **replaced with `()`** whenever `S43_FIREWALL_BLOCKED_PATHS` was unset — i.e. in **every deployment** (`.env`, compose, k8s all leave it unset). `blocked_path_contains` still caught `/.env` + traversal; `/.git`, `/wp-admin`, `/actuator` etc. passed through. | `326bed8` — `_build_config_kwargs()` only passes a kwarg when the env var is set; a set-but-blank `S43_FIREWALL_BLOCKED_PATHS` keeps the default (with a warning). | `test_firewall_config_hardening.py`: absent / `""` / `"   "` / `","` all keep the 11; explicit value replaces. |
| P2-4 (Med) | malformed `S43_FIREWALL_ENABLED` / `_MAX_BODY_BYTES` / a bad CIDR were logged-and-defaulted | `326bed8` — `_env_bool` / `_env_int` raise; new `_env_cidr_csv` validates every IP/CIDR at load; `_parse_networks` raises (naming the field). All propagate to `9164f43`'s fail-closed handler. | `test_firewall_config_hardening.py`: `maybe` / `10MB` / `nonsense` / `10.0.0.0/99` / `999.1.1.1` → `ValueError` from `from_env()`. |

The 5 config states (absent / `""` / valid / malformed / boundary) are
tabulated per field in `PASS2_VALIDATION.md`.

## F. Trusted-proxy model and hop-selection behavior

| ID | Finding | Fix |
|---|---|---|
| **P2-2 (was RELEASE_FINDINGS #7, Critical)** | `_resolve_client_ip()`: `if self._trusted_proxy_networks and not _ip_in_networks(direct_ip, …)` — the `and` short-circuits when the trusted list is empty (the default, `S43_TRUSTED_PROXIES` unset or `""`), the guard is skipped, and `X-Forwarded-For`'s first entry is taken as `client_ip` **from any peer**. Spoofable past `blocked_ip_cidrs` / `allowed_ip_cidrs`; poisons the rate-limiter key and the monitoring `source_ip`. #7 was marked RESOLVED by `3f65ca1`, but `3f65ca1` only fixed the env→field plumbing (#8) — the doc, the finding, and `test_firewall_trusted_proxy_config.py`'s comment all *asserted* "unset = trust nobody" without it being true. | `326bed8` |

Post-fix `_resolve_client_ip`:
1–3. `respect_x_forwarded_for` off / unparseable direct peer ⇒ direct peer.
4. **no trusted proxies ⇒ direct peer** (was: fall through to trusting XFF).
5. direct peer not in trusted set ⇒ direct peer.
6. no / empty XFF ⇒ direct peer.
7. **walk XFF right-to-left**: unparseable entry ⇒ direct peer; trusted-proxy hop ⇒ skip; first non-trusted ⇒ that's the client.
8. whole chain trusted ⇒ direct peer.

`Forwarded` (RFC 7239) is read nowhere ⇒ cannot spoof (P2-3 — not a defect;
adding a parser is a deferred feature). 22 cases in
`test_firewall_proxy_trust.py` (direct / untrusted XFF / untrusted
`Forwarded` / peer-not-trusted / spoof-cannot-evade-block /
spoof-cannot-forge-allowlist / single-hop / multi-hop / mixed
client-prepended chain / whole-chain-trusted / malformed / empty /
`respect=False` / IPv4 / IPv6 / IPv4-mapped-IPv6 / duplicate headers /
casing+whitespace).

## G. Server-level proxy behavior

- All three deployment configs launched `uvicorn … --host 0.0.0.0 --port
  8000` with **no** `--proxy-headers` / `--forwarded-allow-ips`. uvicorn
  0.52.4 default: `--proxy-headers` on, `--forwarded-allow-ips` = `127.0.0.1`
  / `$FORWARDED_ALLOW_IPS`.
- **Currently safe**: verified `ProxyHeadersMiddleware(trusted_hosts=
  "127.0.0.1")` does not rewrite `scope["client"]` for a non-loopback peer.
  External requests in this containerized deployment are never `127.0.0.1`.
- **Footgun (P2-5, Med)**: `FORWARDED_ALLOW_IPS=*` (a common container
  copy-paste) ⇒ uvicorn rewrites `scope["client"]` from XFF for any peer,
  before SentinelFirewall ever runs — defeats P2-2's fix.
- **Mitigation (`52ea75d`)**: pin `--forwarded-allow-ips 127.0.0.1` on the
  API command in `core/api/Dockerfile`, `docker-compose.yml`,
  `deploy/kubernetes/base/s43-api-deployment.yaml`. Verified an explicit CLI
  value beats the env var (`uvicorn.Config(forwarded_allow_ips="127.0.0.1")`
  wins over `FORWARDED_ALLOW_IPS=*`). Behavior-preserving. A guard test
  asserts the flag stays in each file. `S43_TRUSTED_PROXIES` remains the one
  authoritative proxy-trust knob. **Full deploy-time validation (TLS scheme
  handling behind a real proxy) deferred to the deployment pass.**

## H. Fail-closed startup findings

| ID | Finding | Fix |
|---|---|---|
| **P2 / RELEASE_FINDINGS #9 (High)** | `core/api/main.py`: `try: … app.add_middleware(SentinelFirewall, config=FirewallConfig.from_env(), …) except ImportError: warning / except Exception: error` — any import / config / registration failure ⇒ **API boots and serves with no firewall.** | `9164f43` — single `except Exception`; `RuntimeError` at import when `not _is_local_environment()`; loud `logger.error` + continue in `SENTINEL_ENV` ∈ {development, dev, local, test}. `S43_FIREWALL_ENABLED=false` stays the honest opt-out. |
| Circular import (pre-existing, exposed by the above) | `core/api/__init__.py` did `from .main import app` at package init ⇒ `import core.api.middleware.<x>` pulled the whole app ⇒ `core.middleware.sentinel_firewall` → `core.api.middleware.*` → `core.api` → `core.api.main` → `from core.middleware import SentinelFirewall` hit a half-initialized `core.middleware` → `ImportError`. The old fail-open handler swallowed it (silently firewall-less). | `9164f43` — `core/api/__init__.py` exposes `app` lazily via PEP 562 `__getattr__`. Nothing imports `from core.api import app`; `uvicorn core.api.main:app` reads `app` off the module. Both import orders verified. |

Evidence (subprocess tests): `SENTINEL_ENV=production` + bad bool ⇒ non-zero
exit + "required security control", firewall absent; + bad CIDR ⇒ same;
`SENTINEL_ENV=test` + bad config ⇒ exit 0, firewall absent; default ⇒ exit 0,
firewall present.

## I. Files changed and why

| File | Change |
|---|---|
| `core/middleware/sentinel_firewall.py` | P2-1 (`_build_config_kwargs` only-if-set + `keep_default_when_blank` for `blocked_path_prefixes`); P2-4 (`_env_bool`/`_env_int` raise; `_env_cidr_csv` validates CIDRs at load); `_ENV_FIELD_MAP` table. |
| `core/api/middleware/sentinel_firewall_middleware.py` | P2-2 (`_resolve_client_ip`: empty trusted ⇒ direct peer; right-to-left hop walk); P2-4 (`_parse_networks` raises on bad CIDR, names the field). |
| `core/api/main.py` | P2/#9 fail-closed firewall registration. |
| `core/api/__init__.py` | lazy `app` (PEP 562) — break the circular import #9's fix exposed. |
| `core/api/Dockerfile`, `docker-compose.yml`, `deploy/kubernetes/base/s43-api-deployment.yaml` | P2-5 `--forwarded-allow-ips 127.0.0.1` on the API uvicorn command. |
| `RELEASE_FINDINGS.md` | correct #7 (resolved by `326bed8`, not `3f65ca1`), #8 (re-verified), #9 (resolved `9164f43`); add P2-1..P2-5. |
| `docs/security/trusted_proxy_handling.md` | rewrite: two-part fix, hop walk, uvicorn pin, real behavior change for existing deployments. |
| `core/tests/test_firewall_config_hardening.py`, `core/tests/test_firewall_proxy_trust.py` | new — 47 cases. |
| `PASS2_VALIDATION.md`, `HANDOFF_PASS2.md` | new. |

## J. Tests added

`core/tests/test_firewall_config_hardening.py` (27 items) and
`core/tests/test_firewall_proxy_trust.py` (20 items) — see D/E/F/G/H and
`PASS2_VALIDATION.md` for the case lists.

## K. Exact focused-test results

Env: `.venv-pass1`, Python 3.13.5, pytest 9.1.1, `S43_WATCHTOWER_URL=
http://127.0.0.1:59999`.

```
pytest core/tests/test_firewall_config_hardening.py \
       core/tests/test_firewall_proxy_trust.py \
       core/tests/test_firewall_trusted_proxy_config.py -q
=> 49 passed, exit 0
```
Standalone: `test_firewall_config_hardening.py` 27 · `test_firewall_proxy_trust.py`
20 · `test_firewall_trusted_proxy_config.py` 2.

## L. Exact full-suite results

Tested commit `f245cf3`. Same env.
```
pytest core/tests/ --ignore=core/tests/test_bootstrap.py \
       --ignore=core/tests/test_system_smoke.py -q
```
Collection **253 items** (15 files, 2 ignored).
**253 passed · 0 failed · 0 skipped · 0 xfail · 0 xpass · exit 0** · ~67 s.
5 unique warning locations — **unchanged from Pass 1** (`HTTP_422_
UNPROCESSABLE_ENTITY` / testclient-httpx deprecations; pre-existing
`core.monitoring.sparta_core` ImportWarning). No new warnings.
206 (Pass 1) + 47 (Pass 2) = 253.

`test_bootstrap.py` / `test_system_smoke.py` excluded — live HTTP to
`localhost:8000`, `requests` not in `requirements.txt` — no-live-contact
constraint, same as Pass 1. Covered in-process by `test_bootstrap_isolated.py`.

## M. Pass 1 invariant regression results

Pass 1 SI script: **13/13**. Per-suite: `test_v1_auth` 5, `test_users_admin`
25, `test_watchtower_service_auth` 53, `test_watchtower_bridge_auth` 8,
`test_firewall_trusted_proxy_config` 2 — all pass. SI-5 re-verified by
re-parsing `docker-compose.yml` (`s43-core` has no `ports:`). **No Pass 1
invariant regressed.**

## N. Unresolved / deferred findings

1. **P2-3** — parse RFC 7239 `Forwarded`. Not a defect (it is ignored, so
   inert). Adding a parser is a feature; deferred.
2. **P2-5 full validation** — deploy behind a real reverse proxy, confirm
   `X-Forwarded-Proto` scheme handling with `--forwarded-allow-ips` pinned.
   Needs a deployment ⇒ deferred to Pass 6.
3. **A4** — two physical `FirewallConfig` files;
   `core/monitoring/Sentinel_firewall .py` orphaned. Pass 7 cleanup.
4. Carried from Pass 1 (not this pass's scope): test-ordering env fragility;
   `/users` HTTP 500 vs 503 without `DATABASE_URL`;
   `HTTP_422_UNPROCESSABLE_ENTITY` deprecation; `require_admin` ↔
   `require_operator` de-dup; `core.monitoring.sparta_core` casing;
   `docker-compose.yml` `s43-setup` path.
5. `deploy/kubernetes/overlays/beta/configmap-patch.yaml` ships
   `S43_TRUSTED_PROXIES: "CHANGEME_..."`. Post-Pass-2 that placeholder is a
   **fail-closed startup error** (invalid CIDR) rather than a silent no-op —
   an operator must fill it in. Documented in
   `docs/security/trusted_proxy_handling.md`; the overlay file itself is
   left as-is (an operator TODO, not a bug).

## O. Confirmation — no live/external/prohibited mutations

Confirmed: no push / force-push / merge to `main` or `origin/main` / PR
create-merge-close / branch-tag-stash-object deletion / history rewrite /
`reset --hard` or `clean` on the original / repo-visibility or GitHub-
settings change / running-Compose-stack change (no stop/start/rebuild/
restart/network/port/volume) / live-DB access or mutation / migration /
credential rotation / external deployment / secret disclosure / removal of
Pass 0 or Pass 1 recovery material.
Mutations performed, all authorized: 7 commits on the local branch
`integration/beta-hardening-20260901` in the non-synced work clone; `pip`
was not re-run (venv unchanged); added
`C:\Users\heero\AppData\Local\sentinel43-recovery\pass2-20260901\`.

## P. Proposed Pass 3 scope

Per this mission's Pass 3 — **account transactions and bootstrap
correctness** — against `integration/beta-hardening-20260901`:

1. Trace every caller of `create_user`, `authenticate_user`,
   `reverify_password`, and the bootstrap flow before changing any
   transaction ownership. Prove `update_last_login=False` (the
   `reverify_password` path) writes no `last_login_at`.
2. First-admin creation must be atomic across independent processes /
   replicas. `count_active_admins() == 0` + an in-process lock is not
   enough. Choose a DB-backed serialization (advisory lock / a single-row
   lock table / a partial unique index on `role='admin'`), make the decision
   inside the protected transaction, and test with concurrent requests on
   independent Postgres connections. (RELEASE_FINDINGS #12.)
3. Put commit/rollback ownership at a deliberate transaction boundary; use
   `flush` in helpers where appropriate; update every caller; test failed
   inserts, conflicts, rollback, and the absence of partial accounts. Do not
   `ALTER ROLE` or migrate the live DB.
4. Review: role validation (app + DB), disabled-account handling, password-
   verification exception paths, timing differences, Argon2 rehash need,
   bounded off-event-loop hashing, resource / rate limits. Report separately
   what needs a broader policy decision.
5. No silent username/email normalization, no new uniqueness constraint
   without a collision inventory + an approved migration. `create_all` is
   not a migration path — exercise any migration on a disposable DB and
   document backup/recovery.
6. Also covers RELEASE_FINDINGS **#11** (env-account bare SHA-256).
   Finding #10's full plaintext-password-removal redesign is **Pass 4**
   (auth redesign spec), not Pass 3.

---
Stop. No Pass 3, no push, no deploy. Await explicit authorization.
