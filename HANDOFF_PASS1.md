# Sentinel-43 — Pass 1 Handoff

- Date: 2026-09-01
- Pass run: **Pass 1 only** (integrate existing work + establish baseline). Stopped here.
- Do NOT begin Pass 2 without explicit approval.

## Short outcome

Integrated `release/beta-production-hardening` (9 commits) and
`pass1/watchtower-exposure` (5 commits) into a new branch off `origin/main`,
both merges **conflict-free**. Hand-transferred only the unique
user-management feature from `e859b61` (NOT a wholesale cherry-pick),
reconciling `deps.py` so the Critical `5332d54` `/v1` bypass fix is fully
preserved. Wired the users router into `main.py` from the GitHub-web
`Koklar21-patch-295950` edit, keeping the bootstrap comment it dropped.
Full in-process suite: **206 passed / 0 failed / 0 skipped / exit 0** in a
fresh venv. 7 security invariants verified (tests + explicit live checks).
Original OneDrive repo, worktrees, running stack, and `.env` untouched.

---

## A. Exact starting state

| Item | Value |
|---|---|
| Original repo | `C:\Users\heero\OneDrive\Documents\GitHub\Olympus_Complete_Dropin\Sentinel-43` |
| Original `main` HEAD | `e859b61e31aa3cbd7c8a5a1b939b307627d9069a` (unchanged from Pass 0) |
| `origin/main` | `8d2b80f95d54c259ee119984fbf4d4f3d3ea9615` |
| `pass1/watchtower-exposure` | `6dd3a7ef504f5f7964c4d2aefae93c3d1e104ff5` |
| `release/beta-production-hardening` | `79a9d4256a847006beb15ca7b3e019d55f254ac2` |
| `origin/Koklar21-patch-295950` | `0943f92e400f15d984d45e5c0b8d394ab647fecb` |
| tag `pre-beta-hardening-20260830` | `4e281bc41566097899e0b5161d911e9a34aa9de7` |
| Original repo `git status` | `## main...origin/main [ahead 1]`, working tree clean |
| Original repo `git fsck` | clean (0 error/missing/broken/corrupt) |
| `git fetch origin` (authorized) | exit 0, no ref updates |

All refs re-verified against the Pass 0 report before any work — **all matched**.

**Working location (Pass 1 decision: Option B).** New non-synced clone:
`C:\Users\heero\Sentinel-43-work` — `git clone --no-hardlinks` of the OneDrive
repo (read-only on the source), then `origin` re-pointed to
`https://github.com/Koklar21/Sentinel-43.git` and the OneDrive repo kept as
remote `evidence-local`. **Push disabled on both remotes**
(`git remote set-url --push … DISABLED_NO_PUSH`). Fresh venv
`C:\Users\heero\Sentinel-43-work\.venv-pass1` from `requirements.txt` + `pytest`.

## B. Exact ending commit SHA

- Integration branch: `integration/beta-hardening-20260901`
- **HEAD: `49eba9fedf2a1e13d551ea9faf07da0cc57ac5d5`**
- Tested commit: `431f97c50cfc8fdb275f21a7547ff1c0022acde6` (HEAD minus the
  docs-only `PASS1_VALIDATION.md`; suite re-run at `49eba9f` — identical 206/206)
- Base: `8d2b80f` (`origin/main`). `git diff --stat 8d2b80f HEAD` → 37 files, +3939 / −134.
- Branch is **local only. Not pushed.** No PR.

## C. Commits integrated

```
49eba9f  Add Pass 1 integration validation report            (docs)
431f97c  Include test_health_check_log_filter.py (step 5)
9431356  Wire users router into main.py (step 4)
f8cd8bc  Add admin user-management feature (step 3)
05d844b  Integrate pass1/watchtower-exposure (step 2)  [merge of 6dd3a7e]
c0e46a0  Integrate release/beta-production-hardening (step 1) [merge of 79a9d42]
8d2b80f  (origin/main) Delete requirements-test.txt
```

Via the two merges:
- **release** `5332d54` `/v1` JWT scope→role bypass fix · `3f65ca1` firewall
  compat-shim real fields + restore `docs/security/trusted_proxy_handling.md` ·
  `6cf7e97` stop rewriting `last_login_at` (its `core/auth/users.py` part was
  already on `origin/main` via `33fe635`, byte-identical — merge no-op for that
  file) · `c7a7502` non-root Dockerfile · `0eb4941` recovered regression tests ·
  4 doc commits (`RELEASE_FINDINGS.md`, `RELEASE_HARDENING_PLAN.md`,
  `CLEANUP_INVENTORY.md`, `VALIDATION_REPORT.md`, `DEPLOYMENT_RUNBOOK.md`,
  `ROLLBACK_RUNBOOK.md`).
- **pass1** `59e9a73` Watchtower service-token auth + `:9100` host-publish
  removal + bridge authz (F-01/F-02) · `a20e37c` minimize disclosure (F-03/F-07)
  · `ab19b14` Fenrir→Watchtower path (F-06) · mission doc
  (`MISSION_PASS1_WATCHTOWER_EXPOSURE.md`).

## D. Files intentionally extracted from `e859b61`

**Taken (blobs verified identical to `e859b61`):**
- `core/api/routers/users.py` (new, 315) — admin-gated account CRUD
- `core/tests/test_users_admin.py` (new, 569)
- `core/api/deps/__init__.py` — `require_admin` export (+3)
- `core/auth/users.py` — helper fns `get_user_by_id`, `list_users`,
  `set_user_active`, `set_user_role`, `set_user_password` (+50 over the
  base that already had `33fe635`/`6cf7e97`)
- `core/tests/test_health_check_log_filter.py` (new, 258) — step 5 decision

**Hand-merged (could NOT `checkout e859b61 --` — it predates `5332d54`):**
- `core/api/deps/deps.py` — added only `require_admin()` + its 3 imports
  (`Depends`, `AsyncSession`, `get_db_session`) + the `__all__` entry.
  `git diff release:deps.py deps.py` == exactly those additions, nothing else.

**Deliberately NOT taken from `e859b61`** (duplicates of hardening-branch
work, or its divergent variant):
- `core/api/Dockerfile`, `core/api/routers/auth.py`,
  `core/middleware/sentinel_firewall.py` — identical to `release`, taken via
  the release merge
- `core/monitoring/watchtower.py` — `e859b61`'s divergent 16-line variant
  (`96c66ddc`); the integrated file is `pass1`'s (`326acdfd`)
- `core/tests/{test_auth_login,test_bootstrap,test_bootstrap_isolated,
  test_v1_auth,test_internal_broadcast_auth,test_actions_test_inject_auth,
  test_firewall_trusted_proxy_config}.py`, `scripts/S43_System.Tests.ps1` —
  identical to `release`, taken via the release merge
- `core/api/main.py` — `e859b61` did not modify it (step 4 sourced from
  `Koklar21-patch-295950` instead)

## E. Conflicts encountered and semantic resolutions

**No git merge conflicts.** `git merge-tree --write-tree` dry-run: exit 0 for
both merges. Reason: `origin/main` (`8d2b80f`) diverges from the merge-base
`4e281bc` only in `core/auth/users.py` (`33fe635`, byte-identical to release's
`6cf7e97` change) and `requirements-test.txt` (deleted, untouched by either
branch); `release` and `pass1` themselves touch disjoint file sets.

**Semantic reconciliations done by hand (not git conflicts):**

| # | Where | Two intents | Combined result |
|---|---|---|---|
| E-1 | `core/api/deps/deps.py` | `5332d54`: `require_operator` must use the canonical `verify_jwt_token()`; the second verifier `_verify_operator_jwt` + `scope`→`role` fallback + module JWT constants are removed. — vs — `e859b61`: add `require_admin`, which in `e859b61` sat on top of the *pre-5332d54* deps.py. | Kept `5332d54`'s deps.py verbatim; appended `require_admin` only. `require_admin` is an independent function — it does its own `verify_jwt_token()` + `reverify_password()` + live-DB admin check and never touches `require_operator`. Verified: `require_operator` source still contains `verify_jwt_token(token)`, no `scope_claim`, no `_verify_operator_jwt`, no `JWT_SECRET` module attr. One stale docstring sentence in `require_admin` (claimed it avoids `require_operator` because that had "frozen JWT constants" — `5332d54` removed those) rewritten to a factual note; **logic byte-identical to `e859b61`**. Recommended follow-up (Pass 2+): `require_admin` could now simply `Depends(require_operator)` + the DB check — deferred, not done in Pass 1. |
| E-2 | `core/api/main.py` | `pass1`: Watchtower auth/exposure edits (import block untouched by pass1; router-list untouched). — vs — `Koklar21-patch-295950`: add `users_router` import + `include_router`, and (incidentally) delete a 5-line bootstrap-naming comment. | Applied the 2 additions onto `pass1`'s main.py at the same anchor points (`0943f92`'s placement). **Did NOT apply the comment deletion** — authorization step 4 requires preserving unrelated comments absent a technical reason; there is none. `git diff pass1:main.py main.py` == exactly the 2 additions; bootstrap comment intact. |
| E-3 | `core/auth/users.py` | `33fe635` (main-line) vs `6cf7e97` (release) — the `update_last_login` change. | Byte-identical on both sides (`28c79ac`→`788b916`). Git auto-resolved to `788b916`. Then `e859b61`'s 5 helper functions layered on (that file on `e859b61` == this base + helpers, nothing else). |
| E-4 | `test_firewall_trusted_proxy_config.py` | On `release` (`3f65ca1`) and byte-identical on `e859b61`. | Taken once via the release merge. No duplicate. |

**No conflict was left ambiguous. No STOP condition was hit.**

## F. Security invariants verified

| ID | Invariant | Evidence | Result |
|---|---|---|---|
| SI-1 | `5332d54` preserved: `/v1/*` rejects a `scope="operator"` / no-`role` token (403); `require_operator` delegates to `verify_jwt_token`; `_verify_operator_jwt` + JWT module constants gone. | `git diff`, source assertions, `test_v1_auth.py` (5), Step 7 live: `POST /v1/assess` scope-only → **403** | PASS |
| SI-2 | `require_admin` gates `/users`: 401 no-auth, 403 operator-not-admin, 401 admin-without/with-wrong password; role read from live DB. | `test_users_admin.py` (25), Step 7 live (4/4) | PASS |
| SI-3 | Watchtower bridge `/watchtower/{modules,check,status}` → 401 anon (F-01/F-02); `/watchtower/{health,ready}` + `/health` open with minimal bodies (F-03); internal Watchtower app has no `/docs` (F-07); service token 503 fail-closed. | `test_watchtower_service_auth.py` (53), `test_watchtower_bridge_auth.py` (8), Step 7 live (5/5) | PASS |
| SI-4 | `e859b61`'s divergent `watchtower.py` variant NOT present. | blob == `pass1` `326acdfd`, != `e859b61` `96c66ddc` | PASS |
| SI-5 | `:9100` host publication removed from `docker-compose.yml`. | source grep — no `ports:` on `s43-core`, only a commented rollback hint | PASS (static; not deployed) |
| SI-6 | Firewall compat shim maps `trusted_proxy_cidrs` etc. to real fields (`3f65ca1`). | `test_firewall_trusted_proxy_config.py` (2) | PASS |
| SI-7 | users router mounted (`/users` not 404). | Step 7 SI-4, `test_users_admin.py` | PASS |

## G. Full test results

Fresh venv `C:\Users\heero\Sentinel-43-work\.venv-pass1`. OS Windows 11 Home,
Python 3.13.5, pytest 9.1.1. Package versions: fastapi 0.141.1, starlette 1.6.0,
pydantic 2.13.5, httpx 0.28.1, PyJWT 2.13.0, SQLAlchemy 2.0.52, asyncpg 0.31.0,
argon2-cffi 25.1.0, aiohttp 3.14.3, anyio 4.14.2, uvicorn 0.52.4.

Run env: `S43_WATCHTOWER_URL=http://127.0.0.1:59999`, `S43_WATCHTOWER_TIMEOUT=0.2`
(fast-fail the lifespan's watchtower calls; no `s43-core` DNS). No other env —
test modules self-set `S43_JWT_*` via module-level `os.environ.setdefault`.

```
python -m pytest core/tests/ \
  --ignore=core/tests/test_bootstrap.py \
  --ignore=core/tests/test_system_smoke.py -q
```

**206 passed · 0 failed · 0 skipped · 0 xfail · 0 xpass · exit 0** · ~63 s.
Collection: 206 items from 13 files. 5 unique warning locations (all benign —
`HTTP_422_UNPROCESSABLE_ENTITY` deprecation from fastapi+starlette 1.6, the
`httpx`/testclient deprecation, and the pre-existing
`core.monitoring.sparta_core` ImportWarning; details in `PASS1_VALIDATION.md`).

Per file: test_actions_test_inject_auth 6 · test_auth_login 16 ·
test_bootstrap_isolated 4 · test_firewall_trusted_proxy_config 2 ·
test_health_check_log_filter 25 · test_internal_broadcast_auth 5 ·
test_jwt_auth 37 · test_policy_gate_smoke 6 · test_users_admin 25 ·
test_v1_auth 5 · test_watchtower_bridge_auth 8 · test_watchtower_service_auth 53 ·
test_ws_auth 14. Each file also passes standalone.

**Not run:** `test_bootstrap.py`, `test_system_smoke.py` — both hit
`http://localhost:8000` over real HTTP (would contact the running Compose
stack, incl. `POST /bootstrap/admin`) and import `requests` (absent from
`requirements.txt` since `requirements-test.txt` was deleted at `8d2b80f`).
Excluded per the no-live-contact constraint. Covered in-process by
`test_bootstrap_isolated.py` (4, PASS).

Prior undocumented totals ("144" / "105") are neither summed nor compared —
this run is the evidence for the integrated tree.

## H. Failures / deferred findings

No test failures in the full run. Deferred (non-blocking):

1. **Test-ordering fragility (pre-existing, NOT introduced).** Several test
   files — release's own `test_v1_auth.py` and the step-5
   `test_health_check_log_filter.py` — depend on a sibling module's
   collection-time `os.environ.setdefault` to set `S43_JWT_SECRET` before
   `core.api.main` freezes it at import. Full suite: fine (206/206). Some
   2-file partial invocations: the one app-level test in
   `test_health_check_log_filter.py` fails
   (`RuntimeError: S43_WS_REQUIRE_AUTH=true but S43_JWT_SECRET is not
   configured`). Fix (later pass): a `conftest.py` that pins test env once.
2. **`/users` returns HTTP 500 (not 503) when `DATABASE_URL` is unset.**
   `require_admin`'s `Depends(get_db_session)` raises `RuntimeError` before
   `require_admin`'s own try/except runs. Same behavior as `bootstrap.py`'s
   DB-backed routes. Fails closed (no access granted). Real deployments set
   `DATABASE_URL`. Fix (later pass): make `get_db_session` (or a wrapper)
   raise a clean 503, or catch at the router.
3. **`core/api/routers/users.py` uses `status.HTTP_422_UNPROCESSABLE_ENTITY`**
   (deprecated in starlette 1.6). Matches existing `bootstrap.py` usage.
   Cosmetic; codebase-wide rename candidate.
4. **`require_admin` duplicates the `require_operator` auth sequence.**
   Post-`5332d54` it could be `Depends(require_operator)` + the DB check.
   Left as transferred (Pass 1 = integrate, not redesign). Recommend for a
   cleanup/auth pass.
5. Carried forward from Pass 0 (unchanged, not this pass's scope):
   `core/monitoring/sparta_core` casing ImportWarning; `s34_auth/watchtower.py`
   dead module; `docker-compose.yml` `s43-setup` referencing
   `scripts/generate_secrets.py` (real path `core/scripts/`); env-account
   bare-SHA-256 fallback; `/bootstrap/admin` concurrent-first-admin race;
   `_ws_safe_close` reason gap; `/events/proxy` `raw` rebroadcast. See
   `RELEASE_FINDINGS.md` (now in the tree).

## I. Provenance findings — `e859b61` "Agent Host changes for main"

Read-only local git metadata only; no external contact. **Formally UNCONFIRMED.**
Investigation ran *after* integration was complete — it did not delay or alter
the sequence, and found no material integrity/security problem (no STOP).

- Raw object: `parent 8d2b80f`, `tree ad27aea0`; `author` == `committer` ==
  `Justin Armstrong <86022347+Koklar21@users.noreply.github.com>`; author time
  == committer time == `1788286098 -0600` (2026-09-01 12:08:18 MDT); **no GPG
  signature**; message `Agent Host changes for main`, no body/trailers.
- Committer identity is the account's `noreply` address — **not**
  `GitHub <noreply@github.com>`, which is what a github.com web edit stamps
  (cf. `8d2b80f`, committer `GitHub <noreply@github.com>`). ⇒ **not** made via
  the github.com web editor.
- Reflog: plain local `commit:` at 12:08:18, then a `git reset` (to HEAD, no
  move) at 12:14:49. `.git/COMMIT_EDITMSG` == the message. No repo hooks.
  "Agent Host" appears nowhere in tracked files or `.git/config`.
- ⇒ Consistent with an **automated coding-agent / host tool performing a local
  `git commit` of the working tree** under Justin's configured git identity.
  The specific tool cannot be identified from local metadata.
- The commit object is well-formed; its tree is exactly the known union of the
  prior session's user-mgmt work + loose-applied hardening files + untracked
  tests (verified in Pass 0 and re-verified during Step 3 blob comparisons).
- **Not pushed. Not modified by this pass. Not used as the integration base.**
- Open question for Justin (also Pass 0 decision #5): did you run an
  automated agent/host tool on ~Sep 1 12:08 that would have made this commit?

## J. Exact git status

**Work clone** `C:\Users\heero\Sentinel-43-work`:
```
On branch integration/beta-hardening-20260901
nothing to commit, working tree clean
HEAD = 49eba9fedf2a1e13d551ea9faf07da0cc57ac5d5
git fsck --full: 0 errors  (dangling objects only, expected)
remotes: origin -> github.com/Koklar21/Sentinel-43 (push DISABLED);
         evidence-local -> the OneDrive repo (push DISABLED)
.venv-pass1/ present, untracked, added to .git/info/exclude
```

**Original repo** `…\OneDrive\…\Sentinel-43` (verified post-Pass-1, **unchanged**):
```
HEAD = e859b61e31aa3cbd7c8a5a1b939b307627d9069a   (== Pass 0)
## main...origin/main [ahead 1]
git fsck --full: 0 errors
```
`…\Sentinel-43-hardening-b8` worktree: untouched. Running Compose stack: untouched.

## K. Confirmation — no prohibited external/live mutations

Confirmed for this pass: **no** push / force-push / merge into `main` /
`origin/main` change / PR create-merge-close / branch-tag-stash-object
deletion / history rewrite / `reset --hard` or `git clean` on the original /
repo-visibility or GitHub-settings change / running-Compose-stack modification
(no start/stop/rebuild/restart, no network/port/volume change) / live-database
modification / credential rotation / external deployment / secret disclosure /
removal of Pass 0 recovery material.

Mutations performed, all authorized:
- created `C:\Users\heero\Sentinel-43-work` (`git clone --no-hardlinks`,
  read-only on the source) and its `.venv-pass1`
- committed 6 commits on the new local branch `integration/beta-hardening-20260901`
- `git fetch` from GitHub `origin` (authorized authenticated fetch) and
  `pip install` from PyPI into the venv (authorized dependency install, no TLS
  bypass)
- added `C:\Users\heero\AppData\Local\sentinel43-recovery\pass1-20260901\`
  (bundle of the integration branch + `PASS1_VALIDATION.md` + commit/diffstat lists)

## L. Proposed Pass 2 scope

Per THIS mission's Pass 2 — **firewall defaults, proxy trust, and fail-closed
startup** — against `integration/beta-hardening-20260901` @ `49eba9f`:

1. Read the real `FirewallConfig` definition
   (`core/api/middleware/sentinel_firewall_middleware.py`) and how
   `SentinelFirewall` is registered in `core/api/main.py`. `3f65ca1` already
   remapped `_build_config_kwargs()` to real field names — Pass 2 confirms the
   mapping against the actual constructor and its callers, and checks the four
   states (unset / explicitly empty / valid / invalid) per field.
2. Verify constructor security defaults survive when env vars are absent —
   in particular that an unconditional empty `blocked_path_prefixes` cannot
   erase built-in protections. Test unset vs `""` vs valid vs invalid
   separately. Decide + document whether empty security settings are allowed.
3. Empty trusted-proxy config ⇒ trust **no** forwarded headers. Test the full
   trusted-hop chain, malformed `X-Forwarded-For` / `Forwarded`, IPv4/IPv6,
   multiple hops. Also inspect server-level proxy handling (uvicorn
   `--proxy-headers` / any upstream) — the middleware's apparent client addr
   may already be rewritten.
4. Remove any silent fallback that constructs a default config after the
   configured construction fails. Invalid CIDR / bool / non-positive limit /
   unsupported field ⇒ a clear sanitized config error; required firewall
   registration failure ⇒ refuse to serve.
5. Tests: actual request handling (default sensitive paths, allow/block IP
   precedence, header/body limits, spoofed forwarded headers, trusted-proxy
   behavior, startup failure). Then the focused + full regression suite from
   the exact commit, isolated env.
6. Also addresses findings **#7, #8, #9** and **A6** from `RELEASE_FINDINGS.md`
   (7/8 already RESOLVED by `3f65ca1`; #9 "firewall init failure allows
   startup without firewall" is the open item).

Deferred findings 1–4 from section H are candidates for later passes
(H-1 test hygiene → could fold into Pass 2's test work; H-2/H-4 → the auth
pass; H-3 → a cleanup pass).

---
Stop. Await approval for Pass 2.
