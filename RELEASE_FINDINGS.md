# Sentinel-43 — Release Findings Ledger

- Repo: `Sentinel-43` · Base commit: `4e281bc41566097899e0b5161d911e9a34aa9de7` (tag `pre-beta-hardening-20260830`)
- This ledger reflects work from two concurrent sessions: `sentinel-43-b8` (this branch, `release/beta-production-hardening`) and `sentinel-43-9d` (`pass1/watchtower-exposure`, Watchtower exposure/auth). The peer's detailed live-probe evidence (Phase 0A/0B: full route tables, root-cause analysis, F-01..F-07, a Compose-vs-K8s exposure comparison) lives in **their own committed doc, `MISSION_PASS1_WATCHTOWER_EXPOSURE.md` on `pass1/watchtower-exposure`** — not duplicated here to avoid re-losing a second copy of 300+ lines to the file-loss issue noted in `VALIDATION_REPORT.md`. Merge that branch's doc in when the branches merge.

## 19-item prior-review confirm/refute

All 19 confirmed true against `main` @ base commit. None false positive.

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Compose publishes Watchtower on host `9100` | High | **RESOLVED** — `pass1/watchtower-exposure` removed the port publish |
| 2 | Watchtower permits unauthenticated reads/mutations | Critical | **RESOLVED** — `pass1/watchtower-exposure`, service-token auth added |
| 3 | `/watchtower/status` + `/api/watchtower/status` call `_require_operator` | Informational | N/A — working as intended |
| 4 | `/events/proxy` is ordinary HTTP POST | Informational | N/A — confirmed correct, not a defect |
| 5 | `/events/proxy` requires bearer JWT + `X-S43-Password` | Informational | N/A — confirmed correct |
| 6 | `_ws_safe_close` accepts only `websocket`, `code` | Low | Not started (peer's Pass 5 scope, not yet reached) |
| 7 | Firewall trusts XFF when trusted-proxy list is empty | **Critical** | **RESOLVED** — this branch, commit `3f65ca1` |
| 8 | Firewall shim config keys don't match real fields | **Critical** | **RESOLVED** — this branch, commit `3f65ca1` |
| 9 | Firewall init failure allows startup without firewall | High | Not started (this session's remaining lane) |
| 10 | Protected requests resend plaintext password | Medium | Partially addressed — `deps.py` bypass (A1) that let some tokens skip the *role* check is closed (`5332d54`); the full plaintext-password-removal redesign (Phase 3) is not started |
| 11 | Env-account fallback uses bare SHA-256 | High | Not started |
| 12 | `/bootstrap/admin` concurrent first-admin race | Medium | Not started |
| 13 | Prod requires `S43_SECRETS_ROTATED_AT`; Compose doesn't forward it | Medium | Not started |
| 14 | Unauthenticated status routes expose internal details | Low-Medium | Not started (this session's remaining lane — API's own `/config/status` etc.; Watchtower-side equivalents resolved by peer) |
| 15 | K8s CI claims to test auth, only requests public endpoints | High | Not started |
| 16 | Docker Scout `continue-on-error: true` | Medium | Not started |
| 17 | Compose runs API/Watchtower as root | High | **RESOLVED (image)** — this branch, commit `c7a7502`. Compose-side volume-ownership note still pending (deferred to avoid colliding with peer's in-flight `docker-compose.yml` edit). |
| 18 | Dependencies/base image not reproducibly locked | Medium | Not started |
| 19 | Proxy event ingestion rebroadcasts unrestricted `raw` | Medium | Not started |

## Additional findings (A1-A6, origin: `sentinel-43-b8`)

| ID | Finding | Severity | Status |
|---|---|---|---|
| A1 | `deps.py` second JWT verifier accepted `scope` claim as `role` substitute — live-exploitable, empirically proven (forged token: 401 on `/v1/assess` vs. 403 on `/watchtower/status` for the identical token) | **Critical** | **RESOLVED** — commit `5332d54` |
| A2 | CORS wildcard methods/headers + credentials, but explicit origin allow-list | — | False positive |
| A3 | ~244 `Koklar21-patch-*` remote branches, only 1 merge-eligible | Informational | Not actioned (Phase 11) |
| A4 | `core/monitoring/Sentinel_firewall .py` — orphaned, malformed filename | Low | Not actioned (recommend delete, see `CLEANUP_INVENTORY.md`) |
| A5 | `docker-compose.yml`'s `s43-setup` references nonexistent `scripts/generate_secrets.py` (real path: `core/scripts/`) | Medium | Not started |
| A6 | `docs/security/trusted_proxy_handling.md` deleted from `main` | Medium | **RESOLVED** — restored in commit `3f65ca1` |

## Peer findings F-01..F-07 (origin: `sentinel-43-9d`, detail on `pass1/watchtower-exposure`)

All reported **RESOLVED** on that branch as of their last message: Watchtower service-token auth, `:9100` host publish removed, API-bridge `/watchtower/modules`+`/watchtower/check` now authenticated, minimal `/health`+`/ready` bodies, OpenAPI docs disabled on the internal Watchtower app, Fenrir→Watchtower reporting path fixed. Not independently re-verified by this session — see `VALIDATION_REPORT.md`.

## Not yet audited to the same depth

Rate limiting internals, Sparta integrity monitoring, full K8s overlay diff against every Phase 8 control, migration idempotency, full test-suite auth coverage.

## Reporting requirement

Each fix closes with: root cause · scope · files changed · tests · commands+exit status · commit SHA. Repo is not production-ready until every finding above is RESOLVED or explicitly accepted, and the final deployment gate (blocked, no target — see `RELEASE_HARDENING_PLAN.md`) completes.
