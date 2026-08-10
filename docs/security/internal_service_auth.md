# Sentinel-43 — Internal Service Authentication

Machine-to-machine routes do not use the dashboard operator auth model
(JWT + `X-S43-Password`). Each internal caller has its own dedicated
credential, checked independently of `_require_operator()` /
`require_operator()`.

## `/internal/events/broadcast` — FenrirHunter → dashboard

- **Caller:** `core/detection/feniri_hunter.py` (`FenrirHunter._broadcast_to_dashboard`).
  This is the only caller in the codebase (verified by grep for
  `internal/events/broadcast` across `core/` and `docker-compose.yml`).
- **Credential:** `S43_FENRIR_API_TOKEN` — a random token generated with
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`
  (see `docker-compose.yml`'s comment block), sent as
  `Authorization: Bearer <token>`.
- **Server-side check:** `core.api.main._require_fenrir_service_token()`.
  Reads `S43_FENRIR_API_TOKEN` from the environment at call time, fails
  closed with 503 if unset, and compares the bearer token against it with
  `secrets.compare_digest()` (constant-time). The token itself is never
  logged.
- **What this replaced:** the route previously called `_require_operator()`
  — the same JWT + `X-S43-Password` gate used by dashboard operator
  routes. Fenrir's `_headers()` only ever sends `Content-Type` and
  `Authorization`; it never sends `X-S43-Password`. Every real call from
  Fenrir was therefore rejected with 401 before the token was even
  inspected, and counted as a `broadcast_failures` metric — the
  dashboard-broadcast half of Fenrir's finding-reporting pipeline has
  likely never worked in any deployment. `_report_to_watchtower()` (the
  other half of `FenrirHunter._report_finding()`) is unaffected — Watchtower
  authenticates that call differently and was not part of this bug.
- **Why not reuse an operator JWT:** Fenrir is a background service with no
  human operator attached to it; minting or storing a long-lived operator
  JWT (plus a plaintext password for the `X-S43-Password` re-check) for a
  machine process is a larger secret-handling surface than a single shared
  token scoped to exactly one route.

## `/remote-gateway/*` — external remote gateway clients

Already implemented correctly before this sprint — documented here for
completeness, not changed:

- **Credential:** one of `SENTINEL_REMOTE_TOKEN_OWNER` /
  `SENTINEL_REMOTE_TOKEN_ADMIN` / `SENTINEL_REMOTE_TOKEN_AUDITOR`, sent as
  `Authorization: Bearer <token>`. Each token maps to a fixed
  `OperatorRole` (owner/admin/auditor).
- **Server-side check:** `core/api/routers/remote_gateway.py`'s
  `_resolve_operator_role()` / `_authenticate()`. Fails closed (503) if no
  tokens are configured at all, uses `secrets.compare_digest()` on a
  SHA-256 digest of the token (fixed-width, timing-safe), rate-limits
  repeated auth failures per client, and reports both rate-limiting and
  auth failures to Watchtower as security events.
- `POST /events/activate` additionally checks that the request body's
  claimed `operator_role` matches the role actually associated with the
  presented token, rejecting a mismatch with 403 and flagging it to
  Watchtower as a `privilege_escalation` CRITICAL event.
- Role-scoped audit visibility: `GET /audit/{correlation_id}` filters
  results by which roles the authenticated caller's role is permitted to
  see (owner sees all, admin sees admin+auditor, auditor sees only its own
  tier).

## Not internal-service (for contrast)

- `POST /events/proxy` — currently gated with `_require_operator()`
  (dashboard operator JWT + password), despite its docstring describing a
  "local proxy script" caller. Unlike Fenrir, there is no dedicated
  `S43_*_API_TOKEN` wired up for it in `docker-compose.yml`, so there's no
  evidence this one is broken the same way — it may simply mean "run the
  script with an operator's credentials." Left unchanged; flagged in
  `docs/security/endpoint_access_matrix.md` for Justin to confirm the
  intended caller before beta.
