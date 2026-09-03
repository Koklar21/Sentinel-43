# AUTH_TLS_POSTURE_PASS5A.md

Sentinel-43 — Pass 5A, Section 4: TLS / transport-security posture from
repository evidence.

**Scope of this document.** Establish, *from repository evidence only*, what
transport-security posture Sentinel-43 assumes before the browser-session
design (Secure cookies, `SameSite`, CSRF) is implemented. No live deployment
was inspected or altered (mission §4, §28). Where the repo does not establish
a secure production TLS posture, this is recorded as a **blocking deployment
finding** and the new browser-session design is **not** claimed
production-ready.

Code state inspected: integration branch `integration/beta-hardening-20260901`
@ `2f0c749` (runtime code identical to the Pass 3 validated state `86c9aab`;
Pass 4 was docs-only).

---

## 1. Questions this pass must answer

| # | Question | Answer (evidence-based) |
|---|---|---|
| Q1 | Does Sentinel-43 itself terminate TLS? | **No.** uvicorn is launched plain-HTTP on `:8000` in every artifact; no `--ssl-*` flag, no TLS config anywhere in the repo. |
| Q2 | Is TLS expected at an ingress / reverse proxy? | **Partially / by placeholder only.** The k8s **beta** overlay's `ingress.yaml` is the *only* TLS-terminating artifact in the repo, and every value in it is a `CHANGEME` placeholder; ingress-nginx + cert-manager are documented *operator prerequisites the repo does not install*. Compose and the k8s **dev** overlay have no TLS terminator at all. |
| Q3 | Is HTTPS mandatory in a documented production deployment? | **No — because there is no documented production deployment.** `DEPLOYMENT_RUNBOOK.md` "Phase 14 blocker": no production target exists; "Production deployment does not proceed until the owner names a real target." The k8s path is explicitly "**public-beta**, not production-certified." |
| Q4 | Are the design's secure-cookie assumptions valid on the shipped configs? | **Not on Compose or k8s-dev** (plain HTTP → a `Secure` cookie is never returned by the browser; the session is non-functional). **Only on k8s-beta** *if* the operator completes the ingress placeholders. |
| Q5 | Can any production-like config expose the API over plain HTTP? | **Yes — multiple ways, with no app-level guard.** See §4. |
| Q6 | Are WebSocket upgrades expected through TLS? | Only implicitly, on the k8s-beta ingress path (ingress-nginx proxies `wss://` by default). Compose / k8s-dev serve `ws://` plaintext. No repo artifact configures or asserts WS-over-TLS. |

---

## 2. Evidence inventory

Files inspected (all at `2f0c749`):

- `docker-compose.yml` — `s43-api` service, port publishing, command line.
- `core/api/Dockerfile` — `EXPOSE`, `CMD`.
- `deploy/kubernetes/base/` — `s43-api-deployment.yaml` (Deployment + Service),
  `configmap.yaml`, `kustomization.yaml`, `migration-job.yaml`,
  `networkpolicy-*.yaml`, `secret.example.yaml`.
- `deploy/kubernetes/overlays/dev/` — `kustomization.yaml`,
  `configmap-patch.yaml`.
- `deploy/kubernetes/overlays/beta/` — `ingress.yaml`, `configmap-patch.yaml`,
  `kustomization.yaml`, `networkpolicy-ingress.yaml`, `resources-patch.yaml`,
  `poddisruptionbudget.yaml`.
- `deploy/kubernetes/README.md`, `DEPLOYMENT_RUNBOOK.md`,
  `docs/security/trusted_proxy_handling.md`.
- `.env.example`, `docker-compose.yml` header comment.
- `core/api/main.py` — middleware stack, `_validate_security_config()`,
  `_ALLOWED_ORIGINS`.
- Full-tree greps: `set_cookie` / `Set-Cookie` / `Secure` / `HSTS` /
  `Strict-Transport-Security` / `HTTPSRedirectMiddleware` /
  `X-Forwarded-Proto` / `request.url.scheme` / `samesite` — **zero hits in
  `core/` non-test code.**
- Repo-wide search for reverse-proxy config files
  (`nginx`/`caddy`/`traefik`/`haproxy`/`envoy`/`*.conf`) — **none exist**
  (only `docs/security/trusted_proxy_handling.md` and firewall proxy-trust
  tests match).

---

## 3. Per-deployment-path findings

### 3.1 Docker Compose (`docker-compose.yml`) — the documented default

```
s43-api:
  command: uvicorn core.api.main:app --host 0.0.0.0 --port 8000 --forwarded-allow-ips 127.0.0.1
  ports:
    - "8000:8000"
```

- **Plain HTTP on host `:8000`.** No `--ssl-keyfile` / `--ssl-certfile`. No
  TLS-terminating service in the compose file (no nginx/caddy/traefik — the
  only other services are `s43-db`, `s43-redis`, `s43-core`, `s43-setup`).
- The compose header comment's "Production — also set in .env" block lists
  `SENTINEL_ENV=production` and `S43_ALLOWED_ORIGINS=https://yourdomain.com`
  but **provides no TLS terminator** and nothing rejects an `http://` origin.
- `DEPLOYMENT_RUNBOOK.md` "Local Docker Compose (verified this session)"
  drives it over `http://localhost:8000`. This is the *only* end-to-end
  path the runbook marks as verified.
- Verdict: **Compose is a plaintext-HTTP deployment.** It is adequate for
  local development (its documented purpose) and unsafe for any exposure
  beyond loopback. Nothing in the repo would stop an operator running
  `docker compose up` on a public host with `SENTINEL_ENV=production`.

### 3.2 Kubernetes — `base/` + `overlays/dev/`

- `base/s43-api-deployment.yaml`: container port `8000`, `Service` is
  `ClusterIP` port `8000` → `targetPort 8000`. **Plain HTTP.** No TLS.
- `overlays/dev/` adds no ingress (`kustomization.yaml` resources =
  `../../base` only; README: "local dev on kind/Docker Desktop: locally-built
  image, **no ingress**"). Access is via `kubectl port-forward svc/s43-api
  8000:8000` → `curl http://localhost:8000/...` (README "Health
  verification").
- `base/configmap.yaml` sets `SENTINEL_ENV: "production"`; `overlays/dev/
  configmap-patch.yaml` overrides it back to `development`. So **k8s-dev runs
  with `SENTINEL_ENV=development`** (local-test auth fallback on), **k8s-base
  as-is / any overlay that doesn't patch it runs as `production`** — over
  plain HTTP, with no ingress, if applied directly.
- Verdict: **k8s-dev / k8s-base are plaintext-HTTP** unless an operator adds
  their own ingress. `base/` alone is directly applicable and yields a
  `production`-env pod on plain HTTP.

### 3.3 Kubernetes — `overlays/beta/` (the only TLS artifact)

`overlays/beta/ingress.yaml`:

```
annotations:
  cert-manager.io/cluster-issuer: letsencrypt-prod
  nginx.ingress.kubernetes.io/ssl-redirect: "true"
  nginx.ingress.kubernetes.io/use-forwarded-headers: "true"
spec:
  ingressClassName: nginx
  tls:
    - hosts: ["beta.example.invalid"]
      secretName: s43-api-tls
  rules:
    - host: beta.example.invalid
      http:
        paths: [{ path: /, pathType: Prefix, backend: { service: { name: s43-api, port: { number: 8000 } } } }]
```

- This **does** describe a correct TLS topology: TLS terminates at
  ingress-nginx, `ssl-redirect: "true"` forces HTTP→HTTPS at the edge,
  cert-manager + a `letsencrypt-prod` `ClusterIssuer` issue the cert into
  `s43-api-tls`, and the pod is reached over plain HTTP *inside the cluster
  only* (the `networkpolicy-ingress.yaml` restricts pod ingress on `:8000`
  to the `ingress-nginx` namespace).
- **But every operative value is a placeholder the repo cannot fill:**
  - `beta.example.invalid` — RFC 2606 non-resolvable; the file's own
    comment: "replace ... before applying".
  - ingress-nginx — "installed in a namespace literally named
    `ingress-nginx`" is a **prerequisite**; "neither is installed by this
    repo — they're documented operator prerequisites" (`ingress.yaml`
    header; README prerequisites table).
  - cert-manager + `ClusterIssuer letsencrypt-prod` — "For the ...
    annotation ... to do anything — install it and create that ClusterIssuer
    ... before applying" (README).
  - `s43-api-tls` Secret — created by cert-manager only if the above is
    wired; otherwise the `tls:` block references a non-existent Secret and
    ingress-nginx serves its **default self-signed / fake certificate**.
  - The image digest in `overlays/beta/kustomization.yaml` is "a
    deliberately-invalid placeholder"; a registry is "not provided by this
    repo".
- Verdict: **k8s-beta is a *template* for a TLS deployment, not a TLS
  deployment.** Applied as-is it does not stand up (bad host, missing
  image, missing issuer). Completed correctly by an operator it is a sound
  edge-TLS topology. The repo cannot, by itself, guarantee it was completed
  correctly.

---

## 4. Application-level transport awareness — **none**

`core/api/main.py` middleware stack (only two entries):

1. `CORSMiddleware` — `allow_origins=sorted(_ALLOWED_ORIGINS)`,
   `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]`.
2. `SentinelFirewall` (fail-closed registration, Pass 2).

There is **no**:

- `HTTPSRedirectMiddleware` / scheme-based redirect.
- `Strict-Transport-Security` (HSTS) header — anywhere.
- Other security-response-header middleware (`X-Frame-Options`,
  `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`) —
  none in `core/`.
- Reading of `X-Forwarded-Proto` / use of `request.url.scheme` /
  `request.url.is_secure` in application code.
- Any check in `_validate_security_config()` that the deployment is
  HTTPS-fronted, that `S43_ALLOWED_ORIGINS` entries are `https://`, or that a
  production env is not serving plaintext. `_validate_security_config()`
  enforces JWT algorithm, `S43_JWT_SECRET` presence, and
  `S43_WS_REQUIRE_AUTH=true` — nothing transport-related.

**Consequence:** the API cannot tell whether it is being reached over HTTPS
or plain HTTP, does not advertise HSTS, and will not refuse to serve — or
even warn — when `SENTINEL_ENV=production` is set on a plaintext listener.
Every "can this be exposed over plain HTTP?" path in §3 is therefore
**silent** at the app layer.

Interaction with Pass 2's `--forwarded-allow-ips 127.0.0.1`: uvicorn's
`ProxyHeadersMiddleware` only trusts `127.0.0.1`, so behind the k8s-beta
ingress `scope["scheme"]` / `request.url.scheme` stays `"http"` even though
the browser-facing leg is HTTPS. This is *correct and deliberate* for client
-IP trust (see `docs/security/trusted_proxy_handling.md`), but it means the
app has **no trustworthy signal** of the external scheme even when one is
available in `X-Forwarded-Proto`. Any future "set the cookie `Secure` only
when the request is secure" logic would mis-fire here — the cookie must be
issued `Secure` unconditionally and the deployment must guarantee HTTPS
(see §5).

---

## 5. Impact on the Pass 5A / Pass 4 browser-session design

The approved design (AUTH_ARCHITECTURE_PASS4.md §3) puts the refresh
credential in:

```
Set-Cookie: s43_refresh=<opaque>; HttpOnly; Secure; SameSite=Strict; Path=/auth; Max-Age=<ttl>
```

and uses a double-submit CSRF token for `/auth/refresh` + `/auth/logout`.

| Assumption the design makes | Holds on Compose? | Holds on k8s-dev? | Holds on k8s-beta (operator-completed)? |
|---|---|---|---|
| Browser will *send back* a `Secure` cookie | ❌ plaintext — cookie never returned | ❌ plaintext (port-forward is `http://localhost`) | ✅ HTTPS at the edge |
| `SameSite=Strict` meaningful | partial (works, but no TLS to protect the value in transit) | partial | ✅ |
| Refresh value not observable on the wire | ❌ visible in plaintext | ❌ visible in plaintext | ✅ (edge→pod leg is in-cluster, NetworkPolicy-restricted) |
| CSRF double-submit adds value | yes (orthogonal to TLS) | yes | yes |
| HSTS pins the browser to HTTPS | ❌ not sent by app or ingress config | ❌ | ⚠️ ingress `ssl-redirect` only; **no HSTS header configured** |

**`localhost` exception (informational).** Browsers treat `http://localhost`
and `http://127.0.0.1` as "secure contexts" and *do* store/return `Secure`
cookies there. So a developer hitting Compose directly on
`http://localhost:8000` can exercise the cookie flow locally. This does
**not** extend to `http://<lan-ip>:8000`, `http://<hostname>:8000`, or the
`kubectl port-forward` case if bound to a non-loopback address, and it is
not a production posture.

**Net:** the browser-session design is implementable and testable now, but
is **only deployable** on a topology that terminates TLS in front of the API
(k8s-beta done properly, or an operator-supplied reverse proxy in front of
Compose). No such topology is guaranteed by repository artifacts today.

---

## 6. WebSocket / TLS

- The dashboard WebSocket (`core/api/main.py`, `dashboard_websocket`) is
  served on the same `:8000` listener. It carries auth in the first frame
  (`{token, password}`), not in a cookie, so it is not directly affected by
  the `Secure`-cookie problem — **but** the token and (today) the plaintext
  password in that frame are exposed on the wire on every non-TLS path
  exactly as HTTP requests are.
- k8s-beta ingress routes `/` (all paths) to the service; ingress-nginx
  upgrades `wss://` transparently, so WS-over-TLS works there once the
  ingress is completed. Compose / k8s-dev are `ws://` plaintext.
- Pass 5A does **not** change the WebSocket auth contract (mission §21).
  Recorded here only so the transport exposure is not overlooked: **on every
  plaintext path the WS auth frame is as exposed as `X-S43-Password`.**

---

## 7. Verdict — BLOCKING DEPLOYMENT FINDING

> **F-TLS-1 (blocking, deployment).** Repository evidence does **not**
> establish a secure production TLS posture for Sentinel-43.
>
> - The application never terminates TLS and has no transport-security
>   awareness (no HSTS, no scheme check, no HTTPS-required guard, no
>   `Secure`-context enforcement in `_validate_security_config()`).
> - The documented default deployment (Docker Compose) is plaintext HTTP
>   with no reverse-proxy TLS terminator provided or required.
> - The only TLS-terminating artifact (k8s `overlays/beta/ingress.yaml`) is
>   entirely placeholder-driven and depends on operator-installed
>   ingress-nginx + cert-manager + `ClusterIssuer` that the repo does not
>   provide or verify.
> - No production deployment target exists at all
>   (`DEPLOYMENT_RUNBOOK.md` Phase 14 blocker).
> - Multiple shipped configurations can serve `SENTINEL_ENV=production` over
>   plain HTTP with zero warning.
>
> **Consequence for Pass 5A:** implementation of the browser-session design
> may proceed **in isolated development only**. The design **must not be
> described as production-ready**, and any handoff must carry F-TLS-1 as a
> gate on Phase B+ of the `X-S43-Password` retirement (a `Secure` refresh
> cookie is worthless until every production-reachable listener is
> HTTPS-fronted).

### 7.1 Remediation prerequisites (for a later deployment pass — NOT Pass 5A)

1. **Name a production target** (Phase 14) — Docker host or k8s
   context/cluster/namespace.
2. **Guarantee edge TLS** on that target: either
   - k8s-beta ingress completed (real host, real `ClusterIssuer`, verified
     `s43-api-tls` Secret is cert-manager-issued not the ingress default),
     **plus** add
     `nginx.ingress.kubernetes.io/configuration-snippet` or a
     `ConfigMap`-level HSTS so `Strict-Transport-Security` is actually sent;
     or
   - a documented, config-managed reverse proxy (nginx/caddy/traefik) in
     front of Compose with TLS + HTTP→HTTPS redirect + HSTS, added to the
     repo.
3. **App-level defence in depth** (small, additive; propose in the
   deployment pass, not here):
   - `_validate_security_config()`: when `not _is_local_environment()`,
     require every `S43_ALLOWED_ORIGINS` entry to be `https://` (or an
     explicit opt-out env for the "TLS-terminating proxy on a private
     network" case).
   - An HSTS response header in production (`max-age >= 15552000;
     includeSubDomains`), gated on `not _is_local_environment()`.
   - Optionally trust `X-Forwarded-Proto` *from the same CIDR that
     `S43_TRUSTED_PROXIES` already authorises* so the app has a real scheme
     signal for logging/redirects (keep cookies `Secure`-unconditional
     regardless).
4. **Re-test** the full login → refresh → logout cookie flow end-to-end over
   real HTTPS before Phase B of the migration is enabled.

---

## 8. What Pass 5A does with this

- **Proceeds** with the session-model / token-claim / refresh-primitive /
  CSRF-primitive implementation, in isolated dev, against disposable
  PostgreSQL.
- **Issues the refresh cookie spec as `Secure`-unconditional** (never
  scheme-derived) in the design notes, precisely because §4 shows the app
  has no trustworthy scheme signal.
- **Does not activate** any cookie-setting code in a live path (mission
  §5, §12 — CSRF primitives "not activated in production behavior").
- **Carries F-TLS-1** into `HANDOFF_PASS5A.md` as a blocking deployment
  finding and as an explicit precondition on the `X-S43-Password` retirement
  and on any "browser sessions are on" cutover.
- Adds a **non-blocking** recommendation (for the deployment pass) that
  `_validate_security_config()` grow an HTTPS/`https://`-origin assertion in
  non-local environments — flagged, **not implemented in Pass 5A** (it would
  change startup behaviour for existing plaintext deployments, which is
  outside this pass's remit).
