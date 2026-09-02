# Sentinel-43 -- Compose reverse proxy / TLS terminator

`s43-proxy` (nginx) is the Docker Compose front door. It terminates TLS,
redirects HTTP -> HTTPS, sets `X-Forwarded-Proto` / `X-Forwarded-For`, sends
HSTS at the edge, upgrades WebSockets, and forwards to the **internal**
`s43-api:8000` -- which is no longer host-published.

This is the Compose counterpart of `deploy/kubernetes/overlays/beta/ingress.yaml`
(ingress-nginx + cert-manager). Beta-execution Phase 2, finding **F-TLS-1**.

## Local testing (self-signed)

```bash
./deploy/proxy/generate-dev-cert.sh            # -> deploy/proxy/certs/s43.{crt,key}
docker compose up -d
curl -k https://localhost/health              # -k: self-signed
curl -i http://localhost/health               # -> 308 to https
```

`certs/` is gitignored. A self-signed cert proves the **integration** (the
app behind TLS, forwarded headers, secure cookies, WSS upgrade). It does not
prove certificate issuance or renewal -- that is target-specific.

## Real deployment

Provide a real cert + key at `deploy/proxy/certs/s43.crt` / `s43.key` (PEM),
or use the Kubernetes path (`overlays/beta`, cert-manager). Then:

| Concern | Action |
|---|---|
| **Provisioning** | cert-manager + a `ClusterIssuer` (k8s), or `certbot` / your CA (Compose host). Mount the issued PEM pair into the `certs/` volume. |
| **Validation** | `openssl x509 -in certs/s43.crt -noout -dates -subject`; confirm the chain (`openssl verify`) and that SNI matches `S43_TRUSTED_HOSTS`. |
| **Renewal** | cert-manager auto-renews (k8s). On Compose, a `certbot renew` cron + `docker compose kill -s HUP s43-proxy` to reload. |
| **Expiry monitoring** | alert at 21 days remaining (cert-manager emits `CertificateExpiringSoon`; on Compose, a scripted `openssl ... -checkend` in your monitoring). |

`F-TLS-1 stays OPEN` for any target where the above has not been verified
against the real hostname and CA.

## What the app does with the forwarded headers

`s43-api` trusts `X-Forwarded-Proto` / `X-Forwarded-For` **only** from
`S43_TRUSTED_PROXIES` (set to the proxy's fixed compose IP in
`docker-compose.yml`). uvicorn keeps `--forwarded-allow-ips 127.0.0.1` so it
never processes these itself -- `SentinelFirewall` (`X-Forwarded-For`) and
`SecurityHeadersMiddleware` (`X-Forwarded-Proto`, for the HSTS decision) are
the single processors. Refresh cookies are issued `Secure` unconditionally
regardless of the detected scheme.
