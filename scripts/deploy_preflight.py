#!/usr/bin/env python3
# =============================================================================
# Sentinel-43 -- read-only deployment preflight (phase-aware).
#
# TWO PHASES, always explicit -- there is no default:
#
#   prepare   Config / tooling / target-selection / secret-availability /
#             image-identity checks that need NOTHING deployed yet. A pass
#             means "the inputs for a deploy are in order". It is NOT beta
#             acceptance and must never be reported as such.
#
#   verify    Running-target checks: edge TLS, redirect, readiness, docs
#             exposure, effective replica AND worker count. Needs the target
#             actually deployed and reachable (ideally from where it will be
#             reached in production).
#
# Exit codes (evaluated over the MANDATORY checks of the selected phase only):
#   0  every mandatory check for this phase passed
#   1  at least one check FAILED -- a real, confirmed problem
#   2  at least one mandatory check is INCOMPLETE -- it could not be
#      evaluated (inspection error, target unreachable, hostname not yet
#      known, no external vantage point). Never silently treated as success.
#
# Strictly read-only: never bootstraps an admin, writes the database, applies
# a manifest, or starts/stops/scales a container.
#
# Usage:
#   python scripts/deploy_preflight.py compose --phase prepare \
#       --hostname beta.example.org --https-port 443 --http-port 80 \
#       --env-file .env \
#       --image ghcr.io/acme/sentinel43-api@sha256:<64-hex-digest>
#
#   python scripts/deploy_preflight.py compose --phase verify \
#       --hostname beta.example.org --project s43 --env-file .env \
#       -f docker-compose.yml -f docker-compose.beta.yml [--from-external-host]
#
#   python scripts/deploy_preflight.py kube --phase verify \
#       --context <ctx> --namespace <ns> --hostname beta.example.org \
#       [--ca-bundle /path/to/ca.pem]
# =============================================================================
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# --- statuses -----------------------------------------------------------------
PASS = "PASS"
FAIL = "FAIL"
INCOMPLETE = "INCOMPLETE"
NA = "n/a"

EXIT_OK, EXIT_FAIL, EXIT_INCOMPLETE = 0, 1, 2

# A value that looks like a stand-in rather than a real hostname / secret.
PLACEHOLDER_RE = re.compile(
    r"CHANGEME|<[^>]+>|\byour[-_.]|example\.(?:invalid|com|org|net)\b|"
    r"(?:^|[^0-9A-Za-z.])(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(?:$|[^0-9A-Za-z.])",
    re.IGNORECASE,
)

REQUIRED_SECRETS = [
    "S43_JWT_SECRET", "S43_AUTH_PEPPER", "SENTINEL_LOG_SALT",
    "POSTGRES_PASSWORD", "REDIS_PASSWORD", "S43_WATCHTOWER_SERVICE_TOKEN",
    "S43_OPERATOR_PASSWORD_HASH", "S43_SECRETS_ROTATED_AT",
    "SENTINEL_REMOTE_TOKEN_OWNER", "SENTINEL_REMOTE_TOKEN_ADMIN",
    "SENTINEL_REMOTE_TOKEN_AUDITOR", "S43_FENRIR_API_TOKEN",
]

# Backend / sidecar ports that must NOT be reachable from outside the target.
INTERNAL_PORTS = (8000, 9100, 5432, 6379)


def is_placeholder(value: str) -> bool:
    return bool(value) and bool(PLACEHOLDER_RE.search(value))


# =============================================================================
# Report
# =============================================================================
@dataclass
class Result:
    status: str
    name: str
    detail: str = ""
    mandatory: bool = True


@dataclass
class Report:
    phase: str
    target: str
    hostname: str = ""
    results: list[Result] = field(default_factory=list)

    def record(self, status: str, name: str, detail: str = "",
               mandatory: bool = True) -> str:
        self.results.append(Result(status, name, detail, mandatory))
        tag = status if status != NA else "n/a "
        print(f"  [{tag:<10}] {name}" + (f" -- {detail}" if detail else ""))
        return status

    def exit_code(self) -> int:
        if any(r.status == FAIL for r in self.results):
            return EXIT_FAIL
        if any(r.status == INCOMPLETE for r in self.results if r.mandatory):
            return EXIT_INCOMPLETE
        return EXIT_OK

    def summary(self) -> dict[str, int]:
        out = {PASS: 0, FAIL: 0, INCOMPLETE: 0, NA: 0}
        for r in self.results:
            out[r.status] = out.get(r.status, 0) + 1
        return out

    def to_json(self) -> str:
        code = self.exit_code()
        return json.dumps({
            "phase": self.phase,
            "target": self.target,
            "hostname": self.hostname,
            "exit_code": code,
            "acceptance": _acceptance_label(self.phase, code),
            "summary": {k.lower().strip(): v for k, v in self.summary().items()},
            "checks": [
                {"status": r.status, "name": r.name, "detail": r.detail,
                 "mandatory": r.mandatory}
                for r in self.results
            ],
        }, indent=2)


def _acceptance_label(phase: str, code: int) -> str:
    if code != EXIT_OK:
        return "not satisfied"
    if phase == "prepare":
        return "preparation inputs in order (NOT beta acceptance)"
    return "running-target checks passed for this vantage point"


def _run(cmd: list[str], timeout: int = 25) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError as exc:
        return 127, f"{cmd[0]}: not found ({exc})"
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(cmd[:3])}...: timed out after {timeout}s"


# =============================================================================
# Pure helpers -- unit-tested in core/tests/test_deploy_preflight.py
# =============================================================================
def classify_http_redirect(status, location, hostname, https_port):
    """First response to a plain-HTTP request, redirects NOT followed."""
    if status not in (301, 302, 307, 308):
        return FAIL, f"HTTP {status} -- plain HTTP was not redirected to HTTPS"
    if not location:
        return FAIL, f"HTTP {status} but no Location header"
    try:
        u = urllib.parse.urlsplit(location)
    except ValueError:
        return FAIL, f"unparseable Location: {location!r}"
    if (u.scheme or "").lower() != "https":
        return FAIL, f"redirect does not upgrade to https ({u.scheme or 'relative'}): {location}"
    host = (u.hostname or "").lower()
    if host and host != hostname.lower():
        return FAIL, f"redirect points at a different host ({host}): {location}"
    port = u.port or 443
    if port != (https_port or 443):
        return FAIL, f"redirect target port {port} != expected {https_port}"
    return PASS, f"HTTP {status} -> {location}"


def parse_compose_ps(stdout: str) -> list[dict]:
    """`docker compose ps --format json` -- tolerates the JSON-array form and
    the newline-delimited-objects form across Compose versions."""
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        v = json.loads(text)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
        if isinstance(v, dict):
            return [v]
    except ValueError:
        pass
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def compose_base_cmd(project: str, env_file: str, files: list[str] | None) -> list[str]:
    cmd = ["docker", "compose"]
    if project:
        cmd += ["-p", project]
    if env_file:
        cmd += ["--env-file", env_file]
    for f in files or []:
        cmd += ["-f", f]
    return cmd


def _published_ports(svc: dict) -> list[int]:
    """Host-published ports from the structured Publishers list. A loopback-
    only publish still counts -- the proxy must be the sole ingress."""
    ports: list[int] = []
    for pub in svc.get("Publishers") or []:
        if not isinstance(pub, dict):
            continue
        pp = pub.get("PublishedPort") or 0
        try:
            pp = int(pp)
        except (TypeError, ValueError):
            pp = 0
        if pp:
            ports.append(pp)
    return ports


def origin_exact_member(raw: str, hostname: str, scheme: str, port: int):
    members = {o.strip() for o in (raw or "").split(",") if o.strip()}
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    want = f"{scheme}://{hostname}" if default else f"{scheme}://{hostname}:{port}"
    return want in members, want, sorted(members)


def host_exact_member(raw: str, hostname: str):
    """Mirror core/api/middleware/security_headers.py::TrustedHostGuard, but a
    bare '*' is rejected -- a named beta target must not answer on any Host."""
    host = hostname.split(":")[0].strip().lower()
    pats = [p.strip().lower() for p in (raw or "").split(",") if p.strip()]
    if not pats:
        return False, "S43_TRUSTED_HOSTS is unset"
    if "*" in pats:
        return False, "contains '*' -- answers on any Host (too broad for a named target)"
    for pat in pats:
        if host == pat:
            return True, f"exact match {pat!r}"
        if pat.startswith(".") and (host == pat[1:] or host.endswith(pat)):
            return True, f"leading-dot wildcard {pat!r}"
    return False, f"{host!r} not in {pats}"


def validate_trusted_proxies(raw: str):
    entries = [e.strip() for e in (raw or "").split(",") if e.strip()]
    if not entries:
        return FAIL, "S43_TRUSTED_PROXIES is unset -- forwarded headers cannot be trusted"
    bad, broad = [], []
    for e in entries:
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            bad.append(e)
            continue
        # The proxy is one host (or a tiny pool). Anything wider than a /24 v4
        # (or /120 v6) is not "the proxy only".
        if net.prefixlen == 0 or net.num_addresses > 256:
            broad.append(e)
    if bad:
        return FAIL, f"malformed entr{'y' if len(bad) == 1 else 'ies'}: {', '.join(bad)}"
    if broad:
        return FAIL, f"too broad for a single proxy: {', '.join(broad)}"
    return PASS, ", ".join(entries)


def parse_rotated_at(value: str, now: dt.datetime | None = None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    try:
        when = dt.datetime.fromisoformat((value or "").strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return INCOMPLETE, f"not an ISO-8601 timestamp: {value!r}"
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    delta = now - when
    if delta.total_seconds() < -86400:
        return FAIL, f"timestamp is in the future ({when.date()})"
    days = max(delta.days, 0)
    if days > 90:
        return FAIL, f"{days} days ago (> 90)"
    return PASS, f"{days} days ago"


_DIGEST_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\.[a-z0-9-]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*@sha256:[0-9a-f]{64}$"
)


def validate_image_reference(image: str, *, image_id: str = "",
                             source_revision: str = ""):
    if not image:
        return INCOMPLETE, "no --image supplied"
    if is_placeholder(image):
        return FAIL, f"placeholder: {image}"
    if "@sha256:" in image:
        if _DIGEST_RE.match(image):
            return PASS, "immutable registry digest reference"
        return FAIL, "malformed -- want repo[:port]/name@sha256:<64-hex>"
    if re.search(r":sha256[-_.]", image):
        return FAIL, "':sha256-...' is a mutable tag, not a digest -- not pinned"
    # A plain, mutable tag. Only acceptable for a locally-built image whose
    # identity is captured out of band.
    if image_id or source_revision:
        if not re.match(r"^sha256:[0-9a-f]{64}$", image_id):
            return FAIL, f"--image-id must be sha256:<64-hex>, got {image_id!r}"
        if not source_revision or is_placeholder(source_revision):
            return FAIL, "--source-revision missing or a placeholder"
        return PASS, f"local build {image_id[:16]}... from rev {source_revision}"
    return INCOMPLETE, (
        "mutable tag -- for a registry deploy pass repo/name@sha256:<digest>; "
        "for a locally-built image also pass --image-id sha256:<id> "
        "--source-revision <git-sha>"
    )


def k8s_api_container(containers: list[dict], name: str = "s43-api"):
    for c in containers:
        if c.get("name") == name:
            return c, "by name"
    cands = [c for c in containers
             if "api" in (str(c.get("image", "")) + str(c.get("name", ""))).lower()]
    if len(cands) == 1:
        return cands[0], "by image/name heuristic"
    return None, "the API container could not be identified unambiguously"


def k8s_worker_flag(container: dict):
    argv = list(container.get("command") or []) + list(container.get("args") or [])
    joined = " ".join(str(a) for a in argv)
    m = re.search(r"(?:--workers[=\s]+|(?<![\w-])-w[=\s]+)(\d+)", joined)
    if m:
        return int(m.group(1)), f"--workers {m.group(1)}"
    for e in container.get("env") or []:
        if e.get("name") == "WEB_CONCURRENCY":
            v = str(e.get("value", "")).strip()
            if v and v != "1":
                return int(v) if v.isdigit() else 2, f"WEB_CONCURRENCY={v}"
    return None, "no explicit --workers / WEB_CONCURRENCY (uvicorn default: 1)"


def hpa_targets(hpa_items: list[dict], name: str = "s43-api", kind: str = "Deployment"):
    hits = []
    for h in hpa_items:
        ref = (h.get("spec") or {}).get("scaleTargetRef") or {}
        if ref.get("name") == name and ref.get("kind", kind) == kind:
            hits.append((h.get("metadata") or {}).get("name", "?"))
    return hits


def worker_assessment(pid1_cmdline: str, web_concurrency: str, child_count):
    joined = pid1_cmdline or ""
    m = re.search(r"(?:--workers[=\s]+|(?<![\w-])-w[=\s]+)(\d+)", joined)
    if m:
        n = int(m.group(1))
        return (PASS, "uvicorn --workers 1") if n == 1 else (FAIL, f"uvicorn --workers {n}")
    wc = str(web_concurrency or "").strip()
    if wc and wc not in ("1",):
        return FAIL, f"WEB_CONCURRENCY={wc}"
    if child_count is not None and child_count > 1:
        return FAIL, f"{child_count} worker child processes under PID 1"
    if not joined:
        return INCOMPLETE, "could not read the API process launch command"
    return PASS, "single worker (no --workers / WEB_CONCURRENCY / extra children)"


# =============================================================================
# TLS / HTTP
# =============================================================================
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _tls_context(ca_bundle: str | None) -> ssl.SSLContext:
    # Standard chain + hostname verification. A private CA is trusted by
    # ADDING it, never by disabling verification.
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    return ssl.create_default_context()


def http_probe(url: str, ca_bundle: str | None = None, timeout: int = 10):
    """GET without following redirects. Returns (status|None, headers, error)."""
    handlers: list = [_NoRedirect]
    if url.lower().startswith("https"):
        handlers.append(urllib.request.HTTPSHandler(context=_tls_context(ca_bundle)))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "s43-deploy-preflight"})
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, None
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, None
    except Exception as exc:  # noqa: BLE001
        return None, {}, exc


def _url(scheme: str, host: str, port: int, path: str) -> str:
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def _classify_conn_error(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return FAIL, f"certificate not trusted: {exc}"
    if isinstance(exc, ssl.SSLError):
        return FAIL, f"TLS error: {exc}"
    if isinstance(exc, socket.gaierror):
        return INCOMPLETE, f"DNS did not resolve: {exc}"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return INCOMPLETE, "connection timed out"
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
        return INCOMPLETE, f"service not reachable: {exc}"
    return INCOMPLETE, f"{type(exc).__name__}: {exc}"


# =============================================================================
# prepare -- inputs for a deploy, nothing running yet
# =============================================================================
def _parse_env_file(path: str, rep: Report) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError as exc:
        rep.record(FAIL, f"read {path}", str(exc))
    return out


def check_tools(rep: Report, required: list[str]) -> None:
    print("\n== tooling ==")
    for tool in required:
        path = shutil.which(tool)
        rep.record(PASS if path else FAIL, f"{tool} on PATH",
                   path or "not found")


def check_hostname_selected(rep: Report, hostname: str) -> None:
    print("\n== target hostname ==")
    if not hostname:
        rep.record(INCOMPLETE, "beta hostname selected",
                   "pass --hostname once the target is chosen")
        return
    if is_placeholder(hostname):
        rep.record(FAIL, "beta hostname is a real FQDN",
                   f"{hostname!r} looks like a placeholder")
        return
    if "." not in hostname:
        rep.record(FAIL, "beta hostname is a real FQDN",
                   f"{hostname!r} is not fully qualified")
        return
    rep.record(PASS, "beta hostname is a real FQDN", hostname)


def check_image(rep: Report, image: str, image_id: str, source_revision: str) -> None:
    print("\n== image identity ==")
    status, detail = validate_image_reference(
        image, image_id=image_id, source_revision=source_revision)
    rep.record(status, "image reference is an immutable identity", detail)


def check_compose_config(rep: Report, env_file: str, hostname: str,
                         https_port: int) -> None:
    print("\n== compose configuration ==")
    env = _parse_env_file(env_file, rep)
    if not env:
        rep.record(INCOMPLETE, "env file has content", env_file)
        return

    for key in REQUIRED_SECRETS:
        val = env.get(key, "")
        if not val:
            rep.record(FAIL, f"{key} present", "missing")
        elif is_placeholder(val):
            rep.record(FAIL, f"{key} is a real value", "looks like a placeholder")
        else:
            rep.record(PASS, f"{key} present", f"{len(val)} chars")

    status, detail = parse_rotated_at(env.get("S43_SECRETS_ROTATED_AT", ""))
    rep.record(status, "secrets rotated within 90 days", detail)

    senv = env.get("SENTINEL_ENV", "")
    rep.record(PASS if senv and senv.lower() not in {"development", "dev", "local", "test"}
               else FAIL, "SENTINEL_ENV is a non-local environment", senv or "unset")

    origins = env.get("S43_ALLOWED_ORIGINS", "")
    ok, want, members = origin_exact_member(origins, hostname, "https", https_port)
    rep.record(PASS if ok else FAIL,
               "S43_ALLOWED_ORIGINS contains exactly the beta HTTPS origin",
               f"want {want}; have {members}" if not ok else want)
    plaintext = [m for m in members if m.startswith("http://")]
    rep.record(PASS if not plaintext else FAIL,
               "no plaintext http:// origin", ", ".join(plaintext) or "none")

    ok, detail = host_exact_member(env.get("S43_TRUSTED_HOSTS", ""), hostname or "")
    rep.record(PASS if ok else FAIL, "S43_TRUSTED_HOSTS matches the beta hostname",
               detail)

    status, detail = validate_trusted_proxies(env.get("S43_TRUSTED_PROXIES", ""))
    rep.record(status, "S43_TRUSTED_PROXIES is the proxy only", detail)

    insecure = env.get("S43_ALLOW_INSECURE_ORIGINS", "")
    rep.record(PASS if not insecure else FAIL,
               "S43_ALLOW_INSECURE_ORIGINS is not set", insecure or "unset")

    legacy = env.get("S43_REJECT_LEGACY_AUTH", "").lower()
    rep.record(NA if legacy in {"", "false", "0", "no", "off"} else PASS,
               "S43_REJECT_LEGACY_AUTH left off for the initial beta",
               "Phase-E cutover is a later, separate step", mandatory=False)


def check_kube_prereqs(rep: Report, context: str, namespace: str) -> None:
    print("\n== kubernetes prerequisites ==")
    if not context or not namespace:
        rep.record(INCOMPLETE, "kube context + namespace selected",
                   "pass --context and --namespace")
        return
    kc = ["kubectl", "--context", context, "-n", namespace]
    rc, out = _run(kc + ["get", "ns", namespace, "-o", "name"])
    if rc != 0:
        rep.record(INCOMPLETE, "target namespace reachable", out.strip()[:160])
        return
    rep.record(PASS, "target namespace exists", namespace)

    rc, out = _run(kc + ["get", "secret", "sentinel43-secrets", "-o", "json"])
    if rc != 0:
        rep.record(FAIL, "sentinel43-secrets exists in the namespace", out.strip()[:160])
    else:
        try:
            keys = set(json.loads(out).get("data", {}))
        except ValueError:
            keys = set()
        missing = [k for k in ("POSTGRES_PASSWORD", "S43_JWT_SECRET",
                               "S43_AUTH_PEPPER", "DATABASE_URL") if k not in keys]
        rep.record(PASS if not missing else FAIL,
                   "sentinel43-secrets has the required keys",
                   f"missing {missing}" if missing else f"{len(keys)} keys")

    rc, out = _run(kc + ["get", "cm", "-o", "json"])
    if rc != 0:
        rep.record(INCOMPLETE, "ConfigMaps have no placeholders", out.strip()[:160])
    else:
        hits = sorted(set(re.findall(r"CHANGEME[\w-]*", out)))
        rep.record(PASS if not hits else FAIL,
                   "no CHANGEME placeholders in ConfigMaps",
                   ", ".join(hits) or "clean")


# =============================================================================
# verify -- the target is deployed and reachable
# =============================================================================
def check_hostname_resolves(rep: Report, hostname: str) -> bool:
    print("\n== target hostname ==")
    if not hostname or is_placeholder(hostname):
        rep.record(INCOMPLETE, "running target has a real hostname",
                   f"{hostname!r} -- cannot verify a live target without it")
        return False
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(hostname, None)})
        rep.record(PASS, "hostname resolves", ", ".join(addrs))
        return True
    except socket.gaierror as exc:
        rep.record(INCOMPLETE, "hostname resolves", str(exc))
        return False


def check_edge_tls(rep: Report, hostname: str, https_port: int,
                   http_port: int, ca_bundle: str | None) -> None:
    print("\n== edge TLS + HTTP ==")
    try:
        with socket.create_connection((hostname, https_port), timeout=10) as sock:
            with _tls_context(ca_bundle).wrap_socket(
                    sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
    except Exception as exc:  # noqa: BLE001
        status, detail = _classify_conn_error(exc)
        rep.record(status, "edge certificate validates for this hostname", detail)
        return

    # The library already did chain + hostname (incl. wildcard) verification.
    rep.record(PASS, "edge certificate validates for this hostname",
               f"{proto}; trusted chain, hostname matched")

    try:
        not_after = dt.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        days = (not_after - dt.datetime.now(dt.timezone.utc)).days
        rep.record(PASS if days > 21 else FAIL, "certificate not near expiry",
                   f"{days} days left")
    except (KeyError, ValueError) as exc:
        rep.record(INCOMPLETE, "certificate not near expiry", str(exc))

    # Plain HTTP -> HTTPS, redirect NOT followed.
    status, headers, err = http_probe(
        _url("http", hostname, http_port, "/health"), ca_bundle)
    if err is not None:
        s, d = _classify_conn_error(err)
        rep.record(s, "plain HTTP redirects to the HTTPS origin", d)
    else:
        s, d = classify_http_redirect(status, headers.get("location", ""),
                                      hostname, https_port)
        rep.record(s, "plain HTTP redirects to the HTTPS origin", d)

    # HTTPS /health and /ready, separately.
    for path in ("/health", "/ready"):
        status, headers, err = http_probe(
            _url("https", hostname, https_port, path), ca_bundle)
        if err is not None:
            s, d = _classify_conn_error(err)
            rep.record(s, f"HTTPS {path} responds", d)
            continue
        rep.record(PASS if status == 200 else FAIL, f"HTTPS {path} responds",
                   f"HTTP {status}")
        if path == "/health":
            hsts = headers.get("strict-transport-security", "")
            rep.record(PASS if "max-age=" in hsts and "max-age=0" not in hsts
                       else FAIL, "HSTS header present at the edge", hsts or "missing")

    check_docs_exposure(rep, hostname, https_port, ca_bundle)
    check_external_exposure(rep, hostname)
    rep.record(INCOMPLETE, "WSS login/refresh/logout through the edge",
               "run browser_tests/run_target.sh against this https:// URL")


def check_docs_exposure(rep: Report, hostname: str, https_port: int,
                        ca_bundle: str | None) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        status, _headers, err = http_probe(
            _url("https", hostname, https_port, path), ca_bundle)
        if err is not None:
            s, d = _classify_conn_error(err)
            # A connection failure is NOT proof the doc route is protected.
            rep.record(INCOMPLETE if s == INCOMPLETE else s,
                       f"{path} is not publicly served", d)
            continue
        rep.record(PASS if status in (401, 403, 404) else FAIL,
                   f"{path} is not publicly served", f"HTTP {status}")


def check_external_exposure(rep: Report, hostname: str) -> None:
    external = "--from-external-host" in sys.argv
    if not external:
        rep.record(INCOMPLETE,
                   "backend :8000 / watchtower :9100 / db / redis not reachable externally",
                   "re-run with --from-external-host from outside the target network")
        return
    reachable = []
    for port in INTERNAL_PORTS:
        try:
            with socket.create_connection((hostname, port), timeout=4):
                reachable.append(port)
        except OSError:
            pass
    rep.record(PASS if not reachable else FAIL,
               "backend :8000 / watchtower :9100 / db / redis not reachable externally",
               f"reachable: {reachable}" if reachable else "all refused/filtered")


_WORKER_PROBE = (
    "CMD=$(tr '\\0' ' ' < /proc/1/cmdline 2>/dev/null); echo \"CMD=$CMD\"; "
    "echo \"WC=${WEB_CONCURRENCY:-}\"; N=0; "
    "for s in /proc/[0-9]*/stat; do "
    "pp=$(awk '{print $4}' \"$s\" 2>/dev/null) || continue; "
    "[ \"$pp\" = \"1\" ] && N=$((N+1)); done; echo \"CHILDREN=$N\""
)


def check_compose_runtime(rep: Report, project: str, env_file: str,
                          files: list[str]) -> None:
    print("\n== compose runtime (read-only `docker compose` queries) ==")
    base = compose_base_cmd(project, env_file, files)
    rc, out = _run(base + ["ps", "--format", "json", "--all"])
    if rc != 0:
        rep.record(INCOMPLETE, "compose stack is reachable",
                   "run this in the deployment directory on the target host: "
                   + out.strip()[:160])
        return
    svcs = parse_compose_ps(out)
    if not svcs:
        rep.record(INCOMPLETE, "compose stack is reachable", "`compose ps` returned nothing")
        return

    def _svc(s):
        return s.get("Service") or s.get("Name", "")

    def _running(s):
        st = str(s.get("State", "")).lower()
        return st in ("running", "up") or "running" in st

    for expected in ("s43-db", "s43-api", "s43-proxy"):
        present = [s for s in svcs if _svc(s) == expected or expected in _svc(s)]
        if not present:
            rep.record(FAIL, f"{expected} container present", "not found")
        else:
            rep.record(PASS if any(_running(s) for s in present) else FAIL,
                       f"{expected} container running",
                       ", ".join(sorted(str(s.get("State", "?")) for s in present)))

    api = [s for s in svcs if _svc(s) == "s43-api" or _svc(s).startswith("s43-api")]
    running_api = [s for s in api if _running(s)]
    n = len(running_api)
    rep.record(PASS if n == 1 else FAIL,
               "exactly one running s43-api instance (no `--scale s43-api=N`)",
               f"{n} running s43-api container(s)")

    exposed = []
    for s in svcs:
        if _svc(s) in ("s43-api", "s43-core", "s43-db", "s43-redis"):
            for p in _published_ports(s):
                exposed.append(f"{_svc(s)}:{p}")
    rep.record(PASS if not exposed else FAIL,
               "backend / db / redis not host-published (proxy is the only ingress)",
               "; ".join(exposed) or "none published")

    rc, probe = _run(base + ["exec", "-T", "s43-api", "sh", "-c", _WORKER_PROBE])
    if rc != 0:
        rep.record(INCOMPLETE, "exactly one API worker process",
                   f"could not inspect the s43-api container: {probe.strip()[:120]}")
        return
    fields = dict(
        line.split("=", 1) for line in probe.splitlines() if "=" in line
    )
    children = fields.get("CHILDREN", "").strip()
    status, detail = worker_assessment(
        fields.get("CMD", ""), fields.get("WC", ""),
        int(children) - 1 if children.isdigit() else None)
    rep.record(status, "exactly one API worker process", detail)


def check_kube_runtime(rep: Report, context: str, namespace: str) -> None:
    print("\n== kubernetes runtime (read-only) ==")
    if not context or not namespace:
        rep.record(INCOMPLETE, "kube context + namespace supplied",
                   "pass --context and --namespace")
        return
    kc = ["kubectl", "--context", context, "-n", namespace]

    rc, out = _run(kc + ["get", "deploy", "s43-api", "-o", "json"])
    if rc != 0:
        rep.record(INCOMPLETE, "s43-api Deployment readable", out.strip()[:160])
    else:
        try:
            dep = json.loads(out)
        except ValueError as exc:
            rep.record(INCOMPLETE, "s43-api Deployment readable", str(exc))
            dep = None
        if dep:
            spec = dep.get("spec", {})
            st = dep.get("status", {})
            replicas = spec.get("replicas")
            rep.record(PASS if replicas == 1 else FAIL,
                       "s43-api spec.replicas == 1 (login throttle is process-local)",
                       f"replicas={replicas}")
            ready = st.get("readyReplicas")
            if ready is None:
                rep.record(INCOMPLETE, "exactly one s43-api pod is Ready",
                           "status.readyReplicas not reported")
            else:
                rep.record(PASS if ready == 1 else FAIL,
                           "exactly one s43-api pod is Ready", f"readyReplicas={ready}")
            gen = (dep.get("metadata") or {}).get("generation")
            obs = st.get("observedGeneration")
            updated = st.get("updatedReplicas")
            rep.record(PASS if obs == gen and updated == replicas and replicas is not None
                       else INCOMPLETE, "s43-api rollout is complete",
                       f"gen={gen} observed={obs} updated={updated}")
            containers = (spec.get("template", {}).get("spec", {}).get("containers", []))
            api_c, how = k8s_api_container(containers)
            if api_c is None:
                rep.record(INCOMPLETE, "no `--workers > 1` on the API container", how)
            else:
                n, detail = k8s_worker_flag(api_c)
                rep.record(FAIL if n and n > 1 else PASS,
                           "no `--workers > 1` on the API container",
                           f"({how}) {detail}")

    rc, out = _run(kc + ["get", "hpa", "-o", "json"])
    if rc != 0:
        rep.record(INCOMPLETE, "no HorizontalPodAutoscaler targets s43-api",
                   out.strip()[:160])
    else:
        try:
            items = json.loads(out).get("items", [])
        except ValueError:
            items = []
        hits = hpa_targets(items)
        rep.record(PASS if not hits else FAIL,
                   "no HorizontalPodAutoscaler targets s43-api",
                   f"targeting s43-api: {hits}" if hits
                   else f"{len(items)} HPA(s), none target s43-api")

    rc, out = _run(kc + ["get", "job", "s43-migration", "-o",
                         "jsonpath={.status.succeeded}"])
    if rc != 0:
        rep.record(INCOMPLETE, "migration Job has completed", out.strip()[:120])
    else:
        rep.record(PASS if out.strip() == "1" else FAIL,
                   "migration Job has completed", f"succeeded={out.strip() or '0'}")

    for svc in ("s43-api", "s43-core"):
        rc, out = _run(kc + ["get", "svc", svc, "-o", "jsonpath={.spec.type}"])
        if rc != 0:
            rep.record(INCOMPLETE, f"{svc} Service is ClusterIP", out.strip()[:120])
        else:
            rep.record(PASS if out.strip() == "ClusterIP" else FAIL,
                       f"{svc} Service is ClusterIP (not exposed directly)",
                       out.strip() or "empty")

    rc, out = _run(kc + ["get", "cm", "-o", "json"])
    if rc != 0:
        rep.record(INCOMPLETE, "no CHANGEME placeholders in ConfigMaps", out.strip()[:120])
    else:
        hits = sorted(set(re.findall(r"CHANGEME[\w-]*", out)))
        rep.record(PASS if not hits else FAIL,
                   "no CHANGEME placeholders in ConfigMaps", ", ".join(hits) or "clean")


# =============================================================================
# CLI
# =============================================================================
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="target", required=True)

    for name in ("compose", "kube"):
        p = sub.add_parser(name)
        p.add_argument("--phase", choices=("prepare", "verify"), required=True,
                       help="REQUIRED -- there is no default phase")
        p.add_argument("--hostname", default="")
        p.add_argument("--https-port", type=int, default=443)
        p.add_argument("--http-port", type=int, default=80)
        p.add_argument("--ca-bundle", default="",
                       help="PEM for an approved private CA (adds trust; never disables it)")
        p.add_argument("--image", default="")
        p.add_argument("--image-id", default="",
                       help="sha256:<64-hex> of a locally-built image")
        p.add_argument("--source-revision", default="",
                       help="git revision the local image was built from")
        p.add_argument("--from-external-host", action="store_true",
                       help="you are running this from outside the target network")
        p.add_argument("--json", action="store_true", help="emit a structured report")
        if name == "compose":
            p.add_argument("--env-file", default=".env")
            p.add_argument("--project", default="")
            p.add_argument("-f", "--compose-file", action="append", default=[],
                           dest="compose_files")
        else:
            p.add_argument("--context", default="")
            p.add_argument("--namespace", default="")
    return ap


def run(args: argparse.Namespace) -> int:
    rep = Report(phase=args.phase, target=args.target, hostname=args.hostname)
    print(f"Sentinel-43 deployment preflight -- target={args.target} "
          f"phase={args.phase} -- READ ONLY\n{'=' * 66}")
    if args.phase == "prepare":
        print("PREPARE: checking that the inputs for a deploy are in order.\n"
              "A pass here is NOT beta acceptance -- run `--phase verify` "
              "against the deployed target for that.")

    if args.target == "compose":
        if args.phase == "prepare":
            check_tools(rep, ["docker", "openssl"])
            check_hostname_selected(rep, args.hostname)
            check_image(rep, args.image, args.image_id, args.source_revision)
            check_compose_config(rep, args.env_file, args.hostname, args.https_port)
        else:
            if check_hostname_resolves(rep, args.hostname):
                check_edge_tls(rep, args.hostname, args.https_port,
                               args.http_port, args.ca_bundle or None)
            check_compose_runtime(rep, args.project, args.env_file,
                                  args.compose_files)
    else:
        if args.phase == "prepare":
            check_tools(rep, ["kubectl", "openssl"])
            check_hostname_selected(rep, args.hostname)
            check_image(rep, args.image, args.image_id, args.source_revision)
            check_kube_prereqs(rep, args.context, args.namespace)
        else:
            if check_hostname_resolves(rep, args.hostname):
                check_edge_tls(rep, args.hostname, args.https_port,
                               args.http_port, args.ca_bundle or None)
            check_kube_runtime(rep, args.context, args.namespace)

    code = rep.exit_code()
    s = rep.summary()
    print("\n" + "=" * 66)
    print(f"{s[PASS]} passed | {s[FAIL]} failed | {s[INCOMPLETE]} incomplete "
          f"| {s[NA]} n/a")

    fails = [r for r in rep.results if r.status == FAIL]
    incompletes = [r for r in rep.results if r.status == INCOMPLETE and r.mandatory]
    if fails:
        print("\nFAILED -- fix before deploying:")
        for r in fails:
            print(f"  - {r.name}: {r.detail}")
    if incompletes:
        print("\nINCOMPLETE -- mandatory, could not be verified from here:")
        for r in incompletes:
            print(f"  - {r.name}: {r.detail}")

    verdict = {
        EXIT_OK: (f"\n{args.phase.upper()} PASSED. "
                  + ("Preparation inputs are in order -- NOT beta acceptance."
                     if args.phase == "prepare"
                     else "Running-target checks passed for this vantage point.")),
        EXIT_FAIL: f"\n{args.phase.upper()} FAILED -- see FAILED checks above.",
        EXIT_INCOMPLETE: (f"\n{args.phase.upper()} INCOMPLETE -- mandatory checks "
                          "could not be evaluated. Not a pass."),
    }[code]
    print(verdict)

    if getattr(args, "json", False):
        print("\n--- json ---")
        print(rep.to_json())
    return code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
