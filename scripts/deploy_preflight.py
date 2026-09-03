#!/usr/bin/env python3
# =============================================================================
# Sentinel-43 -- read-only deployment preflight (next-PR Phase E).
#
# Verifies a controlled-beta target is ready BEFORE any deploy command is run.
# It is strictly read-only: it never bootstraps an admin, never writes to the
# database, never applies a manifest, never starts a container. Every check
# either passes, fails with a specific reason, or is reported as
# TARGET-REQUIRED (cannot be checked until a real hostname/target is given).
#
# Usage:
#   # Docker Compose target
#   python scripts/deploy_preflight.py compose \
#       --hostname beta.example.org --https-port 443 \
#       --env-file .env --image sentinel43-api:<tag>
#
#   # Kubernetes target
#   python scripts/deploy_preflight.py kube \
#       --context <ctx> --namespace <ns> --hostname beta.example.org
#
# Exit 0 = every applicable check passed. Exit 1 = at least one failed or a
# placeholder was found. TARGET-REQUIRED items do not fail the run but are
# listed; a deploy must not proceed while any remain for the chosen target.
# =============================================================================
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.request

PLACEHOLDER_RE = re.compile(
    r"CHANGEME|example\.(invalid|com|org)$|localhost$|127\.0\.0\.1$|your-",
    re.IGNORECASE,
)

PASS, FAIL, SKIP, TREQ = "PASS", "FAIL", "n/a ", "TARGET"
_results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    _results.append((status, name, detail))
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail else ""))


def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


# ---------------------------------------------------------------------------
# Shared checks
# ---------------------------------------------------------------------------
def check_tools(required: list[str]) -> None:
    print("\n== tooling ==")
    for tool in required:
        path = shutil.which(tool)
        record(PASS if path else FAIL, f"{tool} on PATH", path or "not found")


def check_hostname(hostname: str) -> bool:
    print("\n== hostname ==")
    if not hostname or PLACEHOLDER_RE.search(hostname):
        record(FAIL, "hostname is a real FQDN", f"{hostname!r} looks like a placeholder")
        return False
    record(PASS, "hostname is not a placeholder", hostname)
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(hostname, None)})
        record(PASS, "hostname resolves", ", ".join(addrs))
    except socket.gaierror as exc:
        record(FAIL, "hostname resolves", str(exc))
        return False
    return True


def check_tls(hostname: str, port: int) -> None:
    print("\n== TLS / edge ==")
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
    except Exception as exc:  # noqa: BLE001
        record(FAIL, f"TLS handshake to {hostname}:{port}", str(exc))
        return

    record(PASS, "certificate validates against the system trust store", proto)

    not_after = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days = (not_after - dt.datetime.utcnow()).days
    record(PASS if days > 21 else FAIL, "certificate not near expiry", f"{days} days left")

    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    record(PASS if hostname in sans else FAIL, "hostname is in the certificate SAN", ", ".join(sans))

    for scheme, want, name in (
        ("https", 200, "HTTPS /health responds"),
        ("http", (301, 302, 307, 308), "plain HTTP is redirected to HTTPS"),
    ):
        url = f"{scheme}://{hostname}{'' if port in (443, 80) else f':{port}'}/health"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                code = resp.status
        except urllib.error.HTTPError as exc:
            code = exc.code
        except Exception as exc:  # noqa: BLE001
            record(FAIL, name, str(exc))
            continue
        ok = code == want if isinstance(want, int) else code in want
        record(PASS if ok else FAIL, name, f"HTTP {code}")

    # HSTS + no server banner + a forged Host is rejected
    try:
        req = urllib.request.Request(f"https://{hostname}/health")
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
        record(PASS if "strict-transport-security" in headers else FAIL,
               "HSTS header present at the edge",
               headers.get("strict-transport-security", "missing"))
        record(PASS if "server" not in headers or "nginx" not in headers.get("server", "").lower()
               or "/" not in headers.get("server", "")
               else FAIL, "no version-bearing Server banner", headers.get("server", "(none)"))
    except Exception as exc:  # noqa: BLE001
        record(FAIL, "edge header inspection", str(exc))

    record(TREQ, "WSS upgrade through the edge",
           "run browser_tests/ against this target (Phase C)")
    record(TREQ, "backend :8000 / watchtower :9100 not reachable from outside",
           "port-scan the target's public IP from an external host")


# ---------------------------------------------------------------------------
# Compose target
# ---------------------------------------------------------------------------
def _parse_env_file(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    except OSError as exc:
        record(FAIL, f"read {path}", str(exc))
    return out


REQUIRED_SECRETS = [
    "S43_JWT_SECRET", "S43_AUTH_PEPPER", "SENTINEL_LOG_SALT",
    "POSTGRES_PASSWORD", "REDIS_PASSWORD", "S43_WATCHTOWER_SERVICE_TOKEN",
    "S43_OPERATOR_PASSWORD_HASH", "S43_SECRETS_ROTATED_AT",
    "SENTINEL_REMOTE_TOKEN_OWNER", "SENTINEL_REMOTE_TOKEN_ADMIN",
    "SENTINEL_REMOTE_TOKEN_AUDITOR", "S43_FENRIR_API_TOKEN",
]


def check_compose_env(env_file: str, hostname: str) -> None:
    print("\n== compose configuration ==")
    env = _parse_env_file(env_file)
    if not env:
        return

    for key in REQUIRED_SECRETS:
        val = env.get(key, "")
        if not val or PLACEHOLDER_RE.search(val):
            record(FAIL, f"{key} set to a real value", "missing or placeholder")
        else:
            record(PASS, f"{key} present", f"{len(val)} chars")

    rotated = env.get("S43_SECRETS_ROTATED_AT", "")
    try:
        when = dt.datetime.fromisoformat(rotated.replace("Z", "+00:00"))
        age = (dt.datetime.now(dt.timezone.utc) - when).days
        record(PASS if age <= 90 else FAIL, "secrets rotated within 90 days", f"{age} days ago")
    except ValueError:
        record(FAIL, "S43_SECRETS_ROTATED_AT is an ISO-8601 timestamp", rotated or "unset")

    senv = env.get("SENTINEL_ENV", "")
    record(PASS if senv and senv not in {"development", "dev", "local", "test"} else FAIL,
           "SENTINEL_ENV is a non-local environment", senv or "unset")

    origins = env.get("S43_ALLOWED_ORIGINS", "")
    record(PASS if hostname and f"https://{hostname}" in origins else FAIL,
           "S43_ALLOWED_ORIGINS is the real HTTPS origin", origins or "unset")
    record(PASS if not origins or "http://" not in origins else FAIL,
           "no plaintext http:// origin", origins)

    hosts = env.get("S43_TRUSTED_HOSTS", "")
    record(PASS if hostname and hostname in hosts else FAIL,
           "S43_TRUSTED_HOSTS contains the real hostname", hosts or "unset")

    proxies = env.get("S43_TRUSTED_PROXIES", "")
    record(PASS if proxies and proxies not in {"0.0.0.0/0", "::/0"} else FAIL,
           "S43_TRUSTED_PROXIES is a narrow CIDR (the proxy only)", proxies or "unset")

    record(PASS if env.get("S43_ALLOW_INSECURE_ORIGINS", "") == "" else FAIL,
           "S43_ALLOW_INSECURE_ORIGINS is not set", env.get("S43_ALLOW_INSECURE_ORIGINS", ""))
    record(PASS if env.get("S43_REJECT_LEGACY_AUTH", "").lower() in {"", "false"} else SKIP,
           "S43_REJECT_LEGACY_AUTH left off for the initial beta", "Phase E cutover is later")


def check_compose_runtime(hostname: str) -> None:
    print("\n== compose runtime (read-only `docker` queries) ==")
    rc, out = _run(["docker", "compose", "ps", "--format", "json"])
    services = []
    for line in out.splitlines():
        try:
            services.append(json.loads(line))
        except ValueError:
            pass
    if rc != 0 or not services:
        record(TREQ, "compose stack is running on the target",
               "run this in the deployment directory on the target host")
        return
    names = {s.get("Service") or s.get("Name", "") for s in services}
    for expected in ("s43-db", "s43-api", "s43-proxy"):
        record(PASS if any(expected in n for n in names) else FAIL,
               f"{expected} container present", ", ".join(sorted(names)) or "none")

    published = _run(["docker", "compose", "ps", "--format",
                      "{{.Service}} {{.Publishers}}"])[1]
    bad = [ln for ln in published.splitlines()
           if ("s43-api" in ln or "s43-core" in ln) and "->" in ln]
    record(PASS if not bad else FAIL,
           "backend / watchtower not host-published (proxy is the only ingress)",
           "; ".join(bad) or "ok")

    rc, workers = _run(["docker", "compose", "exec", "-T", "s43-api",
                        "sh", "-c", "ps -eo args | grep -c '[u]vicorn'"])
    if rc == 0:
        n = workers.strip()
        record(PASS if n in {"1", "2"} else FAIL,
               "single uvicorn worker (process-local login throttle is correct)",
               f"{n} uvicorn processes")


# ---------------------------------------------------------------------------
# Kube target
# ---------------------------------------------------------------------------
def check_kube(context: str, namespace: str, hostname: str) -> None:
    print("\n== kubernetes target ==")
    if not context or not namespace:
        record(TREQ, "kube context + namespace supplied", "pass --context and --namespace")
        return
    kc = ["kubectl", "--context", context, "-n", namespace]

    rc, out = _run(kc + ["get", "ns", namespace, "-o", "name"])
    record(PASS if rc == 0 else FAIL, "namespace exists", out.strip())
    if rc != 0:
        return

    rc, out = _run(kc + ["get", "deploy", "s43-api", "-o",
                         "jsonpath={.spec.replicas}"])
    record(PASS if out.strip() == "1" else FAIL,
           "s43-api is a single replica (login throttle is process-local)",
           f"replicas={out.strip() or '?'}")

    rc, out = _run(kc + ["get", "hpa", "-o", "name"])
    record(PASS if rc != 0 or not out.strip() else FAIL,
           "no HorizontalPodAutoscaler on s43-api", out.strip() or "none")

    rc, out = _run(kc + ["get", "job", "s43-migration", "-o",
                         "jsonpath={.status.succeeded}"])
    record(PASS if out.strip() == "1" else TREQ,
           "migration Job has completed", f"succeeded={out.strip() or '0'}")

    rc, out = _run(kc + ["get", "cm", "-o", "yaml"])
    record(FAIL if "CHANGEME" in out else PASS,
           "no CHANGEME placeholders in ConfigMaps", "found CHANGEME" if "CHANGEME" in out else "clean")

    for svc in ("s43-api", "s43-core"):
        rc, out = _run(kc + ["get", "svc", svc, "-o",
                             "jsonpath={.spec.type}"])
        record(PASS if out.strip() in {"", "ClusterIP"} else FAIL,
               f"{svc} Service is ClusterIP (not exposed directly)", out.strip() or "not found")


def check_docs_exposure(hostname: str, port: int) -> None:
    print("\n== API surface ==")
    if not hostname or PLACEHOLDER_RE.search(hostname):
        record(TREQ, "/docs, /redoc, /openapi.json exposure", "needs the real hostname")
        return
    base = f"https://{hostname}" + ("" if port == 443 else f":{port}")
    for path in ("/docs", "/redoc", "/openapi.json"):
        try:
            with urllib.request.urlopen(base + path, timeout=10) as resp:
                code = resp.status
        except urllib.error.HTTPError as exc:
            code = exc.code
        except Exception as exc:  # noqa: BLE001
            record(SKIP, f"{path} reachable", str(exc))
            continue
        record(PASS if code in (401, 403, 404) else FAIL,
               f"{path} is not publicly served", f"HTTP {code}")


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)

    c = sub.add_parser("compose")
    c.add_argument("--hostname", default="")
    c.add_argument("--https-port", type=int, default=443)
    c.add_argument("--env-file", default=".env")
    c.add_argument("--image", default="")

    k = sub.add_parser("kube")
    k.add_argument("--context", default="")
    k.add_argument("--namespace", default="")
    k.add_argument("--hostname", default="")
    k.add_argument("--https-port", type=int, default=443)

    args = ap.parse_args()
    print(f"Sentinel-43 deployment preflight ({args.mode}) -- READ ONLY\n"
          f"{'=' * 60}")

    if args.mode == "compose":
        check_tools(["docker", "openssl", "curl"])
        real = check_hostname(args.hostname)
        check_compose_env(args.env_file, args.hostname)
        if real:
            check_tls(args.hostname, args.https_port)
            check_docs_exposure(args.hostname, args.https_port)
        check_compose_runtime(args.hostname)
        if args.image and PLACEHOLDER_RE.search(args.image):
            record(FAIL, "image reference is pinned", args.image)
        elif args.image:
            record(PASS, "image reference supplied", args.image)
        else:
            record(TREQ, "image digest/tag to deploy", "pass --image")
    else:
        check_tools(["kubectl", "openssl", "curl"])
        real = check_hostname(args.hostname)
        check_kube(args.context, args.namespace, args.hostname)
        if real:
            check_tls(args.hostname, args.https_port)
            check_docs_exposure(args.hostname, args.https_port)

    print("\n" + "=" * 60)
    n_fail = sum(1 for s, *_ in _results if s == FAIL)
    n_treq = sum(1 for s, *_ in _results if s == TREQ)
    n_pass = sum(1 for s, *_ in _results if s == PASS)
    print(f"{n_pass} passed, {n_fail} failed, {n_treq} target-required")
    if n_treq:
        print("\nTARGET-REQUIRED checks still open -- a deploy must not proceed "
              "until each is verified against the named target:")
        for s, name, _ in _results:
            if s == TREQ:
                print(f"  - {name}")
    if n_fail:
        print("\nFAILED checks -- fix before deploying:")
        for s, name, detail in _results:
            if s == FAIL:
                print(f"  - {name}: {detail}")
        return 1
    print("\nAll applicable checks passed." if not n_treq else
          "\nNo failures; target-required checks remain.")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
