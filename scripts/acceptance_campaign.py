#!/usr/bin/env python3
"""Local zero-skip acceptance campaign (serialized, disposable services only).

    python scripts/acceptance_campaign.py --out acceptance_out

Provisions ONLY disposable resources it creates itself (a throwaway PostgreSQL
container on loopback, uvicorn processes on free loopback ports, the
``s43browser`` Compose stack), runs every required job from
``acceptance/suites.json`` one at a time, then asks the gate for the verdict.
It never points a suite at an existing deployment. Required jobs that cannot be
run legitimately here are recorded as ``env_unmet`` -- never omitted, never
skipped.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = [sys.executable, str(ROOT / "scripts" / "acceptance_gate.py")]
PG_NAME = "s43-accept-pg"
PG_PORT = 55432
KUBECONFORM_VERSION = "v0.8.0"


def free_mb() -> int:
    if os.name == "nt":
        class MS(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (n, ctypes.c_ulonglong) for n in ("tp", "ap", "tpf", "apf", "tv", "av", "ax")]
        ms = MS(); ms.l = ctypes.sizeof(ms)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
        return int(ms.ap // (1024 * 1024))
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable"):
            return int(line.split()[1]) // 1024
    return 1 << 30


def wait_memory(label: str, minimum: int, timeout: int = 3 * 3600) -> bool:
    """Delay a heavyweight job until at least ``minimum`` MB of RAM is free.

    SCHEDULING ONLY. The floor decides *when* a job starts; it never changes
    what counts as PASS, FAIL or SKIP. It is not a Sentinel-43 policy: the default
    (700 MB) is an assumed campaign default for one 16 GB laptop that also runs
    Docker Desktop's Kubernetes, and is overridable with --min-free-mb or
    S43_ACCEPT_MIN_FREE_MB. If the floor is still unmet after ``timeout`` the
    whole campaign aborts (exit 4) WITHOUT writing a verdict -- a job that was
    merely deferred is never recorded as failed, skipped or passed.
    """
    deadline = time.monotonic() + timeout
    while free_mb() < minimum:
        if time.monotonic() > deadline:
            print(f"[memory] floor {minimum} MB never reached for {label}; aborting campaign "
                  "(no verdict written)", flush=True)
            raise SystemExit(4)
        print(f"[memory] {free_mb()} MB free < {minimum} MB; deferring {label}", flush=True)
        time.sleep(15)
    return True


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, **kw)


def gate(*args: str, env: dict | None = None) -> int:
    return run(GATE + list(args), env=env).returncode


# ---------------------------------------------------------------- disposable PG
def start_pg(password: str) -> None:
    run(["docker", "rm", "-f", PG_NAME], capture_output=True)
    if not port_free(PG_PORT):
        raise SystemExit(f"loopback port {PG_PORT} is in use; refusing to start the disposable PostgreSQL")
    run(["docker", "run", "-d", "--name", PG_NAME, "-e", "POSTGRES_USER=s43t", "-e", f"POSTGRES_PASSWORD={password}",
         "-e", "POSTGRES_DB=s43t", "-p", f"127.0.0.1:{PG_PORT}:5432", "postgres:16.3"],
        check=True, capture_output=True)
    for _ in range(60):
        if run(["docker", "exec", PG_NAME, "pg_isready", "-U", "s43t", "-d", "s43t"], capture_output=True).returncode == 0:
            time.sleep(2)  # pg_isready is true during the init-time restart; settle
            if run(["docker", "exec", PG_NAME, "pg_isready", "-U", "s43t", "-d", "s43t"], capture_output=True).returncode == 0:
                break
        time.sleep(1)
    else:
        raise SystemExit("disposable PostgreSQL did not become ready")
    run(["docker", "exec", PG_NAME, "psql", "-U", "s43t", "-d", "s43t", "-c", "CREATE DATABASE s43_accept_live"],
        check=True, capture_output=True)


def stop_pg() -> None:
    run(["docker", "rm", "-f", "-v", PG_NAME], capture_output=True)


# ------------------------------------------------------------------- job groups
def job_postgres(out: str, password: str) -> None:
    env = os.environ.copy()
    env["S43_TEST_PG_DSN"] = f"postgresql+asyncpg://s43t:{password}@127.0.0.1:{PG_PORT}/s43t"
    env["S43_TEST_PG_CONTAINER"] = PG_NAME
    gate("run-job", "core-postgres", "--out", out, env=env)


def job_live(out: str, password: str) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import ci_live_tests
    api, wt = free_port(), free_port()
    dsn = f"postgresql+asyncpg://s43t:{password}@127.0.0.1:{PG_PORT}/s43_accept_live"
    # This campaign created the database and picked both ports, so the
    # disposable-target guarantee ci_live_tests' GitHub-only guard protects holds.
    os.environ["S43_ACCEPTANCE_OUT"] = out
    os.environ.pop("S43_TEST_API_URL", None)
    ci_live_tests.run_live_suite(dsn, api_port=api, watchtower_port=wt)


def git_bash() -> str:
    """Git-for-Windows bash. A bare "bash" on Windows resolves to the WSL launcher."""
    if os.name != "nt":
        return "bash"
    git = shutil.which("git")
    for cand in ([Path(git).parents[1] / "bin" / "bash.exe"] if git else []) + [
            Path("C:/Program Files/Git/bin/bash.exe")]:
        if cand.exists():
            return str(cand)
    raise SystemExit("Git bash not found; cannot run browser_tests/run.sh")


def job_browser(out: str) -> None:
    env = os.environ.copy()
    env["S43_ACCEPTANCE_OUT"] = out
    run([git_bash(), "browser_tests/run.sh"], env=env)


def job_container(out: str) -> int:
    """core-isolated inside the runtime image's test stage (what CI's build-and-scan does)."""
    tag = "sentinel43-api:accept-test"
    r = run(["docker", "build", "--target", "test", "-t", tag, "-f", "core/api/Dockerfile", "."])
    if r.returncode:
        return r.returncode
    mount = ["-v", f"{out}:/out", "-e", "S43_ACC_REVISION_FILE=/out/revision.json"]
    gate_in = ["python", "scripts/acceptance_gate.py"]
    rc = run(["docker", "run", "--rm", *mount, tag, *gate_in, "inventory", "--out", "/out",
              "--job", "core-isolated-container"]).returncode
    return rc or run(["docker", "run", "--rm", *mount, tag, *gate_in, "run-job",
                      "core-isolated-container", "--out", "/out"]).returncode


def check_command(name: str) -> list[str]:
    return GATE[:0] + [sys.executable, str(ROOT / "scripts" / "acceptance_campaign.py"), "check", name]


COMPOSE_VALIDATION_PEPPER_PREFIX = "ci-compose-validation-only-NOT-A-SECRET-"


def compose_validation_env() -> dict:
    """Environment for `docker compose config` ONLY.

    Compose files require S43_SESSION_HASH_PEPPER (``${VAR:?...}``) and `config -q`
    interpolates it, so validating the files needs *a* value. It gets a fresh,
    ephemeral, unmistakably non-production one, handed to that one child process and
    never exported, written, or reused: `config` renders the file and starts nothing.
    A value already present in the caller's environment is left alone. The
    requirement itself is not weakened -- the compose files still refuse to start
    without it, and nothing here reaches a real deployment.
    """
    env = os.environ.copy()
    if not env.get("S43_SESSION_HASH_PEPPER"):
        env["S43_SESSION_HASH_PEPPER"] = COMPOSE_VALIDATION_PEPPER_PREFIX + secrets.token_hex(16)
    return env


def do_check(name: str) -> int:
    """Body of a required non-pytest check. Exit code is the check verdict."""
    rendered = []
    if name == "compose":
        rc = 0
        for files in (["docker-compose.yml"], ["docker-compose.yml", "docker-compose.beta.yml"],
                      ["docker-compose.yml", "docker-compose.browser.yml"]):
            cmd = ["docker", "compose", "--env-file", ".env.example"]
            for f in files:
                cmd += ["-f", f]
            r = run(cmd + ["config", "-q"], capture_output=True, text=True, env=compose_validation_env())
            print(files, "rc", r.returncode, r.stderr[-500:])
            rc |= r.returncode
        return rc
    for overlay in ("base", "overlays/dev", "overlays/beta"):
        r = run(["kubectl", "kustomize", f"deploy/kubernetes/{overlay}"], capture_output=True, text=True)
        if r.returncode:
            print(r.stderr); return 1
        dest = ROOT / "acceptance_out" / f"rendered-{overlay.replace('/', '-')}.yaml"
        dest.parent.mkdir(exist_ok=True); dest.write_text(r.stdout, encoding="utf-8")
        rendered.append(dest)
    rc = 0
    if name == "k8s-policy":
        for d in rendered:
            rc |= run([sys.executable, "scripts/k8s_policy_check.py", str(d)]).returncode
        return rc
    if name == "kubeconform":
        exe = shutil.which("kubeconform") or str(ROOT / "acceptance_out" / "kubeconform.exe")
        if not Path(exe).exists():
            url = (f"https://github.com/yannh/kubeconform/releases/download/{KUBECONFORM_VERSION}/"
                   "kubeconform-windows-amd64.zip")
            import io, zipfile
            with urllib.request.urlopen(url, timeout=120) as resp:
                zipfile.ZipFile(io.BytesIO(resp.read())).extract("kubeconform.exe", str(ROOT / "acceptance_out"))
        for d in rendered:
            rc |= run([exe, "-strict", "-summary", "-kubernetes-version", "1.30.0", str(d)]).returncode
        return rc
    if name == "image-scan":
        # Scan an image built from the checked-out tree with the local Trivy image.
        tag = "sentinel43-api:accept"
        r = run(["docker", "build", "-t", tag, "-f", "core/api/Dockerfile", "."])
        if r.returncode:
            return r.returncode
        return run(["docker", "run", "--rm", "-v", "//var/run/docker.sock:/var/run/docker.sock",
                    "aquasec/trivy:latest", "image", "--scanners", "vuln", "--severity", "HIGH,CRITICAL",
                    "--exit-code", "1", "--ignore-unfixed=false", tag]).returncode
    raise SystemExit(f"unknown check {name}")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check"); c.add_argument("name")
    ap.add_argument("--out", default="acceptance_out")
    ap.add_argument("--min-free-mb", type=int, default=int(os.environ.get("S43_ACCEPT_MIN_FREE_MB", "700")),
                    help="campaign scheduling default: defer heavyweight jobs until this much RAM (MB) is free. "
                         "Never affects PASS/FAIL/SKIP; not a Sentinel-43 policy")
    ap.add_argument("--skip-browser", action="store_true", help="record the browser job as unmet instead of running it")
    args = ap.parse_args()
    if args.cmd == "check":
        return do_check(args.name)

    # A fresh timestamped directory per campaign: stale results can never be mistaken for this run's.
    out = str((Path(args.out) / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())).resolve())
    Path(out).mkdir(parents=True)
    print(f"evidence directory: {out}", flush=True)
    password = secrets.token_urlsafe(24)
    for var in ("S43_TEST_PG_DSN", "S43_TEST_PG_CONTAINER", "S43_TEST_API_URL", "S43_BROWSER_BASE_URL"):
        os.environ.pop(var, None)  # only this campaign's own disposable services may feed the suites

    gate("inventory", "--out", out)  # recorded BEFORE any execution
    gate("inventory-all", "--out", out)  # independent whole-tree collection for the omission check
    try:
        wait_memory("core-isolated", args.min_free_mb)
        gate("run-job", "core-isolated", "--out", out)
        wait_memory("postgres jobs", args.min_free_mb)
        start_pg(password)
        job_postgres(out, password)
        job_live(out, password)
    finally:
        stop_pg()

    if args.skip_browser:
        gate("mark-unmet", "browser-disposable", "--out", out, "--reason", "browser job not run (--skip-browser)")
    else:
        wait_memory("browser stack", args.min_free_mb)
        job_browser(out)

    wait_memory("container test stage", args.min_free_mb)
    job_container(out)

    if all(os.environ.get(v) for v in ("S43_TARGET_BASE_URL", "S43_TARGET_OPERATOR_CRED_FILE")):
        gate("run-job", "browser-target", "--out", out)
    else:
        gate("mark-unmet", "browser-target", "--out", out,
             "--reason", "no explicitly authorized isolated target/credentials supplied (S43_TARGET_* unset)")

    for job, name in (("check-compose-config", "compose"), ("check-k8s-policy", "k8s-policy"),
                      ("check-kubeconform", "kubeconform"), ("check-image-scan", "image-scan")):
        # Only the image build + scan is memory-heavy; the render/lint checks are not.
        if job == "check-image-scan":
            wait_memory(job, args.min_free_mb)
        gate("run-check", "--out", out, job, "--", *check_command(name))
    gate("mark-unmet", "check-kind-smoke", "--out", out,
         "--reason", "kind + Calico smoke deploy needs a hosted CI runner / kind binary; none available locally")
    return gate("verify", "--out", out, "--mode", "final-beta")


if __name__ == "__main__":
    raise SystemExit(main())
