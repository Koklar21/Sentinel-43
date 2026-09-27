"""Run the existing live tests against disposable CI services, with cleanup.

Requires an empty PostgreSQL service created by .github/workflows/k8s.yml.
Never points the bootstrap tests at a user-supplied deployment.
"""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]


def wait_ready(process: subprocess.Popen, url: str) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("CI service exited before becoming ready")
        try:
            with urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.25)
    raise RuntimeError("CI service did not become ready within 60 seconds")


def main() -> int:
    database_url = os.environ.get("S43_CI_DATABASE_URL", "")
    parsed = urlsplit(database_url)
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or parsed.scheme != "postgresql+asyncpg"
        or parsed.hostname != "127.0.0.1"
        or parsed.path != "/s43_ci"
    ):
        raise RuntimeError("Live CI tests require the disposable local s43_ci database")
    return run_live_suite(database_url)


def run_live_suite(database_url: str, *, api_port: int = 18000, watchtower_port: int = 19100) -> int:
    """Provision the disposable services on ``database_url`` and run the live suite.

    The CI guard above stays in ``main()``. scripts/acceptance_campaign.py calls
    this directly, with its own guard that only accepts a loopback database it
    created itself.
    """
    jwt_secret = secrets.token_urlsafe(32)
    pepper = secrets.token_urlsafe(32)
    service_token = secrets.token_urlsafe(32)
    # core.audit.store decodes this via bytes.fromhex and requires >= 32
    # decoded bytes -- hex, not urlsafe, and token_hex(32) is exactly that.
    audit_hmac_key = secrets.token_hex(32)
    sensitive = [
        database_url, jwt_secret, pepper, service_token,
        audit_hmac_key,
    ]
    for value in sensitive:
        print(f"::add-mask::{value}", flush=True)

    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(ROOT),
        "DATABASE_URL": database_url,
        "SENTINEL_ENV": "production",
        "S43_ENV": "production",
        "S43_JWT_SECRET": jwt_secret,
        "S43_JWT_ALGORITHM": "HS256",
        "S43_JWT_ISSUER": "sentinel-43-ci",
        "S43_JWT_AUDIENCE": "sentinel-43-ci-dashboard",
        "S43_AUTH_PEPPER": pepper,
        "S43_WS_REQUIRE_AUTH": "true",
        "S43_ENABLE_TEST_INJECTION": "false",
        "S43_SECRETS_ROTATED_AT": datetime.now(timezone.utc).isoformat(),
        # No S43_OPERATOR_USERNAME / S43_OPERATOR_PASSWORD_HASH /
        # S43_BREAK_GLASS_ARMED: the env-operator break-glass login is
        # refused outside development/local/test, armed or not, so in this
        # production-mode API it can authenticate nothing.
        #
        # SENTINEL_ENV=production: the API refuses to start unless this is
        # explicitly true, and per-request password authentication is
        # refused whatever it is set to.
        "S43_REJECT_LEGACY_AUTH": "true",
        "S43_WATCHTOWER_URL": f"http://127.0.0.1:{watchtower_port}",
        "S43_WATCHTOWER_SERVICE_TOKEN": service_token,
        # Mandatory outside development/local/test (core/api/main.py's
        # _start_audit_store()) -- the authoritative audit store cannot be
        # keyed without it.
        "S43_AUDIT_HMAC_KEY": audit_hmac_key,
        # core/api/main.py's _validate_security_config() added two more
        # non-local startup requirements after this script was last updated
        # for them: a Host allow-list, and an explicit assertion that TLS is
        # terminated before traffic reaches the API. Both are genuine,
        # correct requirements for a real deployment (this is not a
        # weakened check) -- this script just never supplied them, so the
        # API failed closed at startup rather than serving anything.
        #
        # S43_TRUSTED_HOSTS=127.0.0.1 is simply true: every request below
        # goes to S43_TEST_API_URL=http://127.0.0.1:18000, so 127.0.0.1 is
        # the only Host header this deployment will ever see.
        "S43_TRUSTED_HOSTS": "127.0.0.1",
        # S43_TLS_TERMINATED_AT_TRUSTED_EDGE is a claim this harness can
        # honestly make for its own narrow purpose: both uvicorn processes
        # are bound to 127.0.0.1 inside a single ephemeral, single-tenant
        # GitHub Actions runner with no external network exposure at all --
        # there is no public edge for TLS to protect, unlike the production
        # deployments (see deploy/kubernetes/, docker-compose.yml's
        # s43-proxy) this check exists for. This is not the same as
        # disabling the check: it still runs, and it would still fail this
        # script closed if the deployment shape ever changed to something
        # actually internet-facing.
        "S43_TLS_TERMINATED_AT_TRUSTED_EDGE": "true",
        # /auth/login enforces Origin/Referer validation outside a local
        # environment (core/api/routers/auth.py's
        # _check_state_change_origin), and test_bootstrap.py /
        # test_system_smoke.py now send an Origin header identifying
        # themselves as this exact address -- allow-list it.
        "S43_ALLOWED_ORIGINS": f"http://127.0.0.1:{api_port}",
    })
    # SENTINEL_ENV=production above, so core.auth.users.init_models() is a
    # deliberate no-op (Alembic owns the schema in a non-local environment).
    # Run the migration explicitly, exactly as a real deployment does, before
    # starting the API -- otherwise it 500s on a missing `users` table and
    # never becomes ready.
    migrate = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    if migrate.returncode != 0:
        for value in sensitive:
            migrate.stderr = migrate.stderr.replace(value, "[REDACTED]")
        print(migrate.stdout)
        print(migrate.stderr)
        raise RuntimeError("alembic upgrade head failed before live CI tests")

    processes: list[subprocess.Popen] = []
    handles = []
    result = 1
    with tempfile.TemporaryDirectory(prefix="s43-ci-") as tmp:
        try:
            for module, port, probe in (
                ("core.monitoring.watchtower:app", watchtower_port, "/watchtower/health"),
                ("core.api.main:app", api_port, "/bootstrap/status"),
            ):
                output = open(Path(tmp) / f"service-{port}.log", "w+")
                handles.append(output)
                process = subprocess.Popen(
                    [sys.executable, "-m", "uvicorn", module,
                     "--host", "127.0.0.1", "--port", str(port)],
                    cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT,
                )
                processes.append(process)
                wait_ready(process, f"http://127.0.0.1:{port}{probe}")

            test_env = os.environ.copy()
            test_env.update({
                "S43_TEST_API_URL": f"http://127.0.0.1:{api_port}",
                # Lets test_bootstrap.py establish its own fresh/initialized
                # state on THIS disposable database (it refuses anything
                # else). test_system_smoke.py's `_live_session` fixture uses
                # the same DSN the same way: reset users, claim bootstrap
                # itself, log in for a real session-bound token. Resolves
                # the D3/D4 gap this comment used to describe -- the harness
                # makes its own first-claim on its own disposable store, not
                # on behalf of any real deployment, exactly like
                # test_bootstrap.py already did. No S43_LIVE_TEST_USERNAME/
                # PASSWORD needed here: those name a pre-existing account on
                # a real target, which this disposable stack never has.
                "S43_LIVE_TEST_DB_DSN": database_url,
            })
            accept_out = os.environ.get("S43_ACCEPTANCE_OUT")
            if accept_out:
                # Zero-skip acceptance: same tests, run through the gate's
                # recorder so every test ID gets a machine-readable result.
                live_cmd = [sys.executable, "scripts/acceptance_gate.py", "run-job",
                            "core-live", "--out", accept_out]
            else:
                live_cmd = [sys.executable, "-m", "pytest", "-q",
                            "core/tests/test_bootstrap.py", "core/tests/test_system_smoke.py"]
            result = subprocess.run(live_cmd, cwd=ROOT, env=test_env, timeout=300).returncode
            return result
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for output in handles:
                if result:
                    output.seek(0)
                    log = output.read()
                    for value in sensitive:
                        log = log.replace(value, "[REDACTED]")
                    print(log[-12000:])
                output.close()


if __name__ == "__main__":
    raise SystemExit(main())
