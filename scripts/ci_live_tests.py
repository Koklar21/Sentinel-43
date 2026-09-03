"""Run the existing live tests against disposable CI services, with cleanup.

Requires an empty PostgreSQL service created by .github/workflows/k8s.yml.
Never points the bootstrap tests at a user-supplied deployment.
"""

from __future__ import annotations

import hashlib
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

    password = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    pepper = secrets.token_urlsafe(32)
    service_token = secrets.token_urlsafe(32)
    sensitive = [database_url, password, jwt_secret, pepper, service_token]
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
        "S43_OPERATOR_USERNAME": "ci-live-operator",
        "S43_OPERATOR_PASSWORD_HASH": hashlib.sha256(password.encode()).hexdigest(),
        "S43_WATCHTOWER_URL": "http://127.0.0.1:19100",
        "S43_WATCHTOWER_SERVICE_TOKEN": service_token,
    })
    processes: list[subprocess.Popen] = []
    handles = []
    result = 1
    with tempfile.TemporaryDirectory(prefix="s43-ci-") as tmp:
        try:
            for module, port, probe in (
                ("core.monitoring.watchtower:app", 19100, "/watchtower/health"),
                ("core.api.main:app", 18000, "/bootstrap/status"),
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
                "S43_TEST_API_URL": "http://127.0.0.1:18000",
                "S43_LIVE_TEST_USERNAME": "ci-live-operator",
                "S43_LIVE_TEST_PASSWORD": password,
            })
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q",
                 "core/tests/test_bootstrap.py", "core/tests/test_system_smoke.py"],
                cwd=ROOT, env=test_env, timeout=300,
            ).returncode
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
