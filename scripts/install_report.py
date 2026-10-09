"""Redacted local diagnostics; not a beta acceptance certificate."""
from __future__ import annotations
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def report():
    checks = {}
    for name, command in {
        "docker_engine": ["docker", "info", "--format", "{{.ServerVersion}}"],
        "compose_config": ["docker", "compose", "config", "--quiet"],
    }.items():
        try:
            p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20, check=False)
            checks[name] = "pass" if p.returncode == 0 else "fail"
        except (OSError, subprocess.TimeoutExpired):
            checks[name] = "incomplete"
    try:
        from scripts.install_compose_status import inspect
        checks["compose_services"] = "pass" if inspect()["status"] == "ready" else "fail"
    except (ImportError, OSError, ValueError, KeyError):
        checks["compose_services"] = "incomplete"
    return {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "checks": checks, "beta_accepted": False, "note": "Read-only local diagnostics; does not establish governed readiness or external-network acceptance."}

if __name__ == "__main__":
    result = report()
    print(json.dumps(result, indent=2))
    sys.exit(0 if all(v == "pass" for v in result["checks"].values()) else 2)
