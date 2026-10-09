"""Non-destructive recovery diagnostics; never prints secrets or mutates deployment."""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def plan():
    checks = []
    for name, command in (("compose_config", ["docker", "compose", "config", "--quiet"]),):
        try:
            p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20, check=False)
            checks.append({"check": name, "ok": p.returncode == 0})
        except (OSError, subprocess.TimeoutExpired):
            checks.append({"check": name, "ok": False})
    try:
        from scripts.install_compose_status import inspect
        state = inspect()
        checks.append({"check": "compose_services", "ok": state["status"] == "ready"})
    except (ImportError, OSError, ValueError, KeyError):
        checks.append({"check": "compose_services", "ok": False})
    return {"checks": checks, "next_step": "Review failures before retrying. No volumes, credentials, or admin accounts were modified."}

if __name__ == "__main__":
    result = plan()
    print(json.dumps(result, indent=2))
    sys.exit(0 if all(c["ok"] for c in result["checks"]) else 2)
