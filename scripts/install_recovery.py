"""Non-destructive deployment checks. No secrets or command output are printed."""
from __future__ import annotations
import json
import subprocess
import sys

def plan():
    checks = []
    for name, command in (("compose_config", ["docker", "compose", "config", "--quiet"]), ("compose_services", ["docker", "compose", "ps", "--all", "--quiet"])):
        try:
            p = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
            checks.append({"check": name, "ok": p.returncode == 0})
        except (OSError, subprocess.TimeoutExpired):
            checks.append({"check": name, "ok": False})
    return {"checks": checks, "next_step": "Review failures before retrying. No volumes, credentials, or admin accounts were modified."}

if __name__ == "__main__":
    result = plan()
    print(json.dumps(result, indent=2))
    sys.exit(0 if all(c["ok"] for c in result["checks"]) else 2)
