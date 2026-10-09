"""Generate a non-destructive recovery checklist; never remove data."""
from __future__ import annotations
import json
import subprocess
import sys

def plan():
    commands = [["docker", "compose", "config", "--quiet"], ["docker", "compose", "ps", "--all"]]
    checks = []
    for command in commands:
        try:
            p = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
            checks.append({"command": " ".join(command), "ok": p.returncode == 0})
        except (OSError, subprocess.TimeoutExpired):
            checks.append({"command": " ".join(command), "ok": False})
    return {"checks": checks, "next_step": "Review failures before retrying. No volumes, credentials, or admin accounts were modified."}

if __name__ == "__main__":
    result = plan()
    print(json.dumps(result, indent=2))
    sys.exit(0 if all(c["ok"] for c in result["checks"]) else 2)
