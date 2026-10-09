"""Read-only Compose status inspection; does not create or mutate services."""
from __future__ import annotations
import json
import subprocess
import sys

def inspect():
    try:
        p = subprocess.run(["docker", "compose", "ps", "--format", "json"], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unavailable", "services": []}
    if p.returncode:
        return {"status": "unavailable", "services": []}
    try:
        services = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
    except (ValueError, TypeError):
        return {"status": "invalid-output", "services": []}
    required = {"s43-db", "s43-migrate", "s43-core", "s43-api", "s43-proxy"}
    names = {s.get("Service") for s in services}
    healthy = all(s.get("State") == "running" and s.get("Health") in ("healthy", "") for s in services if s.get("Service") in required - {"s43-migrate"})
    migrated = any(s.get("Service") == "s43-migrate" and s.get("ExitCode") == 0 for s in services)
    return {"status": "ready" if required <= names and healthy and migrated else "incomplete", "services": sorted(str(n) for n in names if n)}

if __name__ == "__main__":
    result = inspect()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "ready" else 2)
