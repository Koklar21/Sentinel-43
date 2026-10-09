"""Read-only Compose status. Does not replace runtime governance or beta acceptance."""
from __future__ import annotations
import json
import subprocess
import sys

def inspect():
    try:
        p = subprocess.run(["docker", "compose", "ps", "--all", "--format", "json"], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unavailable", "services": []}
    if p.returncode:
        return {"status": "unavailable", "services": []}
    try:
        raw = p.stdout.strip()
        services = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines() if line.strip()]
        if not isinstance(services, list):
            raise ValueError("invalid Compose output")
    except (ValueError, TypeError):
        return {"status": "invalid-output", "services": []}
    by_name = {s.get("Service"): s for s in services if isinstance(s, dict)}
    required = {"s43-db", "s43-core", "s43-api", "s43-proxy"}
    healthy = all(by_name.get(name, {}).get("State") == "running" and by_name[name].get("Health") in ("healthy", "") for name in required)
    present = required <= by_name.keys()
    migration = by_name.get("s43-migrate", {})
    migrated = migration.get("State") == "exited" and str(migration.get("ExitCode")) == "0"
    return {"status": "ready" if present and healthy and migrated else "incomplete", "services": sorted(str(n) for n in by_name if n), "migration_completed": migrated}

if __name__ == "__main__":
    result = inspect()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "ready" else 2)
