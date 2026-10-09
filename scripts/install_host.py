"""Read-only, OS-neutral host prerequisites for Sentinel-43."""
from __future__ import annotations
import json
import platform
import shutil
import subprocess
import sys

def inspect():
    state = {"platform": platform.system(), "architecture": platform.machine(), "python": platform.python_version(), "docker_cli": bool(shutil.which("docker")), "compose": "unavailable", "docker_engine": "unavailable"}
    if not state["docker_cli"]:
        return state
    for key, cmd in (("docker_engine", ["docker", "info", "--format", "{{.ServerVersion}}"]), ("compose", ["docker", "compose", "version", "--short"])):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=12, check=False)
            if result.returncode == 0:
                state[key] = "available"
        except (OSError, subprocess.TimeoutExpired):
            pass
    return state

if __name__ == "__main__":
    state = inspect()
    print(json.dumps(state, indent=2))
    sys.exit(0 if state["docker_engine"] == state["compose"] == "available" else 2)
