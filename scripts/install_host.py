"""Read-only, OS-neutral host prerequisite checks for Sentinel-43."""
from __future__ import annotations
import json
import platform
import shutil
import subprocess
import sys

def inspect():
    result = {"platform": platform.system(), "architecture": platform.machine(), "python": platform.python_version(), "docker_cli": bool(shutil.which("docker"))}
    if not result["docker_cli"]:
        result["docker_engine"] = "unavailable"
        return result
    try:
        p = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=12, check=False)
        result["docker_engine"] = "available" if p.returncode == 0 else "unavailable"
    except (OSError, subprocess.TimeoutExpired):
        result["docker_engine"] = "unavailable"
    return result

if __name__ == "__main__":
    state = inspect()
    print(json.dumps(state, indent=2))
    sys.exit(0 if state["docker_engine"] == "available" else 2)
