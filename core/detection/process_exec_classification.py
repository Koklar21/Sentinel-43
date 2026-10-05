# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Platform-neutral classification for bounded process-execution observations.

Collectors are platform adapters.  They report observation facts; this module
owns the deterministic Sentinel-43 interpretation used by ingress adapters.
"""

from __future__ import annotations

SUSPICIOUS_EXEC_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")


def classify_process_exec(filename: str) -> tuple[str, str, str]:
    """Return (event_type, severity, reason) without taking any action."""
    path = filename.strip()[:512]
    if path.startswith(SUSPICIOUS_EXEC_PREFIXES):
        return (
            "ebpf_suspicious_exec",
            "medium",
            "executable path is in a transient writable directory",
        )
    return ("ebpf_process_exec", "informational", "")
