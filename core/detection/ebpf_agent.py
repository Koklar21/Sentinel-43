# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Optional Linux eBPF process-exec sensor.

The kernel program observes sched_process_exec only. Userspace performs bounded
normalization and forwards evidence to Sentinel-43. It never enforces.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import json
import os
import queue
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass

MAX_EVENTS_PER_SECOND = 200
MAX_DELIVERY_QUEUE = 1024
SUSPICIOUS_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")

_BPF = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();
    event.pid = pid_tgid >> 32;
    event.uid = (u32)uid_gid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    unsigned int off = args->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&event.filename, sizeof(event.filename), (void *)args + off);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


class _ExecEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
    ]


@dataclass(frozen=True, slots=True)
class SensorConfig:
    api_url: str
    token: str
    host_ip: str
    max_events_per_second: int = MAX_EVENTS_PER_SECOND


def classify_exec(filename: str) -> tuple[str, str, str]:
    """Return (event_type, severity, reason) without taking any action."""
    path = filename.strip()[:512]
    if path.startswith(SUSPICIOUS_PREFIXES):
        return (
            "ebpf_suspicious_exec",
            "medium",
            "executable path is in a transient writable directory",
        )
    return ("ebpf_process_exec", "informational", "")


def build_payload(event: _ExecEvent, host_ip: str) -> dict[str, object]:
    comm = bytes(event.comm).split(b"\0", 1)[0].decode("utf-8", "replace")[:64]
    filename = (
        bytes(event.filename).split(b"\0", 1)[0].decode("utf-8", "replace")[:512]
    )
    return {
        "event_id": str(uuid.uuid4()),
        "host_ip": host_ip,
        "pid": int(event.pid),
        "uid": int(event.uid),
        "comm": comm,
        "filename": filename,
    }


def post_event(config: SensorConfig, payload: dict[str, object]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        config.api_url.rstrip("/") + "/internal/ebpf/events",
        data=body,
        headers={
            "Authorization": f"Bearer {config.token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=2.0) as response:
        response.read(1024)


def run(config: SensorConfig) -> None:
    try:
        from bcc import BPF
    except ImportError as exc:
        raise RuntimeError(
            "BCC Python bindings are required for the optional eBPF sensor"
        ) from exc

    bpf = BPF(text=_BPF)
    window_started = time.monotonic()
    emitted = 0
    delivery_queue: queue.Queue[dict[str, object]] = queue.Queue(
        maxsize=MAX_DELIVERY_QUEUE
    )

    def deliver() -> None:
        while True:
            payload = delivery_queue.get()
            try:
                post_event(config, payload)
            except Exception:
                # Coverage degrades; delivery failure is not runtime failure.
                pass
            finally:
                delivery_queue.task_done()

    threading.Thread(
        target=deliver,
        name="s43-ebpf-delivery",
        daemon=True,
    ).start()

    def on_exec(_cpu: int, data: int, _size: int) -> None:
        nonlocal window_started, emitted
        now = time.monotonic()
        if now - window_started >= 1.0:
            window_started, emitted = now, 0
        if emitted >= config.max_events_per_second:
            return
        emitted += 1
        event = ct.cast(data, ct.POINTER(_ExecEvent)).contents
        try:
            delivery_queue.put_nowait(build_payload(event, config.host_ip))
        except queue.Full:
            # Bounded loss is preferable to blocking kernel-event consumption.
            return

    bpf["events"].open_perf_buffer(on_exec, page_cnt=8)
    while True:
        bpf.perf_buffer_poll(timeout=1000)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel-43 eBPF exec sensor")
    parser.add_argument("--api-url", default=os.getenv("S43_EBPF_API_URL", ""))
    parser.add_argument("--token", default=os.getenv("S43_EBPF_INGEST_TOKEN", ""))
    parser.add_argument("--host-ip", default=os.getenv("S43_EBPF_HOST_IP", "127.0.0.1"))
    parser.add_argument(
        "--max-events-per-second",
        type=int,
        default=int(os.getenv("S43_EBPF_MAX_EVENTS_PER_SECOND", str(MAX_EVENTS_PER_SECOND))),
    )
    args = parser.parse_args()
    if not args.api_url or not args.token:
        raise SystemExit("S43_EBPF_API_URL and S43_EBPF_INGEST_TOKEN are required")
    limit = max(1, min(int(args.max_events_per_second), 1000))
    run(SensorConfig(args.api_url, args.token, args.host_ip, limit))


if __name__ == "__main__":
    main()
