# eBPF runtime telemetry and detection

Phase 2 adds an **optional, observation-only Linux eBPF sensor**. It does not
create a second Sentinel-43 authority and it cannot quarantine, kill, block,
change policy, approve actions, or bypass Heart/human gates.

## Flow

`Linux sched_process_exec tracepoint -> bounded userspace sensor -> authenticated
/internal/ebpf/events -> MonitoringManager -> Fenrir -> canonical
ThreatAssessment -> Sentinel43RuntimeAuthority / Heart / existing human gate`

The API process does **not** receive kernel privileges. The sensor is a separate
operator-started Linux process using BCC. If BCC, kernel support, privileges, the
network, or the sensor itself are unavailable, Sentinel-43 continues without
eBPF coverage.

## Scope

Phase 2 observes process execution through the stable
`sched:sched_process_exec` tracepoint. Events contain only event id, host IP,
PID, UID, bounded command name, bounded executable path, severity and reason.
No argv, environment, file contents, credentials, packet payloads, or arbitrary
kernel memory are collected.

A deterministic evidence marker is emitted for execution from `/tmp`,
`/var/tmp`, or `/dev/shm`. This is evidence, not a verdict. Normal process
execs are informational telemetry.

## Bounds and failure semantics

* disabled by default with `S43_EBPF_ENABLED=false`
* dedicated bearer token: `S43_EBPF_INGEST_TOKEN`
* sensor cap: 200 events/second by default, hard-clamped to 1000
* BPF perf buffer is bounded
* request body is a strict Pydantic schema; extra fields are rejected
* endpoint assigns `source=sentinel-ebpf` and trusted producer `ebpf`;
  payloads cannot self-assert producer trust
* sensor delivery errors are dropped locally and never stop Sentinel-43
* missing monitoring returns 503; disabled ingress returns 404

## Linux requirements

Install BCC from the host distribution (for example the distro's Python BCC
package) and run the sensor with only the kernel/BPF privileges required by that
host. Do not grant privileges to the Sentinel-43 API container.

Example:

```bash
export S43_EBPF_API_URL=https://sentinel.example
export S43_EBPF_INGEST_TOKEN='...'
export S43_EBPF_HOST_IP=10.0.0.10
sudo -E python -m core.detection.ebpf_agent
```

The token must also be configured on the API. Production deployment should
provide it through the existing secret-management path, never commit it.
