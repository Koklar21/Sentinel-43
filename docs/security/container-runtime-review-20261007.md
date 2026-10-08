# Sentinel-43 container security review (October 2026)

## Scope and authority

Reviewed the Docker Compose runtime boundary against the Docker security infographic and the existing Kubernetes workload controls. These changes **do not** change Sentinel43RuntimeAuthority, Watchtower authority, detector permissions, governance, or approval gates. Detection remains evidence-only; no detector gains enforcement privileges.

## Changes in this PR

- `s43-api`, `s43-core` (Watchtower), and `s43-migrate` drop all Linux capabilities, prohibit privilege escalation and limit process counts.
- Existing non-root image UID 65532, network topology, proxy port bindings, database and audit/state volumes, health/readiness ordering and runtime commands remain unchanged.
- The Compose stack does **not** automatically inherit Kubernetes `securityContext`. These settings close part of that deployment gap.

## Controls already present

- The shared runtime Dockerfile runs as UID/GID 65532.
- Kubernetes API/core use `runAsNonRoot`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, and resource limits.
- Compose exposes only the TLS reverse proxy to the host; API and Watchtower are internal. State/audit data uses a named volume.
- The setup profile uses `network_mode: none` and is not part of normal service startup.

## Deferred for compatibility review

1. **Read-only Compose root filesystems:** establish explicit writable `/tmp` and `/app/logs` mounts for API and Watchtower, then verify actual Python, audit and startup writes before enabling. Do not turn on read-only mode while guessing about writes.
2. **nginx:** its official image entrypoint and binding to ports 80/443 can require privileges. Determine a tested non-root/high-port or carefully scoped capability design before dropping all capabilities.
3. **PostgreSQL:** initialization and volume ownership can require capabilities. Avoid indiscriminate capability removal. Assess read-only rootfs and process/resource limits with migration and persistence checks.
4. **Image supply chain:** pin reviewed digests in deployment workflows, generate SBOMs, scan images, and verify signatures/provenance. Avoid unreviewed mutable tag updates.
5. **Secrets:** use production secret delivery rather than treating Compose environment interpolation as a secure vault. Do not print resolved secrets in CI artifacts.
6. **Egress and telemetry:** segment workloads, explicitly govern outbound destinations, and keep eBPF/router sensors outside unprivileged API containers. Container network separation alone is not egress filtering.
7. **Host controls:** verify Docker daemon socket isolation, default seccomp, supported AppArmor/SELinux profiles, log rotation and disk-space alerting. Windows Docker Desktop Linux containers run under a Linux VM.
8. **Ingress:** retain the existing 80/443 edge and TLS behavior; do not apply Nullgate's localhost binding to S43 without designing its intended remote-access path.

## Validation boundary

No Docker execution, tests, container redeployment or production changes were performed. Before merge or deployment, validate resolved Compose structure securely, exercise first-run initialization, PostgreSQL migration, API and Watchtower readiness, nginx TLS, audit persistence, and browser/WAN access on a disposable environment. Roll back if privileges or limits interrupt startup.

References:
- https://docs.docker.com/engine/security/
- https://docs.docker.com/reference/compose-file/services/
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
