# Sentinel-43 Independent Review Guide

Thank you for reviewing Sentinel-43.

This document is a map for independent reviewers. It does not replace the project README, the Beta Runbook, or the source code. Findings are more useful than approvals: please report assumptions that do not hold, security boundaries that can be bypassed, failure modes that are unsafe or misleading, and documentation that does not match the implementation.

## Start here

1. Read `README.md` for the project purpose, current maturity, authority model, and component overview.
2. Read `docs/BETA_RUNBOOK.md` before evaluating deployment or beta-readiness claims.
3. Treat `docs/reconstruction/` as historical evidence only. Those records are not the current source of truth.
4. Review the implementation and tests behind any claim you evaluate rather than relying on documentation alone.

## Architectural invariants

Sentinel-43 is a defensive, human-gated system. The intended hierarchy is:

```text
Sentinel43RuntimeAuthority
  -> SystemOrchestrator
     -> detection / monitoring / recommendation components
        -> governed human decision boundary
```

Detection components, telemetry collectors, Heart, Fenrir, Watchtower, Sparta, routers, and host/edge adapters must not become independent enforcement or governance authorities.

Platform-specific collectors are adapters. Sentinel-43 core is intended to remain operating-system neutral.

## High-value review areas

Please prioritize:

- authentication, session, bootstrap, and service-identity separation
- RuntimeAuthority and governance-boundary bypasses
- evidence provenance and trusted-producer boundaries
- SentinelFirewall and trusted-proxy behavior
- monitoring, Watchtower, Fenrir, Heart, and Sparta failure behavior
- telemetry normalization and detector evasion/false-positive risks
- audit integrity and recovery behavior
- Docker/Kubernetes deployment assumptions and secret handling
- WebSocket authentication and reauthorization
- fail-open behavior, unsafe defaults, resource exhaustion, and concurrency defects
- disagreement between README/runbook claims and reachable runtime behavior

## Review boundaries

Do not use production systems, third-party targets, or networks you are not authorized to test. A useful review does not require offensive activity against external systems.

Do not submit real credentials, tokens, private keys, personal data, packet captures, event logs, or machine-local environment files to the repository.

If a finding could expose a credential or a serious exploitable vulnerability, report it privately to the repository owner rather than publishing working exploitation details in a public issue.

## Useful finding format

A strong finding includes:

- affected revision or commit
- affected file/function/route
- severity and practical impact
- expected behavior
- observed behavior
- minimal reproduction or test case
- whether the issue fails open or fails closed
- suggested direction for remediation, if known

Independent disagreement is welcome. The goal is to find defects and invalid assumptions before users do.
