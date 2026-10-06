# Sentinel-43

**Sentinel-43 is a human-gated defensive cybersecurity oversight platform.**

It observes security activity, correlates evidence, classifies suspicious behavior, produces deterministic response recommendations, routes those recommendations through explicit governance, and records the resulting decisions in an auditable trail.

Its governing principle is simple:

> **Deterministic. Advisory. Never Autonomous.**

Sentinel-43 is built to help a human operator answer four questions quickly:

1. **What happened?**
2. **Why does it matter?**
3. **What response is justified by the evidence?**
4. **Who authorized what happened next?**

The system deliberately separates observation, detection, recommendation, governance, and external enforcement. Detection components can identify suspicious behavior and construct evidence. The response engine can plan and stage recommendations. Governance can approve or veto staged decisions. None of those layers silently becomes an unrestricted execution authority.

Sentinel-43 also watches its own operating state. Runtime health, subsystem state, audit integrity, authenticated sessions, service identity, and deployment boundaries are treated as part of the security problem rather than as unrelated plumbing.

The operator-facing dashboard exposes the governed system through authenticated API and WebSocket paths. It provides security visibility, recommendation state, audit information, subsystem health, runtime provenance, and account administration without becoming a second control plane.

In short, Sentinel-43 is not intended to replace the human responsible for a system. It is intended to give that human a coherent, explainable, security-focused view of what is happening and a controlled mechanism for deciding what should happen next.

---

# Technical Reference

## Architectural Rule

Sentinel-43 has one top-level runtime authority: `Sentinel43RuntimeAuthority`.

Subsystems provide evidence, analysis, storage, health information, recommendations, or governed interfaces beneath that authority. They do not independently create competing control planes.

The primary flow is:

```text
Observation
    ↓
Detection and Classification
    ↓
Evidence Correlation
    ↓
Response Planning
    ↓
Governance
    ↓
Human Decision
    ↓
Explicit External Integration Boundary
    ↓
Audit
```

Analysis and approval are not execution. Approval records a governed human decision. External effects require an explicitly integrated enforcement boundary.

## Governance Modes

The owner response engine supports two governed modes:

| Mode | Behavior |
| --- | --- |
| `SHADOW` | Analyze, recommend, stage observational results, and record without granting operational execution. |
| `HUMAN_GATED` | Stage recommendations for an authenticated human approval or veto decision. |

There is no unrestricted autonomous enforcement mode in the owner response engine.

## Owner Runtime Sources

The owner-designated runtime sources are under `Sentinel-43/`.

### `Shadow_mode.py`

The owner response-planning and staging engine.

Responsibilities include:

- mapping threat assessments into response directives
- deterministic response-action selection
- recommendation staging
- deduplication of repeated directives
- SHADOW behavior
- HUMAN_GATED approval and veto transitions
- target sanitization and pseudonymized security logging

It does not own a standalone database, executor thread, external integration authority, API authentication system, or independent lifecycle.

The governed loader verifies the canonical content digest of this file before loading it. A changed or unreviewed owner engine is refused rather than silently accepted.

### `Sentinel_Nexus.py`

Defines the governed integration and recommendation boundary between owner runtime behavior and the surrounding Sentinel-43 system.

### `Sentinel_core.py`

Provides owner runtime and node reporting contracts used by the governed composition.

### `sentinel_AI_escalation.py`

Handles owner-designated threat evidence and escalation contracts. It contributes evidence and escalation context without owning governance or external enforcement.

## Runtime Authority and Governance

The governance implementation lives under `core/governance/`.

### Runtime Authority

`runtime_authority.py` composes the authoritative runtime and exposes governed subsystem capabilities to the API and other trusted callers.

### Orchestrator

`orchestrator.py` coordinates governed recommendation lifecycle. It is the authority that may stage or resolve recommendations produced from Heart and detection evidence.

### Governed Owner Engine Adapter

`sentinel43_engine.py` loads the owner-designated Shadow engine, verifies its canonical integrity digest, and adapts it to Sentinel-43's authoritative storage and authenticated governance context.

The adapter intentionally does not add an execution path to the owner engine.

### Identity Governance

`identity.py` enforces account-management and identity rules at the governance boundary, including administrator protections, account lifecycle operations, and separation of human authority from service identity.

## Heart

Heart is the governed recommendation-lifecycle and recovery component.

It reports evidence and lifecycle state into the governance system. Heart does not independently approve, veto, stage, or execute operational action. When Heart is enabled, the governance authority must also be enabled; the runtime refuses a configuration that would leave Heart without its governing authority.

## Detection

Detection components live primarily under `core/detection/`.

### Fenrir

Fenrir is the threat-hunting and behavioral-analysis layer.

It combines deterministic scoring and correlation mechanisms to decide whether observed activity deserves attention. Its evidence can include:

- threat kind and severity
- behavioral indicators
- source classification
- bounded statistical anomaly information
- agent-sequence evidence
- supported Sigma-compatible rule matches
- evidence provenance
- AI-automation pattern indicators

Fenrir produces evidence. It does not own governance or enforcement.

### Sentinel Threat Detector

`sentinel_threat_detector.py` normalizes and classifies threat observations into the canonical detection contract used by downstream escalation and governance.

The detector preserves the distinction between ordinary human-likely activity, likely automated or AI-driven activity, and mixed or unknown sources. Classification is evidence-bearing rather than a grant of authority.

### Agent Sequence Detection

`agent_sequence_detector.py` correlates bounded sequences of observed behavior so suspicious multi-step activity can be evaluated as a pattern rather than as isolated events.

### Sigma Detection

`sigma_detector.py` provides a bounded Sigma-compatible rule path for supported Sentinel-43 telemetry. Rule matching contributes evidence to the existing detection pipeline rather than bypassing it.

### eBPF Agent

`ebpf_agent.py` supports host-level observation inputs where the deployment provides the required platform capabilities. Those observations still enter the governed detection path.

## Watchtower

Watchtower provides runtime-health and oversight signals.

Its job is to help determine whether Sentinel-43 and its supporting components are operating as expected. Health reporting is separate from threat authority: a subsystem reporting a fault does not gain permission to take unrelated operational action.

## Sparta

Sparta monitors selected integrity and runtime conditions and reports those observations into Sentinel-43's governed monitoring path.

Like other monitoring components, Sparta reports evidence. It is not an independent enforcement authority.

## Audit

The audit subsystem under `core/audit/` preserves authoritative security, governance, and operator-decision records.

The audit design is intended to preserve answers to:

- what occurred
- when it occurred
- which subsystem produced the event
- what evidence or context accompanied it
- which authenticated authority made a governed decision

Integrity-sensitive audit configuration is validated fail-closed where required.

## Authentication and Human Identity

Human accounts and service identities are separate concepts.

Human authority follows a narrow model:

- initial deployment ownership is established through the one-time administrator claim
- the deployment retains a single administrator under normal account-management rules
- the administrator may create and manage trusted observer accounts
- observer authority is limited to the governed capabilities assigned to that role
- ordinary client accounts do not inherit observer or administrator authority
- account roles cannot be silently promoted through client-facing enrollment
- password changes and security-sensitive account changes revoke affected sessions as required
- authenticated session state, refresh rotation, logout, and revocation are handled by the authentication subsystem

Service credentials authenticate machine-to-machine responsibilities. A service identity does not become a human approver merely because it is authenticated.

## API

The API under `core/api/` exposes Sentinel-43's authenticated application boundary.

Its responsibilities include:

- authentication and session handling
- first-administrator bootstrap
- governed account management
- optional client enrollment
- audit access
- monitoring and runtime information
- governed recommendation and decision interfaces
- remote-gateway boundaries
- router telemetry ingestion
- authenticated WebSocket state delivery
- security headers, origin policy, trusted-host policy, and proxy-aware request handling

Security-sensitive non-local configuration is validated fail-closed. Known placeholder values are not accepted as deployment secrets where a generated secret is required.

## Dashboard

The live operator interface is:

```text
dashboard/sentinel_43_dashboard.html
```

with browser assets under:

```text
dashboard/assets/
```

The API serves the dashboard as a single-page application.

The dashboard is a client of the governed API. It does not own security authority, duplicate governance logic, or create a separate backend decision system.

Its operator surfaces include:

- subsystem health
- threat and monitoring information
- staged recommendation state
- pending human decisions
- audit information
- runtime provenance
- administrator account management
- first-administrator onboarding
- authenticated live updates

## Security Boundaries

Sentinel-43 repeatedly applies the following boundaries:

- security-critical configuration fails closed when invalid or missing
- human identities and machine identities remain distinct
- observation does not imply authority
- detection does not imply enforcement
- recommendation does not imply execution
- one runtime authority governs subordinate components
- administrative operations require explicit authenticated authority
- credentials and secret material are kept out of source control and routine logs
- sensitive log targets are pseudonymized with deployment-owned secret material
- forwarded network identity is trusted only through explicitly configured proxy boundaries
- browser origins and host handling are restricted outside local environments
- non-local browser transport is expected to use TLS-protected HTTP and WebSocket paths
- owner-engine integrity is verified before the governed engine is loaded

No real credentials, generated secret values, private keys, tokens, or deployment-specific secret material belong in this README.

## Router Telemetry

Sentinel-43 can receive observation-only edge-device telemetry through its router monitoring path.

The collector restricts trusted sources, forwards authenticated observations into the API, and keeps classification inside Sentinel-43. The collector itself does not assign final threat severity or perform enforcement.

High-signal router observations enter the same monitoring, detection, evidence, and governance path as other supported inputs.

## Deployment Surfaces

### Docker Compose

The repository includes Docker Compose definitions for local and configured multi-service operation.

The local startup wrapper prepares required environment state before Compose interpolation and preserves existing deployment secrets unless an operator deliberately performs a rotation.

Direct Compose startup assumes the required environment has already been configured correctly.

### Kubernetes

Kubernetes resources live under:

```text
deploy/kubernetes/
```

The manifests define the application and supporting service topology while leaving deployment-owned credentials, certificates, registry details, network policy choices, and environment-specific values to the operator.

Template placeholder values are not credentials and must not be treated as valid non-local runtime secrets.

## Repository Layout

```text
Sentinel-43/          owner-designated runtime sources
core/api/             authenticated API and request boundaries
core/auth/            users, sessions, and authentication persistence
core/audit/           authoritative audit storage and integrity
core/detection/       threat detection and evidence production
core/governance/      runtime authority, Heart, identity, and orchestration
core/monitoring/      runtime and subsystem monitoring
core/security/        shared security primitives and validation
dashboard/            operator-facing web application
deploy/               deployment definitions
migrations/           database schema migrations
scripts/              operational and deployment tooling
docs/                 detailed technical and operator documentation
```

## Operational Documentation

Detailed procedures and environment-specific operating instructions belong under `docs/` and the deployment directories rather than in this README.

Useful technical references include:

- `REVIEWING.md` for architecture-review guidance
- `docs/security/` for security-specific documentation
- `docs/SIGMA_DETECTION.md` for the supported Sigma detection contract
- `deploy/kubernetes/README.md` for Kubernetes-specific configuration
- `Sentinel-43/README.md` for owner runtime source details

## What Sentinel-43 Is Not

Sentinel-43 is not:

- an autonomous attack platform
- an offensive-security framework
- an unrestricted self-directed response engine
- a hidden enforcement system
- a substitute for human operational authority

It is a defensive observation, analysis, recommendation, governance, and audit platform.

## Licensing

Sentinel-43 is dual-licensed:

1. **AGPL-3.0-or-later**
2. **Commercial license**

See `LICENSE` and `COMMERCIAL_LICENSE.md` for the authoritative terms.

## Disclaimer

Sentinel-43 is provided **AS IS**, without warranty of any kind.

Use it only on systems and environments you own or are explicitly authorized to operate.
