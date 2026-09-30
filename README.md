# Sentinel-43

## Late Alpha Development Build

Sentinel-43 is currently in:

> LATE ALPHA — Architecture Consolidation, Beta Hardening, and Deployment Preparation

Sentinel-43 is undergoing architecture consolidation and hardening,
session-authentication hardening, deployment validation, migration
infrastructure work, security regression testing, and Beta-readiness
preparation.

This release is intended for controlled development and validation.

It is NOT currently certified or recommended for unrestricted production
deployment.

**Deploying a controlled beta?** See [`docs/BETA_RUNBOOK.md`](docs/BETA_RUNBOOK.md)
— the one authoritative runbook for both the Compose and Kubernetes paths.
It explicitly is not a production or public-sector readiness statement.

---

# Mission

Sentinel-43 is a defensive cybersecurity oversight platform designed to
observe, analyze, classify, recommend, govern, and audit security events
while maintaining human control over enforcement decisions.

Sentinel-43 is intentionally designed as a human-gated system.

The platform may:

- detect and receive threat observations
- correlate security activity
- classify risk
- generate recommendations
- explain decisions
- route decisions through governance workflows
- maintain durable audit records
- expose operational state to authenticated interfaces
- integrate with independently authenticated internal services

Sentinel-43 does not grant its advisory core autonomous authority to
perform enforcement.

Core principle:

> Deterministic. Advisory. Never Autonomous.

Sentinel-43 exists to assist operators, not replace them.

---

# Current Development Status

Sentinel-43 has progressed beyond the early Alpha architecture stage.

Current Late Alpha work focuses on:

- canonical runtime-authority consolidation
- owner-designated core integration
- security hardening
- session-authentication hardening
- database migration infrastructure
- Docker deployment validation
- Kubernetes deployment architecture
- TLS edge requirements
- trusted-proxy enforcement
- firewall fail-closed behavior
- service-identity isolation
- Watchtower endpoint protection
- WebSocket authentication hardening
- database transaction safety
- concurrency validation
- Beta deployment preparation
- security regression testing
- repository and documentation normalization
- runtime and deployment provenance reporting

The system currently has established Docker-based components for:

- Sentinel-43 API
- Sentinel-43 core
- PostgreSQL
- migration execution
- reverse-proxy / TLS-edge integration

Kubernetes deployment support is also being developed and hardened for
Beta deployment.

Production readiness has NOT yet been declared.

---

# Late Alpha Security Hardening

Sentinel-43 has undergone multiple dedicated security-hardening passes.

Established security work includes:

- protected Watchtower routes
- service-token authentication boundaries
- human/service identity separation
- reduced public service exposure
- authenticated API bridge behavior
- protected WebSocket paths
- firewall secure defaults
- trusted-proxy validation
- fail-closed firewall startup behavior
- administrator authorization enforcement
- first-administrator bootstrap concurrency protection
- PostgreSQL transaction validation
- account transaction atomicity
- password-verification hardening
- malformed-password-hash fail-closed behavior
- event-loop-safe password verification
- login throttling
- authentication timing mitigation
- security regression testing
- real PostgreSQL concurrency testing
- single runtime-authority composition boundary
- governed first-administrator dashboard onboarding
- runtime-authority provenance reporting
- removal of direct Watchtower manual-state authority
- removal of direct Sparta recovery authority
- removal of human-decision handling from the service-token remote gateway

Security-sensitive behavior is tested against explicit invariants rather
than relying solely on application startup or unit-level mocks.

Sentinel-43's security architecture continues to be reviewed during Late
Alpha.

---

# Active Late Alpha Security Work

Several security areas remain intentionally open while Beta preparation
continues.

These include:

## Session Authentication and Legacy Retirement

Sentinel-43's non-local authentication path is session-aware.

The current architecture includes:

- short-lived access tokens
- session-bound token identifiers
- server-side refresh-session state
- refresh credential rotation
- refresh replay detection
- explicit logout/revocation
- browser-safe credential handling
- CSRF protection
- bounded token lifetime
- account-state validation
- WebSocket session-state validation

The repeated-password legacy protected-request path is refused outside
local/dev/test environments. The environment-backed break-glass operator is
also restricted to local/dev/test use and does not provide a production
authentication bypass.

Any remaining legacy compatibility behavior is retained only for bounded
development/migration purposes and must not be treated as a deployable
production authentication mode.

---

## Database Migration Infrastructure

Sentinel-43 is establishing Alembic as the authoritative production
database migration mechanism.

The migration architecture is being designed to support:

- existing pre-migration databases
- fresh installations
- schema compatibility validation
- fail-closed schema-drift detection
- explicit migration execution
- migration rollback validation
- PostgreSQL-backed migration testing
- Docker migration jobs
- Kubernetes migration jobs

Production API replicas are not intended to independently migrate the
database during normal startup.

Schema migration is treated as an explicit deployment operation.

---

## TLS / HTTPS

Production browser-session deployment requires an authenticated and
encrypted HTTPS transport path.

Sentinel-43 does not currently declare its Late Alpha browser-session
architecture production-ready until a named deployment target provides
verified TLS termination and HTTPS-only access.

The intended production model is:

    Client
        |
        | HTTPS / WSS
        v
    Controlled TLS Edge
        |
        v
    Sentinel-43 Internal Services

TLS may terminate at an approved reverse proxy, ingress controller, load
balancer, or equivalent controlled edge.

Sentinel-43 does not assume that an unspecified external component
"probably" provides TLS.

TLS posture must be explicitly configured and validated before production
browser-session deployment.

---

# System Philosophy

Sentinel-43 is built around five mandatory principles:

1. Human authority remains final.
2. Significant actions are auditable.
3. Recommendations must be explainable.
4. Security controls fail closed whenever practical.
5. Enforcement remains separated from analysis.

Sentinel-43 may recommend action.

Sentinel-43 does not claim autonomous authority to execute operational
action.

---

# Operational Flow

Sentinel-43 follows a structured defensive decision pipeline:

    Observe
        ↓
    Analyze
        ↓
    Hunt
        ↓
    Correlate
        ↓
    Recommend
        ↓
    Govern / Approve
        ↓
    Controlled Export / Independently Governed Enforcement
        ↓
    Audit

Not every deployment must contain every optional subsystem.

The core architectural boundary remains:

    Analysis != Governance != Enforcement

The current Late Alpha runtime does not support autonomous external
execution. Governed approval records intent and authority; any external
effect must remain independently controlled and explicitly integrated.

---

# Canonical Runtime Authority

The live runtime is composed beneath one top-level authority:
`Sentinel43RuntimeAuthority`.

That authority owns the live Sentinel-43 governance composition, including
the subordinate `SystemOrchestrator`, the owner-designated response engine,
the owner-designated Nexus / node / AI-escalation components, governed
identity/session mutation, and the shared monitoring/evidence boundary.

The owner-designated sources under `Sentinel-43/` are live runtime sources,
not historical examples. `Shadow_mode.py` is the single owner response
engine; `Sentinel_Nexus.py`, `Sentinel_core.py`, and
`sentinel_AI_escalation.py` are subordinate components loaded beneath the
same runtime authority.

The API, dashboard, Watchtower, Fenrir, Sparta, remote gateway, deployment
reporting, and other integrations must not create parallel governance or
execution authority.

Runtime provenance is exposed as read-only authority/deployment state so an
operator can determine which Sentinel-43 authority and owner components are
actually active without receiving subordinate mutation objects.

---

# Core Architecture

Sentinel-43 is separated into independent functional and trust layers.

---

## 1. Core Advisory Engine

Role:

> Deterministic Risk Assessment and Recommendation

The core advisory engine performs:

- threat-assessment intake
- policy evaluation
- recommendation generation
- workflow-state tracking
- audit persistence
- explanation generation
- governance-aware decision routing

The core advisory engine does NOT directly perform:

- firewall modification
- endpoint isolation
- account suspension
- remote execution
- host quarantine
- packet filtering
- infrastructure enforcement

The core answers:

> "What is happening, what does policy say, and what should be recommended?"

---

## 2. API Layer

Role:

> Authenticated access to Sentinel-43 capabilities and state

The API layer provides controlled access to Sentinel-43 functionality.

Responsibilities include:

- authenticated request handling
- authorization enforcement
- administrative operations
- governance interfaces
- health/readiness reporting
- dashboard state access
- WebSocket connectivity
- internal service integration

The API layer is protected by Sentinel-43 authentication, authorization,
firewall, and trusted-proxy controls.

Publicly exposed API behavior is intentionally minimized.

Internal service interfaces must not silently become public interfaces.

---

## 3. Watchtower

Role:

> Oversight and System Health

Watchtower monitors the health and integrity of Sentinel-43 and its
dependencies.

Responsibilities include:

- service monitoring
- configuration validation
- resource monitoring
- dependency validation
- error-rate monitoring
- state tracking
- health reporting
- system-posture visibility

Watchtower answers:

> "Is Sentinel-43 operating correctly?"

Watchtower interfaces are authenticated.

Detailed Watchtower information is not intended to be anonymously exposed
through public-facing endpoints.

Health and readiness interfaces should reveal only the information required
for their operational purpose.

---

## 4. Fenrir

Role:

> Threat Hunting and Behavioral Analysis

Fenrir identifies suspicious behavior, correlates observations, detects
patterns, and generates risk context for Sentinel-43.

Responsibilities include:

- behavioral analysis
- threat hunting
- risk scoring
- event correlation
- pattern detection
- anomaly identification
- recommendation support
- supporting evidence generation

Fenrir answers:

> "Does this activity require attention?"

Fenrir does not perform enforcement.

Fenrir and other machine/service identities remain cryptographically and
logically separated from human authentication.

---

## 5. Governance Layer

Role:

> Human Decision Authority

The Governance Layer manages approval workflows and operator review.

Responsibilities include:

- approval requests
- escalation workflows
- human-review queues
- decision recording
- policy validation
- operator approval tracking
- rejection tracking
- review-state visibility

Governance answers:

> "Should action be taken?"

Human, organizational, legal, and regulatory authority supersede
automation behavior.

Governance cannot be bypassed by the advisory core.

---

## 6. Jormungandr

Role:

> Defensive Enforcement and Containment

Jormungandr represents the independently governed defensive enforcement
layer.

It may apply approved security controls only within explicitly authorized
policy and governance boundaries.

Potential responsibilities include:

- defensive policy enforcement
- containment
- traffic control
- access restriction
- approved response execution
- protective controls

Jormungandr answers:

> "How is the approved response applied?"

Jormungandr is not part of the autonomous authority of the advisory core.

It must never bypass required governance.

---

## 7. Audit Layer

Role:

> Accountability and Traceability

The Audit Layer records significant system activity.

Responsibilities include:

- decision recording
- event tracking
- approval logging
- rejection logging
- configuration history
- system activity records
- evidence preservation
- audit-chain history
- deterministic audit hashing

Audit answers:

> "What happened, when, why, and by whom?"

Security-relevant decisions should not exist without an associated audit
trail.

---

## 8. Adapters

Role:

> Explicit External Integration

Adapters connect Sentinel-43 to independently governed external systems.

Examples include:

- SOAR integrations
- SIEM forwarding
- queue publishers
- case-management systems
- review pipelines
- infrastructure control planes

Adapters are explicit.

Undocumented external integrations are not part of the Sentinel-43 design.

---

## 9. Human Interfaces

Role:

> Human Oversight and Administration

Human-facing interfaces may provide:

- review
- approval
- oversight
- auditing
- administration
- health visibility
- governance visibility

Examples include:

- dashboards
- analyst consoles
- approval interfaces
- governance panels

Interfaces consume controlled API state rather than bypassing Sentinel-43
security boundaries.

---

## 10. Kubernetes Deployment Enforcement

Role:

> Deployment Isolation and Infrastructure Guardrails

Kubernetes is an additional security and deployment layer around the
Sentinel-43 runtime. It does not become a second governance authority.

The controlled-Beta Kubernetes path provides or is being hardened around:

- non-root workloads
- explicit service accounts and service boundaries
- Kubernetes Secrets
- default-deny and least-required NetworkPolicy rules
- internal-only PostgreSQL access
- migration Jobs as the single schema-migration actor
- readiness and liveness separation
- ingress-controlled external exposure
- TLS / certificate-management integration
- runtime/deployment provenance reporting
- deployment-specific trusted-proxy and host configuration

The current Kubernetes manifests intentionally run the API as a singleton
because several runtime states remain process-local, including event
idempotency, Fenrir lifecycle state, Sparta watchdog state, and dashboard
WebSocket clients. Horizontal API scaling must not be enabled until those
shared-state requirements are deliberately externalized.

Kubernetes enforcement supplements application-layer authorization,
governance, Jormungandr boundaries, the Sentinel-43 firewall, Watchtower,
Fenrir, and Sparta. It does not bypass or replace any of them.

---

# Service Identity Separation

Sentinel-43 distinguishes human identities from machine/service identities.

Internal services must authenticate through explicitly defined service
credentials.

Service authentication must not silently satisfy human authentication.

Human authentication must not silently satisfy service authentication.

Current internal security boundaries include dedicated authentication for
components such as:

- Watchtower
- Fenrir
- Sparta
- remote-gateway integrations
- other explicitly registered internal services

Service credentials must:

- remain secret
- be generated using cryptographically secure randomness
- be independently rotatable
- not be committed to source control
- not appear in logs
- not be exposed through health endpoints
- not be accepted as human login credentials

---

# Network Trust Model

Sentinel-43 does not automatically trust forwarded network identity.

Forwarded client-address information is accepted only through explicitly
trusted proxy boundaries.

Untrusted clients must not be able to obtain trusted status merely by
supplying forwarding headers.

When trusted proxy configuration is unavailable or invalid, Sentinel-43
uses fail-closed behavior where practical.

Deployment operators are responsible for ensuring that:

- proxy boundaries are explicitly configured
- internal services are not unnecessarily published
- database ports are not publicly exposed
- any future shared-state datastore is not publicly exposed
- service credentials remain internal
- TLS termination is explicitly configured for production
- public endpoints expose only necessary information

---

# Firewall Model

Sentinel-43 includes application-layer firewall controls intended to provide
secure defaults around exposed API behavior.

The firewall architecture is designed around:

- explicit configuration
- fail-closed production behavior
- trusted-proxy awareness
- controlled route exposure
- sanitized denial behavior
- security-event visibility

Failure to establish required production firewall configuration must not
silently downgrade Sentinel-43 into an unrestricted state.

---

# Dashboard

The Sentinel-43 dashboard provides operational visibility into:

- system health
- Watchtower state
- Fenrir findings
- governance queues
- pending approvals
- staged approvals
- audit records
- event history
- service status
- backend-reported state
- runtime configuration visibility
- console/diagnostic information
- WebSocket connection state
- dependency-event channels

The dashboard is an operational interface rather than merely a reporting
page.

It should allow an authorized operator to answer:

1. Is Sentinel-43 healthy?
2. Is anything waiting for review?
3. What did the backend report?
4. What changed?
5. What configuration is active?
6. What failed?

---

# WebSocket Security

Sentinel-43 supports authenticated WebSocket communication for live
operational state.

Credentials must never be placed in WebSocket URLs.

WebSocket authentication is undergoing additional Late Alpha hardening as
part of the session-authentication migration.

The target architecture requires:

- authenticated initial connection
- no credential-bearing query parameters
- bounded credential lifetime
- account/session-state validation
- sanitized close behavior
- authenticated subscription establishment
- controlled reconnect behavior

The exact WebSocket authentication contract remains subject to change
during Late Alpha.

Clients must not depend on undocumented message shapes.

---

# Docker Architecture

Sentinel-43 uses a multi-service Docker architecture.

A deployment may contain services corresponding to:

    s43-api
    s43-core
    s43-db
    s43-migrate
    s43-proxy

Roles:

s43-api
    Sentinel-43 API and authenticated interface layer.

s43-core
    Core Sentinel-43 processing/advisory services.

s43-db
    PostgreSQL persistent storage.

s43-migrate
    One-shot database migration execution.

s43-proxy
    Reverse-proxy / TLS-edge integration.

Exact service layout remains subject to change until Beta.

Internal database services and any future shared-state services should not
be exposed publicly.

---

# PostgreSQL

Sentinel-43 uses PostgreSQL for persistent relational state required by
the current application architecture.

Current development and validation use PostgreSQL 16.x.

Security-sensitive database behavior is tested against real PostgreSQL
where transaction or concurrency semantics matter.

Examples include:

- account creation
- administrator bootstrap
- session rotation
- session revocation
- transaction rollback
- concurrency behavior
- migration validation

Database behavior must not be considered validated merely because it
passes against a lightweight substitute database.

---

# Redis

Redis is reserved for shared transient state, and no deployment target
currently runs one. Nothing in `core/` or `dashboard/` opens a Redis
connection, `docker-compose.yml` defines no Redis service, and the
Kubernetes manifests no longer provision one.

This is a deliberate position, not an oversight. Sentinel-43 does not
introduce Redis merely to replace simpler, well-defined persistence
behavior, and an unused datastore in a deployment is attack surface plus a
false signal that shared state exists.

Two components would genuinely need it before it comes back: the firewall's
rate limiter and the event idempotency ledger are both in-process today,
which is a large part of why `s43-api` runs as a singleton (see
`deploy/kubernetes/README.md`). Whichever change makes one of those shared
should reintroduce Redis along with a client in `core/` -- not ahead of it.

If it is reintroduced, it must not be publicly exposed.

---

# Database Migrations

Sentinel-43 is transitioning to Alembic-managed database migrations.

The intended production model is:

    Migration Step
        ↓
    Schema Validation
        ↓
    API / Application Startup

API replicas should not independently execute production migrations during
normal startup.

For multi-replica environments, exactly one authorized migration actor
should apply schema changes.

Migration behavior must be:

- explicit
- reviewable
- repeatable
- tested
- auditable
- fail-closed on incompatible schema state

---

# Kubernetes Architecture

Sentinel-43 includes Kubernetes deployment support intended for controlled
Beta and later production deployments.

The Kubernetes architecture is designed around:

- non-root containers
- explicit service boundaries
- Kubernetes Secrets
- controlled configuration
- readiness probes
- liveness/health behavior
- migration Jobs
- ingress-based external access
- TLS termination
- certificate-management integration
- internal-only database services
- default-deny / least-required NetworkPolicy enforcement
- least-required network exposure

A production Kubernetes deployment is expected to use a dedicated migration
Job or equivalent single migration actor before application rollout.

Each API replica must not independently attempt schema migration.

Ingress and TLS configuration must be completed with deployment-specific
values.

Placeholder configuration must never be treated as production-ready.

The current Kubernetes deployment intentionally keeps `s43-api` at one
replica with non-overlapping rollout behavior until process-local state is
made safely shared.

---

# Container Security

Sentinel-43 containers are being hardened around:

- non-root execution
- minimized host exposure
- explicit service boundaries
- controlled environment configuration
- secret injection rather than source-controlled credentials
- health/readiness separation
- migration isolation
- reduced unnecessary host port publication

Production deployments should expose only the edge services required by the
deployment architecture.

PostgreSQL, internal service interfaces, administrative interfaces, and any
future shared-state datastore should remain internal unless explicitly
required.

---

# Secrets

Sentinel-43 requires cryptographically strong secrets for security-sensitive
operations.

Secrets may be required for:

- JWT signing
- service authentication
- database authentication
- cryptographic hashing
- internal service identity
- session security
- deployment integration

Secrets must:

- be generated using a cryptographically secure random generator
- be unique to the deployment where appropriate
- never be committed to Git
- never be copied into documentation
- never be emitted into application logs
- be independently rotatable where architecture permits
- be stored using an appropriate deployment secret mechanism

Examples include:

Docker / local development:
    environment injection or protected local secret files

Kubernetes:
    Kubernetes Secrets or an approved external secret-management system

Production operators must understand the impact of rotating each credential
before rotation.

Some credential rotation may intentionally invalidate active authentication
state.

---

# Environment Files

Real `.env` files are deployment-specific and may contain sensitive
information.

They must not be committed to source control.

The repository may provide:

    .env.example

for configuration documentation.

Files such as:

    .env
    .env.old
    .env.bak.*
    secret dumps
    credential exports

must not be included in distributable source repositories when they contain
real deployment credentials.

---

# Failure Behavior

Sentinel-43 is designed to fail closed where security boundaries require
it.

Examples include:

- invalid authentication
- malformed credentials
- malformed password hashes
- insufficient authorization
- invalid trusted-proxy configuration
- required firewall configuration failure
- invalid policy modes
- missing required cryptographic material
- incompatible database schema
- failed security-sensitive transactions

Failure handling must not silently convert a protected operation into an
unprotected one.

---

# First Administrator Bootstrap

Sentinel-43 supports controlled creation of the first administrative
account.

The first-administrator path is protected against concurrent bootstrap
attempts using PostgreSQL transaction-level coordination.

The security invariant is:

> Exactly one initial bootstrap operation may succeed.

Bootstrap closes once the first account exists, and no application path
reopens it: deactivating or demoting every administrator does not. Deleting
every account row directly in the database would. Outside local/dev/test, the first claim is authorized by the deployment
secret holder through `S43_BOOTSTRAP_CLAIM_TOKEN`; an empty or incorrect
claim token is refused. Emergency administrator recovery is also defined:
a trusted deployment operator uses the exec-only recovery CLI through
`Sentinel43RuntimeAuthority.identity`, with authoritative audit and no
network-facing recovery endpoint. See `docs/BETA_RUNBOOK.md` §16a.

This does NOT mean Sentinel-43 supports only one administrator.

Additional administrators may exist according to normal authorization and
account-management policy.

---

# Password Security

Human password verification uses a modern password-verification mechanism.

Security-sensitive password work is designed to:

- avoid blocking the asynchronous event loop
- fail closed on malformed hashes
- reduce account-enumeration timing differences
- support login throttling
- avoid logging credentials
- avoid exposing password material through error messages

Authentication architecture remains under Late Alpha modernization.

---

# Policy Gate

The policy gate evaluates whether an advisory action may proceed through a
workflow mode.

Responsibilities include:

- action normalization
- mode validation
- governance lookup
- allow / deny / human-review decisions
- deterministic decision output

The policy gate does not:

- perform enforcement
- modify infrastructure
- silently downgrade invalid modes

Invalid policy modes are treated as caller errors and fail explicitly.

---

# Operational Modes

Operational modes govern recommendation workflow behavior rather than
granting autonomous enforcement authority.

| Mode | Behavior |
| ---- | -------- |
| SHADOW | Observe and record. |
| HUMAN_GATED | Recommendations require explicit operator approval before controlled export. |

`ACTIVE`, `AUTONOMOUS`, `AUTONOMOUS_VETO`, and delayed autonomous
execution modes are not supported by the live owner core.

Governance remains authoritative.

---

# Audit and Accountability

Sentinel-43 records security and governance activity necessary to reconstruct
significant decisions.

Audit information may include:

- event records
- recommendations
- workflow states
- approvals
- rejections
- authentication events
- security denials
- configuration changes
- system-state transitions

Sensitive credentials must never be written into audit records.

Audit answers:

> What happened, when, why, and under whose authority?

---

# Development Validation

Late Alpha validation includes:

- unit testing
- integration testing
- PostgreSQL-backed tests
- concurrency testing
- authentication regression testing
- authorization regression testing
- service-identity isolation testing
- firewall testing
- trusted-proxy testing
- WebSocket testing
- migration testing
- Docker validation
- security-invariant testing

Security-sensitive fixes are expected to include behavioral evidence rather
than relying solely on source inspection.

---

# Local Load Testing

A local load-test harness may be used for controlled validation.

Example:

    pwsh .\tools\S43_Nightmare_LoadTest.ps1 `
      -BaseUrl "http://localhost:8000" `
      -Batches 1 `
      -HitsPerBatch 100 `
      -Concurrency 10 `
      -IUnderstand

Stress testing must only be performed against systems you own or are
explicitly authorized to test.

Large tests can heavily stress:

- API workers
- PostgreSQL
- any reintroduced shared-state datastore
- Docker
- host CPU
- host memory
- network resources

Do not run Sentinel-43 stress-testing tools against third-party systems
without authorization.

---

# Stability

The following architectural principles are considered stable:

- human authority remains final
- advisory-only core boundary
- analysis/enforcement separation
- governance-controlled operational response
- auditability
- explainability
- fail-closed security posture
- human/service identity separation
- explicit service boundaries

The following remain subject to change during Late Alpha:

- authentication/session implementation
- WebSocket authentication details
- database migration integration
- Docker service layout
- Kubernetes manifests
- TLS-edge configuration
- internal helper APIs
- dashboard message formats
- adapter interfaces
- development tooling
- deployment automation

Do not build external integrations against undocumented internal APIs.

---

# Beta Exit Criteria

Sentinel-43 will not be declared Beta solely because the code runs.

Late Alpha must establish, at minimum:

- stable session authentication
- verified rejection of legacy protected-request authentication outside local/dev/test
- bounded local/dev/test break-glass behavior
- tested database migration infrastructure
- validated fresh-install migration
- validated existing-database migration
- Docker deployment stability
- named TLS-secured deployment architecture
- Kubernetes deployment validation
- service-identity isolation
- firewall/trusted-proxy validation
- WebSocket authentication hardening
- complete security regression testing
- repository normalization
- deployment documentation
- secret-generation documentation
- reproducible installation procedure

Only after these requirements are satisfied should Sentinel-43 transition
from Late Alpha into formal Beta testing.

---

# What Sentinel-43 Is Not

Sentinel-43 is not:

- an autonomous attack platform
- an offensive security framework
- a self-directed response engine
- a system with unrestricted autonomous enforcement authority
- a hidden enforcement tool
- a covert surveillance platform

Sentinel-43 assists operators.

Operators and authorized governance structures remain responsible for final
operational decisions.

---

# Long-Term Vision

Sentinel-43 is intended to provide the security oversight and governance
foundation for larger operational environments.

Its purpose is to provide:

- visibility
- analysis
- threat context
- accountability
- governance
- controlled defensive response integration

while maintaining human authority over operational enforcement.

The platform is intended to remain modular.

Health monitoring, threat hunting, governance, audit, authentication,
interfaces, and defensive enforcement remain separated by explicit
architectural and trust boundaries.

---

# Licensing

Sentinel-43 is distributed under its established dual-license model.

## AGPL v3.0

Open-source use, modification, and distribution are governed by the GNU
Affero General Public License v3.0 according to the license terms included
with the repository.

## Commercial License

Commercial, enterprise, governmental, or proprietary use may require a
separate commercial license according to the commercial licensing terms
included with Sentinel-43.

Refer to the repository licensing documents for authoritative terms.

---

# Disclaimer

Sentinel-43 is currently Late Alpha software.

It is provided:

> AS IS

without warranty of any kind.

Late Alpha builds may contain incomplete features, changing interfaces,
deployment limitations, or unresolved security findings.

Do not deploy an unfinished Late Alpha build into a production environment
and then act surprised when reality develops teeth.