Sentinel-43 Advisory Engine

Sentinel-43 is a deterministic, advisory-first risk assessment and response recommendation engine.

It evaluates structured threat assessments and produces:

- Policy-aligned recommendations
- Human-readable explanations
- Durable audit records
- Reviewable workflow states
- Governance-aware decision outcomes
- WebSocket-delivered dashboard state updates
- Human-gated approval visibility

Sentinel-43 does not directly enforce operational actions.

The core does not:

- block users
- quarantine hosts
- disable accounts
- modify firewall rules
- terminate sessions
- execute remote actions
- change infrastructure state without external integration

Any enforcement capability must exist outside the core through explicitly wired external adapters.

The core exists to:

- analyze
- classify
- recommend
- explain
- record
- route decisions into review workflows

Nothing else.

---

Current Build Status

Sentinel-43 is currently in Alpha / Public Beta Preparation.

This build is intended for:

- local development
- private beta validation
- architecture testing
- dashboard integration testing
- governance workflow testing
- WebSocket authentication testing
- advisory decision pipeline validation

This build is not production-certified.

Known active integration areas:

- S34 authentication support
- JWT extraction and validation helpers
- dashboard WebSocket authentication handshake
- policy gate validation
- governance queue visibility
- Watchtower and dependency event channels
- Docker Compose startup stability
- API endpoint load testing

---

Core Design Constraints

These constraints are intentional and mandatory across all environments and modes.

Sentinel-43 Core Never Performs Autonomous Enforcement

The core engine never directly executes controls against infrastructure, users, endpoints, or networks.

All operational actions must occur through:

- external adapters
- external orchestration systems
- human approval workflows
- independently governed control planes

Sentinel-43 may recommend an action. It does not directly execute that action.

---

No Hidden Behavior

Sentinel-43 prohibits:

- covert surveillance
- undocumented integrations
- hidden network communication
- silent data harvesting
- undeclared outbound transmission
- opaque enforcement behavior

All recommendations and workflow transitions must be explainable and reviewable.

---

Explainability Is Mandatory

Every decision must provide:

- deterministic reasoning
- policy traceability
- stable auditability
- reviewable recommendation paths

No recommendation may be generated through hidden or non-auditable pathways.

---

Governance Always Overrides Automation

Human, organizational, legal, and regulatory authority always supersede automation behavior.

Sentinel-43 may recommend actions.

It does not claim authority to execute them autonomously.

---

Architecture

Sentinel-43 is intentionally separated into independent layers.

1. Core Engine

The core performs:

- threat assessment intake
- policy evaluation
- recommendation generation
- workflow state tracking
- audit persistence
- explanation generation

The core does not perform:

- firewall modification
- endpoint isolation
- account suspension
- remote execution
- host quarantine
- packet filtering
- infrastructure enforcement

The core is deterministic and advisory-only.

---

2. S34 Authentication Layer

The S34 authentication layer provides import-safe support for authentication and authorization workflows.

Current S34 support includes:

- constants
- structured auth exceptions
- JWT / bearer-token extraction helpers
- runtime auth globals
- policy gate integration support

Key files:

core/s34_auth/
  __init__.py
  constants.py
  exceptions.py
  extract_token.py
  globals.py
  policy_gate.py

The S34 layer should remain:

- import-safe
- dependency-light
- explicit
- fail-closed
- free of hidden runtime side effects

JWT extraction and WebSocket authentication are handled explicitly. Tokens must not be placed in WebSocket URLs.

---

3. Policy Gate

The policy gate evaluates whether an advisory action may proceed through a workflow mode.

The policy gate is responsible for:

- action normalization
- mode validation
- governance lookup
- allow / deny / human-review decisions
- deterministic decision output

The policy gate does not:

- decode JWTs
- extract bearer tokens
- perform enforcement
- modify infrastructure
- silently downgrade invalid modes

Invalid policy modes are treated as caller errors and must fail loudly.

---

4. Adapters

Adapters are optional external integrations that consume approved recommendations.

Examples:

- SOAR integrations
- queue publishers
- SIEM forwarding
- case-management connectors
- review pipelines
- infrastructure control-plane integrations

Adapters are external by design and are never embedded into the governance core.

Adapters must be explicitly configured and independently governed.

---

5. Interfaces

Interfaces are external human-facing systems used for:

- review
- approval
- oversight
- auditing
- administration

Examples:

- dashboards
- analyst consoles
- workflow approval systems
- governance review panels

Interfaces are intentionally separated from the core engine.

---

6. Dashboard and WebSocket Bridge

The dashboard consumes API and WebSocket state from the backend.

The WebSocket bridge supports:

- authenticated connection setup
- "auth_required" server challenge handling
- JWT-based auth frames
- live action queue updates
- governance pending snapshots
- Watchtower state updates
- dependency state updates
- polling fallback when WebSocket connectivity is unavailable

Expected WebSocket authentication flow:

Client connects
Server sends auth_required
Client sends auth frame
Server confirms authenticated / auth_ok / connected
Client subscribes to configured channels
Dashboard receives live state updates

The client must not subscribe before authentication is accepted.

---

Operational Modes

Operational modes govern recommendation workflow behavior, not enforcement.

Mode| Behavior
"SHADOW"| Observe and record only. Recommendations are logged but never staged for execution review.
"HUMAN_GATED"| Recommendations are staged and require explicit operator approval before export.
"AUTONOMOUS_VETO"| Conservative allow-list mode. High-risk recommendations are denied automatically.

---

Advisory Build Mode Mapping

Some advisory builds expose alternate interface terminology:

Advisory Interface| Governance Core
"ADVISORY"| "SHADOW"
"HUMAN_GATED"| "HUMAN_GATED"
"ACTIVE_PLANNING"| "AUTONOMOUS_VETO"

The governance module remains the canonical source of truth.

---

Failure Behavior

Sentinel-43 is intentionally designed to fail closed in production environments.

Audit Failure

If audit persistence fails:

- the recommendation is blocked
- the workflow decision is not approved
- the engine returns a blocked outcome

Exception:

- only in "dev"
- only when "SENTINEL_DEV_ALLOW_AUDIT_FAIL_OPEN=1"

Fail-open behavior must never be enabled in production.

---

Invalid Modes

Invalid policy modes are rejected loudly.

Invalid modes must not silently downgrade to another mode.

Expected behavior:

Invalid mode -> validation error

This prevents caller bugs from being hidden behind conservative fallback behavior.

---

Missing Cryptographic Secret

If:

GHOST_DEVICE_HASH_SECRET

is missing or empty:

- startup fails
- the engine raises "RuntimeError"
- no insecure fallback is permitted

---

Unknown Actions

Unknown actions are denied by default outside "SHADOW" mode.

This behavior is intentional.

In "SHADOW" mode, unknown actions may be recorded for visibility without automatic workflow promotion.

---

Evaluation Workflow

Standard evaluation flow:

1. An upstream detector generates a structured assessment.
2. Sentinel-43 evaluates the assessment against governance policy.
3. A recommendation and explanation are generated.
4. A durable audit record is persisted.
5. Workflow handling occurs according to mode:
   - "SHADOW"
   - "HUMAN_GATED"
   - "AUTONOMOUS_VETO"
6. Approved recommendations may be exported to external adapters.

The core never directly executes operational controls.

---

Threat Input Model

Sentinel-43 consumes structured threat assessments, not raw detections.

Detection systems are intentionally separated from governance evaluation.

Field| Type| Description
"identity"| "str"| Subject identifier
"source_ip"| "str"| Origin IP address
"threat_kind"| "str"| Threat classification
"severity"| "str"| Threat severity
"source_kind"| "str"| Detection source classification
"score"| "float"| Numeric risk score
"tags"| "list[str]"| Classification tags
"metadata"| "dict"| Supplemental structured context

---

Recommendation Output Model

Sentinel-43 produces recommendations only.

These are not enforcement actions.

Recommendation| Meaning
"LOG_ONLY"| Record event only
"FLAG_SUSPICIOUS"| Increase monitoring visibility
"STEP_UP_AUTH"| Recommend additional authentication
"RATE_LIMIT"| Recommend throttling
"TEMP_BLOCK_IDENTITY"| Recommend temporary identity restriction
"TEMP_BLOCK_IP"| Recommend temporary IP restriction
"HARD_BLOCK_IDENTITY"| Recommend permanent identity restriction
"HARD_BLOCK_IP"| Recommend permanent IP restriction
"QUARANTINE_SESSION"| Recommend session isolation
"REQUIRE_HUMAN_REVIEW"| Escalate to operator review
"OPEN_INCIDENT"| Recommend incident creation

Enforcement must always occur outside the core.

---

Approval Workflow

In "HUMAN_GATED" mode:

- recommendations are staged
- operators explicitly approve or reject them
- all workflow transitions are auditable

Example:

engine.approve(decision_id, operator_id, reason)
engine.reject(decision_id, operator_id, reason)

Approved decisions remain advisory artifacts until consumed externally.

---

Audit and Storage

Sentinel-43 uses durable local persistence for audit and workflow state.

Stored data may include:

- event logs
- decision records
- workflow states
- deduplication tracking
- audit chain history

The engine includes:

- bounded retention cleanup
- pseudonymized identity logging
- sanitized key generation
- deterministic audit hashing

---

Environment Variables

Variable| Required| Default| Description
"GHOST_DEVICE_HASH_SECRET"| Yes| —| HMAC secret for device hashing
"SENTINEL_SYSTEM_ID"| No| "sentinel43"| Engine instance identifier
"SENTINEL_AUDIT_DB"| No| "audit.db"| SQLite audit database path
"SENTINEL_AUDIT_JSONL"| No| —| Optional JSONL audit sink
"SENTINEL_LOG_SALT"| No| —| Salt for pseudonymized logs
"SENTINEL_ACTION_DEDUPE_TTL"| No| "3600"| Recommendation dedupe window
"SENTINEL_LOG_RETENTION_DAYS"| No| "90"| Event log retention
"SENTINEL_ACTION_RETENTION_DAYS"| No| "365"| Decision retention
"SENTINEL_ALLOWED_OPERATORS"| No| —| Allowed operator IDs
"SENTINEL_VELOCITY_WINDOW_SECONDS"| No| "60"| Velocity limiter window
"SENTINEL_VELOCITY_LIMIT"| No| "10"| Velocity event limit
"SENTINEL_AUTH_MAX_AGE_SECONDS"| No| "900"| Max auth context age
"SENTINEL_ENV"| No| "prod"| Runtime environment
"SENTINEL_DEV_ALLOW_AUDIT_FAIL_OPEN"| No| "0"| Dev-only audit fail-open

---

WebSocket Authentication

The dashboard WebSocket must authenticate using an explicit auth frame.

Credentials must not be placed in the WebSocket URL.

Expected frame pattern:

{
  "type": "auth",
  "payload": {
    "token": "<jwt>"
  }
}

The backend may send:

{
  "type": "auth_required"
}

The client must answer with an auth frame before sending subscription requests.

---

Quick Start

Generate a secret:

python -c "import secrets; print(secrets.token_hex(32))"

Set environment variables:

export GHOST_DEVICE_HASH_SECRET=<generated_secret>
export SENTINEL_ENV=dev

Run the advisory engine:

python sentinel43_nexus_onefile_advisory.py

For Docker-based development:

docker compose up --build

Check API health:

curl http://localhost:8000/health

---

Local Load Testing

A local load-test harness may be used for private-beta validation.

Recommended first pass:

pwsh .\tools\S43_Nightmare_LoadTest.ps1 `
  -BaseUrl "http://localhost:8000" `
  -Batches 1 `
  -HitsPerBatch 100 `
  -Concurrency 10 `
  -IUnderstand

Full stress testing should only be run against systems you own and control.

Large tests such as:

40 batches × 50,000 hits = 2,000,000 requests

may heavily stress Docker, Redis, Postgres, API workers, and local hardware.

Do not run large tests against public or third-party infrastructure.

---

Stability

The following are considered stable:

- governance modes
- audit schema
- threat input model
- recommendation output model
- workflow semantics
- advisory-only core boundary

The following may change during alpha and beta development:

- internal helper APIs
- dashboard event names
- WebSocket message shapes
- S34 auth internals
- adapter interfaces
- Docker service layout

Build against the public advisory interface only.

---

Licensing

Sentinel-43 is distributed under a dual-license model.

AGPL v3.0

Open-source use, modification, and distribution are governed by the GNU Affero General Public License v3.0.

Commercial License

Commercial, enterprise, governmental, or proprietary deployment requires a separate commercial license.

Without explicit written permission, you may not:

- sell Sentinel-43 as proprietary software
- deploy it commercially outside the applicable license terms
- bundle it into paid products outside the applicable license terms
- redistribute it for profit outside the applicable license terms

---

Disclaimer

Sentinel-43 is provided:

AS IS

without warranty of any kind.

The authors are not liable for damages arising from use, misuse, deployment failure, operational misuse, or unsupported modification.

Do not deploy unfinished infrastructure into production and then act surprised when reality develops teeth.