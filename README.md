# Sentinel-43

## Mission

Sentinel-43 is a defensive cybersecurity oversight platform designed to observe, analyze, classify, recommend, govern, and audit security events while maintaining human control over enforcement decisions.

Sentinel-43 is intentionally designed as a human-gated system.

The platform may detect threats, correlate activity, generate risk assessments, generate recommendations, explain decisions, and record durable audit trails, but it does not autonomously perform enforcement actions without approval through defined governance workflows.

Core principle:

> Deterministic. Advisory. Never Autonomous.

Sentinel-43 exists to assist operators, not replace them.

---

# System Philosophy

Sentinel-43 is built around five mandatory principles:

1. Human authority remains final.
2. All significant actions are auditable.
3. Recommendations must be explainable.
4. Security controls fail closed whenever practical.
5. Enforcement is separated from analysis.

Sentinel-43 may recommend action.

Sentinel-43 does not claim authority to execute operational action autonomously.

---

# What Sentinel-43 Does

Sentinel-43 evaluates structured threat assessments and produces:

* Policy-aligned recommendations
* Human-readable explanations
* Durable audit records
* Reviewable workflow states
* Governance-aware decision outcomes
* WebSocket-delivered dashboard state updates
* Human-gated approval visibility

The core exists to:

* Analyze
* Classify
* Recommend
* Explain
* Record
* Route decisions into review workflows

Nothing else.

---

# What Sentinel-43 Does Not Do

The Sentinel-43 core does not directly:

* Block users
* Quarantine hosts
* Disable accounts
* Modify firewall rules
* Terminate sessions
* Execute remote actions
* Change infrastructure state without external integration
* Perform autonomous enforcement

Any enforcement capability must exist outside the core through explicitly wired external adapters, independently governed control planes, or human-approved workflows.

---

# Current Build Status

Sentinel-43 is currently in:

> Alpha / Public Beta Preparation

This build is intended for:

* Local development
* Private beta validation
* Architecture testing
* Dashboard integration testing
* Governance workflow testing
* WebSocket authentication testing
* Advisory decision pipeline validation
* API endpoint load testing

This build is not production-certified.

Known active integration areas:

* S34 authentication support
* JWT extraction and validation helpers
* Dashboard WebSocket authentication handshake
* Policy gate validation
* Governance queue visibility
* Watchtower and dependency event channels
* Docker Compose startup stability
* API endpoint load testing
* Dashboard/backend state synchronization

---

# Operational Flow

Sentinel-43 follows a structured decision pipeline:

> Observe → Analyze → Hunt → Correlate → Recommend → Approve → Enforce → Audit

Each subsystem supports a specific stage of this pipeline.

---

# Core Architecture

Sentinel-43 is intentionally separated into independent layers.

## 1. Core Advisory Engine

Role: Deterministic Risk Assessment and Recommendation

The core advisory engine performs:

* Threat assessment intake
* Policy evaluation
* Recommendation generation
* Workflow state tracking
* Audit persistence
* Explanation generation
* Governance-aware decision routing

The core advisory engine does not perform:

* Firewall modification
* Endpoint isolation
* Account suspension
* Remote execution
* Host quarantine
* Packet filtering
* Infrastructure enforcement

The core engine is deterministic and advisory-only.

It answers:

> "What is happening, what does policy say, and what should be recommended?"

---

## 2. Watchtower

Role: Oversight and System Health

Watchtower continuously monitors the health and integrity of Sentinel-43 itself.

Responsibilities:

* Service monitoring
* Configuration validation
* Resource monitoring
* Dependency validation
* Error-rate monitoring
* State tracking
* Health reporting
* System posture visibility

Watchtower answers:

> "Is Sentinel-43 operating correctly?"

---

## 3. Fenrir

Role: Threat Hunting and Behavioral Analysis

Fenrir is the threat hunting and behavioral analysis layer.

Fenrir is responsible for identifying suspicious behavior, correlating observations, detecting patterns, and generating risk assessments that can be reviewed by the advisory engine and governance workflow.

Responsibilities:

* Behavioral analysis
* Threat hunting
* Risk scoring
* Event correlation
* Pattern detection
* Anomaly identification
* Recommendation support
* Supporting evidence generation

Fenrir answers:

> "Does this activity require attention?"

Fenrir does not perform enforcement.

Fenrir produces observations, findings, risk context, recommendations, and supporting evidence.

---

## 4. Governance Layer

Role: Human Decision Authority

The Governance Layer manages approval workflows and operator review.

Responsibilities:

* Approval requests
* Escalation workflows
* Human review queues
* Decision recording
* Policy validation
* Operator approval tracking
* Rejection tracking
* Review-state visibility

Governance answers:

> "Should action be taken?"

Human, organizational, legal, and regulatory authority always supersede automation behavior.

Governance always overrides automation.

---

## 5. Jormungandr

Role: Defensive Enforcement and Containment

Jormungandr is the defensive enforcement and containment layer.

Jormungandr applies approved security controls and containment actions only within explicitly approved policy boundaries.

Responsibilities:

* Defensive policy enforcement
* Containment actions
* Traffic control
* Access restriction
* Security response execution
* Protective controls
* Approved response application

Jormungandr answers:

> "How is the approved response applied?"

Jormungandr acts only after a recommendation has passed through the required governance path.

Jormungandr must never bypass governance.

---

## 6. Audit Layer

Role: Accountability and Traceability

The Audit Layer records all significant system activity.

Responsibilities:

* Decision recording
* Event tracking
* Approval logging
* Rejection logging
* Configuration history
* System activity records
* Evidence preservation
* Audit chain history
* Deterministic audit hashing

Audit answers:

> "What happened, when, why, and by whom?"

No major decision should exist without an audit trail.

---

## 7. Adapters

Role: Explicit External Integration

Adapters are optional external integrations that consume approved recommendations.

Examples:

* SOAR integrations
* Queue publishers
* SIEM forwarding
* Case-management connectors
* Review pipelines
* Infrastructure control-plane integrations

Adapters are external by design and are never embedded into the governance core.

Adapters must be explicitly configured and independently governed.

---

## 8. Interfaces

Role: Human-Facing Oversight and Administration

Interfaces are external human-facing systems used for:

* Review
* Approval
* Oversight
* Auditing
* Administration

Examples:

* Dashboards
* Analyst consoles
* Workflow approval systems
* Governance review panels

Interfaces are intentionally separated from the core engine.

---

# Dashboard

The Sentinel-43 dashboard provides operational visibility into:

* System health
* Watchtower status
* Fenrir findings
* Governance queues
* Pending approvals
* Staged approvals
* Audit records
* Event history
* Service status
* Backend-reported records
* Current runtime configuration
* Console and diagnostic logs
* WebSocket connection state
* Dependency event channels

The dashboard is an operational interface, not merely a reporting tool.

The dashboard must answer:

1. Is Sentinel-43 healthy?
2. Is anything waiting for operator review?
3. What did the backend report?
4. What changed recently?
5. What configuration is active?
6. What failed?

---

# Dashboard and WebSocket Bridge

The dashboard consumes API and WebSocket state from the backend.

The WebSocket bridge supports:

* Authenticated connection setup
* `auth_required` server challenge handling
* JWT-based auth frames
* Live action queue updates
* Governance pending snapshots
* Watchtower state updates
* Dependency state updates
* Polling fallback when WebSocket connectivity is unavailable

Expected WebSocket authentication flow:

1. Client connects.
2. Server sends `auth_required`.
3. Client sends an auth frame.
4. Server confirms `authenticated`, `auth_ok`, or `connected`.
5. Client subscribes to configured channels.
6. Dashboard receives live state updates.

The client must not subscribe before authentication is accepted.

Credentials must not be placed in WebSocket URLs.

Expected auth frame pattern:

```json
{
  "type": "auth",
  "payload": {
    "token": "<jwt>"
  }
}
```

The backend may send:

```json
{
  "type": "auth_required"
}
```

The client must answer with an auth frame before sending subscription requests.

---

# Security Model

Sentinel-43 is designed around defensive security principles.

Key characteristics:

* Human-gated decision making
* Explainable recommendations
* Audit-first design
* Fail-closed defaults
* Authentication and authorization controls
* Traceable decision paths
* Separation of analysis and enforcement
* Explicit governance boundaries
* No hidden operational behavior

---

# Core Design Constraints

These constraints are intentional and mandatory across all environments and modes.

## Sentinel-43 Core Never Performs Autonomous Enforcement

The core engine never directly executes controls against infrastructure, users, endpoints, or networks.

All operational actions must occur through:

* External adapters
* External orchestration systems
* Human approval workflows
* Independently governed control planes

Sentinel-43 may recommend an action.

It does not directly execute that action.

---

## No Hidden Behavior

Sentinel-43 prohibits:

* Covert surveillance
* Undocumented integrations
* Hidden network communication
* Silent data harvesting
* Undeclared outbound transmission
* Opaque enforcement behavior

All recommendations and workflow transitions must be explainable and reviewable.

---

## Explainability Is Mandatory

Every decision must provide:

* Deterministic reasoning
* Policy traceability
* Stable auditability
* Reviewable recommendation paths

No recommendation may be generated through hidden or non-auditable pathways.

---

## Governance Always Overrides Automation

Sentinel-43 may recommend actions.

It does not claim authority to execute them autonomously.

Human review, organizational policy, legal requirements, and regulatory authority always override automated behavior.

---

# S34 Authentication Layer

The S34 authentication layer provides import-safe support for authentication and authorization workflows.

Current S34 support includes:

* Constants
* Structured auth exceptions
* JWT / bearer-token extraction helpers
* Runtime auth globals
* Policy gate integration support

Key files:

```text
core/s34_auth/
  __init__.py
  constants.py
  exceptions.py
  extract_token.py
  globals.py
  policy_gate.py
```

The S34 layer should remain:

* Import-safe
* Dependency-light
* Explicit
* Fail-closed
* Free of hidden runtime side effects

JWT extraction and WebSocket authentication are handled explicitly.

Tokens must not be placed in WebSocket URLs.

---

# Policy Gate

The policy gate evaluates whether an advisory action may proceed through a workflow mode.

The policy gate is responsible for:

* Action normalization
* Mode validation
* Governance lookup
* Allow / deny / human-review decisions
* Deterministic decision output

The policy gate does not:

* Decode JWTs
* Extract bearer tokens
* Perform enforcement
* Modify infrastructure
* Silently downgrade invalid modes

Invalid policy modes are treated as caller errors and must fail loudly.

---

# Operational Modes

Operational modes govern recommendation workflow behavior, not enforcement.

| Mode              | Behavior                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------ |
| `SHADOW`          | Observe and record only. Recommendations are logged but never staged for execution review. |
| `HUMAN_GATED`     | Recommendations are staged and require explicit operator approval before export.           |
| `AUTONOMOUS_VETO` | Conservative allow-list mode. High-risk recommendations are denied automatically.          |

## Advisory Build Mode Mapping

Some advisory builds expose alternate interface terminology.

| Advisory Interface | Governance Core   |
| ------------------ | ----------------- |
| `ADVISORY`         | `SHADOW`          |
| `HUMAN_GATED`      | `HUMAN_GATED`     |
| `ACTIVE_PLANNING`  | `AUTONOMOUS_VETO` |

The governance module remains the canonical source of truth.

---

# Failure Behavior

Sentinel-43 is intentionally designed to fail closed in production environments.

## Audit Failure

If audit persistence fails:

* The recommendation is blocked.
* The workflow decision is not approved.
* The engine returns a blocked outcome.

Exception:

Audit fail-open behavior is allowed only when:

* Environment is `dev`
* `SENTINEL_DEV_ALLOW_AUDIT_FAIL_OPEN=1`

Fail-open behavior must never be enabled in production.

---

## Invalid Modes

Invalid policy modes are rejected loudly.

Invalid modes must not silently downgrade to another mode.

Expected behavior:

```text
Invalid mode -> validation error
```

This prevents caller bugs from being hidden behind conservative fallback behavior.

---

## Missing Cryptographic Secret

If `GHOST_DEVICE_HASH_SECRET` is missing or empty:

* Startup fails.
* The engine raises `RuntimeError`.
* No insecure fallback is permitted.

---

## Unknown Actions

Unknown actions are denied by default outside `SHADOW` mode.

This behavior is intentional.

In `SHADOW` mode, unknown actions may be recorded for visibility without automatic workflow promotion.

---

# Evaluation Workflow

Standard evaluation flow:

1. An upstream detector generates a structured assessment.
2. Sentinel-43 evaluates the assessment against governance policy.
3. A recommendation and explanation are generated.
4. A durable audit record is persisted.
5. Workflow handling occurs according to mode:

   * `SHADOW`
   * `HUMAN_GATED`
   * `AUTONOMOUS_VETO`
6. Approved recommendations may be exported to external adapters.
7. The core never directly executes operational controls.

---

# Threat Input Model

Sentinel-43 consumes structured threat assessments, not raw detections.

Detection systems are intentionally separated from governance evaluation.

| Field         | Type        | Description                     |
| ------------- | ----------- | ------------------------------- |
| `identity`    | `str`       | Subject identifier              |
| `source_ip`   | `str`       | Origin IP address               |
| `threat_kind` | `str`       | Threat classification           |
| `severity`    | `str`       | Threat severity                 |
| `source_kind` | `str`       | Detection source classification |
| `score`       | `float`     | Numeric risk score              |
| `tags`        | `list[str]` | Classification tags             |
| `metadata`    | `dict`      | Supplemental structured context |

---

# Recommendation Output Model

Sentinel-43 produces recommendations only.

These are not enforcement actions.

| Recommendation         | Meaning                                  |
| ---------------------- | ---------------------------------------- |
| `LOG_ONLY`             | Record event only                        |
| `FLAG_SUSPICIOUS`      | Increase monitoring visibility           |
| `STEP_UP_AUTH`         | Recommend additional authentication      |
| `RATE_LIMIT`           | Recommend throttling                     |
| `TEMP_BLOCK_IDENTITY`  | Recommend temporary identity restriction |
| `TEMP_BLOCK_IP`        | Recommend temporary IP restriction       |
| `HARD_BLOCK_IDENTITY`  | Recommend permanent identity restriction |
| `HARD_BLOCK_IP`        | Recommend permanent IP restriction       |
| `QUARANTINE_SESSION`   | Recommend session isolation              |
| `REQUIRE_HUMAN_REVIEW` | Escalate to operator review              |
| `OPEN_INCIDENT`        | Recommend incident creation              |

Enforcement must always occur outside the core.

---

# Approval Workflow

In `HUMAN_GATED` mode:

* Recommendations are staged.
* Operators explicitly approve or reject them.
* All workflow transitions are auditable.
* Approved decisions remain advisory artifacts until consumed externally.

Example interface:

```python
engine.approve(decision_id, operator_id, reason)
engine.reject(decision_id, operator_id, reason)
```

Approved recommendations do not become enforcement by themselves.

They must be consumed by an external adapter, control plane, or operator-approved workflow.

---

# Audit and Storage

Sentinel-43 uses durable local persistence for audit and workflow state.

Stored data may include:

* Event logs
* Decision records
* Workflow states
* Deduplication tracking
* Audit chain history
* Approval history
* Rejection history
* Configuration history

The engine includes:

* Bounded retention cleanup
* Pseudonymized identity logging
* Sanitized key generation
* Deterministic audit hashing

---

# Environment Variables

| Variable                             | Required | Default      | Description                    |
| ------------------------------------ | -------: | ------------ | ------------------------------ |
| `GHOST_DEVICE_HASH_SECRET`           |      Yes | —            | HMAC secret for device hashing |
| `SENTINEL_SYSTEM_ID`                 |       No | `sentinel43` | Engine instance identifier     |
| `SENTINEL_AUDIT_DB`                  |       No | `audit.db`   | SQLite audit database path     |
| `SENTINEL_AUDIT_JSONL`               |       No | —            | Optional JSONL audit sink      |
| `SENTINEL_LOG_SALT`                  |       No | —            | Salt for pseudonymized logs    |
| `SENTINEL_ACTION_DEDUPE_TTL`         |       No | `3600`       | Recommendation dedupe window   |
| `SENTINEL_LOG_RETENTION_DAYS`        |       No | `90`         | Event log retention            |
| `SENTINEL_ACTION_RETENTION_DAYS`     |       No | `365`        | Decision retention             |
| `SENTINEL_ALLOWED_OPERATORS`         |       No | —            | Allowed operator IDs           |
| `SENTINEL_VELOCITY_WINDOW_SECONDS`   |       No | `60`         | Velocity limiter window        |
| `SENTINEL_VELOCITY_LIMIT`            |       No | `10`         | Velocity event limit           |
| `SENTINEL_AUTH_MAX_AGE_SECONDS`      |       No | `900`        | Max auth context age           |
| `SENTINEL_ENV`                       |       No | `prod`       | Runtime environment            |
| `SENTINEL_DEV_ALLOW_AUDIT_FAIL_OPEN` |       No | `0`          | Dev-only audit fail-open       |

---

# Quick Start

Generate a secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set environment variables:

```bash
export GHOST_DEVICE_HASH_SECRET=<generated_secret>
export SENTINEL_ENV=dev
```

Run the advisory engine:

```bash
python sentinel43_nexus_onefile_advisory.py
```

For Docker-based development:

```bash
docker compose up --build
```

Check API health:

```bash
curl http://localhost:8000/health
```

---

# Local Load Testing

A local load-test harness may be used for private-beta validation.

Recommended first pass:

```powershell
pwsh .\tools\S43_Nightmare_LoadTest.ps1 `
  -BaseUrl "http://localhost:8000" `
  -Batches 1 `
  -HitsPerBatch 100 `
  -Concurrency 10 `
  -IUnderstand
```

Full stress testing should only be run against systems you own and control.

Large tests such as:

```text
40 batches × 50,000 hits = 2,000,000 requests
```

may heavily stress Docker, Redis, Postgres, API workers, and local hardware.

Do not run large tests against public or third-party infrastructure.

---

# Stability

The following are considered stable:

* Governance modes
* Audit schema
* Threat input model
* Recommendation output model
* Workflow semantics
* Advisory-only core boundary
* Human-gated decision model

The following may change during alpha and beta development:

* Internal helper APIs
* Dashboard event names
* WebSocket message shapes
* S34 auth internals
* Adapter interfaces
* Docker service layout
* Dashboard layout
* Development tooling

Build against the public advisory interface only.

---

# What Sentinel-43 Is Not

Sentinel-43 is not:

* An autonomous attack platform
* An offensive security framework
* A self-directed response engine
* An AI system that makes final decisions
* A hidden enforcement tool
* A covert surveillance system

Sentinel-43 assists operators.

Operators remain responsible for final enforcement decisions.

---

# Long-Term Vision

Sentinel-43 serves as the security oversight and governance foundation for larger operational environments.

Its purpose is to provide visibility, analysis, accountability, and controlled response capabilities while maintaining human authority over security actions.

Sentinel-43 is intended to grow into a modular defensive security platform where health monitoring, threat hunting, governance, audit, and defensive containment remain separated but coordinated.

---

# Licensing

Sentinel-43 is distributed under a dual-license model.

## AGPL v3.0

Open-source use, modification, and distribution are governed by the GNU Affero General Public License v3.0.

## Commercial License

Commercial, enterprise, governmental, or proprietary deployment requires a separate commercial license.

Without explicit written permission, you may not:

* Sell Sentinel-43 as proprietary software
* Deploy it commercially outside the applicable license terms
* Bundle it into paid products outside the applicable license terms
* Redistribute it for profit outside the applicable license terms

---

# Disclaimer

Sentinel-43 is provided:

> AS IS

without warranty of any kind.

The authors are not liable for damages arising from use, misuse, deployment failure, operational misuse, or unsupported modification.

Do not deploy unfinished infrastructure into production and then act surprised when reality develops teeth.
