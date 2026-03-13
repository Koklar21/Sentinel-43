# Sentinel-43 Advisory Engine

Sentinel-43 is a deterministic, advisory-first risk assessment and response recommendation engine.

It helps human operators and review systems make more consistent decisions by converting threat assessments into:

- a policy-based response recommendation
- a human-readable explanation
- a durable audit record
- a workflow state for review and export

Sentinel-43 does **not** directly enforce actions. It does not block users, quarantine systems, or execute controls unless an external adapter is built and wired separately.

---

## Core Design Constraints

These are intentional and non-negotiable:

- No autonomous enforcement in the core
- No covert surveillance or hidden harvesting
- No hidden integrations or side effects
- No opaque black-box decision path
- No bypassing human, legal, or organizational authority

The core exists to analyze, recommend, explain, and record.

---

## What This File Does

`sentinel43_nexus_onefile_advisory.py` is a hardened public advisory build of Sentinel-43.

It provides:

- deterministic risk-to-response planning
- policy-driven recommendation selection
- human-readable explanations
- SQLite-backed decision and audit storage
- approval and rejection workflow states
- export of approved decisions for external adapters

It does **not** execute enforcement.

---

## Architecture

Sentinel-43 follows a separated architecture:

### Core
Analysis, scoring, recommendation planning, and audit recording.

The core performs:
- threat assessment intake
- response planning
- explanation generation
- decision persistence
- workflow state tracking

The core does **not** perform:
- network enforcement
- account disabling
- host quarantine
- firewall updates
- direct operational actions

### Adapters
Optional external integrations that consume Sentinel recommendations.

Examples:
- queue publishers
- SOAR handoff adapters
- case management connectors
- review pipelines
- control-plane integrations

Adapters are external to the core by design.

### Interfaces
Human-facing dashboards, review tools, and administrative approval surfaces.

---

## Workflow

The normal flow is:

1. A threat assessment is created by an upstream detector or service
2. Sentinel-43 evaluates the assessment against policy
3. A response directive is generated
4. A decision record is stored
5. Depending on mode, the recommendation is either:
   - recorded directly, or
   - staged for human review
6. Approved decisions can be exported for external adapter consumption

---

## Modes

Sentinel-43 supports workflow modes that affect review flow, not enforcement:

### `ADVISORY`
Analyze, recommend, and log.

### `HUMAN_GATED`
Recommendations are staged for explicit human approval.

### `ACTIVE_PLANNING`
Produces time-sensitive planning recommendations while remaining advisory-only.

---

## Threat Input Model

The engine consumes threat assessments, not raw detections.

Input includes:

- identity
- source IP
- threat kind
- severity
- source kind
- score
- supporting tags
- metadata

This keeps detection logic separate from response planning.

---

## Response Output Model

Sentinel-43 produces recommendations such as:

- `LOG_ONLY`
- `FLAG_SUSPICIOUS`
- `STEP_UP_AUTH`
- `RATE_LIMIT`
- `TEMP_BLOCK_IDENTITY`
- `TEMP_BLOCK_IP`
- `HARD_BLOCK_IDENTITY`
- `HARD_BLOCK_IP`
- `QUARANTINE_SESSION`
- `REQUIRE_HUMAN_REVIEW`
- `OPEN_INCIDENT`

These are **recommendations only**.

Any actual enforcement must be implemented outside the core.

---

## Audit and Storage

The advisory engine uses SQLite for durable local storage.

Stored data includes:

- event logs
- decision records
- decision workflow status
- deduplication state for repeated recommendations

Built-in retention cleanup is included to reduce uncontrolled DB growth.

Privacy-oriented handling includes:

- pseudonymized logging for sensitive values
- bounded/sanitized key generation
- source and decision audit records

---

## Approval Workflow

In `HUMAN_GATED` mode, recommendations are staged and require operator approval or rejection.

The engine supports:

- `approve(decision_id, operator_id, reason)`
- `reject(decision_id, operator_id, reason)`

Approved decisions remain advisory artifacts until consumed by an external adapter.

---

## Export for External Adapters

Approved decisions can be exported in JSON-friendly form for downstream systems.

This allows the advisory core to remain isolated while still participating in a broader response workflow.

Example use cases:
- case management
- review pipelines
- external orchestration
- SOAR or control-plane handoff

---

## Environment Variables

Common environment variables include:

- `SENTINEL_SYSTEM_ID`
- `SENTINEL_DB_PATH`
- `SENTINEL_ACTION_DEDUPE_TTL`
- `SENTINEL_LOG_RETENTION_DAYS`
- `SENTINEL_ACTION_RETENTION_DAYS`
- `SENTINEL_LOG_SALT`
- `SENTINEL_ALLOWED_OPERATORS`

The engine also supports legacy `AEGIS_*` fallback resolution for compatibility.

---

## Quick Start

Run the one-file advisory build directly:

```bash
python sentinel43_nexus_onefile_advisory.py