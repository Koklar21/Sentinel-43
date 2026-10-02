# Sentinel-43/ — owner-designated orchestration core

This directory holds the owner-designated Sentinel-43 orchestration sources.
All four are current runtime sources. Shadow_mode.py is the single response
engine; Sentinel_Nexus.py, Sentinel_core.py, and sentinel_AI_escalation.py
are loaded as subordinate runtime components owned by
Sentinel43RuntimeAuthority.

## Instruction this integration follows

On 2026-09-22 the repository owner, Justin Armstrong, instructed the
implementing Claude Code session, in writing:

> "The Sentinel-43/ directory shown by Justin is the intended core ... Their
> responsibilities must be integrated into the functioning system."

and, later the same day:

> "Make the original orchestration layer authoritative, with Heart operating
> beneath it. Preserve human authorization, fail-closed behavior, existing
> durable state, and the prohibition on autonomous execution."

and, on the approval lifecycle:

> "Extend the existing policy vocabulary to represent the engine's rate
> limiting, step-up authentication, temporary/hard account blocks, and
> incident creation accurately. Require authenticated, authorized human
> approval. This does not authorize external enforcement or autonomous
> execution."
>
> "Account/session actions remain inapplicable to anonymous sources. Do not
> invent accounts, substitute IP operations, silently drop actions, or
> approve only part of the reviewed recommendation."
>
> "Use a durable internal incident record, reusing an existing facility if
> available. An audit entry alone does not count as an incident. No external
> incident integration is authorized."

This README records that instruction. It is not itself an approval, and it
does not replace the owner's review of the change that implements it.

## What runs

- `Shadow_mode.py` → `Sentinel43ResponseEngine` is the **orchestration engine**.
  `core/governance/sentinel43_engine.py` loads this file **unmodified** (its
  sha256 is recorded on every decision it makes). The top-level
  `Sentinel43RuntimeAuthority` owns that engine and the subordinate
  `SystemOrchestrator`; every Heart finding enters through that Sentinel-43
  authority boundary. The engine's own code decides:
  - what response a finding warrants (`plan_response`),
  - whether it is staged, including its dedupe (`stage_directive`),
  - approve / veto, behind its fail-closed `operator_authenticator`
    (`approve_action`, `veto_action`).
- Adapted, and only these:
  - **Storage:** its `ActionStore` is served by the one durable
    `SentinelCoreStore`; there is no second ledger.
  - **Execution is absent:** the owner engine itself has no ACTIVE mode,
    executor loop, standalone integration execution, or execute-on-approval
    path. The store adapter also refuses executor claims as defense in depth.
    Approval is recorded; nothing is executed.
  - **Authentication:** its authenticator is bound to the server-verified
    human principal of the decision in progress.
  - **Its event log:** `ActionStore.log_event` for the engine's governance
    modules is appended to the one canonical `AuditStore`, so the engine's own
    account of what it did is durable -- in that ledger, never a second one.
  - **Principal:** pre-authentication evidence is presented to it as
    `anonymous|<source_ip>`, so distinct sources are not collapsed into one.
- Every engine action is mapped to the policy operation that states ITS
  meaning, never to a different one:

  | engine action | policy operation |
  | --- | --- |
  | `TEMP_BLOCK_IP` / `HARD_BLOCK_IP` | `network_block` |
  | `RATE_LIMIT` | `rate_limit` |
  | `STEP_UP_AUTH` | `step_up_auth` |
  | `TEMP_BLOCK_IDENTITY` | `account_block_temporary` |
  | `HARD_BLOCK_IDENTITY` | `account_block_extended` |
  | `QUARANTINE_SESSION` | `quarantine` |
  | `OPEN_INCIDENT` | `incident_open` |

  Each of these requires an authenticated, authorized human decision in
  `HUMAN_GATED` and is observe-only in `SHADOW`. None of them authorizes
  enforcement outside Sentinel-43.
- **An action that names an account acts on the account, and only on a real
  one.** `STEP_UP_AUTH`, `TEMP_BLOCK_IDENTITY`, `HARD_BLOCK_IDENTITY` and
  `QUARANTINE_SESSION` target the account the request pipeline authenticated
  (`SecurityContext.principal_id`), carried through as in-process provenance
  exactly like the evidence producer: a registered producer reports it, the
  detector collects the distinct accounts a window saw, and the authority uses
  it only when the window names exactly one. The subject key
  (`<identity type>|<source address>`) is never read as an account, no account
  is invented, and no address operation is substituted for one.

  **Today no producer reports one.** The only registered producer is the
  firewall, and it emits its event while *rejecting* a request -- before
  anything authenticates it. So account-scoped responses stay unapprovable in
  production until an authenticated-stage evidence producer is authorized.
  That is the owner's decision; this code does not close it by inventing a
  target. (`core/tests/test_heart_ingestion.py` asserts both halves.)
- A recommendation is approved as a whole or not at all. If any of its actions
  has no valid target or no policy operation, approval is unavailable -- the
  reasons are shown in the API and the dashboard -- and it can still be
  vetoed. Approving only the supported part would authorize a different set
  than the reviewer saw.
- **Incidents.** `OPEN_INCIDENT` opens a durable record in the existing
  `SentinelCoreStore` (`incidents` table), readable at `GET /incidents` and
  named on the decision's audit record. It is opened only by an approved
  decision, it is retracted if that decision cannot be recorded, and it
  reaches nothing outside this system. Today every engine plan that contains
  `OPEN_INCIDENT` also quarantines a session and blocks an account, so no real
  recommendation can reach it until the evidence carries an account
  identifier -- which is the owner's decision to make, not this code's.

## Which original oversight controls are active

The original oversight responsibilities remain active, but the obsolete
standalone `OversightEngine` implementation has been removed from the live
owner engine. The controls are enforced by the current engine, Heart, and
`SystemOrchestrator` against the one durable store:

| Oversight control | Where it is enforced now |
| --- | --- |
| back-pressure (`max_pending`) | staging ceiling, `count_actions(PENDING)` |
| dedupe (`dedupe_ttl_seconds`) | the engine's own `stage_directive`, over `SentinelCoreStore.dedupe_allow` |
| action budget per target | `count_actions_for_target` over the budget window, before anything is staged (`SENTINEL_OVERSIGHT_BUDGET_*`) |
| two-signal corroboration for HIGH | the Heart's corroboration, by distinct trusted producers |
| SHADOW = advisory only | `stage_recommendation` observes, never stages a decision |
| HUMAN_GATED = stage for a human | the engine's own `stage_directive` |
| ACTIVE = stage with a veto delay | refused: no autonomous execution |
| operator authentication | `resolve_recommendation`, bound to a verified human |

Its per-*source* budget is not enforced here: a durable row records the
subject it targets, not which producer reported it, so there is nothing to
count a source against. The ingestion rate limit bounds one producer's flow
at the boundary instead.

## Current owner-source runtime wiring

- `Sentinel_Nexus.py` is the live Nexus entry contract. Public recommendation
  staging and resolution enter `Sentinel43RuntimeAuthority`, cross the Nexus,
  and only then hand off to the subordinate `SystemOrchestrator`.
- `Sentinel_core.py` is the live node/core contract. It owns no local worker,
  scheduler, Watchtower, audit DB, approval queue, or executor; it reports into
  the same runtime authority.
- `sentinel_AI_escalation.py` is the live AI/detection escalation contract.
  It carries evidence and recommendation vocabulary but does not plan or
  execute responses; the owner engine remains authoritative for planning.
  The existing detector retains the original AI-threat distinction as the
  composition of `ThreatSourceKind.AI_AUTOMATION_LIKELY` with the canonical
  threat kind. Deterministic malware/virus, spyware, exfiltration, credential,
  Sigma, and agent-sequence evidence is summarized in the assessment's bounded
  `ai_pattern_profile`. The owner escalation layer then adds its own stable
  assessment fingerprint under the reserved `ai_escalation` indicator before
  the assessment reaches Heart. That provenance therefore enters the existing
  authoritative audit path instead of terminating inside the escalation
  facade.
- `Shadow_mode.py` is the one live response engine. It requires an injected
  governed `ActionStore`, supports only SHADOW/HUMAN_GATED, and contains no
  standalone SQLite runtime or autonomous executor.
- `core/governance/owner_components.py` loads the three non-engine owner
  sources by path, records their canonical SHA-256 provenance, and binds one
  instance of each to the single `Sentinel43RuntimeAuthority`.

All four owner sources ship in the runtime image. None creates a second
authority, store, approval queue, scheduler, Watchtower, or executor.


### AI evidence persistence

No additional AI-specific database or schema is used.

The durable recommendation row in `SentinelCoreStore` remains intentionally
small and decision-bound: target, action set, threat kind, severity,
`source_kind`, score, principal, and status. The full detector indicators,
including `ai_pattern_profile` and owner `ai_escalation` fingerprint
provenance, are already carried by Heart into the canonical authenticated
`AuditStore` record.

Duplicating those indicators into another table/column would create two
sources of truth for the same evidence. If future response authorization ever
requires a new field to survive independently of the audit record, that field
must be added deliberately to the existing governed store and bound into the
staging-integrity checks; this preservation pass does not invent one.

## Rules

- These are current owner sources and may be updated deliberately when the
  architecture requires it. Any change to `Shadow_mode.py` must update the
  reviewed `EXPECTED_ENGINE_SHA256` pin in the same change.
- `ACTIVE` / `AUTONOMOUS_VETO` stays prohibited. Nothing here may be wired to
  execute an effect.
- Security review: a bounded review of the changed authority boundary and
  adapters was performed on 2026-09-22 by the same session that implemented
  them (findings and fixes are in that change's history). It is **not** an
  independent review; the separate review this README previously required is
  still outstanding.
- The runtime refuses to load a `Shadow_mode.py` whose sha256 differs from the
  reviewed file (`EXPECTED_ENGINE_SHA256` in `core/governance/sentinel43_engine.py`).
