# Sentinel-43/ — owner-designated orchestration core

This directory holds the original Sentinel-43 orchestration sources. One of
them now runs as the orchestration engine; the rest are preserved design
sources.

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
  sha256 is recorded on every decision it makes) and hands it to
  `SystemOrchestrator`, which is the single authority every Heart finding is
  reported to. The engine's own code decides:
  - what response a finding warrants (`plan_response`),
  - whether it is staged, including its dedupe (`stage_directive`),
  - approve / veto, behind its fail-closed `operator_authenticator`
    (`approve_action`, `veto_action`).
- Adapted, and only these:
  - **Storage:** its `ActionStore` is served by the one durable
    `SentinelCoreStore`; there is no second ledger.
  - **Execution is contained:** `_executor_loop` and `_execute_approved_now`
    are no-ops, executor claims are refused, and ACTIVE mode is refused.
    Approval is recorded; nothing is executed.
  - **Authentication:** its authenticator is bound to the server-verified
    human principal of the decision in progress.
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
- **An action that names an account or a session has nothing to act on yet.**
  The subject a finding carries is `<identity type>|<source address>`: the
  only trusted producer (the request firewall) reports an `IdentityType`, so
  the subject names a *class* of caller and an address, never an account. So
  `STEP_UP_AUTH`, `TEMP_BLOCK_IDENTITY`, `HARD_BLOCK_IDENTITY` and
  `QUARANTINE_SESSION` are recorded as having no valid target. No account is
  invented for them and no address operation is substituted.
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

## What does not run, and why

- `Sentienal_Nexus.py`, `Shadow_mode.py`'s own `OversightEngine`/`SentinelNexus`,
  and `sentinel_AI_escalation.py` are alternative versions of the same stack.
  Running them alongside the engine would create a second authority and a
  second (in-memory) approval queue, and their approval paths execute on
  approval. `sentinel_AI_escalation.py` carries the same response engine as
  `Shadow_mode.py`.
- `Sentienal_core.py`'s Watchtower generates anomalies with `random.random()`
  against hard-coded principals, and its IAM "quarantine" only logs. There is
  no real capability to run.

These files are not loaded and are excluded from the runtime image.

## Rules

- Do not edit these files: the runtime records the engine file's sha256, and
  its behavior is the owner's design.
- `ACTIVE` / `AUTONOMOUS_VETO` stays prohibited. Nothing here may be wired to
  execute an effect.
- Security review: a bounded review of the changed authority boundary and
  adapters was performed on 2026-09-22 by the same session that implemented
  them (findings and fixes are in that change's history). It is **not** an
  independent review; the separate review this README previously required is
  still outstanding.
- The runtime refuses to load a `Shadow_mode.py` whose sha256 differs from the
  reviewed file (`EXPECTED_ENGINE_SHA256` in `core/governance/sentinel43_engine.py`).
