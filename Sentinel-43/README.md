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
- Only engine actions the policy vocabulary states exactly are approvable
  (`TEMP_BLOCK_IP`/`HARD_BLOCK_IP` → `network_block`; `QUARANTINE_SESSION` →
  `quarantine`, for an authenticated principal only). A recommendation is
  approved as a whole or not at all: if any of its actions has no policy
  operation (step-up authentication, rate limiting, identity blocks), no valid
  target, or no integration (incidents), approval is unavailable -- the reasons
  are shown in the API and dashboard -- and the recommendation can be vetoed.

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
