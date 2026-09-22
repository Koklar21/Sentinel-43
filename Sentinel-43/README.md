# Sentinel-43/ — owner-designated orchestration core

This directory holds the original Sentinel-43 orchestration sources. By the
owner's explicit direction, one of them now runs as the orchestration engine;
the rest are preserved design sources.

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
  (`TEMP_BLOCK_IP`/`HARD_BLOCK_IP` → `network_block`, `QUARANTINE_SESSION` →
  `quarantine`). The engine's other recommendations are staged as it decides
  but recorded as unsupported and can only be vetoed.

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
- Outstanding: the separate security review this README previously required
  before runtime wiring has not been performed.
