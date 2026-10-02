# AI/agent behavioral sequence detection

Phase 3 adds deterministic sequence recognition to the existing
`SentinelThreatDetector`. It is a detection layer, not an agent controller and
not a second runtime authority.

## Contract

The detector consumes explicit, trusted agent activity event types. It does not
read prompts, infer hidden intent, call an LLM, or execute tools. Sequence
matching runs over the existing bounded per-`(source_identity, source_ip)`
window, so events from different subjects cannot combine into one finding.

Initial ordered patterns are:

- discovery/enumeration -> secret/credential access: high
- secret/credential access -> external transfer/data export: critical
- policy/permission probing -> privileged action/permission change: high

A complete match adds structured `agent_sequence_matches` evidence and a
high/critical score floor to the normal `ThreatAssessment`. It does not itself
quarantine, kill, block, change policy, approve an action, or bypass Heart or a
human gate.

## Integration boundary

This first Phase 3 change defines and verifies the sequence matcher. A separate
integration change must establish a trusted producer for agent activity facts.
Payload text alone must never be able to assert trusted producer provenance.

Canonical response authority remains:

`trusted evidence -> MonitoringManager -> Fenrir/SentinelThreatDetector ->
ThreatAssessment -> Sentinel43RuntimeAuthority -> Heart / existing human gates`


## Correlation boundary

Agent sequence steps must come from the trusted `agent_runtime` producer and
share the same server-carried agent correlation id. The surrounding detector
window remains bounded by source identity and host IP, but host co-location
alone cannot combine activity from two different agents into one sequence.

The agent ingress assigns its normalized `correlation_id` from the validated,
bounded `agent_id` field. Monitoring carries that value as observational
producer correlation metadata. Sequence detection uses it only when provenance
is `agent_runtime`; another producer using agent-like event names cannot form
an agent behavioral sequence.

Existing MonitoringManager and detector event-id replay suppression remain the
replay boundary. Phase 3 does not create a second replay cache or state store.
