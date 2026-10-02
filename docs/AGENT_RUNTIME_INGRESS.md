# Agent runtime evidence ingress

Phase 3 agent sequence detection accepts explicit activity observations through
an optional authenticated internal endpoint:

`POST /internal/agent-runtime/events`

It is disabled by default. Enable with `S43_AGENT_RUNTIME_ENABLED=true` and
provide a dedicated `S43_AGENT_RUNTIME_INGEST_TOKEN`.

The endpoint accepts a strict allowlist of activity facts used by the sequence
matcher. Arbitrary event types are rejected. It also validates the subject as an
IPv4 or IPv6 address and assigns these server-owned provenance values:

- source: `sentinel-agent-runtime`
- identity: `service:agent-runtime`
- trusted producer: `agent_runtime`

The producer token authenticates an observer. It is not an operator credential
and grants no action, approval, policy, quarantine, process, container, or user
control.

Flow:

`agent observer -> authenticated ingress -> MonitoringManager ->
Fenrir/SentinelThreatDetector -> ThreatAssessment -> Sentinel43RuntimeAuthority
-> Heart / existing human gates`

The endpoint carries bounded metadata (`agent_id`, `tool_name`, and
`resource`) for evidence context. It does not accept prompt contents, model
reasoning, arbitrary tool arguments, secrets, or response authority.
