# Sentinel-43 Sigma Rules

This directory is the default read-only rule source for the optional Phase-1
Sigma-compatible detector.

Sentinel-43 does **not** claim complete Sigma compatibility. Rules are parsed
with pySigma, then validated against the bounded event-local subset documented
in `docs/SIGMA_DETECTION.md`. Unsupported constructs are rejected and shown
in Fenrir's Sigma status rather than approximated.

No rule in this directory receives enforcement authority. A match becomes
evidence inside the existing `SentinelThreatDetector -> Fenrir ->
Sentinel43RuntimeAuthority -> Heart` path.

The repository intentionally ships no enabled detection rule here by default.
Deployments may bake or mount reviewed `.yml` / `.yaml` rules into this
directory and set:

```
S43_SIGMA_ENABLED=true
S43_SIGMA_RULES_PATH=/app/rules/sigma
```

A minimal S43-compatible example is:

```yaml
title: Repeated Firewall Block Signal
id: 2fe0d3ab-3a18-4a5d-9f3a-68edb90fb2fe
status: test
logsource:
  product: sentinel43
  category: security
detection:
  selection:
    EventType: firewall_block
    Status: blocked
  condition: selection
level: high
```

Review and validate rules before deployment. Rule files are configuration, not
a trusted code-execution surface.
