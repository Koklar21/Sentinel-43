# Sigma-compatible deterministic detection

Sentinel-43 Phase 1 adds an optional, bounded Sigma-compatible deterministic
matcher to the existing Fenrir detection pipeline.

It is intentionally **not** a complete Sigma implementation.

## Architecture

Sigma is an evidence producer inside the existing detector:

```text
trusted S43 producer
    -> MonitoringManager normalization / rate / replay controls
    -> bounded Sigma event projection
    -> SentinelThreatDetector
         - existing deterministic scoring
         - optional Sigma matching
    -> canonical ThreatAssessment
    -> Fenrir reporting
    -> Watchtower
    -> Sentinel43RuntimeAuthority
    -> Heart corroboration / human-governed response path
```

Sigma has no direct reference to the runtime authority, Heart, governance
orchestrator, response engine, Watchtower client, subprocess execution, or
policy mutation. It cannot approve, veto, quarantine, kill, block, or execute
a response.

A Sigma match does **not** become an independent corroboration source. The
underlying trusted producer (for example `firewall`) remains the
`evidence_sources` identity. Sigma is analysis of that evidence, not a second
sensor.

## Parser

Rule YAML and Sigma condition syntax are parsed with **pySigma**. Sentinel-43
then compiles only the subset it can evaluate faithfully against normalized
telemetry. Unsupported constructs are rejected instead of translated into
something merely similar.

## Supported Phase-1 subset

Phase 1 is event-local. It supports:

- field-bound scalar string, number, boolean, and null comparisons;
- Sigma string wildcard semantics;
- the common string modifiers that pySigma lowers to Sigma strings, including
  `contains`, `startswith`, `endswith`, `all`, and `cased`;
- boolean `and`, `or`, and `not`;
- pySigma-resolved selection expressions such as `1 of selection_*`;
- rule identity/title/level/tags and logsource product/category/service.

The following are deliberately unsupported in Phase 1:

- Sigma correlation/timeframe rules;
- unbound keyword searches;
- regular-expression values;
- CIDR expressions;
- field-reference comparisons;
- query expressions;
- compare/exists/expansion expressions;
- fields absent from the bounded S43 telemetry projection.

Temporal/cross-event correlation belongs to Phase 3 of the detection
strengthening pass and is not smuggled into Phase 1.

## S43 field projection

Sigma never receives an arbitrary raw producer payload.

`MonitoringManager` first performs S43's existing normalization, producer
allow-list, subject validation, replay suppression, and rate controls. It then
creates a scalar-only projection from trusted/canonical fields.

Common Sigma aliases include:

| Sigma field | S43 projected field |
| --- | --- |
| `EventType` | `event_type` |
| `Source` | `source` |
| `SourceIdentity` / `IdentityType` | `source_identity` |
| `SourceIp` / `src_ip` | `source_ip` |
| `User` / `Username` / `TargetUsername` | authenticated `principal_id` |
| `Status` | `status` |
| `StatusCode` | `status_code` |
| `Success` | `success` |
| `Severity` | `severity` |
| `ThreatKind` | `threat_kind` |
| `Action` | `action` |
| `IntegrityStatus` | `integrity_status` |
| `RuntimeEvent` | `runtime_event` |
| `Platform`, `Workload`, `PodName`, `NodeName` | matching normalized runtime fields |

Unknown fields reject the rule at load time. Secrets, Authorization headers,
passwords, arbitrary nested payloads, and unbounded arrays are never projected
to Sigma.

## Match evidence and scoring

Each accepted match preserves:

- detector identity and version;
- Sigma rule ID (or deterministic file-hash fallback when the rule has no ID);
- title;
- level;
- tags;
- source rule path;
- SHA-256 of the source rule file;
- originating S43 event ID.

Matches are folded into the existing `ThreatAssessment.indicators`.

Sigma level establishes a **score floor**, not an additive bonus:

| Sigma level | S43 score floor |
| --- | ---: |
| informational | 10 |
| low | 20 |
| medium | 40 |
| high | 65 |
| critical | 85 |

Multiple matching rules do not blindly stack scores. Existing deterministic
S43 evidence can still produce a higher score.

## Bounds and performance

Rules are parsed/compiled at Fenrir construction, not for every event.

Defaults:

- maximum loaded rules: 256;
- maximum Sigma matches retained for one event: 8;
- maximum Sigma matches retained in one assessment window: 32;
- maximum individual rule file: 1 MiB.

Sigma runs only after the event passes the existing MonitoringManager trusted
producer, replay, rate, and subject checks.

## Failure isolation

Sigma is optional.

If the configured rule path cannot be loaded, Fenrir records Sigma coverage as
`degraded` and continues with the existing deterministic detector.

If one loaded matcher fails while evaluating an event, that failure is counted
and the base S43 detector still processes the event.

Invalid or unsupported rule files are reported as rejected issues. Valid
supported rules in the same rule directory remain active.

## Configuration

```env
S43_SIGMA_ENABLED=false
S43_SIGMA_RULES_PATH=/app/rules/sigma
S43_SIGMA_MAX_RULES=256
S43_SIGMA_MAX_MATCHES_PER_EVENT=8
```

Docker Compose explicitly forwards these variables. Kubernetes base declares
them disabled by default.

A deployment that enables Sigma must make reviewed `.yml` or `.yaml` rule
files available at `S43_SIGMA_RULES_PATH`.

## Status

Fenrir's existing status snapshot includes `sigma_detection` with:

- enabled/configured/active state;
- coverage state;
- loaded/rejected rule counts;
- bounded issue details;
- evaluation/match/truncation/failure counters.

A Sigma outage is loss of detection coverage, not loss of Sentinel-43 runtime
authority.
