# Detection producer wiring

Sentinel-43 has one detection path and one runtime authority. Detection-capable
subsystems may contribute evidence, but they do not gain response authority by
being registered as producers.

## Canonical flow

```
trusted producer
  -> MonitoringManager
  -> embedded Watchtower scan
  -> Fenrir / SentinelThreatDetector
  -> canonical ThreatAssessment
  -> Sentinel43RuntimeAuthority / Heart / existing human gates
```

`MonitoringManager.attach_threat_ingestor()` is the producer trust boundary.
A payload cannot make itself trusted by setting `source` or
`source_identity`. The composition root registers the producer kind and its
fixed source label, while the caller supplies the in-process
`trusted_producer` marker and a validated subject identity/address.

## Registered producers

- `firewall` -> configured SentinelFirewall monitoring source
- `ebpf` -> `sentinel-ebpf`
- `sparta` -> `sentinel-sparta`

SpartaCore converts its internal integrity event names to canonical detection
event types before ingestion:

- `TamperDetected` -> `sparta_tamper_detected`
- `IntegrityCompromised` -> `sparta_integrity_compromised`
- `FileUnavailable` -> `sparta_file_unavailable`
- `RecoveryAcknowledged` -> `sparta_recovery_acknowledged`

The first three are suspicious evidence types. Recovery is deliberately not
suspicious evidence.

Sparta is embedded in the API process, so its threat subject uses the existing
`service:sparta-node` identity and loopback address. Producer provenance is
assigned by Sparta's in-process monitoring bridge; arbitrary event payload text
cannot override it.

## Authority boundary

Registration only allows evidence to reach the existing detector. Sparta,
Watchtower, eBPF, Sigma, and Fenrir do not independently quarantine, terminate,
block, approve, modify policy, or bypass Heart/human gates. Runtime decisions
remain owned by `Sentinel43RuntimeAuthority`.

Additional existing producers should be wired by the same contract rather than
adding parallel detector instances, queues, or enforcement paths.
