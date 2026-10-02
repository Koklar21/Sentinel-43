# Behavioral and anomaly detection

Sentinel-43's Phase 4 strengthens the existing bounded Fenrir statistical
anomaly layer. It does not create a second detector authority, a second event
store, or an enforcement path.

## Baseline learning

Fenrir learns per-subject score behavior only from fresh detector evidence.
Repeated polls, replayed evidence, sequence regressions, and observations
without an evidence sequence do not advance the baseline.

Once the minimum observation count has established a mature baseline, an
observation that crosses the configured z-score or cumulative-pressure
threshold is reported as anomaly evidence but is not learned into that
baseline. This prevents a detected outlier from shifting the mean/variance
toward itself or ratcheting cumulative pressure simply because it was already
flagged.

Warm-up observations remain learnable so a baseline can be established.

## Authority boundary

Statistical output is evidence only:

`trusted evidence -> SentinelThreatDetector -> FenrirAnomalyLayer ->
Fenrir finding -> Sentinel43RuntimeAuthority -> Heart / existing human gates`

The anomaly layer cannot quarantine, terminate processes or containers, block
users, mutate policy, approve actions, or bypass human gates.
