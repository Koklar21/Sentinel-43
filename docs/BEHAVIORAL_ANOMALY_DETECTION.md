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


## Stable baselines

A mature baseline with zero variance is not treated as absence of information.
If repeated accepted observations establish the same score, the first upward
departure is considered statistically anomalous even though a finite z-score
cannot be calculated. Downward departures remain non-escalating because this
layer models increases in threat behavior, not arbitrary statistical novelty.


## Behavioral dimension: failure ratio

Phase 4 also baselines the detector-derived failure ratio for each existing
identity/IP subject. The ratio is computed inside SentinelThreatDetector from
the same bounded event window used for scoring, so the anomaly layer does not
create another raw-event store.

A mature subject whose failure ratio rises sharply above its learned behavior
can therefore produce anomaly evidence even when its aggregate threat score is
unchanged. The behavioral baseline follows the same freshness, replay,
bounded-key, stale-pruning, and anomaly-poisoning rules as score baselining.

Missing behavioral metadata falls back to score-only anomaly handling. A
behavioral shift is evidence only; it does not independently enforce or change
policy.
