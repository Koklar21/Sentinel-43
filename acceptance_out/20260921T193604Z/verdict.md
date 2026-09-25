# ACCEPTANCE FAIL

revision `f3e15bb13bde77c5f539112f72f0d46e9e1cb79c` (branch feat/heart-detection-ingestion-20260921), tree fingerprint `fc1b19a2a51946ed`, 16 uncommitted file(s)

test IDs reconciled: 1108; totals: {"passed": 1108}

| job | status | counts | notes |
|---|---|---|---|
| core-isolated | PASS | {"passed": 980} |  |
| core-postgres | PASS | {"passed": 114} |  |
| core-live | PASS | {"passed": 14} |  |
| browser-disposable | FAIL | {} | required job has no result (never ran / artifact missing) |
| browser-target | ENV-UNMET | {} | prerequisite unmet: ['no explicitly authorized isolated target/credentials supplied (S43_TARGET_* unset)'] |
| check-compose-config | FAIL | {} | required job has no result (never ran / artifact missing) |
| check-k8s-policy | FAIL | {} | required job has no result (never ran / artifact missing) |
| check-kubeconform | FAIL | {} | required job has no result (never ran / artifact missing) |
| check-image-scan | FAIL | {} | required job has no result (never ran / artifact missing) |
| check-kind-smoke | ENV-UNMET | {} | prerequisite unmet: ['kind + Calico smoke deploy needs a hosted CI runner / kind binary; none available locally'] |
