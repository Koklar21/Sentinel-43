# ACCEPTANCE FAIL

revision `327d90aed9fa36b2606b10608f403827b74e97cd` (branch feat/heart-detection-ingestion-20260921), tree fingerprint `2a5052aba0cff77e`, 7 uncommitted file(s)

test IDs reconciled: 2098; totals: {"passed": 2098}

| job | status | counts | notes |
|---|---|---|---|
| core-isolated | PASS | {"passed": 980} |  |
| core-isolated-container | PASS | {"passed": 980} |  |
| core-postgres | PASS | {"passed": 114} |  |
| core-live | PASS | {"passed": 14} |  |
| browser-disposable | PASS | {"passed": 10} |  |
| browser-target | ENV-UNMET | {} | prerequisite unmet: ['no explicitly authorized isolated target/credentials supplied (S43_TARGET_* unset)'] |
| check-compose-config | PASS | {} |  |
| check-k8s-policy | PASS | {} |  |
| check-kubeconform | PASS | {} |  |
| check-image-scan | FAIL | {} | required job has no result (never ran / artifact missing) |
| check-kind-smoke | ENV-UNMET | {} | prerequisite unmet: ['kind + Calico smoke deploy needs a hosted CI runner / kind binary; none available locally'] |
