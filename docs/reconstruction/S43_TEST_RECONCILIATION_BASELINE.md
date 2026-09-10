# Sentinel-43 — Test Reconciliation Baseline

Captured at the start of the test-reconciliation pass.

## Git baseline

| | |
|---|---|
| branch | `main` |
| HEAD SHA | `9dfd82963b96359b1847df2930d109fa7d2f23b8` |
| ahead of `origin/main` | 1 commit |

### Staged (do NOT alter — deliberate prior-pass work)

```
D  core/api/config/__init__.py
D  core/api/config/config.py
```

`core/api/config/` deletion is **staged** — it is the scaffold-wrapped orphan
package (nothing imports `core.api.config`). Left staged intentionally.

### Modified (unstaged — prior repair-pass work, not part of this pass)

```
M  core/api/Dockerfile
M  core/api/deps/__init__.py
M  core/api/deps/deps.py
M  core/api/main.py
M  core/api/routers/routers.py
M  core/audit/__init__.py
M  core/cli/generate_secrets.py
M  core/governance/__init__.py
M  core/monitoring/exceptions.py
M  core/monitoring/watchtower.py
M  core/monitoring/watchtower_client.py
M  core/policy_gate/__init__.py
M  docker-compose.yml
```

### Untracked

```
?? core/governance/composition.py   (deliberate prior-pass work — governance composition builder)
```

`core/governance/composition.py` is **untracked** and intentionally so. Not
touched by this pass.

## Test baseline

Environment: `s43:test` image (Dockerfile `test` stage), `SENTINEL_ENV=test`,
`S43_ENV=test`. Command:

```
python -m pytest core/tests -q --no-header -p no:cacheprovider --continue-on-collection-errors
```

| metric | count |
|---|---|
| collected | 719 (+ 3 files that fail at collection) |
| **passed** | **453** |
| **failed** | **164** |
| **skipped** | **93** |
| **errors** | **12** (3 collection-level, 9 setup/teardown) |

### Collection errors (whole files)

| file | cause |
|---|---|
| `test_break_glass_pg.py` | `SyntaxError` line 215 |
| `test_operator_hash_validation.py` | `SyntaxError` line 12 |
| `test_policy_gate_smoke.py` | `ImportError: cannot import name 'MODE_AUTONOMOUS_VETO' from core.policy_gate.governance` |

### Failures / errors grouped by file

| count | file |
|---|---|
| 25 | `test_users_admin.py` |
| 22 | `test_jwt_auth.py` |
| 16 | `test_auth_login.py` |
| 14 | `test_ws_auth.py` |
| 14 | `test_service_identity_separation.py` |
| 10 | `test_package_integrity.py` |
| 10 | `test_firewall_config_hardening.py` |
|  9 | `test_schema_authority.py` |
|  6 | `test_system_smoke.py` |
|  6 | `test_session_primitives.py` |
|  6 | `test_actions_test_inject_auth.py` |
|  5 | `test_v1_auth.py` |
|  5 | `test_internal_broadcast_auth.py` |
|  5 | `test_bootstrap.py` |
|  5 | `test_login_throttle.py` (errors) |
|  4 | `test_password_verification.py` |
|  4 | `test_bootstrap_isolated.py` (errors) |
|  2 | `test_security_headers.py` |
|  2 | `test_auth_log_sanitization.py` |
|  1 | `test_watchtower_bridge_auth.py` |
|  1 | `test_tls_posture.py` |
|  1 | `test_health_check_log_filter.py` |

### Known failure clusters (pre-reconciliation)

1. **SentinelFirewall rejects `TestClient`** — `{"error":"request_blocked","detail":"Invalid client address"}` (HTTP 400). `core/tests/` has no `conftest.py`. Affects most HTTP-route modules.
2. **`test_firewall_config_hardening.py`** — env var names in tests don't match `FirewallConfig.from_env()`.
3. **`test_login_throttle.py`** — `AttributeError: module 'core.api.routers.auth' has no attribute '_login_lock'` (renamed private symbol).
4. **`test_policy_gate_smoke.py`** — imports removed legacy governance constants.
5. **`test_package_integrity.py`** — `core.audit` expects historical `AuditEvent`/`AuditLogger`; `AuditStore` test calls `.append()` before `.initialize()`; `core.monitoring` sparta lazy-export drift.
6. **2 syntax-error files.**

## Hard rules for this pass

Test-only reconciliation. No weakening of SentinelFirewall, auth, authz,
Argon2id, governance authority. No production API changes to satisfy stale
tests. Production code changes only with proven defect + evidence.
