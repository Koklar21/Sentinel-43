# Sentinel-43

**Sentinel-43 is a human-gated defensive cybersecurity oversight platform.**

It watches security activity, turns observations into structured threat context and recommendations, routes those recommendations through governance, and preserves an auditable record of what happened and why.

Sentinel-43 is designed around one rule:

> **Deterministic. Advisory. Never Autonomous.**

The system can analyze and recommend. A human remains the final authority for operational decisions.

> **Current status:** Controlled Beta Candidate. Repository-level source blockers for controlled beta are closed. A specific deployment becomes an accepted controlled-beta target only after the evidence gates in the [Beta Runbook](docs/BETA_RUNBOOK.md) pass. Production readiness is not established.

For controlled-beta deployment requirements, use the authoritative [Beta Runbook](docs/BETA_RUNBOOK.md).

---

## What Sentinel-43 Does

Sentinel-43 brings several defensive functions into one governed workflow:

- receives and normalizes security observations
- detects and correlates suspicious activity
- builds threat context and supporting evidence
- produces deterministic recommendations
- routes recommendations through human governance
- tracks pending, approved, vetoed, expired, and staged decisions
- records significant security and governance activity in an audit trail
- exposes live operational state through an authenticated dashboard
- monitors its own runtime health and supporting services

The result is not a machine that decides what to do on its own. It is a system that helps an operator understand **what happened, why it matters, what could be done, and who authorized the next step**.

---

## How It Works

The normal Sentinel-43 flow is:

```text
Observe
  ↓
Detect / Analyze
  ↓
Correlate Evidence
  ↓
Generate Recommendation
  ↓
Human Governance
  ↓
Approved External Integration
  ↓
Audit
```

Analysis, governance, and enforcement are deliberately separate.

The live runtime supports two governance modes:

| Mode | Purpose |
| --- | --- |
| `SHADOW` | Observe, analyze, recommend, and record without approving operational action. |
| `HUMAN_GATED` | Require an authenticated human decision before a recommendation can proceed through the governed workflow. |

Autonomous enforcement modes are not part of the live Sentinel-43 runtime.

---

## Main Components

### Sentinel-43 Runtime Authority

`Sentinel43RuntimeAuthority` is the single top-level runtime authority.

It owns the governed composition of the system and keeps subordinate components from becoming independent control planes.

The owner-designated runtime sources are under `Sentinel-43/`:

- `Shadow_mode.py` — response/recommendation engine
- `Sentinel_Nexus.py` — governed integration and recommendation boundary
- `Sentinel_core.py` — node/runtime reporting contract
- `sentinel_AI_escalation.py` — threat-evidence and escalation contract

### Fenrir

Fenrir is the threat-hunting and behavioral-analysis layer.

It helps answer:

> **Does this activity deserve attention?**

Fenrir produces evidence and threat observations. It does not own governance or enforcement.

### Heart

Heart manages governed recommendation lifecycle and recovery state.

It stages and resolves recommendations through the runtime authority rather than bypassing it.

### Watchtower

Watchtower provides system-health and oversight signals.

It helps answer:

> **Is Sentinel-43 itself operating correctly?**

### Sparta

Sparta monitors selected integrity and runtime conditions and reports them into the governed system.

### Audit

The audit layer preserves authoritative security and governance records with integrity checking.

It is intended to answer:

> **What happened, when, why, and under whose authority?**

### Dashboard

The authenticated web dashboard is the operator-facing control and visibility surface.

It provides access to:

- system and subsystem health
- threat and monitoring information
- governance state
- pending actions
- audit information
- runtime provenance
- administrator account management
- first-administrator onboarding
- live WebSocket updates

The dashboard consumes the same governed API boundaries as other clients. It does not create its own authority.

---

## Human Authority

Human authority is a hard design boundary, not a presentation preference.

Sentinel-43 may:

- analyze
- classify
- recommend
- explain
- stage a decision
- record a decision

Sentinel-43 does not grant its advisory core unrestricted autonomous authority to modify infrastructure, quarantine systems, suspend accounts, alter firewall policy, or perform other external enforcement.

External effects must remain explicitly integrated and independently governed.

---

## Authentication and Administration

Sentinel-43 distinguishes human identities from service identities.

Human accounts use a deliberately narrow authority model:

- the one-time bootstrap claim creates the deployment's **sole administrator**
- every later human account is an **observer**
- observers may review staged actions and submit human approve/veto decisions
- only the sole administrator may create/disable observer accounts or reset their passwords
- administrator role is not promotable, demotable, or transferable through normal account-management APIs
- authenticated sessions, refresh rotation, logout/revocation, and password reset remain governed

Internal services use separate service credentials and cannot silently become human approvers.

### First Administrator

An empty deployment supports a one-time first-administrator claim. That claim is the only normal path that creates an administrator account. The database also enforces at most one administrator row; initialized deployments are expected to retain exactly one.

Outside local/dev/test, that claim must be authorized with the deployment-owned `S43_BOOTSTRAP_CLAIM_TOKEN`.

After the first account exists, normal account-management rules apply.

Emergency administrator recovery is intentionally an exec-only deployment operation rather than a privileged network endpoint. See [Beta Runbook §16a](docs/BETA_RUNBOOK.md) for the current procedure.

---

## Running Sentinel-43

Sentinel-43 supports Docker Compose for local and controlled-beta work, with Kubernetes manifests available for controlled deployment validation.

### Configuration

Start from the example environment file:

```bash
cp .env.example .env
```

Generate real secrets with the repository's secret-generation tool rather than reusing example values.

Do not commit your real `.env`, credentials, certificates, or generated secrets.

### Docker Compose

The base stack is defined in:

- `docker-compose.yml`
- `docker-compose.beta.yml` for controlled-beta overrides

For the controlled-beta Compose procedure, secret requirements, migration order, health checks, and verification steps, follow [docs/BETA_RUNBOOK.md](docs/BETA_RUNBOOK.md).

### Kubernetes

Kubernetes manifests live under:

```text
deploy/kubernetes/
```

They include base resources plus development and beta overlays.

The beta overlay intentionally ships with invalid placeholder deployment values for items that must be supplied by the operator, including real registry/image information and environment-specific network/TLS configuration.

See [deploy/kubernetes/README.md](deploy/kubernetes/README.md).

---

## Dashboard

When the API is running, the served dashboard is:

```text
dashboard/sentinel_43_dashboard.html
```

with its live assets under:

```text
dashboard/assets/
```

The API serves this SPA directly.

The previous unused Python dashboard scaffold has been removed so there is now one dashboard implementation in the repository.

---

## Repository Layout

```text
Sentinel-43/                 owner-designated runtime sources
core/                        API, governance, detection, audit, auth, monitoring
dashboard/                   live HTML/CSS/JavaScript operator dashboard
browser_tests/               real-browser SPA acceptance coverage
deploy/kubernetes/           Kubernetes base and overlays
migrations/                  database migrations
scripts/                     deployment, acceptance, and operational tooling
docs/                        operator, security, and beta documentation
docs/reconstruction/         historical reconstruction/verification records
```

Historical reconstruction documents are retained for provenance. They are not the current source of truth for runtime capability or beta readiness.

---

## Security Model

Sentinel-43 is designed around several recurring security rules:

- fail closed when security-critical configuration is invalid or missing
- keep human and machine identities separate
- keep analysis separate from enforcement
- keep one top-level runtime authority
- require explicit authorization for administrative operations
- preserve authoritative audit records
- avoid exposing internal services unnecessarily
- trust forwarded network identity only through configured trusted proxies
- keep credentials out of URLs, logs, and source control
- use HTTPS/WSS for non-local browser deployments

The current security and deployment requirements are documented in the [Beta Runbook](docs/BETA_RUNBOOK.md), not duplicated here line by line.

---

## Deployment Status

Sentinel-43 is currently a **Controlled Beta Candidate**.

The repository-level beta-closure work is complete: the runtime authority is consolidated, human and service identities are separated, session authentication and administrator recovery are closed, audit/readiness behavior is wired, the real dashboard is the only operator UI, deployment definitions are present, and live verification tooling exists for endpoint, browser, and endurance checks.

This status does **not** declare every deployment a controlled beta automatically. A specific target must still produce the required deployment evidence, including its real TLS/hostname and trusted-proxy posture, target browser/WSS acceptance, the strict `final-beta` acceptance verdict, and any deployment-path prerequisites in the [Beta Runbook](docs/BETA_RUNBOOK.md).

Production and public-sector readiness remain separate tiers and are not established by beta closure.

---

## What Sentinel-43 Is Not

Sentinel-43 is not:

- an autonomous attack platform
- an offensive-security framework
- an unrestricted self-directed response engine
- a hidden enforcement system
- a substitute for human operational authority

It is a defensive oversight, analysis, governance, and audit platform.

---

## Documentation

Useful starting points:

- [Controlled Beta Runbook](docs/BETA_RUNBOOK.md)
- [Kubernetes Deployment Guide](deploy/kubernetes/README.md)
- [Trusted Proxy Handling](docs/security/trusted_proxy_handling.md)
- [Owner Runtime Sources](Sentinel-43/README.md)
- [Historical Reconstruction Records](docs/reconstruction/)

---

## Licensing

Sentinel-43 is dual-licensed:

1. **AGPL-3.0-or-later**
2. **Commercial license**

See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) for the authoritative terms.

---

## Disclaimer

Sentinel-43 is currently Controlled Beta Candidate software.

It is provided **AS IS**, without warranty of any kind. Interfaces, deployment behavior, and internal implementation may still change during controlled-beta validation.

Use it only on systems and environments you own or are explicitly authorized to operate.
