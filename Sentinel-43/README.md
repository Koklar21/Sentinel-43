# Sentinel-43/ — historical design prototypes (NOT the runtime)

This directory is **preserved deliberately** as historical design material. It is
**not** a runtime package, **not** a supported entrypoint, and **not** part of the
Sentinel-43 application image (it is excluded by the repository `.dockerignore`).

## Status

- The Python files here are earlier Heart / Shadow / escalation prototypes. They are
  kept unchanged so the project's design history is not lost.
- Some of them contain `ACTIVE` / `AUTONOMOUS_VETO`-style behavior. That behavior is
  **prohibited from the live Sentinel-43 runtime**. Sentinel-43 is advisory-first,
  human-governed, fail-closed, and incapable of autonomous enforcement; the only
  governance modes in the live system are `SHADOW` and `HUMAN_GATED`.
- Nothing under `core/`, no Dockerfile, Compose file, Kubernetes manifest, workflow or
  script imports or launches these files. Keep it that way.

## What is supported instead

- Live Heart: `core/governance/heart.py`.
- Canonical human approval / veto path: the operator-authenticated action routes in
  `core/api/main.py`, backed by the audited action store.

## Rules for this directory

- Do not delete, rename, rewrite, modernize, import, or execute these files.
- No file here may be wired into the runtime without a written impact analysis,
  explicit owner authorization, and a separate security review.
