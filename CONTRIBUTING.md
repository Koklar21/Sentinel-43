# Contributing to Sentinel-43

Thank you for helping improve Sentinel-43.

## Licensing of Contributions

Sentinel-43 is dual-licensed under:

- AGPL-3.0-or-later; or
- the Sentinel-43 Commercial License in `COMMERCIAL_LICENSE.md`.

Unless a separate written agreement with the repository owner says otherwise, by submitting a contribution you represent that you have the right to submit it and agree that your contribution may be distributed as part of Sentinel-43 under the project's existing dual-license model:

`AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial`

Do not submit third-party code unless its license is compatible with the project and its required copyright, attribution, and license notices are preserved.

## Security Findings

Do not put credentials, secrets, personal data, packet captures containing sensitive data, or working exploitation details for serious vulnerabilities into a public issue or pull request. Follow `SECURITY.md` instead.

## Architectural Boundary

Contributions must preserve the project's human-gated authority model. Telemetry and detection components produce evidence and recommendations; they do not gain independent governance or enforcement authority.

## Review

Keep changes scoped and explain the behavior being changed, the reason for the change, and the validation performed. Documentation must describe reachable behavior rather than aspirational behavior.
