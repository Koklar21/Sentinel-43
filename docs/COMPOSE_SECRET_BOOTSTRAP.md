# Compose secret bootstrap entrypoint

Use `python scripts/compose_bootstrap.py` from Windows, Linux, or macOS to
provision the local `.env` file **without starting Docker**. On first install,
it generates deployment secrets and a matching PostgreSQL `DATABASE_URL`.
On an existing installation, it preserves the database password and all
existing managed secret values, adding only missing managed keys.

To start Compose explicitly after provisioning:

```shell
python scripts/compose_bootstrap.py --start
```

For controlled beta, use `--beta --start`. This only selects the beta
override; it does **not** replace the controlled-beta runbook, required TLS,
image identity, or deployment preflight checks.

Existing installations must already have a matching `POSTGRES_PASSWORD`
and `DATABASE_URL`. The entrypoint refuses missing or conflicting database
configuration instead of attempting a destructive database password reset.
Existing placeholder or invalid managed secrets are also rejected rather
than silently rotated. Use the documented coordinated rotation procedure
when rotation is actually intended.

Do not commit `.env`, copy it into an image, or paste its values into logs.
The command does not create a human administrator: first-run administrator
creation remains inside the existing governed application bootstrap flow.

The entrypoint is a convenience launcher, not a Docker daemon hook. Direct
`docker compose up` still bypasses provisioning and depends on existing
Compose/runtime secret validation. Operators should use the entrypoint for
fresh installations. No Docker or test execution was performed as part of
this change.
