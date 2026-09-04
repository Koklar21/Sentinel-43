#!/usr/bin/env bash
# =============================================================================
# Sentinel-43 -- browser TARGET-ACCEPTANCE runner.
#
#   S43_TARGET_BASE_URL=https://beta.example.org ./browser_tests/run_target.sh
#
# Runs the shipped SPA against a REAL deployed target over ordinary trusted-CA
# HTTPS. This runner NEVER builds, starts, stops, scales, or `down -v`s a
# Compose stack, and never bootstraps an admin.
#
# Read-only edge checks (browser_tests/target_acceptance/test_target_readonly.py) run with
# just the base URL. Authenticated acceptance needs a designated beta test
# account supplied through a credentials file -- missing creds is an ERRORED
# (incomplete) run, never a green skip:
#
#   S43_TARGET_OPERATOR_CRED_FILE=/path/op.json          # {"username","password"}
#   S43_TARGET_CA_BUNDLE=/path/ca.pem                    # optional approved private CA
#   # admin-mutation scenarios (opt-in, dedicated throwaway accounts only):
#   S43_TARGET_ADMIN_SCOPE=explicit-dedicated-account
#   S43_TARGET_ADMIN_CRED_FILE=/path/admin.json
#   S43_TARGET_MUTATION_OPERATOR_CRED_FILE=/path/mut-op.json
#
# Prereq: the .venv-browser from requirements-browser.txt (see run.sh).
# =============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${S43_TARGET_BASE_URL:?set S43_TARGET_BASE_URL=https://<beta-fqdn> (a real, deployed target)}"
case "$S43_TARGET_BASE_URL" in
    https://*) ;;
    *) echo "S43_TARGET_BASE_URL must be an https:// URL" >&2; exit 2 ;;
esac

PY=${S43_BROWSER_PYTHON:-.venv-browser/Scripts/python.exe}
[ -x "$PY" ] || PY=.venv-browser/bin/python

echo "== target acceptance against ${S43_TARGET_BASE_URL} (no stack is started) =="
# -rA so an ERRORED (missing-credential) suite is loud rather than a quiet skip.
exec "$PY" -m pytest browser_tests/target_acceptance/ -q -p no:cacheprovider -rA "$@"
