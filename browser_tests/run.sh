#!/usr/bin/env bash
# =============================================================================
# Sentinel-43 -- browser SPA smoke: bring up an isolated HTTPS stack, run the
# Playwright tests against the real served SPA, tear the stack down.
#
#   ./browser_tests/run.sh
#
# Prereqs: docker + compose; a browser venv with playwright + chromium:
#   python -m venv .venv-browser
#   .venv-browser/Scripts/python -m pip install -r requirements-browser.txt
#   .venv-browser/Scripts/python -m playwright install chromium
#
# Nothing here touches the user's own stack: the project is `s43browser`,
# every container is renamed, and the proxy is on 127.0.0.1:8443/8081.
# This is the DISPOSABLE runner. It always builds and tears down its own
# isolated s43browser stack on https://s43.beta.test:8443. To run the browser
# suite against a REAL deployed target, use browser_tests/run_target.sh --
# that one never touches a Compose stack. Refuse a stray S43_BROWSER_BASE_URL
# so nobody thinks this runner is hitting their target.
# =============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -n "${S43_BROWSER_BASE_URL:-}" ] && \
   [ "${S43_BROWSER_BASE_URL}" != "https://s43.beta.test:8443" ]; then
    echo "run.sh is the disposable runner and only serves https://s43.beta.test:8443." >&2
    echo "For a real target: browser_tests/run_target.sh  (S43_TARGET_BASE_URL=https://<fqdn>)" >&2
    exit 2
fi

PROJECT=s43browser
ENV_FILE=.env.browser
COMPOSE=(docker compose -p "$PROJECT" --env-file "$ENV_FILE"
         -f docker-compose.yml -f docker-compose.browser.yml)
PY=${S43_BROWSER_PYTHON:-.venv-browser/Scripts/python.exe}
[ -x "$PY" ] || PY=.venv-browser/bin/python

cleanup() {
    if [ -n "${S43_BROWSER_KEEP:-}" ]; then
        echo "S43_BROWSER_KEEP set -- leaving the s43browser stack up. Tear down with:"
        echo "  ${COMPOSE[*]} down -v"
        return
    fi
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- test CA + leaf (gitignored) ---
[ -f browser_tests/certs/s43.fullchain.crt ] || bash browser_tests/certs/generate-test-ca.sh

# --- runtime image, built once and reused for hash generation below ---
# core.auth.users.hash_password (needed to mint the stack's operator
# credential) pulls in sqlalchemy and the rest of the runtime's dependency
# graph, not just argon2 -- "install the one missing package" turns out not
# to be minimal at all. Building the real image and running the helper
# inside a throwaway container from it needs nothing extra in
# .venv-browser, and computes the hash with the exact same code/environment
# that will later verify it -- the same pattern
# scripts/ci_live_tests.py already uses for its own break-glass hash.
HASH_HELPER_IMAGE=s43browser-hash-helper
docker build -q -t "$HASH_HELPER_IMAGE" -f core/api/Dockerfile . >/dev/null

# --- fresh disposable secrets for this stack only ---
rm -f "$ENV_FILE"
PYTHONPATH=. "$PY" core/scripts/generate_secrets.py --write "$ENV_FILE" >/dev/null
PGPW=$(grep '^POSTGRES_PASSWORD=' "$ENV_FILE" | cut -d= -f2)
cat >> "$ENV_FILE" <<EOF

# --- browser-smoke stack (browser_tests/run.sh) ---
SENTINEL_ENV=beta
DATABASE_URL=postgresql+asyncpg://s43:${PGPW}@s43-db:5432/s43
S43_JWT_ALGORITHM=HS256
S43_JWT_ISSUER=sentinel-43
S43_JWT_AUDIENCE=sentinel-43-dashboard
S43_OPERATOR_USERNAME=browser-envop-unused
# Compose interpolates \$VAR / \${VAR} when it reads an --env-file, so every
# literal \$ in the Argon2id hash must be doubled to \$\$ -- otherwise
# "\$argon2id\$v=19\$m=..." is parsed as a run of undefined variable
# references and the container starts with a mangled, non-Argon2id value
# confirmed via "docker compose config" while fixing this -- and backticks
# in THIS comment must never come back: they are live command substitution
# inside an unquoted heredoc (bash does not treat "#" as a comment marker
# there), so a backtick-quoted command here previously executed for real
# and spliced its stdout into the generated secrets file. That is what
# actually produced the original hosted failure's "S43_SESSION_HASH_PEPPER
# is missing" / "POSTGRES_PASSWORD ... defaulting to a blank string" --
# both were real warnings from a "docker compose config" invoked here,
# against the .env.browser file as it existed mid-construction, not from
# the real "docker compose up" that ran afterward.
S43_OPERATOR_PASSWORD_HASH=$(docker run --rm "$HASH_HELPER_IMAGE" python -c "
import secrets
from core.auth.users import hash_password
print(hash_password(secrets.token_urlsafe(32)).replace('\$', '\$\$'))
")
S43_WS_REQUIRE_AUTH=true
# Genuinely true here, not a CI-only assertion of convenience: s43-proxy
# (nginx, docker-compose.browser.yml) really does terminate HTTPS/WSS with
# the throwaway test CA's cert before forwarding to s43-api -- the whole
# point of this stack is testing that real edge. core/api/main.py's
# _validate_security_config() added this requirement within the same PR
# that added the browser stack's own S43_TRUSTED_PROXIES pin to the proxy's
# address, without this stack ever picking it up.
S43_TLS_TERMINATED_AT_TRUSTED_EDGE=true
S43_ALLOWED_ORIGINS=https://s43.beta.test:8443
S43_TRUSTED_HOSTS=s43.beta.test
S43_ENABLE_TEST_INJECTION=false
S43_FENRIR_ENABLED=false
SENTINEL_FENRIR_ENABLED=false
FENRIR_ENABLED=false
S43_WS_SESSION_RECHECK_SECONDS=10
EOF

echo "== building + starting the s43browser stack =="
"${COMPOSE[@]}" up -d --build

echo "== running browser tests =="
if [ -n "${S43_ACCEPTANCE_OUT:-}" ]; then
    # Acceptance run: the ONE canonical execution path is the gate's run-job, which
    # builds the pytest command from acceptance/suites.json (recorder plugin, report
    # path, job identity) and writes <out>/jobs/browser-disposable.{results,meta}.json
    # from the real execution. Extra pytest args would change what is being accepted.
    if [ "$#" -ne 0 ]; then
        echo "S43_ACCEPTANCE_OUT is set: extra pytest arguments are not allowed (they would narrow the accepted run)." >&2
        exit 2
    fi
    S43_BROWSER_PYTHON="$PY" S43_BROWSER_BASE_URL="https://s43.beta.test:8443" \
      "$PY" scripts/acceptance_gate.py run-job browser-disposable --out "$S43_ACCEPTANCE_OUT"
else
    # Developer run (no evidence recorded).
    # target/ is the real-target acceptance suite -- never part of the disposable run.
    S43_BROWSER_BASE_URL="https://s43.beta.test:8443" \
      "$PY" -m pytest browser_tests/ --ignore=browser_tests/target_acceptance \
      -q -p no:cacheprovider "$@"
fi
