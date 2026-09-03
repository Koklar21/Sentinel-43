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
# =============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

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
S43_OPERATOR_PASSWORD_HASH=$(printf 'disabled-%s' "$RANDOM$RANDOM" | sha256sum | cut -d' ' -f1)
S43_WS_REQUIRE_AUTH=true
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
S43_BROWSER_BASE_URL="https://s43.beta.test:8443" \
  "$PY" -m pytest browser_tests/ -q -p no:cacheprovider "$@"
