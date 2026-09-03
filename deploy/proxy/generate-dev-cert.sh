#!/usr/bin/env bash
# =============================================================================
# Sentinel-43 -- generate a SELF-SIGNED cert for LOCAL beta testing only.
#
# Writes deploy/proxy/certs/s43.{crt,key} (gitignored). NOT for any real
# deployment -- browsers will warn, and it does not prove certificate
# issuance/renewal. See deploy/proxy/README.md.
#
# Usage:  ./deploy/proxy/generate-dev-cert.sh [hostname]   (default: localhost)
# =============================================================================
set -euo pipefail

# Git Bash / MSYS mangles the openssl "/CN=..." argument into a Windows path.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

HOST="${1:-localhost}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$DIR"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/s43.key" -out "$DIR/s43.crt" \
    -days 365 -subj "/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1"

chmod 600 "$DIR/s43.key"
echo "wrote $DIR/s43.crt and $DIR/s43.key (self-signed, CN=$HOST, 365d)"
