#!/usr/bin/env bash
# =============================================================================
# Sentinel-43 -- generate a test CA + leaf certificate for the browser SPA
# smoke stack (next-PR Phase C).
#
# Writes (all gitignored):
#   ca.crt / ca.key            -- the throwaway test CA
#   s43.crt / s43.key          -- leaf for CN=s43.beta.test (+ SAN localhost, 127.0.0.1)
#   s43.fullchain.crt          -- leaf + CA, mounted into nginx
#   spki.txt                   -- base64(SHA-256(SubjectPublicKeyInfo)) of the leaf,
#                                 passed to Chromium via
#                                 --ignore-certificate-errors-spki-list so the
#                                 browser trusts THIS cert only -- not a blanket
#                                 --ignore-certificate-errors.
#
# This proves the browser <-> nginx TLS integration. It does NOT close F-TLS-1:
# that needs the real target hostname + a CA the intended clients already trust.
# =============================================================================
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "${BASH_SOURCE[0]}")"
HOST="${1:-s43.beta.test}"

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 \
    -subj "/CN=Sentinel-43 Browser Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

openssl req -newkey rsa:2048 -nodes -keyout s43.key -out s43.csr -subj "/CN=$HOST"
cat > s43.ext <<EXT
subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in s43.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out s43.crt -days 365 -extfile s43.ext

# nginx serves the leaf + CA as one file. docker-compose.browser.yml mounts
# this whole directory at /etc/nginx/certs (replacing the base dir mount),
# and nginx.conf reads /etc/nginx/certs/s43.crt + /etc/nginx/certs/s43.key.
mv s43.crt s43.leaf.crt
cat s43.leaf.crt ca.crt > s43.crt
cp s43.crt s43.fullchain.crt

SPKI=$(openssl x509 -in s43.leaf.crt -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | openssl enc -base64)
printf 'SPKI_SHA256_BASE64=%s\n' "$SPKI" > spki.txt

openssl verify -CAfile ca.crt s43.leaf.crt
echo "wrote ca.crt s43.crt (leaf+CA) s43.key spki.txt (host=$HOST, 365d)"
echo "SPKI pin: $SPKI"
