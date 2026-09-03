# =============================================================================
# Sentinel-43 -- generate a SELF-SIGNED cert for LOCAL beta testing only.
# Writes deploy/proxy/certs/s43.{crt,key} (gitignored). NOT for any real
# deployment. See deploy/proxy/README.md.
#
# Usage:  .\deploy\proxy\generate-dev-cert.ps1 [-Hostname localhost]
# Requires OpenSSL on PATH (ships with Git for Windows).
# =============================================================================
param([string]$Hostname = "localhost")

$ErrorActionPreference = "Stop"
$dir = Join-Path $PSScriptRoot "certs"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

& openssl req -x509 -newkey rsa:2048 -nodes `
    -keyout (Join-Path $dir "s43.key") -out (Join-Path $dir "s43.crt") `
    -days 365 -subj "/CN=$Hostname" `
    -addext "subjectAltName=DNS:$Hostname,DNS:localhost,IP:127.0.0.1"

Write-Host "wrote $dir\s43.crt and $dir\s43.key (self-signed, CN=$Hostname, 365d)"
