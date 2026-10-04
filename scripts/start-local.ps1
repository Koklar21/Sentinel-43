# =============================================================================
# Sentinel-43 — canonical local Compose startup
#
# Responsibilities:
#   - create .env from .env.example on first local startup
#   - generate missing deployment secrets before Compose is evaluated
#   - preserve existing valid secrets on ordinary restarts
#   - derive DATABASE_URL from POSTGRES_PASSWORD
#   - enforce the local-only runtime settings used by the Compose stack
#   - reject duplicate .env keys before startup
#   - validate secrets and Compose interpolation before starting containers
#
# Secret rotation is deliberately NOT part of ordinary startup. Use the
# generator's explicit --force mode when an intentional rotation is required.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$Build
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EnvPath = Join-Path $RepoRoot ".env"
$EnvExamplePath = Join-Path $RepoRoot ".env.example"
$GeneratorPath = Join-Path $RepoRoot "core\scripts\generate_secrets.py"
$CanonicalLocalOrigins = "https://localhost,https://127.0.0.1,http://localhost:5500,http://127.0.0.1:5500,http://localhost:8000,http://127.0.0.1:8000"

function Get-PythonCommand {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return $python.Source
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return $py.Source
    }

    throw "Python was not found on PATH."
}

function Read-Env {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $values = @{}
    $duplicates = @()

    foreach ($line in Get-Content $Path) {
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            continue
        }

        $key = $matches[1]
        $value = $matches[2]

        if ($values.ContainsKey($key)) {
            $duplicates += $key
            continue
        }

        $values[$key] = $value
    }

    if ($duplicates.Count -gt 0) {
        $names = ($duplicates | Sort-Object -Unique) -join ", "
        throw "Duplicate .env key(s) detected: $names"
    }

    return $values
}

function Set-EnvValue {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$Lines,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [AllowEmptyString()]
        [string]$Value
    )

    $pattern = '^\s*' + [regex]::Escape($Key) + '='
    $found = $false

    for ($index = 0; $index -lt $Lines.Count; $index++) {
        if ($Lines[$index] -match $pattern) {
            if ($found) {
                throw "Duplicate .env key detected while updating: $Key"
            }

            $Lines[$index] = "$Key=$Value"
            $found = $true
        }
    }

    if (-not $found) {
        if ($Lines.Count -gt 0 -and $Lines[$Lines.Count - 1] -ne "") {
            $Lines.Add("")
        }

        $Lines.Add("$Key=$Value")
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$Lines
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $text = ($Lines -join [Environment]::NewLine).TrimEnd() + [Environment]::NewLine
    [System.IO.File]::WriteAllText($Path, $text, $encoding)
}

if (-not (Test-Path $EnvExamplePath)) {
    throw ".env.example was not found at $EnvExamplePath"
}

if (-not (Test-Path $GeneratorPath)) {
    throw "Secret generator was not found at $GeneratorPath"
}

$python = Get-PythonCommand
$createdEnv = $false

Push-Location $RepoRoot

try {
    if (-not (Test-Path $EnvPath)) {
        Copy-Item $EnvExamplePath $EnvPath
        $createdEnv = $true
        Write-Host "Created .env from .env.example."
    }
    else {
        # Fail before changing anything if the existing file already contains
        # ambiguous duplicate assignments.
        [void](Read-Env -Path $EnvPath)
    }

    if ($createdEnv) {
        # The fresh template intentionally contains CHANGE_ME placeholders.
        # This one-time generation replaces them with real secrets.
        & $python $GeneratorPath --write $EnvPath --force
    }
    else {
        # Ordinary startup never rotates credentials. Missing managed secrets
        # may be added, but existing values are preserved.
        & $python $GeneratorPath --write $EnvPath
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Secret generation failed with exit code $LASTEXITCODE."
    }

    $envValues = Read-Env -Path $EnvPath
    $postgresPassword = $envValues["POSTGRES_PASSWORD"]

    if (
        [string]::IsNullOrWhiteSpace($postgresPassword) -or
        $postgresPassword -in @("CHANGE_ME", "CHANGEME", "replace-me")
    ) {
        throw "POSTGRES_PASSWORD is missing or still a placeholder."
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content $EnvPath) {
        $lines.Add($line)
    }

    # Canonical local-only runtime posture.
    Set-EnvValue $lines "SENTINEL_ENV" "development"
    Set-EnvValue $lines "S43_ENV" "development"
    Set-EnvValue $lines "S43_RUNTIME_PLATFORM" "compose"
    Set-EnvValue $lines "S43_RUNTIME_ROLE" "api"
    Set-EnvValue $lines "S43_INSTANCE_ID" "s43-api"

    # Canonical authentication / browser posture for the local HTTPS proxy.
    Set-EnvValue $lines "S43_REJECT_LEGACY_AUTH" "true"
    Set-EnvValue $lines "S43_WS_REQUIRE_AUTH" "true"
    Set-EnvValue $lines "S43_ALLOWED_ORIGINS" $CanonicalLocalOrigins
    Set-EnvValue $lines "S43_TLS_TERMINATED_AT_TRUSTED_EDGE" "false"

    # Local startup keeps authority features explicit and subordinate.
    Set-EnvValue $lines "S43_GOVERNANCE_ENABLED" "false"
    Set-EnvValue $lines "S43_GOVERNANCE_REQUIRED" "true"
    Set-EnvValue $lines "S43_HEART_ENABLED" "false"

    # Detection remains active locally while optional external sensors stay
    # opt-in through their own configuration.
    Set-EnvValue $lines "S43_FENRIR_ENABLED" "true"
    Set-EnvValue $lines "S43_FENRIR_NODE_ID" "sentinel-43-primary"
    Set-EnvValue $lines "S43_FENRIR_MIN_SEVERITY" "MEDIUM"

    # DATABASE_URL is derived every startup so it cannot drift from the
    # generated PostgreSQL password.
    Set-EnvValue $lines "DATABASE_URL" "postgresql+asyncpg://s43:$postgresPassword@s43-db:5432/s43"

    Write-Utf8NoBom -Path $EnvPath -Lines $lines

    # Re-read after normalization to catch accidental duplicates immediately.
    [void](Read-Env -Path $EnvPath)

    & $python $GeneratorPath --check $EnvPath
    if ($LASTEXITCODE -ne 0) {
        throw "Secret validation failed. Existing invalid secrets were preserved rather than silently rotated."
    }

    docker compose config --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose configuration validation failed."
    }

    # Validate the effective Compose value, not only the .env text. Shell
    # variables outrank .env during interpolation, so a stale exported value
    # must be caught before containers start and strand the HTTPS dashboard.
    $composeConfigJson = docker compose config --format json
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose rendered configuration inspection failed."
    }

    $composeConfig = $composeConfigJson | ConvertFrom-Json
    $effectiveOrigins = $composeConfig.services.'s43-api'.environment.S43_ALLOWED_ORIGINS
    if ([string]::IsNullOrWhiteSpace($effectiveOrigins)) {
        throw "Rendered Compose configuration is missing S43_ALLOWED_ORIGINS for s43-api."
    }

    $effectiveOriginSet = @(
        $effectiveOrigins -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    )

    $requiredDashboardOrigins = @(
        "https://localhost",
        "https://127.0.0.1"
    )
    $missingDashboardOrigins = @(
        $requiredDashboardOrigins |
            Where-Object { $_ -notin $effectiveOriginSet }
    )

    if ($missingDashboardOrigins.Count -gt 0) {
        $missing = $missingDashboardOrigins -join ", "
        throw (
            "Local dashboard origin contract failed. Effective Compose " +
            "S43_ALLOWED_ORIGINS is missing: $missing. Remove stale shell " +
            "overrides and run this launcher again."
        )
    }

    if ($Build) {
        docker compose build
        if ($LASTEXITCODE -ne 0) {
            throw "Docker Compose build failed."
        }
    }

    docker compose up -d
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose startup failed."
    }

    docker compose ps
}
finally {
    Pop-Location
}
