# =============================================================================
# Sentinel-43 — local router telemetry control
#
# VS Code / PowerShell-friendly wrapper for configuring and running the
# host-side router syslog collector. The router is evidence-only; this script
# does not grant it governance or enforcement authority.
# =============================================================================

[CmdletBinding()]
param(
    [ValidateSet("Configure", "Listen", "Test", "Status", "Disable")]
    [string]$Mode = "Status",

    [string]$RouterIp = "",

    [ValidateRange(1, 65535)]
    [int]$SyslogPort = 5514,

    [ValidateRange(1, 1000)]
    [int]$MaxEventsPerSecond = 50,

    [string]$ListenAddress = "0.0.0.0",

    [string]$ApiUrl = "https://localhost/internal/router/events",

    [string]$CaCert = "deploy/proxy/certs/s43.crt",

    [switch]$RegenerateToken,

    [switch]$OpenWindowsFirewall,

    [switch]$NoRestart
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EnvPath = Join-Path $RepoRoot ".env"
$CollectorPath = Join-Path $RepoRoot "scripts\router_syslog_collector.py"

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
    param([Parameter(Mandatory = $true)][string]$Path)

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
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$Lines
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    $text = ($Lines -join [Environment]::NewLine).TrimEnd() + [Environment]::NewLine
    [System.IO.File]::WriteAllText($Path, $text, $encoding)
}

function New-RouterToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }

    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Test-IpAddress {
    param([Parameter(Mandatory = $true)][string]$Value)

    $parsed = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$parsed)
}

function Get-EnvLines {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content $EnvPath) {
        $lines.Add($line)
    }
    return $lines
}

function Clear-RouterShellOverrides {
    foreach ($key in @(
        "S43_ROUTER_ENABLED",
        "S43_ROUTER_INGEST_TOKEN",
        "S43_ROUTER_SOURCE_IP"
    )) {
        Remove-Item "Env:$key" -ErrorAction SilentlyContinue
    }
}

function Set-RouterFirewallRule {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$Port
    )

    if (-not $OpenWindowsFirewall) {
        return
    }

    if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
        throw "Windows Firewall cmdlets are unavailable on this host."
    }

    $ruleName = "Sentinel-43 Router Syslog"
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol UDP `
        -LocalPort $Port `
        -RemoteAddress $RemoteAddress `
        -Profile Any | Out-Null

    Write-Host "Windows Firewall rule '$ruleName' allows UDP $Port only from $RemoteAddress."
}

function Restart-RouterIngress {
    if ($NoRestart) {
        Write-Host "Router settings saved; s43-api was not recreated because -NoRestart was supplied."
        return
    }

    Clear-RouterShellOverrides

    Push-Location $RepoRoot
    try {
        docker compose --env-file $EnvPath config --quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Docker Compose configuration validation failed."
        }

        docker compose --env-file $EnvPath up -d --force-recreate s43-api
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to recreate s43-api with router telemetry settings."
        }
    }
    finally {
        Pop-Location
    }
}

function Show-Status {
    $values = Read-Env -Path $EnvPath
    $token = [string]$values["S43_ROUTER_INGEST_TOKEN"]
    $tokenState = if ($token.Length -ge 32) { "configured" } else { "missing" }

    Write-Host "Sentinel-43 router telemetry"
    Write-Host "  enabled:      $($values['S43_ROUTER_ENABLED'])"
    Write-Host "  router ip:    $($values['S43_ROUTER_SOURCE_IP'])"
    Write-Host "  listen:       $($values['S43_ROUTER_LISTEN_ADDRESS']):$($values['S43_ROUTER_SYSLOG_PORT'])/udp"
    Write-Host "  max events/s: $($values['S43_ROUTER_MAX_EVENTS_PER_SECOND'])"
    Write-Host "  api url:      $($values['S43_ROUTER_API_URL'])"
    Write-Host "  ca cert:      $($values['S43_ROUTER_CA_CERT'])"
    Write-Host "  token:        $tokenState"
}

if (-not (Test-Path $EnvPath)) {
    throw ".env was not found. Run .\scripts\start-local.ps1 first."
}

if (-not (Test-Path $CollectorPath)) {
    throw "Router collector was not found at $CollectorPath"
}

$python = Get-PythonCommand

switch ($Mode) {
    "Configure" {
        $current = Read-Env -Path $EnvPath
        $effectiveRouterIp = if ($RouterIp) {
            $RouterIp
        }
        else {
            [string]$current["S43_ROUTER_SOURCE_IP"]
        }

        if (-not $effectiveRouterIp -or -not (Test-IpAddress -Value $effectiveRouterIp)) {
            throw "Configure requires a valid -RouterIp."
        }

        $token = [string]$current["S43_ROUTER_INGEST_TOKEN"]
        if (
            $RegenerateToken -or
            [string]::IsNullOrWhiteSpace($token) -or
            $token -in @("CHANGE_ME", "CHANGEME", "replace-me") -or
            $token.Length -lt 32
        ) {
            $token = New-RouterToken
        }

        $lines = Get-EnvLines
        Set-EnvValue $lines "S43_ROUTER_ENABLED" "true"
        Set-EnvValue $lines "S43_ROUTER_INGEST_TOKEN" $token
        Set-EnvValue $lines "S43_ROUTER_SOURCE_IP" $effectiveRouterIp
        Set-EnvValue $lines "S43_ROUTER_LISTEN_ADDRESS" $ListenAddress
        Set-EnvValue $lines "S43_ROUTER_SYSLOG_PORT" ([string]$SyslogPort)
        Set-EnvValue $lines "S43_ROUTER_MAX_EVENTS_PER_SECOND" ([string]$MaxEventsPerSecond)
        Set-EnvValue $lines "S43_ROUTER_API_URL" $ApiUrl
        Set-EnvValue $lines "S43_ROUTER_CA_CERT" $CaCert
        Write-Utf8NoBom -Path $EnvPath -Lines $lines

        [void](Read-Env -Path $EnvPath)
        Set-RouterFirewallRule -RemoteAddress $effectiveRouterIp -Port $SyslogPort
        Restart-RouterIngress

        Write-Host ""
        Show-Status
        Write-Host ""
        Write-Host "Configure the router's remote syslog destination to this computer on UDP port $SyslogPort."
        if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
            $candidates = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.IPAddress -notlike "127.*" -and
                    $_.IPAddress -notlike "169.254.*"
                } |
                Select-Object -ExpandProperty IPAddress -Unique

            if ($candidates) {
                Write-Host "Candidate local IPv4 address(es): $($candidates -join ', ')"
            }
        }
        Write-Host "Then run: .\scripts\router-monitor.ps1 -Mode Listen"
    }

    "Listen" {
        Push-Location $RepoRoot
        try {
            & $python $CollectorPath --env-file $EnvPath
            if ($LASTEXITCODE -ne 0) {
                throw "Router collector exited with code $LASTEXITCODE."
            }
        }
        finally {
            Pop-Location
        }
    }

    "Test" {
        Push-Location $RepoRoot
        try {
            & $python $CollectorPath --env-file $EnvPath --test-event "router telemetry test observation"
            if ($LASTEXITCODE -ne 0) {
                throw "Router ingress test failed with code $LASTEXITCODE."
            }
        }
        finally {
            Pop-Location
        }
    }

    "Disable" {
        $lines = Get-EnvLines
        Set-EnvValue $lines "S43_ROUTER_ENABLED" "false"
        Write-Utf8NoBom -Path $EnvPath -Lines $lines
        Restart-RouterIngress
        Write-Host "Router telemetry disabled. The existing token was retained for deliberate re-enable."
    }

    "Status" {
        Show-Status
    }
}
