<#
.SYNOPSIS
    Sentinel-43 local endurance / soak runner.

.DESCRIPTION
    Repeatedly verifies a running local Sentinel-43 stack without mutating
    application state or destroying Docker volumes.

    Each cycle performs lightweight pulse checks:
      GET /
      GET /health
      GET /ready
      GET /status
      GET /watchtower/health
      GET /watchtower/ready

    Every FullSweepEvery cycles it also runs scripts/S43_System.Tests.ps1 in
    a child PowerShell process. Every cycle records Docker container state
    and resource usage. Failed cycles capture recent container logs.

.PARAMETER ApiUrl
    Sentinel-43 API/front-door URL.

.PARAMETER Credential
    Operator/admin credential used by the comprehensive endpoint sweep.

.PARAMETER DurationMinutes
    Total soak duration. Default: 120 minutes.

.PARAMETER IntervalSeconds
    Delay between cycles. Default: 60 seconds.

.PARAMETER FullSweepEvery
    Run the comprehensive endpoint sweep every N cycles. Default: 5.

.PARAMETER MaxConsecutiveFailures
    Stop early after this many failed cycles in a row. Default: 3.

.PARAMETER OutputDirectory
    Directory for reports and diagnostics.

.PARAMETER ComposeProject
    Docker Compose project label. Default: sentinel-43.

.PARAMETER SkipCertificateCheck
    Pass certificate bypass to pulse checks and the comprehensive harness.

.EXAMPLE
    $cred = Get-Credential
    pwsh ./scripts/S43_Endurance.Tests.ps1 -Credential $cred -DurationMinutes 120

.EXAMPLE
    $cred = Get-Credential
    pwsh ./scripts/S43_Endurance.Tests.ps1 -Credential $cred -DurationMinutes 720 -IntervalSeconds 120 -FullSweepEvery 5
#>

[CmdletBinding()]
param(
    [string]$ApiUrl = $(if ($env:S43_TEST_API_URL) { $env:S43_TEST_API_URL } else { "http://localhost:8000" }),
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateRange(1, 10080)][int]$DurationMinutes = 120,
    [ValidateRange(5, 3600)][int]$IntervalSeconds = 60,
    [ValidateRange(1, 1000)][int]$FullSweepEvery = 5,
    [ValidateRange(1, 50)][int]$MaxConsecutiveFailures = 3,
    [string]$OutputDirectory = "",
    [string]$ComposeProject = "sentinel-43",
    [switch]$SkipCertificateCheck
)

$ErrorActionPreference = "Stop"
$ApiUrl = $ApiUrl.TrimEnd("/")

$repoRoot = Split-Path -Parent $PSScriptRoot
$systemHarness = Join-Path $PSScriptRoot "S43_System.Tests.ps1"

if (-not (Test-Path -LiteralPath $systemHarness)) {
    throw "Missing endpoint harness: $systemHarness"
}

if (-not $Credential) {
    if ($env:S43_LIVE_TEST_USERNAME -and $env:S43_LIVE_TEST_PASSWORD) {
        $secure = ConvertTo-SecureString $env:S43_LIVE_TEST_PASSWORD -AsPlainText -Force
        $Credential = [System.Management.Automation.PSCredential]::new(
            $env:S43_LIVE_TEST_USERNAME,
            $secure
        )
    }
    else {
        throw "Provide -Credential or set S43_LIVE_TEST_USERNAME and S43_LIVE_TEST_PASSWORD."
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $stamp = [DateTimeOffset]::UtcNow.ToString("yyyyMMdd-HHmmss")
    $OutputDirectory = Join-Path $repoRoot "test-results/endurance-$stamp"
}

$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$cycleDir = Join-Path $OutputDirectory "cycles"
$dockerDir = Join-Path $OutputDirectory "docker"
$failureDir = Join-Path $OutputDirectory "failures"

foreach ($dir in @($OutputDirectory, $cycleDir, $dockerDir, $failureDir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$iwrParameters = (Get-Command Invoke-WebRequest).Parameters
$oldCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
$legacyCertBypass = $false

if ($SkipCertificateCheck -and -not $iwrParameters.ContainsKey("SkipCertificateCheck")) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $legacyCertBypass = $true
}

function Invoke-PulseRequest {
    param([Parameter(Mandatory)][string]$Path)

    $params = @{
        Uri         = "$ApiUrl$Path"
        Method      = "GET"
        TimeoutSec  = 10
        ErrorAction = "Stop"
    }

    if ($iwrParameters.ContainsKey("UseBasicParsing")) {
        $params["UseBasicParsing"] = $true
    }

    if ($SkipCertificateCheck -and $iwrParameters.ContainsKey("SkipCertificateCheck")) {
        $params["SkipCertificateCheck"] = $true
    }

    if ($iwrParameters.ContainsKey("SkipHttpErrorCheck")) {
        $params["SkipHttpErrorCheck"] = $true
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $response = Invoke-WebRequest @params
        $sw.Stop()
        return [pscustomobject]@{
            Path       = $Path
            StatusCode = [int]$response.StatusCode
            DurationMs = [int]$sw.ElapsedMilliseconds
            Error      = ""
        }
    }
    catch {
        $sw.Stop()
        $status = 0
        try {
            if ($_.Exception.Response) {
                $status = [int]$_.Exception.Response.StatusCode
            }
        }
        catch {
            $status = 0
        }

        return [pscustomobject]@{
            Path       = $Path
            StatusCode = $status
            DurationMs = [int]$sw.ElapsedMilliseconds
            Error      = $_.Exception.Message
        }
    }
}

function Get-ProjectContainers {
    try {
        return @(
            & docker ps --filter "label=com.docker.compose.project=$ComposeProject" --format "{{.Names}}" 2>$null
        ) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }
    }
    catch {
        return @()
    }
}

function Save-DockerSnapshot {
    param([Parameter(Mandatory)][int]$Cycle)

    $prefix = Join-Path $dockerDir ("cycle-{0:D5}" -f $Cycle)

    try {
        $psRows = & docker ps -a --filter "label=com.docker.compose.project=$ComposeProject" --format "{{json .}}" 2>&1
        Set-Content -LiteralPath "$prefix-ps.jsonl" -Value $psRows -Encoding UTF8
    }
    catch {
        Set-Content -LiteralPath "$prefix-ps-error.txt" -Value $_.Exception.Message -Encoding UTF8
    }

    $names = Get-ProjectContainers
    if ($names.Count -eq 0) {
        Set-Content -LiteralPath "$prefix-stats.txt" -Value "No running Compose containers found for project '$ComposeProject'." -Encoding UTF8
        return
    }

    try {
        $stats = & docker stats --no-stream @names --format "{{json .}}" 2>&1
        Set-Content -LiteralPath "$prefix-stats.jsonl" -Value $stats -Encoding UTF8
    }
    catch {
        Set-Content -LiteralPath "$prefix-stats-error.txt" -Value $_.Exception.Message -Encoding UTF8
    }
}

function Save-FailureLogs {
    param([Parameter(Mandatory)][int]$Cycle)

    $dir = Join-Path $failureDir ("cycle-{0:D5}" -f $Cycle)
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    foreach ($name in (Get-ProjectContainers)) {
        try {
            $safeName = $name -replace '[^A-Za-z0-9_.-]', '_'
            $logs = & docker logs --tail 250 $name 2>&1
            Set-Content -LiteralPath (Join-Path $dir "$safeName.log") -Value $logs -Encoding UTF8
        }
        catch {
            # Best effort only. The primary cycle failure remains authoritative.
        }
    }
}

function Invoke-FullSweep {
    param([Parameter(Mandatory)][int]$Cycle)

    $report = Join-Path $cycleDir ("cycle-{0:D5}-full.json" -f $Cycle)
    $log = Join-Path $cycleDir ("cycle-{0:D5}-full.log" -f $Cycle)
    $shell = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    $oldUser = $env:S43_LIVE_TEST_USERNAME
    $oldPassword = $env:S43_LIVE_TEST_PASSWORD

    try {
        $env:S43_LIVE_TEST_USERNAME = $Credential.UserName
        $env:S43_LIVE_TEST_PASSWORD = $Credential.GetNetworkCredential().Password

        $args = @(
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            $systemHarness,
            "-ApiUrl",
            $ApiUrl,
            "-ReportPath",
            $report
        )

        if ($SkipCertificateCheck) {
            $args += "-SkipCertificateCheck"
        }

        $output = & $shell @args 2>&1
        $exitCode = $LASTEXITCODE
        Set-Content -LiteralPath $log -Value $output -Encoding UTF8

        return [pscustomobject]@{
            ExitCode   = $exitCode
            ReportPath = $report
            LogPath    = $log
        }
    }
    finally {
        $env:S43_LIVE_TEST_USERNAME = $oldUser
        $env:S43_LIVE_TEST_PASSWORD = $oldPassword
    }
}

$pulseEndpoints = @(
    "/",
    "/health",
    "/ready",
    "/status",
    "/audit/health",
    "/bootstrap/status",
    "/watchtower/health",
    "/watchtower/ready",
    "/openapi.json"
)

$rows = @()
$start = [DateTimeOffset]::UtcNow
$deadline = $start.AddMinutes($DurationMinutes)
$cycle = 0
$consecutiveFailures = 0
$peakConsecutiveFailures = 0
$stoppedEarly = $false
$stopReason = ""

Write-Host ""
Write-Host "Sentinel-43 Local Endurance Run" -ForegroundColor Cyan
Write-Host "Target:             $ApiUrl"
Write-Host "Duration:           $DurationMinutes minutes"
Write-Host "Interval:           $IntervalSeconds seconds"
Write-Host "Full sweep every:   $FullSweepEvery cycle(s)"
Write-Host "Failure stop limit: $MaxConsecutiveFailures consecutive cycle(s)"
Write-Host "Output:             $OutputDirectory"
Write-Host ""

try {
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $cycle++
        $cycleStart = [DateTimeOffset]::UtcNow
        $cycleFailed = $false
        $pulseResults = @()

        Write-Host ("[{0}] Cycle {1}" -f $cycleStart.ToString("u"), $cycle) -ForegroundColor Cyan

        foreach ($path in $pulseEndpoints) {
            $result = Invoke-PulseRequest -Path $path
            $pulseResults += $result

            if ($result.StatusCode -eq 200) {
                Write-Host ("  [PASS] GET {0,-24} HTTP {1}  {2} ms" -f $path, $result.StatusCode, $result.DurationMs) -ForegroundColor Green
            }
            else {
                $cycleFailed = $true
                Write-Host ("  [FAIL] GET {0,-24} HTTP {1}  {2}" -f $path, $result.StatusCode, $result.Error) -ForegroundColor Red
            }
        }

        $fullSweepRan = (($cycle - 1) % $FullSweepEvery -eq 0)
        $fullSweepExit = $null

        if ($fullSweepRan) {
            Write-Host "  Running comprehensive endpoint sweep..." -ForegroundColor DarkCyan
            $full = Invoke-FullSweep -Cycle $cycle
            $fullSweepExit = $full.ExitCode

            if ($full.ExitCode -eq 0) {
                Write-Host "  [PASS] Comprehensive endpoint sweep" -ForegroundColor Green
            }
            else {
                $cycleFailed = $true
                Write-Host "  [FAIL] Comprehensive endpoint sweep (exit $($full.ExitCode))" -ForegroundColor Red
            }
        }

        Save-DockerSnapshot -Cycle $cycle

        if ($cycleFailed) {
            $consecutiveFailures++
            if ($consecutiveFailures -gt $peakConsecutiveFailures) {
                $peakConsecutiveFailures = $consecutiveFailures
            }
            Save-FailureLogs -Cycle $cycle
        }
        else {
            $consecutiveFailures = 0
        }

        $cycleEnd = [DateTimeOffset]::UtcNow
        $rows += [pscustomobject]@{
            cycle                = $cycle
            started_at_utc       = $cycleStart.ToString("o")
            completed_at_utc     = $cycleEnd.ToString("o")
            duration_seconds     = [math]::Round(($cycleEnd - $cycleStart).TotalSeconds, 3)
            failed               = $cycleFailed
            consecutive_failures = $consecutiveFailures
            full_sweep_ran       = $fullSweepRan
            full_sweep_exit_code = $fullSweepExit
            pulse                = $pulseResults
        }

        $rows | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory "cycles.json") -Encoding UTF8

        if ($consecutiveFailures -ge $MaxConsecutiveFailures) {
            $stoppedEarly = $true
            $stopReason = "Reached $MaxConsecutiveFailures consecutive failed cycles."
            Write-Host ""
            Write-Host $stopReason -ForegroundColor Red
            break
        }

        $remaining = ($deadline - [DateTimeOffset]::UtcNow).TotalSeconds
        if ($remaining -le 0) {
            break
        }

        $sleepFor = [Math]::Min($IntervalSeconds, [Math]::Max(0, [int]$remaining))
        if ($sleepFor -gt 0) {
            Start-Sleep -Seconds $sleepFor
        }
    }
}
finally {
    if ($legacyCertBypass) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCertCallback
    }
}

$end = [DateTimeOffset]::UtcNow
$failedCycles = @($rows | Where-Object failed).Count
$successfulCycles = $rows.Count - $failedCycles
$fullSweeps = @($rows | Where-Object full_sweep_ran).Count
$failedFullSweeps = @(
    $rows | Where-Object {
        $_.full_sweep_ran -and
        $null -ne $_.full_sweep_exit_code -and
        $_.full_sweep_exit_code -ne 0
    }
).Count

$summary = [ordered]@{
    started_at_utc             = $start.ToString("o")
    completed_at_utc           = $end.ToString("o")
    requested_duration_minutes = $DurationMinutes
    actual_duration_minutes    = [math]::Round(($end - $start).TotalMinutes, 3)
    api_url                    = $ApiUrl
    total_cycles               = $rows.Count
    successful_cycles          = $successfulCycles
    failed_cycles              = $failedCycles
    full_sweeps                = $fullSweeps
    failed_full_sweeps         = $failedFullSweeps
    peak_consecutive_failures  = $peakConsecutiveFailures
    stopped_early              = $stoppedEarly
    stop_reason                = $stopReason
    survived                   = (
        -not $stoppedEarly -and
        $failedCycles -eq 0 -and
        $failedFullSweeps -eq 0
    )
}

$summaryPath = Join-Path $OutputDirectory "summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Endurance summary" -ForegroundColor Cyan
Write-Host "Cycles:             $($rows.Count)"
Write-Host "Successful:         $successfulCycles" -ForegroundColor Green
Write-Host "Failed:             $failedCycles" -ForegroundColor $(if ($failedCycles) { "Red" } else { "Green" })
Write-Host "Full sweeps:        $fullSweeps"
Write-Host "Failed full sweeps: $failedFullSweeps" -ForegroundColor $(if ($failedFullSweeps) { "Red" } else { "Green" })
Write-Host "Peak fail streak:   $peakConsecutiveFailures"
Write-Host "Summary:            $summaryPath"

if ($summary.survived) {
    Write-Host ""
    Write-Host "SURVIVED: requested soak completed without endpoint failures." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "NOT CLEAN: inspect summary.json, cycles.json and failures/ diagnostics." -ForegroundColor Red
exit 1
