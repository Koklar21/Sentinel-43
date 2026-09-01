<#
.SYNOPSIS
    Sentinel-43 live system acceptance checks (PowerShell).

.DESCRIPTION
    Hits a running Sentinel-43 API container over real HTTP and asserts the
    security-relevant behaviors from the beta endpoint-hardening sprint's
    manual acceptance checklist: bootstrap status/relock, unauthenticated
    and unauthorized rejection on protected routes, and the internal-service
    auth boundary on /internal/events/broadcast.

    This is intentionally NOT a Pester script. The only Pester available in
    this environment is the very old Windows-bundled v3.4.0, and pinning
    this script to its (materially different) syntax vs. modern Pester 5.x
    would make it silently wrong on any machine with a newer Pester
    installed. Plain PowerShell with explicit pass/fail counting has no
    such version hazard and needs no new dependency, per this sprint's
    "don't install new tools just to check a box" rule.

    This intentionally does NOT attempt to create an admin account (that
    can only ever succeed once per deployment — see
    core/tests/test_bootstrap.py and core/tests/test_bootstrap_isolated.py,
    which already cover that flow, live and isolated respectively). It only
    exercises checks that are safe to run repeatedly against a live,
    already-initialized deployment without mutating state.

.PARAMETER ApiUrl
    Base URL of the running Sentinel-43 API. Defaults to http://localhost:8000,
    matching S43_TEST_API_URL's default in core/tests/test_bootstrap.py.

.EXAMPLE
    pwsh ./scripts/S43_System.Tests.ps1
    pwsh ./scripts/S43_System.Tests.ps1 -ApiUrl http://localhost:8000
#>

param(
    [string]$ApiUrl = $(if ($env:S43_TEST_API_URL) { $env:S43_TEST_API_URL } else { "http://localhost:8000" })
)

$ErrorActionPreference = "Stop"

$script:PassCount = 0
$script:FailCount = 0
$script:Failures = @()

function Test-Case {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body
    )

    try {
        & $Body
        $script:PassCount++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    }
    catch {
        $script:FailCount++
        $script:Failures += $Name
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        Write-Host "         $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Invoke-S43Request {
    <#
    Windows PowerShell 5.1's Invoke-WebRequest throws on 4xx/5xx instead of
    returning the response (that's -SkipHttpErrorCheck, a PowerShell 7+
    only parameter). Every check here needs the actual status code of
    rejection responses, so failures are caught and normalized into the
    same [pscustomobject] shape (StatusCode/Content) a success returns,
    rather than treating an expected 401/403/422/409 as a script error.
    #>
    param(
        [string]$Method = "GET",
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Headers = @{},
        [object]$Body = $null
    )

    $uri = "$ApiUrl$Path"
    $params = @{
        Method         = $Method
        Uri            = $uri
        Headers        = $Headers
        # Windows PowerShell 5.1's Invoke-WebRequest builds an IE-COM-backed
        # HTML DOM for the response by default, which throws "NonInteractive
        # mode" when no IE engine is available (e.g. this harness, most CI
        # runners). -UseBasicParsing skips that and just returns the raw
        # content, which is all this script ever reads.
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $params["Body"] = ($Body | ConvertTo-Json -Compress)
        $params["ContentType"] = "application/json"
    }

    try {
        $response = Invoke-WebRequest @params -ErrorAction Stop
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Content    = $response.Content
        }
    }
    catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($null -eq $webResponse) { throw }
        $stream = $webResponse.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        return [pscustomobject]@{
            StatusCode = [int]$webResponse.StatusCode
            Content    = $content
        }
    }
    catch {
        # PowerShell 5.1 wraps HttpResponseException-style failures here too
        # depending on the underlying handler; fall back to the same
        # extraction if an HTTP response is attached to the error record.
        if ($_.Exception.Response) {
            $webResponse = $_.Exception.Response
            $stream = $webResponse.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $content = $reader.ReadToEnd()
            return [pscustomobject]@{
                StatusCode = [int]$webResponse.StatusCode
                Content    = $content
            }
        }
        throw
    }
}

function Assert-StatusCode {
    param(
        [Parameter(Mandatory)][int]$Expected,
        [Parameter(Mandatory)]$Response,
        [string]$Context = ""
    )
    if ($Response.StatusCode -ne $Expected) {
        throw "Expected HTTP $Expected$(if ($Context) { " ($Context)" }), got $($Response.StatusCode): $($Response.Content.Substring(0, [Math]::Min(200, $Response.Content.Length)))"
    }
}

Write-Host ""
Write-Host "Sentinel-43 System Acceptance Checks" -ForegroundColor Cyan
Write-Host "Target: $ApiUrl"
Write-Host ""

# -----------------------------------------------------------------------
# Baseline connectivity
# -----------------------------------------------------------------------
Write-Host "Baseline connectivity" -ForegroundColor Cyan

Test-Case "GET /health returns 200" {
    $r = Invoke-S43Request -Path "/health"
    Assert-StatusCode -Expected 200 -Response $r
}

Test-Case "GET /ready returns 200" {
    $r = Invoke-S43Request -Path "/ready"
    Assert-StatusCode -Expected 200 -Response $r
}

# -----------------------------------------------------------------------
# Bootstrap gate
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "Bootstrap gate" -ForegroundColor Cyan

Test-Case "GET /bootstrap/status returns a boolean 'initialized' field" {
    $r = Invoke-S43Request -Path "/bootstrap/status"
    Assert-StatusCode -Expected 200 -Response $r
    $data = $r.Content | ConvertFrom-Json
    if ($null -eq $data.initialized) { throw "Response has no 'initialized' field: $($r.Content)" }
}

Test-Case "POST /bootstrap/admin rejects a too-short password with 422" {
    $r = Invoke-S43Request -Method POST -Path "/bootstrap/admin" -Body @{
        username = "pwtest-$([guid]::NewGuid().ToString().Substring(0,8))"
        password = "short"
    }
    Assert-StatusCode -Expected 422 -Response $r
}

Test-Case "POST /bootstrap/admin refuses once an admin already exists (409) or reports uninitialized" {
    $status = Invoke-S43Request -Path "/bootstrap/status"
    $initialized = ($status.Content | ConvertFrom-Json).initialized

    if ($initialized) {
        $r = Invoke-S43Request -Method POST -Path "/bootstrap/admin" -Body @{
            username = "should-not-be-created-$([guid]::NewGuid().ToString().Substring(0,8))"
            password = "a-perfectly-long-enough-password"
        }
        Assert-StatusCode -Expected 409 -Response $r -Context "deployment already initialized"
    }
    else {
        Write-Host "         (deployment not yet initialized -- relock check skipped, nothing to relock)" -ForegroundColor DarkYellow
    }
}

# -----------------------------------------------------------------------
# Operator route authorization boundary
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "Operator route authorization" -ForegroundColor Cyan

Test-Case "GET /watchtower/status rejects missing credentials with 401" {
    $r = Invoke-S43Request -Path "/watchtower/status"
    Assert-StatusCode -Expected 401 -Response $r
}

Test-Case "GET /watchtower/status rejects a malformed bearer token with 401" {
    $r = Invoke-S43Request -Path "/watchtower/status" -Headers @{ Authorization = "Bearer not-a-real-jwt" }
    Assert-StatusCode -Expected 401 -Response $r
}

Test-Case "GET /system/routes rejects missing credentials with 401" {
    $r = Invoke-S43Request -Path "/system/routes"
    Assert-StatusCode -Expected 401 -Response $r
}

Test-Case "POST /auth/login rejects an unknown user with 401" {
    $r = Invoke-S43Request -Method POST -Path "/auth/login" -Body @{
        username = "definitely-not-a-real-user-$([guid]::NewGuid().ToString().Substring(0,8))"
        password = "whatever-password-123"
    }
    Assert-StatusCode -Expected 401 -Response $r
}

Test-Case "POST /auth/login rejects a missing password field with 422" {
    $r = Invoke-S43Request -Method POST -Path "/auth/login" -Body @{ username = "someone" }
    Assert-StatusCode -Expected 422 -Response $r
}

# -----------------------------------------------------------------------
# Internal service auth boundary (/internal/events/broadcast)
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "Internal service authentication" -ForegroundColor Cyan

Test-Case "POST /internal/events/broadcast rejects missing credentials (401 or 503)" {
    $r = Invoke-S43Request -Method POST -Path "/internal/events/broadcast" -Body @{
        event_type = "acceptance_test"
        channel    = "security"
        data       = @{ note = "S43_System.Tests.ps1" }
    }
    if ($r.StatusCode -ne 401 -and $r.StatusCode -ne 503) {
        throw "Expected 401 (no service token configured to compare against isn't the caller's problem) or 503 (server misconfigured), got $($r.StatusCode)"
    }
}

Test-Case "POST /internal/events/broadcast rejects an operator-shaped JWT instead of the service token" {
    $r = Invoke-S43Request -Method POST -Path "/internal/events/broadcast" -Headers @{
        Authorization = "Bearer eyJhbGciOiJIUzI1NiJ9.fake.jwt"
    } -Body @{
        event_type = "acceptance_test"
        channel    = "security"
        data       = @{ note = "S43_System.Tests.ps1" }
    }
    if ($r.StatusCode -ne 401 -and $r.StatusCode -ne 503) {
        throw "Expected 401/503, got $($r.StatusCode)"
    }
}

# -----------------------------------------------------------------------
# Optional: live credential round-trip (only if provided)
# -----------------------------------------------------------------------
if ($env:S43_LIVE_TEST_USERNAME -and $env:S43_LIVE_TEST_PASSWORD) {
    Write-Host ""
    Write-Host "Live credential round-trip (S43_LIVE_TEST_USERNAME set)" -ForegroundColor Cyan

    Test-Case "Login with configured live credentials succeeds and reaches a protected route" {
        $login = Invoke-S43Request -Method POST -Path "/auth/login" -Body @{
            username = $env:S43_LIVE_TEST_USERNAME
            password = $env:S43_LIVE_TEST_PASSWORD
        }
        Assert-StatusCode -Expected 200 -Response $login
        $token = ($login.Content | ConvertFrom-Json).token
        if (-not $token) { throw "Login response had no token: $($login.Content)" }

        $protected = Invoke-S43Request -Path "/watchtower/status" -Headers @{
            Authorization    = "Bearer $token"
            "X-S43-Password" = $env:S43_LIVE_TEST_PASSWORD
        }
        Assert-StatusCode -Expected 200 -Response $protected -Context "valid token + password against a protected route"
    }
}
else {
    Write-Host ""
    Write-Host "Skipping live credential round-trip (S43_LIVE_TEST_USERNAME / S43_LIVE_TEST_PASSWORD not set)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "----------------------------------------" -ForegroundColor Cyan
Write-Host "Passed: $script:PassCount   Failed: $script:FailCount"
if ($script:FailCount -gt 0) {
    Write-Host ""
    Write-Host "Failed checks:" -ForegroundColor Red
    foreach ($f in $script:Failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
exit 0
