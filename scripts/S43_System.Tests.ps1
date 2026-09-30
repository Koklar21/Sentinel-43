<#
.SYNOPSIS
    Sentinel-43 comprehensive live endpoint and health-check harness.

.DESCRIPTION
    Tests a running Sentinel-43 deployment over real HTTP/HTTPS without
    requiring Pester or any third-party PowerShell module.

    The harness deliberately separates three kinds of checks:

      1. HEALTH
         Explicit liveness/readiness/bootstrap/audit checks with strong
         expected status codes.

      2. READ-ONLY ROUTE SWEEP
         Logs in as a real operator, calls GET /system/routes, and exercises
         every registered read-only HTTP route in the running application.
         Routes with path parameters receive harmless synthetic identifiers.
         A 404 for a synthetic resource proves the route is reachable; a 5xx
         is still a failure.

      3. MUTATION-GUARD SWEEP
         POST/PUT/PATCH/DELETE routes are NOT executed with valid credentials
         by default. They are probed anonymously (or with deliberately invalid
         public input for bootstrap/auth routes) and must reject the request
         rather than mutate live state. A successful unauthenticated mutation
         is treated as a security failure.

    GET /system/routes is used instead of /openapi.json because Sentinel-43
    intentionally disables OpenAPI/docs outside local/dev. The route inventory
    therefore comes from the actual running app.

    The /ws WebSocket route is tested separately. With a valid operator
    session the harness performs the real auth_required -> auth -> connected
    handshake using the current token-only session contract.

    Optional direct Watchtower tests can be enabled with -WatchtowerUrl.
    The public /watchtower/health and /watchtower/ready probes are always
    checked; service-token-gated read routes are checked when a Watchtower
    service token is available.

    This script is safe to run repeatedly against an initialized deployment.
    It does not create users, approve/veto actions, replay events, dispatch
    remote operations, register Watchtower modules, or otherwise intentionally
    change application state.

.PARAMETER ApiUrl
    Base URL of the Sentinel-43 API/front door.

.PARAMETER Credential
    Operator/admin PSCredential used for the authenticated route sweep.
    If omitted, S43_LIVE_TEST_USERNAME and S43_LIVE_TEST_PASSWORD are used.

.PARAMETER PublicOnly
    Run only public health/bootstrap checks. Without this switch, missing
    operator credentials are a failure because "all endpoints" were not tested.

.PARAMETER WatchtowerUrl
    Optional direct URL for the s43-core Watchtower service, for example
    http://localhost:9100 when that service is intentionally host-reachable.
    Docker Compose normally exposes it only inside the Compose network, so
    leaving this blank is valid.

.PARAMETER WatchtowerServiceToken
    Optional direct-Watchtower bearer token. Defaults to
    S43_WATCHTOWER_SERVICE_TOKEN.

.PARAMETER SpartaToken
    Optional bearer token for /node service routes. Defaults to
    S43_SPARTA_NODE_TOKEN.

.PARAMETER FenrirToken
    Optional bearer token for internal Fenrir service routes. Defaults to
    S43_FENRIR_API_TOKEN.

.PARAMETER RemoteGatewayToken
    Optional bearer token for /remote-gateway read routes. Defaults to the
    first configured SENTINEL_REMOTE_TOKEN_OWNER/ADMIN/AUDITOR value.

.PARAMETER AllowNotReady
    Report API /ready=503 as WARN instead of FAIL. /health and /audit/health
    remain hard failures when unhealthy.

.PARAMETER SkipCertificateCheck
    Allow self-signed HTTPS certificates for local/controlled test targets.

.PARAMETER ReportPath
    Optional JSON report path.

.EXAMPLE
    $cred = Get-Credential
    pwsh ./scripts/S43_System.Tests.ps1 -ApiUrl http://localhost:8000 -Credential $cred

.EXAMPLE
    $cred = Get-Credential
    pwsh ./scripts/S43_System.Tests.ps1 -ApiUrl https://localhost -Credential $cred -SkipCertificateCheck -ReportPath ./s43-endpoint-report.json

.EXAMPLE
    pwsh ./scripts/S43_System.Tests.ps1 -PublicOnly
#>

[CmdletBinding()]
param(
    [string]$ApiUrl = $(if ($env:S43_TEST_API_URL) { $env:S43_TEST_API_URL } else { "http://localhost:8000" }),
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$PublicOnly,
    [string]$WatchtowerUrl = $(if ($env:S43_SYSTEM_TEST_WATCHTOWER_URL) { $env:S43_SYSTEM_TEST_WATCHTOWER_URL } else { "" }),
    [string]$WatchtowerServiceToken = $(if ($env:S43_WATCHTOWER_SERVICE_TOKEN) { $env:S43_WATCHTOWER_SERVICE_TOKEN } else { "" }),
    [string]$SpartaToken = $(if ($env:S43_SPARTA_NODE_TOKEN) { $env:S43_SPARTA_NODE_TOKEN } else { "" }),
    [string]$FenrirToken = $(if ($env:S43_FENRIR_API_TOKEN) { $env:S43_FENRIR_API_TOKEN } else { "" }),
    [string]$RemoteGatewayToken = $(if ($env:SENTINEL_REMOTE_TOKEN_OWNER) {
        $env:SENTINEL_REMOTE_TOKEN_OWNER
    }
    elseif ($env:SENTINEL_REMOTE_TOKEN_ADMIN) {
        $env:SENTINEL_REMOTE_TOKEN_ADMIN
    }
    elseif ($env:SENTINEL_REMOTE_TOKEN_AUDITOR) {
        $env:SENTINEL_REMOTE_TOKEN_AUDITOR
    }
    else {
        ""
    }),
    [int]$TimeoutSec = 10,
    [switch]$AllowNotReady,
    [switch]$SkipCertificateCheck,
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"
$ApiUrl = $ApiUrl.TrimEnd("/")
$WatchtowerUrl = $WatchtowerUrl.TrimEnd("/")

if ($TimeoutSec -lt 1 -or $TimeoutSec -gt 120) {
    throw "TimeoutSec must be between 1 and 120."
}

$script:Results = @()
$script:PassCount = 0
$script:WarnCount = 0
$script:FailCount = 0
$script:SkipCount = 0
$script:AuthenticatedSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$script:AnonymousSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$script:IwrParameters = (Get-Command Invoke-WebRequest).Parameters
$script:OriginalCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
$script:UsingLegacyTlsBypass = $false

if (
    $SkipCertificateCheck -and
    -not $script:IwrParameters.ContainsKey("SkipCertificateCheck")
) {
    # Windows PowerShell 5.1 has no -SkipCertificateCheck. This callback is
    # restored before exit.
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $script:UsingLegacyTlsBypass = $true
}

function Restore-S43TlsState {
    if ($script:UsingLegacyTlsBypass) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback =
            $script:OriginalCertificateCallback
    }
}

function Write-Section {
    param([Parameter(Mandatory)][string]$Name)

    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
}

function Get-BodyPreview {
    param(
        [AllowNull()][string]$Content,
        [int]$MaxLength = 220
    )

    if ([string]::IsNullOrWhiteSpace($Content)) {
        return ""
    }

    $singleLine = ($Content -replace "\s+", " ").Trim()
    if ($singleLine.Length -le $MaxLength) {
        return $singleLine
    }

    return $singleLine.Substring(0, $MaxLength) + "..."
}

function Add-Result {
    param(
        [Parameter(Mandatory)][ValidateSet("PASS", "WARN", "FAIL", "SKIP")][string]$Outcome,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [int]$StatusCode = 0,
        [string]$Detail = "",
        [int]$DurationMs = 0
    )

    $script:Results += [pscustomobject]@{
        Outcome    = $Outcome
        Category   = $Category
        Mode       = $Mode
        Method     = $Method
        Path       = $Path
        StatusCode = $StatusCode
        DurationMs = $DurationMs
        Detail     = $Detail
    }

    switch ($Outcome) {
        "PASS" {
            $script:PassCount++
            $color = "Green"
        }
        "WARN" {
            $script:WarnCount++
            $color = "Yellow"
        }
        "FAIL" {
            $script:FailCount++
            $color = "Red"
        }
        default {
            $script:SkipCount++
            $color = "DarkGray"
        }
    }

    $statusText = if ($StatusCode -gt 0) { " HTTP $StatusCode" } else { "" }
    Write-Host ("[{0}] {1,-7} {2,-6} {3}{4} - {5}" -f $Outcome, $Category, $Method, $Path, $statusText, $Detail) -ForegroundColor $color
}

function Convert-HttpErrorResponse {
    param(
        [Parameter(Mandatory)]$ErrorRecord,
        [Parameter(Mandatory)][System.Diagnostics.Stopwatch]$Stopwatch
    )

    $response = $ErrorRecord.Exception.Response
    if ($null -eq $response) {
        return [pscustomobject]@{
            StatusCode = 0
            Content    = ""
            DurationMs = [int]$Stopwatch.ElapsedMilliseconds
            Error      = $ErrorRecord.Exception.Message
        }
    }

    $statusCode = 0
    try {
        $statusCode = [int]$response.StatusCode
    }
    catch {
        $statusCode = 0
    }

    $content = ""

    try {
        if ($response.PSObject.Methods.Name -contains "GetResponseStream") {
            $stream = $response.GetResponseStream()
            if ($null -ne $stream) {
                $reader = [System.IO.StreamReader]::new($stream)
                try {
                    $content = $reader.ReadToEnd()
                }
                finally {
                    $reader.Dispose()
                }
            }
        }
        elseif ($null -ne $response.Content) {
            $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
    }
    catch {
        $content = ""
    }

    return [pscustomobject]@{
        StatusCode = $statusCode
        Content    = $content
        DurationMs = [int]$Stopwatch.ElapsedMilliseconds
        Error      = $ErrorRecord.Exception.Message
    }
}

function Invoke-S43Request {
    param(
        [string]$BaseUrl = $ApiUrl,
        [ValidateSet("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")][string]$Method = "GET",
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Headers = @{},
        [AllowNull()][object]$Body = $null,
        [AllowNull()][Microsoft.PowerShell.Commands.WebRequestSession]$Session = $null
    )

    $uri = $BaseUrl.TrimEnd("/") + $Path
    $params = @{
        Uri         = $uri
        Method      = $Method
        Headers     = $Headers
        TimeoutSec  = $TimeoutSec
        ErrorAction = "Stop"
        UserAgent   = "Sentinel-43-System-Tests/2"
    }

    if ($script:IwrParameters.ContainsKey("UseBasicParsing")) {
        $params["UseBasicParsing"] = $true
    }

    if ($null -ne $Session) {
        $params["WebSession"] = $Session
    }

    if ($SkipCertificateCheck -and $script:IwrParameters.ContainsKey("SkipCertificateCheck")) {
        $params["SkipCertificateCheck"] = $true
    }

    if ($script:IwrParameters.ContainsKey("SkipHttpErrorCheck")) {
        $params["SkipHttpErrorCheck"] = $true
    }

    if ($null -ne $Body) {
        $params["Body"] = ($Body | ConvertTo-Json -Depth 12 -Compress)
        $params["ContentType"] = "application/json"
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $response = Invoke-WebRequest @params
        $stopwatch.Stop()

        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Content    = [string]$response.Content
            DurationMs = [int]$stopwatch.ElapsedMilliseconds
            Error      = ""
        }
    }
    catch {
        $stopwatch.Stop()
        return Convert-HttpErrorResponse -ErrorRecord $_ -Stopwatch $stopwatch
    }
}

function ConvertFrom-S43Json {
    param(
        [Parameter(Mandatory)]$Response,
        [Parameter(Mandatory)][string]$Context
    )

    try {
        return $Response.Content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "$Context returned non-JSON content: $(Get-BodyPreview $Response.Content)"
    }
}

function New-BearerHeaders {
    param([AllowNull()][string]$Token)

    if ([string]::IsNullOrWhiteSpace($Token)) {
        return @{}
    }

    return @{
        Authorization = "Bearer $Token"
    }
}

function Get-EffectiveCredential {
    if ($null -ne $Credential) {
        return $Credential
    }

    if ($env:S43_LIVE_TEST_USERNAME -and $env:S43_LIVE_TEST_PASSWORD) {
        $securePassword = ConvertTo-SecureString $env:S43_LIVE_TEST_PASSWORD -AsPlainText -Force
        return [System.Management.Automation.PSCredential]::new(
            $env:S43_LIVE_TEST_USERNAME,
            $securePassword
        )
    }

    return $null
}

function Resolve-RoutePath {
    param([Parameter(Mandatory)][string]$Template)

    $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)

        $name = $match.Groups[1].Value.ToLowerInvariant()

        if ($name -match "(^|_)user(_|$)|user_id|account_id") {
            return "00000000-0000-0000-0000-000000000000"
        }

        if ($name -match "(^|_)id$|action_id|event_id|finding_id|record_id|incident_id|correlation_id") {
            return "s43-smoke-does-not-exist"
        }

        if ($name -match "index|offset|count|number") {
            return "1"
        }

        return "s43-smoke"
    }

    return [regex]::Replace(
        $Template,
        "\{([^}:]+)(?::[^}]+)?\}",
        $evaluator
    )
}

function Get-ReadRouteContext {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OperatorToken
    )

    if ($Path -like "/node/*" -and $Path -ne "/node/health") {
        if ($SpartaToken) {
            return [pscustomobject]@{
                Headers           = New-BearerHeaders $SpartaToken
                CredentialPresent = $true
                Identity          = "sparta-service"
            }
        }

        return [pscustomobject]@{
            Headers           = @{}
            CredentialPresent = $false
            Identity          = "sparta-service"
        }
    }

    if ($Path -like "/remote-gateway/*") {
        if ($RemoteGatewayToken) {
            return [pscustomobject]@{
                Headers           = New-BearerHeaders $RemoteGatewayToken
                CredentialPresent = $true
                Identity          = "remote-gateway-service"
            }
        }

        return [pscustomobject]@{
            Headers           = @{}
            CredentialPresent = $false
            Identity          = "remote-gateway-service"
        }
    }

    if ($Path -like "/internal/*") {
        if ($FenrirToken) {
            return [pscustomobject]@{
                Headers           = New-BearerHeaders $FenrirToken
                CredentialPresent = $true
                Identity          = "internal-service"
            }
        }

        return [pscustomobject]@{
            Headers           = @{}
            CredentialPresent = $false
            Identity          = "internal-service"
        }
    }

    return [pscustomobject]@{
        Headers           = New-BearerHeaders $OperatorToken
        CredentialPresent = -not [string]::IsNullOrWhiteSpace($OperatorToken)
        Identity          = "operator"
    }
}

function Test-HealthEndpoint {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet("health", "readiness", "bootstrap")][string]$Kind = "health"
    )

    $response = Invoke-S43Request -Path $Path -Session $script:AnonymousSession

    if ($response.StatusCode -eq 200) {
        $detail = "healthy"
        if ($Kind -eq "bootstrap") {
            try {
                $body = ConvertFrom-S43Json -Response $response -Context $Path
                if ($null -eq $body.initialized) {
                    throw "missing initialized field"
                }
                $detail = "initialized=$($body.initialized)"
                if ($null -ne $body.claim_token_required) {
                    $detail += "; claim_token_required=$($body.claim_token_required)"
                }
            }
            catch {
                Add-Result -Outcome "FAIL" -Category "HEALTH" -Mode $Kind -Method "GET" -Path $Path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail $_.Exception.Message
                return
            }
        }

        Add-Result -Outcome "PASS" -Category "HEALTH" -Mode $Kind -Method "GET" -Path $Path -StatusCode 200 -DurationMs $response.DurationMs -Detail $detail
        return
    }

    if (
        $Kind -eq "readiness" -and
        $response.StatusCode -eq 503 -and
        $AllowNotReady
    ) {
        Add-Result -Outcome "WARN" -Category "HEALTH" -Mode $Kind -Method "GET" -Path $Path -StatusCode 503 -DurationMs $response.DurationMs -Detail ("not ready: " + (Get-BodyPreview $response.Content))
        return
    }

    $detail = if ($response.StatusCode -eq 0) {
        "transport error: $($response.Error)"
    }
    else {
        Get-BodyPreview $response.Content
    }

    Add-Result -Outcome "FAIL" -Category "HEALTH" -Mode $Kind -Method "GET" -Path $Path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail $detail
}

function Test-ReadRoute {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][string]$OperatorToken
    )

    $path = Resolve-RoutePath $Template
    $context = Get-ReadRouteContext -Path $Template -OperatorToken $OperatorToken

    $response = Invoke-S43Request -Method $Method -Path $path -Headers $context.Headers -Session $script:AnonymousSession
    $status = $response.StatusCode
    $preview = Get-BodyPreview $response.Content

    if ($status -eq 0) {
        Add-Result -Outcome "FAIL" -Category "ROUTE" -Mode "read:$($context.Identity)" -Method $Method -Path $Template -StatusCode 0 -DurationMs $response.DurationMs -Detail "transport error: $($response.Error)"
        return
    }

    if (-not $context.CredentialPresent -and $context.Identity -ne "operator") {
        if ($status -eq 401 -or $status -eq 403) {
            Add-Result -Outcome "PASS" -Category "ROUTE" -Mode "auth-boundary:$($context.Identity)" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail "service credential not supplied; route rejected anonymous caller"
            return
        }

        if ($status -ge 500) {
            Add-Result -Outcome "FAIL" -Category "ROUTE" -Mode "auth-boundary:$($context.Identity)" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail $preview
            return
        }

        Add-Result -Outcome "WARN" -Category "ROUTE" -Mode "auth-boundary:$($context.Identity)" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail "service token unavailable; endpoint was not fully authenticated"
        return
    }

    if ($status -ge 200 -and $status -lt 300) {
        Add-Result -Outcome "PASS" -Category "ROUTE" -Mode "read:$($context.Identity)" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail "request completed"
        return
    }

    if ($status -eq 404) {
        Add-Result -Outcome "PASS" -Category "ROUTE" -Mode "read:$($context.Identity)" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail "registered route reached; synthetic resource not found"
        return
    }

    if ($status -eq 400 -or $status -eq 409 -or $status -eq 422 -or $status -eq 429) {
        Add-Result -Outcome "WARN" -Category "ROUTE" -Mode "read:$($context.Identity)" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail ("registered route requires live/valid input: " + $preview)
        return
    }

    if ($status -eq 401 -or $status -eq 403) {
        Add-Result -Outcome "FAIL" -Category "ROUTE" -Mode "read:$($context.Identity)" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail ("supplied credential rejected: " + $preview)
        return
    }

    Add-Result -Outcome "FAIL" -Category "ROUTE" -Mode "read:$($context.Identity)" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail $preview
}

function Test-MutationGuard {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Template
    )

    $path = Resolve-RoutePath $Template
    $body = $null
    $expected = @(401, 403, 404, 409, 422, 429)

    switch ("$Method $Template") {
        "POST /auth/login" {
            $body = @{
                username = "s43-smoke-$([guid]::NewGuid().ToString('N').Substring(0, 10))"
                password = "not-a-real-password-12345"
            }
            $expected = @(401, 429)
        }
        "POST /auth/refresh" {
            $expected = @(401, 403)
        }
        "POST /auth/logout" {
            # Anonymous logout may be modeled as an idempotent success or a
            # rejection. Either is safe because the anonymous session has no
            # Sentinel-43 refresh cookie to revoke.
            $expected = @(200, 204, 401, 403)
        }
        "POST /bootstrap/admin" {
            $body = @{
                username = "s43-smoke"
                password = "short"
            }
            # local/uninitialized -> validation; initialized -> conflict;
            # non-local without a presented deployment claim -> forbidden.
            $expected = @(403, 409, 422)
        }
    }

    $response = Invoke-S43Request -Method $Method -Path $path -Body $body -Session $script:AnonymousSession
    $status = $response.StatusCode
    $preview = Get-BodyPreview $response.Content

    if ($status -eq 0) {
        Add-Result -Outcome "FAIL" -Category "ROUTE" -Mode "mutation-guard" -Method $Method -Path $Template -StatusCode 0 -DurationMs $response.DurationMs -Detail "transport error: $($response.Error)"
        return
    }

    if ($expected -contains $status) {
        $detail = if ($status -ge 200 -and $status -lt 300) {
            "safe anonymous/idempotent response"
        }
        else {
            "mutation safely rejected without valid mutation authority/input"
        }

        Add-Result -Outcome "PASS" -Category "ROUTE" -Mode "mutation-guard" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail $detail
        return
    }

    if ($status -ge 200 -and $status -lt 300) {
        Add-Result -Outcome "FAIL" -Category "ROUTE" -Mode "mutation-guard" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail "unexpected unauthenticated mutation success"
        return
    }

    if ($status -ge 500) {
        Add-Result -Outcome "FAIL" -Category "ROUTE" -Mode "mutation-guard" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail $preview
        return
    }

    Add-Result -Outcome "WARN" -Category "ROUTE" -Mode "mutation-guard" -Method $Method -Path $Template -StatusCode $status -DurationMs $response.DurationMs -Detail ("unexpected but non-mutating rejection: " + $preview)
}

function Receive-S43WebSocketText {
    param(
        [Parameter(Mandatory)][System.Net.WebSockets.ClientWebSocket]$Socket
    )

    $chunks = New-Object System.Collections.Generic.List[byte]
    $buffer = New-Object byte[] 8192

    while ($true) {
        $segment = [System.ArraySegment[byte]]::new($buffer)
        $cts = New-Object System.Threading.CancellationTokenSource
        $cts.CancelAfter($TimeoutSec * 1000)

        try {
            $result = $Socket.ReceiveAsync($segment, $cts.Token).GetAwaiter().GetResult()
        }
        finally {
            $cts.Dispose()
        }

        if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
            throw "WebSocket closed before the expected message."
        }

        for ($i = 0; $i -lt $result.Count; $i++) {
            $chunks.Add($buffer[$i])
        }

        if ($result.EndOfMessage) {
            break
        }
    }

    return [System.Text.Encoding]::UTF8.GetString($chunks.ToArray())
}

function Send-S43WebSocketJson {
    param(
        [Parameter(Mandatory)][System.Net.WebSockets.ClientWebSocket]$Socket,
        [Parameter(Mandatory)][object]$Body
    )

    $json = $Body | ConvertTo-Json -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $segment = [System.ArraySegment[byte]]::new($bytes)
    $cts = New-Object System.Threading.CancellationTokenSource
    $cts.CancelAfter($TimeoutSec * 1000)

    try {
        $Socket.SendAsync(
            $segment,
            [System.Net.WebSockets.WebSocketMessageType]::Text,
            $true,
            $cts.Token
        ).GetAwaiter().GetResult()
    }
    finally {
        $cts.Dispose()
    }
}

function Test-S43WebSocket {
    param(
        [Parameter(Mandatory)][string]$OperatorToken
    )

    if ([string]::IsNullOrWhiteSpace($OperatorToken)) {
        Add-Result -Outcome "SKIP" -Category "WS" -Mode "session" -Method "WS" -Path "/ws" -Detail "no operator token"
        return
    }

    $apiUri = [Uri]$ApiUrl
    $builder = [System.UriBuilder]::new($apiUri)
    $builder.Scheme = if ($apiUri.Scheme -eq "https") { "wss" } else { "ws" }
    $builder.Port = $apiUri.Port
    $builder.Path = "/ws"
    $builder.Query = ""
    $wsUri = $builder.Uri

    $socket = New-Object System.Net.WebSockets.ClientWebSocket

    try {
        $origin = "$($apiUri.Scheme)://$($apiUri.Authority)"
        $socket.Options.SetRequestHeader("Origin", $origin)

        if (
            $SkipCertificateCheck -and
            $socket.Options.PSObject.Properties.Name -contains "RemoteCertificateValidationCallback"
        ) {
            $socket.Options.RemoteCertificateValidationCallback = { $true }
        }

        $cts = New-Object System.Threading.CancellationTokenSource
        $cts.CancelAfter($TimeoutSec * 1000)

        try {
            $socket.ConnectAsync($wsUri, $cts.Token).GetAwaiter().GetResult()
        }
        finally {
            $cts.Dispose()
        }

        $firstText = Receive-S43WebSocketText -Socket $socket
        $first = $firstText | ConvertFrom-Json -ErrorAction Stop

        if ($first.type -eq "auth_required") {
            Send-S43WebSocketJson -Socket $socket -Body @{
                type = "auth"
                payload = @{
                    token = $OperatorToken
                }
            }

            $connectedText = Receive-S43WebSocketText -Socket $socket
            $connected = $connectedText | ConvertFrom-Json -ErrorAction Stop

            if ($connected.type -ne "connected") {
                throw "Expected connected frame after auth; got: $(Get-BodyPreview $connectedText)"
            }
        }
        elseif ($first.type -ne "connected") {
            throw "Expected auth_required or connected frame; got: $(Get-BodyPreview $firstText)"
        }

        Add-Result -Outcome "PASS" -Category "WS" -Mode "session" -Method "WS" -Path "/ws" -StatusCode 101 -Detail "real WebSocket authentication handshake completed"
    }
    catch {
        Add-Result -Outcome "FAIL" -Category "WS" -Mode "session" -Method "WS" -Path "/ws" -Detail $_.Exception.Message
    }
    finally {
        if ($socket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            try {
                $socket.CloseAsync(
                    [System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure,
                    "system test complete",
                    [System.Threading.CancellationToken]::None
                ).GetAwaiter().GetResult()
            }
            catch {
                # The test result was already recorded; close is best-effort.
            }
        }

        $socket.Dispose()
    }
}

function Test-DirectWatchtower {
    if ([string]::IsNullOrWhiteSpace($WatchtowerUrl)) {
        Add-Result -Outcome "SKIP" -Category "WATCH" -Mode "direct" -Method "GET" -Path "/watchtower/*" -Detail "WatchtowerUrl not supplied; Compose normally keeps s43-core internal"
        return
    }

    Write-Section "Direct Watchtower health and endpoints"

    foreach ($path in @("/watchtower/health", "/watchtower/ready")) {
        $response = Invoke-S43Request -BaseUrl $WatchtowerUrl -Path $path -Session $script:AnonymousSession

        if ($response.StatusCode -eq 200) {
            Add-Result -Outcome "PASS" -Category "WATCH" -Mode "health" -Method "GET" -Path $path -StatusCode 200 -DurationMs $response.DurationMs -Detail "Watchtower probe healthy"
        }
        elseif (
            $path -eq "/watchtower/ready" -and
            $response.StatusCode -eq 503 -and
            $AllowNotReady
        ) {
            Add-Result -Outcome "WARN" -Category "WATCH" -Mode "health" -Method "GET" -Path $path -StatusCode 503 -DurationMs $response.DurationMs -Detail "Watchtower not ready"
        }
        else {
            Add-Result -Outcome "FAIL" -Category "WATCH" -Mode "health" -Method "GET" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail (Get-BodyPreview $response.Content)
        }
    }

    $watchtowerReadRoutes = @(
        "/watchtower/status",
        "/watchtower/modules",
        "/watchtower/dependencies",
        "/watchtower/events/recent?limit=1"
    )

    if ($WatchtowerServiceToken) {
        $headers = New-BearerHeaders $WatchtowerServiceToken

        foreach ($path in $watchtowerReadRoutes) {
            $response = Invoke-S43Request -BaseUrl $WatchtowerUrl -Path $path -Headers $headers -Session $script:AnonymousSession

            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Add-Result -Outcome "PASS" -Category "WATCH" -Mode "service-read" -Method "GET" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail "service-token route completed"
            }
            else {
                Add-Result -Outcome "FAIL" -Category "WATCH" -Mode "service-read" -Method "GET" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail (Get-BodyPreview $response.Content)
            }
        }
    }
    else {
        foreach ($path in $watchtowerReadRoutes) {
            $response = Invoke-S43Request -BaseUrl $WatchtowerUrl -Path $path -Session $script:AnonymousSession
            if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403) {
                Add-Result -Outcome "PASS" -Category "WATCH" -Mode "service-auth-boundary" -Method "GET" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail "anonymous request rejected; service token not supplied"
            }
            elseif ($response.StatusCode -ge 500) {
                Add-Result -Outcome "FAIL" -Category "WATCH" -Mode "service-auth-boundary" -Method "GET" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail (Get-BodyPreview $response.Content)
            }
            else {
                Add-Result -Outcome "WARN" -Category "WATCH" -Mode "service-auth-boundary" -Method "GET" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail "Watchtower service token not supplied"
            }
        }
    }

    foreach ($path in @(
        "/watchtower/modules/register",
        "/watchtower/modules/heartbeat",
        "/watchtower/dependencies/report",
        "/watchtower/analyze"
    )) {
        $response = Invoke-S43Request -BaseUrl $WatchtowerUrl -Method "POST" -Path $path -Session $script:AnonymousSession

        if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 422) {
            Add-Result -Outcome "PASS" -Category "WATCH" -Mode "mutation-guard" -Method "POST" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail "mutation safely rejected without service authority/input"
        }
        elseif ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
            Add-Result -Outcome "FAIL" -Category "WATCH" -Mode "mutation-guard" -Method "POST" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail "unexpected anonymous Watchtower mutation success"
        }
        else {
            Add-Result -Outcome "FAIL" -Category "WATCH" -Mode "mutation-guard" -Method "POST" -Path $path -StatusCode $response.StatusCode -DurationMs $response.DurationMs -Detail (Get-BodyPreview $response.Content)
        }
    }
}

function Write-S43Report {
    param(
        [int]$RegisteredRouteCount = 0,
        [int]$RegisteredMethodCount = 0
    )

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Sentinel-43 endpoint test summary" -ForegroundColor Cyan
    Write-Host "Target:              $ApiUrl"
    Write-Host "Registered routes:   $RegisteredRouteCount"
    Write-Host "Registered methods:  $RegisteredMethodCount"
    Write-Host "Passed:              $script:PassCount" -ForegroundColor Green
    Write-Host "Warnings:            $script:WarnCount" -ForegroundColor Yellow
    Write-Host "Failed:              $script:FailCount" -ForegroundColor $(if ($script:FailCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Skipped:             $script:SkipCount" -ForegroundColor DarkGray

    if ($script:FailCount -gt 0) {
        Write-Host ""
        Write-Host "Failures:" -ForegroundColor Red
        $script:Results |
            Where-Object Outcome -eq "FAIL" |
            ForEach-Object {
                Write-Host ("  {0} {1} -> {2} {3}" -f $_.Method, $_.Path, $_.StatusCode, $_.Detail) -ForegroundColor Red
            }
    }

    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        $report = [ordered]@{
            generated_at_utc       = [DateTimeOffset]::UtcNow.ToString("o")
            api_url                = $ApiUrl
            watchtower_url         = $WatchtowerUrl
            registered_route_count = $RegisteredRouteCount
            registered_method_count = $RegisteredMethodCount
            summary                = [ordered]@{
                passed   = $script:PassCount
                warnings = $script:WarnCount
                failed   = $script:FailCount
                skipped  = $script:SkipCount
            }
            results                = $script:Results
        }

        $report | ConvertTo-Json -Depth 12 | Set-Content -Path $ReportPath -Encoding UTF8
        Write-Host ""
        Write-Host "JSON report: $ReportPath" -ForegroundColor Cyan
    }
}

try {
    Write-Host ""
    Write-Host "Sentinel-43 Comprehensive Endpoint + Health Checks" -ForegroundColor Cyan
    Write-Host "API target: $ApiUrl"

    # -------------------------------------------------------------------------
    # Public health / readiness
    # -------------------------------------------------------------------------
    Write-Section "API health and readiness"

    Test-HealthEndpoint -Path "/health" -Kind "health"
    Test-HealthEndpoint -Path "/ready" -Kind "readiness"
    Test-HealthEndpoint -Path "/audit/health" -Kind "health"
    Test-HealthEndpoint -Path "/bootstrap/status" -Kind "bootstrap"

    if ($PublicOnly) {
        Add-Result -Outcome "SKIP" -Category "AUTH" -Mode "public-only" -Method "GET" -Path "/system/routes" -Detail "PublicOnly selected; authenticated route sweep intentionally skipped"
        Test-DirectWatchtower
        Write-S43Report
        if ($script:FailCount -gt 0) { exit 1 }
        exit 0
    }

    # -------------------------------------------------------------------------
    # Operator login / session verification
    # -------------------------------------------------------------------------
    Write-Section "Operator session"

    $effectiveCredential = Get-EffectiveCredential

    if ($null -eq $effectiveCredential) {
        Add-Result -Outcome "FAIL" -Category "AUTH" -Mode "session" -Method "POST" -Path "/auth/login" -Detail "operator credentials required for full endpoint sweep; pass -Credential or set S43_LIVE_TEST_USERNAME/S43_LIVE_TEST_PASSWORD"
        Test-DirectWatchtower
        Write-S43Report
        exit 1
    }

    $username = $effectiveCredential.UserName
    $password = $effectiveCredential.GetNetworkCredential().Password

    $login = Invoke-S43Request -Method "POST" -Path "/auth/login" -Body @{
        username = $username
        password = $password
    } -Session $script:AuthenticatedSession

    # Do not retain an extra plaintext copy after the login request.
    $password = $null

    if ($login.StatusCode -ne 200) {
        Add-Result -Outcome "FAIL" -Category "AUTH" -Mode "session" -Method "POST" -Path "/auth/login" -StatusCode $login.StatusCode -DurationMs $login.DurationMs -Detail (Get-BodyPreview $login.Content)
        Test-DirectWatchtower
        Write-S43Report
        exit 1
    }

    $loginBody = ConvertFrom-S43Json -Response $login -Context "/auth/login"
    $operatorToken = ""

    if ($loginBody.access_token) {
        $operatorToken = [string]$loginBody.access_token
    }
    elseif ($loginBody.token) {
        $operatorToken = [string]$loginBody.token
    }

    if ([string]::IsNullOrWhiteSpace($operatorToken)) {
        Add-Result -Outcome "FAIL" -Category "AUTH" -Mode "session" -Method "POST" -Path "/auth/login" -StatusCode 200 -DurationMs $login.DurationMs -Detail "login response contained no access_token/token"
        Test-DirectWatchtower
        Write-S43Report
        exit 1
    }

    Add-Result -Outcome "PASS" -Category "AUTH" -Mode "session" -Method "POST" -Path "/auth/login" -StatusCode 200 -DurationMs $login.DurationMs -Detail "session-bound access token issued"

    $operatorHeaders = New-BearerHeaders $operatorToken

    $verify = Invoke-S43Request -Path "/auth/verify" -Headers $operatorHeaders -Session $script:AuthenticatedSession

    if ($verify.StatusCode -eq 200) {
        $verifyBody = ConvertFrom-S43Json -Response $verify -Context "/auth/verify"
        if ($verifyBody.valid -eq $false) {
            Add-Result -Outcome "FAIL" -Category "AUTH" -Mode "session" -Method "GET" -Path "/auth/verify" -StatusCode 200 -DurationMs $verify.DurationMs -Detail "verify endpoint returned valid=false"
        }
        else {
            Add-Result -Outcome "PASS" -Category "AUTH" -Mode "session" -Method "GET" -Path "/auth/verify" -StatusCode 200 -DurationMs $verify.DurationMs -Detail "access token verified"
        }
    }
    else {
        Add-Result -Outcome "FAIL" -Category "AUTH" -Mode "session" -Method "GET" -Path "/auth/verify" -StatusCode $verify.StatusCode -DurationMs $verify.DurationMs -Detail (Get-BodyPreview $verify.Content)
    }

    # -------------------------------------------------------------------------
    # Discover the live route surface
    # -------------------------------------------------------------------------
    Write-Section "Live registered API routes"

    $routesResponse = Invoke-S43Request -Path "/system/routes" -Headers $operatorHeaders -Session $script:AuthenticatedSession

    if ($routesResponse.StatusCode -ne 200) {
        Add-Result -Outcome "FAIL" -Category "ROUTES" -Mode "discovery" -Method "GET" -Path "/system/routes" -StatusCode $routesResponse.StatusCode -DurationMs $routesResponse.DurationMs -Detail (Get-BodyPreview $routesResponse.Content)
        Test-S43WebSocket -OperatorToken $operatorToken
        Test-DirectWatchtower
        Write-S43Report
        exit 1
    }

    $routeData = ConvertFrom-S43Json -Response $routesResponse -Context "/system/routes"
    $registeredRoutes = @($routeData.routes)
    $reportedRouteCount = [int]$routeData.route_count

    if ($registeredRoutes.Count -ne $reportedRouteCount) {
        Add-Result -Outcome "FAIL" -Category "ROUTES" -Mode "discovery" -Method "GET" -Path "/system/routes" -StatusCode 200 -DurationMs $routesResponse.DurationMs -Detail "route_count=$reportedRouteCount but routes array contains $($registeredRoutes.Count)"
    }
    else {
        Add-Result -Outcome "PASS" -Category "ROUTES" -Mode "discovery" -Method "GET" -Path "/system/routes" -StatusCode 200 -DurationMs $routesResponse.DurationMs -Detail "$reportedRouteCount registered routes discovered"
    }

    $registeredMethodCount = 0
    $webSocketRegistered = $false

    foreach ($route in ($registeredRoutes | Sort-Object path)) {
        $template = [string]$route.path
        $methods = @($route.methods | Where-Object { $_ })

        if ($methods.Count -eq 0) {
            if ($template -eq "/ws") {
                $webSocketRegistered = $true
                continue
            }

            Add-Result -Outcome "SKIP" -Category "ROUTE" -Mode "mount/non-http" -Method "-" -Path $template -Detail "registered mount or non-HTTP route"
            continue
        }

        foreach ($method in ($methods | Sort-Object -Unique)) {
            $upperMethod = ([string]$method).ToUpperInvariant()

            if ($upperMethod -eq "OPTIONS") {
                Add-Result -Outcome "SKIP" -Category "ROUTE" -Mode "cors-preflight" -Method $upperMethod -Path $template -Detail "OPTIONS is framework/CORS plumbing, not a business endpoint"
                continue
            }

            $registeredMethodCount++

            if ($upperMethod -eq "GET" -or $upperMethod -eq "HEAD") {
                Test-ReadRoute -Method $upperMethod -Template $template -OperatorToken $operatorToken
            }
            elseif ($upperMethod -in @("POST", "PUT", "PATCH", "DELETE")) {
                Test-MutationGuard -Method $upperMethod -Template $template
            }
            else {
                Add-Result -Outcome "WARN" -Category "ROUTE" -Mode "unknown-method" -Method $upperMethod -Path $template -Detail "registered method not handled by the harness"
            }
        }
    }

    # -------------------------------------------------------------------------
    # WebSocket
    # -------------------------------------------------------------------------
    Write-Section "WebSocket"

    if ($webSocketRegistered) {
        Test-S43WebSocket -OperatorToken $operatorToken
    }
    else {
        Add-Result -Outcome "FAIL" -Category "WS" -Mode "registration" -Method "WS" -Path "/ws" -Detail "/ws missing from live route inventory"
    }

    # -------------------------------------------------------------------------
    # Optional direct Watchtower
    # -------------------------------------------------------------------------
    Test-DirectWatchtower

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    Write-S43Report -RegisteredRouteCount $reportedRouteCount -RegisteredMethodCount $registeredMethodCount

    if ($script:FailCount -gt 0) {
        exit 1
    }

    exit 0
}
finally {
    Restore-S43TlsState
}
