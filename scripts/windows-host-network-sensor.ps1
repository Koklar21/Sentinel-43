param(
    [string]$ApiUrl = $env:S43_HOST_NETWORK_API_URL,
    [string]$Token = $env:S43_HOST_NETWORK_INGEST_TOKEN,
    [int]$PollSeconds = 2,
    [int]$MaxEventsPerSecond = 200
)

$ErrorActionPreference = "Stop"
if (-not $ApiUrl -or -not $Token) { throw "S43_HOST_NETWORK_API_URL and S43_HOST_NETWORK_INGEST_TOKEN are required" }
if ($PollSeconds -lt 1 -or $PollSeconds -gt 60) { throw "PollSeconds must be 1..60" }
if ($MaxEventsPerSecond -lt 1 -or $MaxEventsPerSecond -gt 1000) { throw "MaxEventsPerSecond must be 1..1000" }

$hostIp = (Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
    Sort-Object InterfaceMetric |
    Select-Object -First 1 -ExpandProperty IPAddress)
if (-not $hostIp) { throw "No preferred non-loopback IPv4 address found" }

$seen = @{}
$headers = @{ Authorization = "Bearer $Token" }

while ($true) {
    $windowStart = [DateTime]::UtcNow
    $emitted = 0
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin @("0.0.0.0","::","127.0.0.1","::1") }

    foreach ($c in $connections) {
        if ($emitted -ge $MaxEventsPerSecond) { break }
        $key = "$($c.LocalAddress)|$($c.LocalPort)|$($c.RemoteAddress)|$($c.RemotePort)|$($c.OwningProcess)|$($c.State)"
        if ($seen.ContainsKey($key)) { continue }

        $processName = ""
        try { $processName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch {}
        # Get-NetTCPConnection does not expose connection direction. Do not infer it
        # from ephemeral-port ranges: services can use high ports and clients can
        # bind low ports. "unknown" preserves the observation without inventing fact.
        $direction = "unknown"

        $body = @{
            event_id = [guid]::NewGuid().ToString()
            host_ip = $hostIp
            direction = $direction
            protocol = "tcp"
            local_ip = $c.LocalAddress
            local_port = [int]$c.LocalPort
            remote_ip = $c.RemoteAddress
            remote_port = [int]$c.RemotePort
            process_id = [int]$c.OwningProcess
            process_name = $processName
            state = [string]$c.State
        } | ConvertTo-Json -Compress

        try {
            Invoke-RestMethod -Uri ($ApiUrl.TrimEnd("/") + "/internal/host-network/events") -Method Post -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 2 | Out-Null
            $seen[$key] = [DateTime]::UtcNow
            $emitted++
        } catch {
            Write-Warning "Host telemetry delivery failed; observation was not accepted: $($_.Exception.Message)"
        }
    }

    $cutoff = [DateTime]::UtcNow.AddMinutes(-15)
    @($seen.Keys) | ForEach-Object { if ($seen[$_] -lt $cutoff) { $seen.Remove($_) } }
    Start-Sleep -Seconds $PollSeconds
}
