# =============================================================================
# Sentinel-43 - universal network-edge deployment orchestrator
#
# Standalone/manual by design. This script is NOT wired into bootstrap or
# Docker-file generation. Edge devices remain evidence-only telemetry sources.
#
# Pipeline: identify -> fetch -> configure -> deploy -> verify -> report
# =============================================================================

[CmdletBinding()]
param(
    [ValidateSet("Deploy", "Identify", "Status", "Listen", "Test", "Disable")]
    [string]$Mode = "Deploy",

    [string[]]$EdgeSource = @(),
    [ValidateRange(1, 65535)][int]$SyslogPort = 5514,
    [ValidateRange(1, 1000)][int]$MaxEventsPerSecond = 50,
    [string]$ListenAddress = "0.0.0.0",
    [string]$ApiUrl = "https://localhost/internal/router/events",
    [string]$CaCert = "deploy/proxy/certs/s43.crt",
    [switch]$RegenerateToken,
    [switch]$SkipFirewall,
    [switch]$NoRestart,
    [switch]$StartCollector,
    [switch]$InternetFacingCheck
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$EnvPath = Join-Path $RepoRoot ".env"
$CollectorPath = Join-Path $RepoRoot "scripts\router_syslog_collector.py"
$FirewallRuleName = "Sentinel-43 Edge Telemetry"

function Write-Step([string]$Name) { Write-Host ""; Write-Host "== $Name ==" -ForegroundColor Cyan }
function Test-Admin {
    if (-not $IsWindows -and $PSVersionTable.PSEdition -eq "Core") { return $true }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-PythonCommand {
    foreach ($name in @("python", "py")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    throw "Python was not found on PATH."
}
function Test-IpAddress([string]$Value) {
    $parsed = $null
    return [Net.IPAddress]::TryParse($Value, [ref]$parsed)
}
function Read-Env([string]$Path) {
    $values = @{}; $dupes = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { continue }
        $key=$matches[1]; $value=$matches[2]
        if ($values.ContainsKey($key)) { $dupes += $key } else { $values[$key]=$value }
    }
    if ($dupes.Count) { throw "Duplicate .env key(s): $(($dupes|Sort-Object -Unique)-join ', ')" }
    return $values
}
function Get-EnvLines {
    $lines=[Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -LiteralPath $EnvPath) { [void]$lines.Add([string]$line) }
    return ,$lines
}
function Set-EnvValue {
    param([Collections.Generic.List[string]]$Lines,[string]$Key,[AllowEmptyString()][string]$Value)
    $pattern='^\s*'+[regex]::Escape($Key)+'='; $found=$false
    for($i=0;$i-lt$Lines.Count;$i++){
        if($Lines[$i]-match$pattern){
            if($found){throw "Duplicate .env key while updating: $Key"}
            $Lines[$i]="$Key=$Value"; $found=$true
        }
    }
    if(-not$found){
        if($Lines.Count-and$Lines[$Lines.Count-1]-ne""){[void]$Lines.Add("")}
        [void]$Lines.Add("$Key=$Value")
    }
}
function Write-EnvAtomic([Collections.Generic.List[string]]$Lines) {
    $encoding=New-Object Text.UTF8Encoding($false)
    $text=($Lines-join[Environment]::NewLine).TrimEnd()+[Environment]::NewLine
    $tmp="$EnvPath.s43-edge.tmp"; [IO.File]::WriteAllText($tmp,$text,$encoding)
    [IO.File]::Replace($tmp,$EnvPath,"$EnvPath.s43-edge.bak",$true)
}
function New-IngestToken {
    $bytes=New-Object byte[] 32; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function Get-NetworkIdentity {
    $result=[ordered]@{ Gateways=@(); HostIPv4=@(); HostIPv6=@(); Dns=@(); Interfaces=@() }
    if($IsWindows -or $PSVersionTable.PSEdition -eq "Desktop"){
        $routes=Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Where-Object {$_.NextHop -and $_.NextHop-ne"0.0.0.0"} | Sort-Object RouteMetric,InterfaceMetric
        $result.Gateways=@($routes|Select-Object -ExpandProperty NextHop -Unique)
        $ips=Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object {$_.AddressState-eq"Preferred"}
        $result.HostIPv4=@($ips|Where-Object {$_.AddressFamily-eq"IPv4"-and$_.IPAddress-notlike"127.*"-and$_.IPAddress-notlike"169.254.*"}|Select-Object -ExpandProperty IPAddress -Unique)
        $result.HostIPv6=@($ips|Where-Object {$_.AddressFamily-eq"IPv6"-and$_.IPAddress-notlike"fe80:*"-and$_.IPAddress-ne"::1"}|Select-Object -ExpandProperty IPAddress -Unique)
        $result.Interfaces=@(Get-NetAdapter -ErrorAction SilentlyContinue|Where-Object Status-eq"Up"|Select-Object -ExpandProperty Name)
        $result.Dns=@(Get-DnsClientServerAddress -ErrorAction SilentlyContinue|ForEach-Object ServerAddresses|Where-Object{$_}|Select-Object -Unique)
    }
    return [pscustomobject]$result
}
function Get-EdgeFingerprint([string[]]$Sources) {
    $items=@()
    foreach($ip in $Sources){
        $mac=""; $name=""
        if($IsWindows -or $PSVersionTable.PSEdition-eq"Desktop"){
            $n=Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue|Select-Object -First 1
            if($n){$mac=$n.LinkLayerAddress}
        }
        try{$name=([Net.Dns]::GetHostEntry($ip)).HostName}catch{}
        $items += [pscustomobject]@{Address=$ip;HostName=$name;Mac=$mac}
    }
    return $items
}
function Resolve-TrustedSources($Network,[string[]]$Requested) {
    $sources=@($Requested|Where-Object{$_}|Select-Object -Unique)
    if(-not$sources.Count){$sources=@($Network.Gateways)}
    if(-not$sources.Count){throw "No network edge/default gateway could be identified. Supply -EdgeSource explicitly."}
    foreach($ip in $sources){if(-not(Test-IpAddress $ip)){throw "Invalid edge source address: $ip"}}
    return $sources
}
function Test-PortOwner([int]$Port) {
    if(Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue){
        $ep=Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue|Select-Object -First 1
        if($ep){
            $proc=Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue
            return [pscustomobject]@{Pid=$ep.OwningProcess;Name=$proc.ProcessName;Address=$ep.LocalAddress}
        }
    }
    return $null
}
function Set-EdgeFirewall([string[]]$Sources,[int]$Port) {
    if($SkipFirewall){return}
    if(-not(Test-Admin)){throw "Administrator privileges are required to configure the Windows firewall."}
    if(-not(Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)){throw "Windows Firewall cmdlets are unavailable."}
    Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction Stop
    New-NetFirewallRule -DisplayName $FirewallRuleName -Direction Inbound -Action Allow -Protocol UDP -LocalPort $Port -RemoteAddress $Sources -Profile Any -ErrorAction Stop|Out-Null
    $rule=Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction Stop
    $port=$rule|Get-NetFirewallPortFilter
    if($rule.Enabled-ne"True"-or$port.LocalPort-ne[string]$Port-or$port.Protocol-ne"UDP"){throw "Firewall rule verification failed."}
}
function Save-Configuration([string[]]$Sources) {
    $current=Read-Env $EnvPath
    $token=[string]$current["S43_ROUTER_INGEST_TOKEN"]
    if($RegenerateToken-or[string]::IsNullOrWhiteSpace($token)-or$token.Length-lt32-or$token-in@("CHANGE_ME","CHANGEME","replace-me")){$token=New-IngestToken}
    $lines=Get-EnvLines
    # Legacy singular source is retained for server compatibility. The universal
    # collector consumes the comma-separated trusted-source set.
    Set-EnvValue $lines "S43_ROUTER_ENABLED" "true"
    Set-EnvValue $lines "S43_ROUTER_INGEST_TOKEN" $token
    Set-EnvValue $lines "S43_ROUTER_SOURCE_IP" $Sources[0]
    Set-EnvValue $lines "S43_EDGE_SOURCE_IPS" ($Sources-join",")
    Set-EnvValue $lines "S43_ROUTER_LISTEN_ADDRESS" $ListenAddress
    Set-EnvValue $lines "S43_ROUTER_SYSLOG_PORT" ([string]$SyslogPort)
    Set-EnvValue $lines "S43_ROUTER_MAX_EVENTS_PER_SECOND" ([string]$MaxEventsPerSecond)
    Set-EnvValue $lines "S43_ROUTER_API_URL" $ApiUrl
    Set-EnvValue $lines "S43_ROUTER_CA_CERT" $CaCert
    Write-EnvAtomic $lines
    $verify=Read-Env $EnvPath
    $expected=@{
        S43_ROUTER_ENABLED="true"; S43_ROUTER_SOURCE_IP=$Sources[0]; S43_EDGE_SOURCE_IPS=($Sources-join",");
        S43_ROUTER_LISTEN_ADDRESS=$ListenAddress; S43_ROUTER_SYSLOG_PORT=[string]$SyslogPort;
        S43_ROUTER_MAX_EVENTS_PER_SECOND=[string]$MaxEventsPerSecond; S43_ROUTER_API_URL=$ApiUrl; S43_ROUTER_CA_CERT=$CaCert
    }
    foreach($key in $expected.Keys){if([string]$verify[$key]-ne[string]$expected[$key]){throw "Configuration read-back failed for $key"}}
    if(([string]$verify["S43_ROUTER_INGEST_TOKEN"]).Length-lt32){throw "Ingest credential read-back failed."}
}
function Restart-Ingress {
    if($NoRestart){return}
    Push-Location $RepoRoot
    try{
        docker compose --env-file $EnvPath config --quiet
        if($LASTEXITCODE-ne0){throw "Docker Compose validation failed."}
        docker compose --env-file $EnvPath up -d --force-recreate s43-api
        if($LASTEXITCODE-ne0){throw "s43-api recreation failed."}
    }finally{Pop-Location}
}
function Test-Ingress {
    $python=Get-PythonCommand
    Push-Location $RepoRoot
    try{
        & $python $CollectorPath --env-file $EnvPath --test-event "edge deployment verification observation"
        if($LASTEXITCODE-ne0){throw "Authenticated S43 edge-ingress verification failed."}
    }finally{Pop-Location}
}
function Start-Collector {
    $owner=Test-PortOwner $SyslogPort
    if($owner){
        $proc=Get-CimInstance Win32_Process -Filter "ProcessId = $($owner.Pid)" -ErrorAction SilentlyContinue
        if(-not $proc -or [string]::IsNullOrWhiteSpace([string]$proc.CommandLine) -or $proc.CommandLine -notmatch [regex]::Escape($CollectorPath)){
            throw "Port conflict: UDP $SyslogPort is owned by PID $($owner.Pid) ($($owner.Name)), not the Sentinel-43 edge collector."
        }
        Write-Host "Collector/listener already owns UDP $SyslogPort (PID $($owner.Pid), $($owner.Name)); not starting a duplicate."
        return
    }
    $python=Get-PythonCommand
    Start-Process -FilePath $python -ArgumentList @($CollectorPath,"--env-file",$EnvPath) -WorkingDirectory $RepoRoot
    Start-Sleep -Seconds 1
    if(-not(Test-PortOwner $SyslogPort)){throw "Collector did not bind UDP $SyslogPort."}
}
function Test-InternetPosture {
    $env=Read-Env $EnvPath; $issues=@()
    if(([string]$env["SENTINEL_ENV"]).ToLower()-notin@("production","prod")){$issues+="SENTINEL_ENV is not production"}
    if(-not$env["S43_TRUSTED_HOSTS"]){$issues+="S43_TRUSTED_HOSTS is missing"}
    if(-not$env["S43_ALLOWED_ORIGINS"]){$issues+="S43_ALLOWED_ORIGINS is missing"}
    if(([string]$env["S43_TLS_TERMINATED_AT_TRUSTED_EDGE"]).ToLower()-ne"true"){$issues+="trusted-edge TLS assertion is not enabled"}
    if(-not(Test-Path (Join-Path $RepoRoot $CaCert)) -and -not(Test-Path $CaCert)){$issues+="configured CA certificate is missing"}
    return $issues
}
function Show-Status {
    $v=Read-Env $EnvPath; $token=if(([string]$v["S43_ROUTER_INGEST_TOKEN"]).Length-ge32){"configured"}else{"missing"}
    Write-Host "Sentinel-43 universal edge telemetry"
    Write-Host "  enabled: $($v['S43_ROUTER_ENABLED'])"
    Write-Host "  sources: $($v['S43_EDGE_SOURCE_IPS'])"
    Write-Host "  listen:  $($v['S43_ROUTER_LISTEN_ADDRESS']):$($v['S43_ROUTER_SYSLOG_PORT'])/udp"
    Write-Host "  api:     $($v['S43_ROUTER_API_URL'])"
    Write-Host "  token:   $token"
    $statusPort=[string]$v["S43_ROUTER_SYSLOG_PORT"]
    if([string]::IsNullOrWhiteSpace($statusPort)){$statusPort=[string]$SyslogPort}
    $owner=Test-PortOwner ([int]$statusPort)
    if($owner){Write-Host "  listener: PID $($owner.Pid) $($owner.Name)"}else{Write-Host "  listener: stopped"}
}

if(-not(Test-Path $EnvPath)){throw ".env was not found."}
if(-not(Test-Path $CollectorPath)){throw "Edge collector was not found at $CollectorPath"}

switch($Mode){
"Identify"{
    Write-Step "IDENTIFY"; $net=Get-NetworkIdentity; $sources=Resolve-TrustedSources $net $EdgeSource
    $net|Format-List; Get-EdgeFingerprint $sources|Format-Table -AutoSize
}
"Deploy"{
    Write-Step "IDENTIFY"
    $net=Get-NetworkIdentity; $sources=Resolve-TrustedSources $net $EdgeSource
    Write-Host "Trusted edge source(s): $($sources-join', ')"
    Get-EdgeFingerprint $sources|Format-Table -AutoSize

    Write-Step "FETCH"
    Write-Host "Local edge identity/capabilities collected. Device-side configuration will only be claimed when a supported management interface is available."

    Write-Step "CONFIGURE"
    Save-Configuration $sources
    Set-EdgeFirewall $sources $SyslogPort
    Write-Host "Configuration persisted and read-back verified."

    Write-Step "DEPLOY"
    Restart-Ingress
    if($StartCollector){Start-Collector}else{Write-Host "Collector auto-start skipped; use -StartCollector when ready."}

    Write-Step "VERIFY"
    Test-Ingress
    if($InternetFacingCheck){
        $issues=Test-InternetPosture
        if($issues.Count){Write-Host "Internet-facing ACTION REQUIRED:" -ForegroundColor Yellow; $issues|ForEach-Object{Write-Host "  - $_"}}
        else{Write-Host "Internet-facing configuration prerequisites passed. No WAN port was opened."}
    }

    Write-Step "REPORT"
    Show-Status
    Write-Host "ACTION REQUIRED: configure each discovered edge device to send supported syslog/telemetry to this host on UDP $SyslogPort if its management interface cannot be configured programmatically." -ForegroundColor Yellow
}
"Listen"{
    $python=Get-PythonCommand; & $python $CollectorPath --env-file $EnvPath
    if($LASTEXITCODE-ne0){throw "Collector exited with code $LASTEXITCODE."}
}
"Test"{Test-Ingress}
"Status"{Show-Status}
"Disable"{
    $lines=Get-EnvLines; Set-EnvValue $lines "S43_ROUTER_ENABLED" "false"; Write-EnvAtomic $lines
    if(Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue){Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction Stop}
    Restart-Ingress; Write-Host "Edge telemetry disabled; ingest credential retained."
}
}
