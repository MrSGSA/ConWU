param(
    [Parameter(Mandatory)][string]$HostName,
    [Parameter(Mandatory)][string]$ObserverAddress,
    [Parameter(Mandatory)][string]$RemoteDirectory,
    [Parameter(Mandatory)][string]$WinDivert,
    [ValidateRange(1024,65535)][int]$FirstPort = 47221,
    [ValidateRange(1024,65535)][int]$SecondPort = 47222,
    [switch]$Fresh
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if ($HostName -notmatch '^[a-zA-Z0-9@.-]+$' -or $RemoteDirectory -notmatch '^/tmp/streamlink-[a-zA-Z0-9-]+$' -or $ObserverAddress -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'Unexpected SSH/observer argument' }
if (Get-NetTCPConnection -State Listen -LocalPort 43983 -ErrorAction SilentlyContinue) { throw 'Isolated control port already in use' }
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$prefix=Join-Path (Resolve-Path artifacts) "m5-observer-public-$stamp"
$client=Join-Path (Get-Location) 'tests/ConWU.TcpObserverTests/bin/Release/net10.0/ConWU.TcpObserverTests.dll'
$remoteCommand="cd $RemoteDirectory && timeout 160 ./StreamLink.TcpObserverTests --serve-syn $ObserverAddress $RemoteDirectory/followup-config.json $FirstPort $SecondPort"
$sshArgs="-o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -L 127.0.0.1:43983:127.0.0.1:43983 $HostName `"$remoteCommand`""
$forward=Start-Process ssh -ArgumentList $sshArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput "$prefix-server.log" -RedirectStandardError "$prefix-server-error.log"
try {
    $deadline=[DateTime]::UtcNow.AddSeconds(25)
    do {
        if ($forward.HasExited) { throw 'Isolated server/SSH exited before ready' }
        if ((Get-Content -LiteralPath "$prefix-server.log" -Raw -ErrorAction SilentlyContinue) -match 'Ready:') { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Isolated server readiness timed out' }
        Start-Sleep -Milliseconds 200
    } while ($true)
    & scp -q -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=yes "${HostName}:$RemoteDirectory/followup-config.json" "$prefix-config.json"
    if ($LASTEXITCODE -ne 0) { throw 'Failed to fetch isolated certificate pin' }
    $probeMode=if($Fresh){'--native-observe-fresh'}else{'--native-observe'}
    & dotnet $client $probeMode "$prefix-config.json" (Resolve-Path $WinDivert) "$prefix.json" fwa.lifesizecloud.com:3478 stun.nextcloud.com:3478 stun.sipnet.com:3478 > "$prefix-client.log" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Probe failed; see $prefix-client.log" }
    Get-Content -LiteralPath "$prefix.json"
} finally {
    # This is the temporary SSH child created here, never an installed service.
    # The remote observer also has a mandatory 150/160 second lifetime.
    if (!$forward.HasExited) { Stop-Process -Id $forward.Id -Force }
    $forward.Dispose()
    Write-Output "Evidence prefix: $prefix"
}
