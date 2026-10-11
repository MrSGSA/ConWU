param([ValidateSet('Local')][string]$Profile='Local', [string]$OutputDirectory)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root ('artifacts\validation-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$results=[Collections.Generic.List[object]]::new()
Push-Location $root
try {
 $commit=(& git rev-parse HEAD).Trim()
 $dirty=[bool](& git status --porcelain)
 function Invoke-Check([string]$Name,[string]$Program,[string[]]$Arguments){
  $watch=[Diagnostics.Stopwatch]::StartNew()
  $log=Join-Path $OutputDirectory ($Name+'.txt')
  & $Program @Arguments *> $log
  $code=$LASTEXITCODE
  $results.Add([pscustomobject]@{name=$Name;exitCode=$code;status=$(if($code -eq 0){'Pass'}else{'Fail'});elapsedMs=$watch.ElapsedMilliseconds;log=$log;command=@($Program)+$Arguments})
  if($code -ne 0){throw "$Name failed with exit $code; see $log"}
 }
 # Rebuild before evidence collection. The test backend never loads WinDivert.
 Invoke-Check 'native-build' 'pwsh' @('-NoProfile','-File','scripts\Build.ps1')
 Invoke-Check 'endpoint-lifetime' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--','--output',(Join-Path $OutputDirectory 'lease.json'))
 Invoke-Check 'native-managed' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--managed','out\native\udp2raw-protocol-test.exe','--output',(Join-Path $OutputDirectory 'attach.json'))
 Invoke-Check 'native-negative' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--reject-attach','out\native\udp2raw-protocol-test.exe','--output',(Join-Path $OutputDirectory 'attach-negative.json'))
 Invoke-Check 'protocol-profile' 'py' @('-3','tests\protocol_loopback.py','--output',(Join-Path $OutputDirectory 'protocol.json'))
} finally {
 $hashes=@('out\native\udp2raw-native.exe','out\native\udp2raw-protocol-test.exe') | Where-Object {Test-Path -LiteralPath $_} | ForEach-Object {
   [pscustomobject]@{path=$_;sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
 }
 $status=if($results.Count -eq 5 -and @($results|Where-Object status -eq 'Fail').Count -eq 0){'Pass'}else{'Fail'}
 [pscustomobject]@{planVersion='1.0';profile=$Profile;status=$status;sourceCommit=$commit;dirty=$dirty;os=[Environment]::OSVersion.VersionString;native=$hashes;results=$results;
   gate='Local only: no driver, no NAT, no release claim';remainingGates=@('M1 controlled two-Windows 30 rounds and WAN','M2 SO + business','M3 product integration','M4 Wintun UDP_DIRECT','M5-M9')} |
   ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json')
 Pop-Location
}
Write-Output "Local validation $status. Manifest: $(Join-Path $OutputDirectory 'manifest.json')"
