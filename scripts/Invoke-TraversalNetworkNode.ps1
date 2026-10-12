param([Parameter(Mandatory)][string]$Configuration,[Parameter(Mandatory)][string]$Output)
$ErrorActionPreference='Stop'
$Configuration=[IO.Path]::GetFullPath($Configuration)
$Output=[IO.Path]::GetFullPath($Output)
if(Test-Path -LiteralPath $Output){throw 'Use a fresh output path; previous evidence is never overwritten.'}
$folder=Split-Path -Parent $Configuration
$node=Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
$rule='StreamLink-M4-Network-'+[guid]::NewGuid().ToString('N')
try {
 $hashes=@('StreamLink.MeshHarness.dll','StreamLink.Core.dll','StreamLink.Service.dll','components\udp2raw-native.exe','components\streamlink-tun.dll','components\wintun.dll','components\WinDivert.dll','components\WinDivert64.sys') | ForEach-Object {
  $path=Join-Path $folder $_
  if(Test-Path -LiteralPath $path){[pscustomobject]@{file=$_;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}}
 }
 [pscustomobject]@{planVersion='1.0';startedUtc=[DateTime]::UtcNow;os=[Environment]::OSVersion.VersionString;kind=$node.Kind;route=$node.Route;durationSeconds=$node.LifetimeSeconds;
  sourcePort=$node.SourcePort;reflectorPort=$node.ReflectorPort;loadMbps=$(if($null -eq $node.MeasureLoad -or $node.MeasureLoad){50}else{0});loadSeconds=$(if($null -eq $node.MeasureLoad -or $node.MeasureLoad){20}else{0});
  reflectedPortOffset=$node.ReflectedPortOffset;requireLearnedSource=$node.RequireLearnedSource;localHelper=$node.LocalHelper;controlOnlyOverExistingOverlay=$true;binaries=$hashes;
  adapters=@(Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed)
 } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ($Output+'.environment.json')
 if($node.Route -eq 'host') {
  $protocol=if($node.Kind -eq 'tcp'){'TCP'}else{'UDP'}
  New-NetFirewallRule -Name $rule -DisplayName $rule -Direction Inbound -Action Allow -Protocol $protocol -LocalAddress $node.Local -RemoteAddress $node.Peer -LocalPort @([string]$node.SourcePort,[string]$node.ReflectorPort) | Out-Null
 }
 & (Join-Path $folder 'StreamLink.MeshHarness.exe') traversal-run $Configuration $Output 2>&1 | Tee-Object -FilePath ($Output+'.log')
 if($LASTEXITCODE -ne 0){throw "Independent Wintun test exited $LASTEXITCODE"}
} catch {
 if(-not(Test-Path -LiteralPath $Output)){[pscustomobject]@{status='Fail';stage='harness/startup';error=$_.Exception.Message;log=$Output+'.log'} | ConvertTo-Json | Set-Content -LiteralPath $Output}
 throw
} finally { Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue }
