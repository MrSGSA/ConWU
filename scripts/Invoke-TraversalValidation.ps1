param([ValidateSet('Local')][string]$Profile='Local', [string]$OutputDirectory)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root ('artifacts\validation-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$results=[Collections.Generic.List[object]]::new()
$completed=$false
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
 Invoke-Check 'native-managed' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--managed',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--output',(Join-Path $OutputDirectory 'attach.json'))
 Invoke-Check 'native-negative' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--reject-attach',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--output',(Join-Path $OutputDirectory 'attach-negative.json'))
 Invoke-Check 'native-prepared-so' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--prepared-so',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--output',(Join-Path $OutputDirectory 'prepared-so.json'))
 Invoke-Check 'native-router' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--native-router',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--output',(Join-Path $OutputDirectory 'native-router.json'))
 Invoke-Check 'native-capture-broker' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--capture-broker',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','30','--output',(Join-Path $OutputDirectory 'capture-broker.json'))
 Invoke-Check 'native-tcp-source-learning' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--tcp-prflx',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','30','--output',(Join-Path $OutputDirectory 'tcp-source-learning.json'))
 Invoke-Check 'native-port-window' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--port-window',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','30','--output',(Join-Path $OutputDirectory 'native-port-window.json'))
 Invoke-Check 'native-port-window-wide' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--port-window-wide',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--output',(Join-Path $OutputDirectory 'native-port-window-wide.json'))
 Invoke-Check 'native-path-timeout' 'dotnet' @('run','--project','tests\StreamLink.EndpointPoc','-c','Release','--no-build','--','--path-timeout',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--output',(Join-Path $OutputDirectory 'native-timeout.json'))
 Invoke-Check 'protocol-profile' 'py' @('-3','tests\protocol_loopback.py','--output',(Join-Path $OutputDirectory 'protocol.json'))
 Invoke-Check 'mesh-watch' 'dotnet' @('run','--project','tests\StreamLink.MeshWatchTests','-c','Release','--','--output',(Join-Path $OutputDirectory 'watch.json'))
 Invoke-Check 'mesh-traversal-control' 'dotnet' @('run','--project','tests\StreamLink.MeshTraversalTests','-c','Release','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--output',(Join-Path $OutputDirectory 'traversal-control.json'))
 Invoke-Check 'mesh-runner-traversal' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','30','--output',(Join-Path $OutputDirectory 'runner-traversal.json'))
 Invoke-Check 'mesh-runner-udp-exploration' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','30','--output',(Join-Path $OutputDirectory 'runner-udp-exploration.json'),'--exploration-only')
 Invoke-Check 'mesh-runner-tcp-source-learning' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'runner-tcp-source-learning.json'),'--source-only')
 Invoke-Check 'tcp-endpoint-pool' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','30','--output',(Join-Path $OutputDirectory 'tcp-endpoint-pool.json'),'--pool-only')
 Invoke-Check 'mesh-runner-lifecycle' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'runner-lifecycle.json'),'--lifecycle-only')
 Invoke-Check 'native-wire-budget' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'wire-budget.json'),'--wire-only')
 Invoke-Check 'port-prediction-factory' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'prediction-factory.json'),'--prediction-only')
 Invoke-Check 'port-prediction-runner' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','30','--output',(Join-Path $OutputDirectory 'prediction-runner.json'),'--prediction-runner-only')
 Invoke-Check 'port-prediction-model' 'dotnet' @('run','--project','tests\StreamLink.PredictionTests','-c','Release','--','--output',(Join-Path $OutputDirectory 'prediction-model.json'))
 Invoke-Check 'tcp-shape-observer' 'dotnet' @('run','--project','tests\StreamLink.TcpObserverTests','-c','Release','--','--output',(Join-Path $OutputDirectory 'tcp-observer.json'))
 Invoke-Check 'mesh-nomination-model' 'dotnet' @('run','--project','tests\StreamLink.NominationTests','-c','Release','--','--output',(Join-Path $OutputDirectory 'nomination-model.json'))
 Invoke-Check 'mesh-connections' 'dotnet' @('run','--project','tests\StreamLink.MeshConnectionTests','-c','Release')
 Invoke-Check 'mesh-regression' 'dotnet' @('run','--project','tests\StreamLink.MeshTests','-c','Release')
 Invoke-Check 'managed-router' 'dotnet' @('run','--project','tests\StreamLink.ManagedPathTests','-c','Release','--','--output',(Join-Path $OutputDirectory 'managed-router.json'))
 Invoke-Check 'delivery-feedback-router' 'dotnet' @('run','--project','tests\StreamLink.ManagedPathTests','-c','Release','--no-build','--','--feedback-only','--output',(Join-Path $OutputDirectory 'delivery-feedback-router.json'))
 Invoke-Check 'standby-router' 'dotnet' @('run','--project','tests\StreamLink.ManagedPathTests','-c','Release','--no-build','--','--standby-only','--output',(Join-Path $OutputDirectory 'standby-router.json'))
 Invoke-Check 'diagnostic-control' 'dotnet' @('run','--project','tests\StreamLink.ManagedPathTests','-c','Release','--no-build','--','--diagnostic-control-only','--output',(Join-Path $OutputDirectory 'diagnostic-control.json'))
 Invoke-Check 'diagnostic-readiness' 'dotnet' @('run','--project','tests\StreamLink.ManagedPathTests','-c','Release','--no-build','--','--diagnostic-readiness-only','--output',(Join-Path $OutputDirectory 'diagnostic-readiness.json'))
 Invoke-Check 'diagnostic-session-model' 'dotnet' @('run','--project','tests\StreamLink.ManagedPathTests','-c','Release','--no-build','--','--diagnostic-session-model-only','--output',(Join-Path $OutputDirectory 'diagnostic-session-model.json'))
 Invoke-Check 'quality-assessment-model' 'dotnet' @('run','--project','tests\StreamLink.ManagedPathTests','-c','Release','--no-build','--','--quality-assessment-only','--output',(Join-Path $OutputDirectory 'quality-assessment-model.json'))
 Invoke-Check 'quality-agreement-model' 'dotnet' @('run','--project','tests\StreamLink.ManagedPathTests','-c','Release','--no-build','--','--quality-agreement-only','--output',(Join-Path $OutputDirectory 'quality-agreement-model.json'))
 foreach($case in @('quality-udp-retain','quality-native-benefit','quality-native-fault')){
  Invoke-Check $case 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory "$case.json"),"--$case-only")
 }
 Invoke-Check 'diagnostic-udp-product' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'diagnostic-udp-product.json'),'--diagnostic-runner-only')
 Invoke-Check 'diagnostic-native-product' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'diagnostic-native-product.json'),'--native-diagnostic-runner-only')
 Invoke-Check 'diagnostic-business-protection' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'diagnostic-business-protection.json'),'--diagnostic-busy-only')
 Invoke-Check 'standby-native-runner' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'standby-native-runner.json'),'--standby-only')
 Invoke-Check 'standby-udp-runner' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'standby-udp-runner.json'),'--udp-standby-only')
 Invoke-Check 'delivery-feedback-runner' 'dotnet' @('run','--project','tests\StreamLink.MeshRunnerTraversalTests','-c','Release','--no-build','--','--native',(Join-Path $root 'out\native\udp2raw-protocol-test.exe'),'--rounds','1','--output',(Join-Path $OutputDirectory 'delivery-feedback-runner.json'),'--feedback-only')
 Invoke-Check 'udp-foundation' 'dotnet' @('run','--project','tests\StreamLink.TraversalTests','-c','Release')
 Invoke-Check 'shared-enhancement-admission' 'dotnet' @('run','--project','tests\StreamLink.TraversalTests','-c','Release','--no-build','--','--enhancement',(Join-Path $OutputDirectory 'enhancement-admission.json'))
 Invoke-Check 'udp-managed' 'dotnet' @('run','--project','tests\StreamLink.TraversalTests','-c','Release','--no-build','--','--managed',(Join-Path $OutputDirectory 'udp-managed.json'))
 Invoke-Check 'udp-exploration' 'dotnet' @('run','--project','tests\StreamLink.TraversalTests','-c','Release','--no-build','--','--probability',(Join-Path $OutputDirectory 'udp-exploration.json'))
 Invoke-Check 'udp-exploration-boundaries' 'dotnet' @('run','--project','tests\StreamLink.TraversalTests','-c','Release','--no-build','--','--probability-boundaries',(Join-Path $OutputDirectory 'udp-exploration-boundaries.json'))
 Invoke-Check 'udp-exploration-intersection-model' 'dotnet' @('run','--project','tests\StreamLink.TraversalTests','-c','Release','--no-build','--','--probability-model',(Join-Path $OutputDirectory 'udp-exploration-model.json'))
 Invoke-Check 'egress-correctness' 'dotnet' @('run','--project','tests\StreamLink.EgressTests','-c','Release','--',(Join-Path $OutputDirectory 'egress-correctness.json'),'--correctness-only')
 $completed=$true
} finally {
 $hashes=@('out\native\udp2raw-native.exe','out\native\udp2raw-protocol-test.exe') | Where-Object {Test-Path -LiteralPath $_} | ForEach-Object {
   [pscustomobject]@{path=$_;sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}
 }
 $status=if($completed -and @($results|Where-Object status -eq 'Fail').Count -eq 0){'Pass'}else{'Fail'}
 [pscustomobject]@{planVersion='1.0';profile=$Profile;status=$status;sourceCommit=$commit;dirty=$dirty;os=[Environment]::OSVersion.VersionString;native=$hashes;results=$results;
   gate='Local only: no driver, no NAT, no release claim';remainingGates=@('M1 controlled two-Windows 30 rounds and WAN','M2 SO + business','M3 product integration','M4 Wintun UDP_DIRECT','M5-M9')} |
   ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json')
 Pop-Location
}
Write-Output "Local validation $status. Manifest: $(Join-Path $OutputDirectory 'manifest.json')"
