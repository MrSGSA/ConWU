#requires -Version 7.0
param([Parameter(Mandatory)][string]$OutputDirectory,[string]$Version='1.0.1-rc.1',[ValidateSet('Full','InstallerRefresh','CandidateCore')][string]$Profile='Full')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a fresh evidence directory'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
Push-Location $repo
try {
 $commit=(& git rev-parse HEAD).Trim()
 $repeatRounds=if($Profile -eq 'Full'){'30'}else{'1'}
 if(@(& git status --porcelain).Count){throw 'Core verification requires a frozen clean source tree'}
 $rows=[Collections.Generic.List[object]]::new()
 function Run([string]$Name,[string]$Exe,[string[]]$Arguments,[int]$Seconds=300,[hashtable]$Environment=@{}) {
  $info=[Diagnostics.ProcessStartInfo]::new($Exe);$info.WorkingDirectory=$repo;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
  $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  foreach($a in $Arguments){$info.ArgumentList.Add($a)}
  foreach($key in $Environment.Keys){$info.Environment[$key]=$Environment[$key]}
  $clock=[Diagnostics.Stopwatch]::StartNew();$p=[Diagnostics.Process]::Start($info)
  $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync();$timeout=$false
  if(-not $p.WaitForExit($Seconds*1000)){$timeout=$true;$p.Kill($true);$p.WaitForExit(10000)|Out-Null}
  $code=if($timeout){124}else{$p.ExitCode}
  [IO.File]::WriteAllText((Join-Path $OutputDirectory "$Name.log"),$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult())
  $row=[ordered]@{name=$Name;exitCode=$code;timedOut=$timeout;seconds=$clock.Elapsed.TotalSeconds;status=$(if($code -eq 0){'Pass'}else{'Fail'});sourceCommit=$commit;log="$Name.log"}
  $rows.Add($row);$p.Dispose()
  $rows.ToArray()|ConvertTo-Json -Depth 6|Set-Content (Join-Path $OutputDirectory 'steps.partial.json') -Encoding utf8NoBOM
  Write-Output "$Name $($row.status)"
 }
 function Managed([string]$Name,[string[]]$Extra=@(),[int]$Seconds=300) {
  Run $Name 'dotnet' (@('run','--project',"tests/StreamLink.$Name",'-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--')+$Extra) $Seconds
 }
 $native=Join-Path $repo 'out/native/udp2raw-protocol-test.exe'
 Run 'native-parser' (Join-Path $repo 'out/native/udp2raw-parser-test.exe') @() 120 @{STREAMLINK_PARSER_CORPUS=(Join-Path $OutputDirectory 'parser-corpus.txt')}
 Run 'native-so-state' (Join-Path $repo 'out/native/native-so-state-test.exe') @()
 Managed 'NativeInputTests' @((Join-Path $OutputDirectory 'parser-corpus.txt'))
 foreach($name in @('Tests','PairingTests','WindowsTests','ConnectionTests','MappingTests','MeshTests','TraversalTests','MeshConnectionTests','MeshWatchTests','ControlTests','AdapterContractTests','Rc2PortableTests','QualityTests')){
  # This suite now also runs membership governance and creator-offline recovery.
  # Keep every case's own deadline; allow the sequential suite to finish.
  if($name -eq 'MeshConnectionTests'){Managed $name @() 600}else{Managed $name}
 }
 Run 'runner-retry-wake' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--network-wake-only',(Join-Path $OutputDirectory 'retry-wake.json'))
 Managed 'PersonalFeatureTests' @((Join-Path $OutputDirectory 'personal.json'))
 Managed 'RenderingTests' @((Join-Path $OutputDirectory 'tray/result.json'))
 Managed 'WebTests'
 Managed 'UnifiedHostTests'
 Managed 'ManagedPathTests' @('--output',(Join-Path $OutputDirectory 'managed.json'))
 Managed 'NominationTests' @('--output',(Join-Path $OutputDirectory 'nomination.json'))
 Managed 'MeshTraversalTests' @('--native',$native,'--output',(Join-Path $OutputDirectory 'mesh-traversal.json'))
 Managed 'TcpObserverTests' @('--output',(Join-Path $OutputDirectory 'observer.json'))
 Managed 'PredictionTests' @('--output',(Join-Path $OutputDirectory 'prediction-policy-only.json'))
 Managed 'HelperLedgerTests' @('--output',(Join-Path $OutputDirectory 'helper.json'))
 Managed 'EgressTests' @((Join-Path $OutputDirectory 'egress.json'),'--correctness-only')
 Run 'legacy-wire-native' 'py' @('-3','tests/legacy_wire_loopback.py','--output',(Join-Path $OutputDirectory 'legacy-native.json'))
 Managed 'LegacyWireTests' @('--native-report',(Join-Path $OutputDirectory 'legacy-native.json'),'--output',(Join-Path $OutputDirectory 'legacy-wire.json'))
 Managed 'LegacyControlTests' @('--native',$native,'--output',(Join-Path $OutputDirectory 'legacy-control.json'),'--rounds',$repeatRounds) 900
 Run 'mesh-native-wire' 'dotnet' @('run','--project','tests/StreamLink.MeshTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--raw',$native)
 Run 'direct-short-native' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--direct-short-native',$native,(Join-Path $OutputDirectory 'direct-short-native'))
 Run 'approval-invitation' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--approval-invitation-only')
 Run 'approval-guest-service' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--approval-guest-service')
 Run 'coordination-faults' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--coordination-faults')
 Run 'leave-timeouts' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--leave-timeout-only')
 Run 'saved-settings' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--saved-settings-only')
 Run 'control-lifecycle' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--control-lifecycle-only')
 Run 'connection-view' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--connection-view-only')
 Run 'ui-responsiveness' 'dotnet' @('run','--project','tests/StreamLink.WebTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--ui-responsiveness')
 Run 'direct-short-service' 'dotnet' @('run','--project','tests/StreamLink.MeshConnectionTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--direct-short-service')
 # Enabled personal paths: 30 SO/UDP deterministic rounds plus real factory
 # source-learning, resource cancellation, stale-network and failure cleanup.
 foreach($mode in @('baseline','source','network','shutdown-failure')) {
  $rounds=if($mode -eq 'baseline'){$repeatRounds}else{'1'}
  Run "runner-$mode" 'dotnet' @('run','--project','tests/StreamLink.MeshRunnerTraversalTests','-c','Release','-p:StreamLinkPersonalFeature=true',"-p:StreamLinkReleaseVersion=$Version",'--','--native',$native,'--rounds',$rounds,'--output',(Join-Path $OutputDirectory "runner-$mode.json"),"--$mode-only") 1500
 }
 Run 'browser' 'node' @('scripts/Test-AqBrowser.cjs',(Join-Path $OutputDirectory 'browser')) 180
 Run 'https-coordination' 'pwsh' @('-NoProfile','-File','scripts/Test-Coordination.ps1') 180 @{StreamLinkPersonalFeature='true';StreamLinkReleaseVersion=$Version}
 $dirty=@(& git status --porcelain).Count -gt 0 -or (& git rev-parse HEAD).Trim() -ne $commit
 $pass=@($rows|Where-Object status -eq 'Fail').Count -eq 0 -and -not $dirty
 [ordered]@{schemaVersion=1;spec='AQ-1';sourceCommit=$commit;sourceDirtyAfter=$dirty;version=$Version;profile=$Profile;legacyControlRounds=[int]$repeatRounds;runnerBaselineRounds=[int]$repeatRounds;fullThirtyRoundGate=$($Profile -eq 'Full');status=$(if($pass){'Pass'}else{'Fail'});steps=$rows.ToArray();
  scope='Frozen personal core, deterministic/native-loopback/actual Windows control + headless Edge. Separate bundle/official-driver/SCM results required; physical WAN and user streaming not claimed.';
  repetitionScope='Full repeats transport/control 30 times. InstallerRefresh and CandidateCore cover every same core case once; neither claims a new 30-round reliability result. CandidateCore is a single-pass core regression after targeted feature/lifecycle tests.';
  ordinaryTokenGate=$(if((Get-Content (Join-Path $OutputDirectory 'ControlTests.log') -Raw).Contains('BLOCKED ordinary-token')){'BlockedEnvironment'}else{'SeeControlTestsLog'});
  excluded='Archived research drivers; disabled prediction runtime historical freshness failure; extra transports; formal eight-stack/long-run matrices; unverified ordinary/cross-account interactive launch'}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8NoBOM
 if(-not $pass){exit 1}
}finally{Pop-Location}
