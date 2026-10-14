#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Bundle,[Parameter(Mandatory)][string]$ControlServerDll,[Parameter(Mandatory)][string]$Output,
 [string]$SshTarget='Administrator@10.129.129.1',[string]$HostKeyAlias='10.126.126.2',
 [string]$LocalIp='10.129.129.2',[string]$PeerIp='10.129.129.1',
 [string]$RemoteDirectory='E:/Codex_Workspace/Streamlink/personal-v3-harness',
 [ValidateSet('tcp','udp','legacy')][string]$Kind='udp',[ValidateSet('host','public')][string]$DataRoute='host',
 [ValidateRange(1,5)][int]$Rounds=5,[switch]$MeasureLoad,[switch]$MetadataViaSshForward,
 [ValidateSet('correct','local-offset','remote-offset')][string]$SourceFixture='correct',[string]$CoordinationFile)
$ErrorActionPreference='Stop'
$Bundle=[IO.Path]::GetFullPath($Bundle);$Output=[IO.Path]::GetFullPath($Output);$ControlServerDll=[IO.Path]::GetFullPath($ControlServerDll)
if(Test-Path -LiteralPath $Output){throw 'Fresh evidence directory required'}
if($RemoteDirectory -notmatch '^[A-Za-z]:/[A-Za-z0-9_./-]+$'){throw 'Remote staging path rejected'}
New-Item -ItemType Directory -Path $Output | Out-Null
$controlRoot=Join-Path $Bundle ('control-'+[guid]::NewGuid().ToString('N'));$port=45369
$ssh=@('-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o',"HostKeyAlias=$HostKeyAlias",'-o','ConnectTimeout=5')
function Encode([string]$t){[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($t))}
$info=[Diagnostics.ProcessStartInfo]::new('dotnet');$info.UseShellExecute=$false;$info.CreateNoWindow=$true
foreach($arg in @($ControlServerDll,'--serve',$LocalIp,[string]$port,$controlRoot,'900')){$info.ArgumentList.Add($arg)}
$server=if(-not $CoordinationFile){[Diagnostics.Process]::Start($info)}else{$null};$rule='StreamLink-Personal-Control-'+[guid]::NewGuid().ToString('N')
$rows=[Collections.Generic.List[object]]::new();$remote=$null;$local=$null;$forward=$null
try{
 New-NetFirewallRule -Name $rule -DisplayName $rule -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $LocalIp -RemoteAddress $PeerIp -LocalPort $port | Out-Null
 $ready=[Diagnostics.Stopwatch]::StartNew();$coord=if($CoordinationFile){[IO.Path]::GetFullPath($CoordinationFile)}else{Join-Path $controlRoot 'coordination.json'}
 while(-not(Test-Path -LiteralPath $coord)){if($null -eq $server -or $server.HasExited -or $ready.Elapsed.TotalSeconds -gt 20){throw 'Isolated pinned HTTPS coordination not ready'};Start-Sleep -Milliseconds 100}
 $coordinator=Get-Content -LiteralPath $coord -Raw|ConvertFrom-Json
 [ordered]@{url=$coordinator.url;fixture='PF2-01-v1';sourceFixture=$SourceFixture;metadataOnly=$true;externalCoordinator=[bool]$CoordinationFile}|ConvertTo-Json|Set-Content (Join-Path $Output 'coordination-scope.json')
 if($MetadataViaSshForward){
  $forward=Start-Process ssh.exe -ArgumentList (@($ssh)+@('-o','ExitOnForwardFailure=yes','-N','-R',"127.0.0.1:${port}:${LocalIp}:$port",$SshTarget)) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Output 'metadata-forward.log') -RedirectStandardError (Join-Path $Output 'metadata-forward-error.log')
  Start-Sleep -Milliseconds 600;if($forward.HasExited){throw 'Isolated metadata-only SSH forward was rejected'}
 }
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Invoke-TraversalNetworkNode.ps1') -Destination $Bundle
 & scp @ssh (Join-Path $Bundle 'Invoke-TraversalNetworkNode.ps1') "${SshTarget}:$RemoteDirectory/"
 if($LASTEXITCODE){throw 'Remote runner copy failed'}
 for($round=1;$round -le $Rounds;$round++){
  $tag='mesh-v3-'+[guid]::NewGuid().ToString('N');$prepared=Join-Path $Bundle $tag
  & (Join-Path $Bundle 'StreamLink.MeshHarness.exe') traversal-prepare $prepared $coord $LocalIp $PeerIp $Kind $DataRoute > (Join-Path $Output "round-$round-addresses.json")
  if($LASTEXITCODE){throw 'Isolated Mesh profiles failed'}
  $a=Get-Content -LiteralPath (Join-Path $prepared 'local.private.json') -Raw|ConvertFrom-Json
  $b=Get-Content -LiteralPath (Join-Path $prepared 'remote.private.json') -Raw|ConvertFrom-Json
  if($MetadataViaSshForward){$b.Profile.Mesh.Pair.Service="https://127.0.0.1:$port/"}
  $a.SourcePort=45400+2*$round;$b.SourcePort=$a.SourcePort+1
  foreach($n in @($a,$b)){$n.MeasureLoad=[bool]$MeasureLoad;$n.Profile.AllowManualQualityRequests=[bool]$MeasureLoad;$n.CaptureBroker=$Kind -eq 'tcp';$n.LifetimeSeconds=120
   if($Kind -eq 'legacy'){$n.Profile.ListenPort=$n.SourcePort;$n.Profile.ManualEndpoint="$($n.Local):$($n.SourcePort)"}
   if($DataRoute -eq 'public'){$n.Profile.TcpStun=@('stun.space4sgsa.com:3478');$n.Profile.UdpStun=@('stun.space4sgsa.com:3478')}
  }
  if($SourceFixture -ne 'correct'){
   if($DataRoute -ne 'host' -or $Kind -ne 'tcp'){throw 'Source-offset fixture is controlled host TCP only; not a physical NAT claim'}
   $a.Profile.TcpPeerReflexive=$true;$b.Profile.TcpPeerReflexive=$true;$a.LocalHelper=$true;$b.LocalHelper=$true
   if($SourceFixture -eq 'local-offset'){$a.ReflectedPortOffset=1;$b.PeerAnnouncedPortOffset=1;$b.RequireLearnedSource=$true}else{$b.ReflectedPortOffset=1;$a.PeerAnnouncedPortOffset=1;$a.RequireLearnedSource=$true}
  }
  $pa=Join-Path $Bundle "$tag-local.private.json";$pb=Join-Path $Bundle "$tag-remote.private.json"
  $a|ConvertTo-Json -Depth 25|Set-Content -LiteralPath $pa -Encoding utf8NoBOM;$b|ConvertTo-Json -Depth 25|Set-Content -LiteralPath $pb -Encoding utf8NoBOM
  & scp @ssh $pb "${SshTarget}:$RemoteDirectory/"
  if($LASTEXITCODE){throw 'Private peer profile copy failed'}
  $remoteResult="$RemoteDirectory/$tag-remote-result.json"
  $remoteCommand=Encode "& '$RemoteDirectory/Invoke-TraversalNetworkNode.ps1' -Configuration '$RemoteDirectory/$(Split-Path $pb -Leaf)' -Output '$remoteResult'"
  $remote=Start-Process ssh.exe -ArgumentList (@($ssh)+@($SshTarget,"powershell -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand $remoteCommand")) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Output "round-$round-remote.log") -RedirectStandardError (Join-Path $Output "round-$round-remote-error.log")
  $result=Join-Path $Output "round-$round-local.json"
  $localCommand=Encode "& '$($Bundle.Replace("'","''"))/Invoke-TraversalNetworkNode.ps1' -Configuration '$($pa.Replace("'","''"))' -Output '$($result.Replace("'","''"))'"
  $local=Start-Process powershell.exe -ArgumentList "-NoProfile -NonInteractive -OutputFormat Text -EncodedCommand $localCommand" -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Output "round-$round-local.log") -RedirectStandardError (Join-Path $Output "round-$round-local-error.log")
  if(-not $local.WaitForExit(160000)){throw 'Owned local fixture exceeded watchdog; do not automatically repeat'}
  if(-not $remote.WaitForExit(30000)){throw 'Peer supervisor did not exit within bounded teardown'}
  & scp @ssh "${SshTarget}:$remoteResult" "${SshTarget}:$remoteResult.environment.json" "${SshTarget}:$remoteResult.log" $Output
  $copied=$LASTEXITCODE;$rows.Add([ordered]@{round=$round;localExit=$local.ExitCode;remoteExit=$remote.ExitCode;resultCopied=$copied})
  foreach($p in @($pa,$pb,(Join-Path $prepared 'local.private.json'),(Join-Path $prepared 'remote.private.json'))){Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue}
  if($copied){throw 'Peer result copy failed; infrastructure failure, not a transport negative'}
  $localResult=Get-Content -LiteralPath $result -Raw|ConvertFrom-Json
  $peerResult=Get-Content -LiteralPath (Join-Path $Output (Split-Path $remoteResult -Leaf)) -Raw|ConvertFrom-Json
  if($localResult.exitCode -ne $local.ExitCode -or $peerResult.exitCode -ne $remote.ExitCode -or
      $localResult.scenarioVerdict -ne 'Pass' -or $peerResult.scenarioVerdict -ne 'Pass' -or $local.ExitCode -or $remote.ExitCode){throw 'Unified JSON/exit verdict failed; evidence retained'}
  $local.Dispose();$local=$null;$remote.Dispose();$remote=$null
 }
}finally{
 foreach($p in @($local,$remote,$forward)){if($null -ne $p){try{if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit(5000)|Out-Null}}finally{$p.Dispose()}}}
 if(Test-Path -LiteralPath $controlRoot){Set-Content -LiteralPath (Join-Path $controlRoot 'stop') -Value stop}
 if($server){if(-not $server.WaitForExit(10000)){$server.Kill($true);$server.WaitForExit(5000)|Out-Null};$server.Dispose()}
 if(Test-Path -LiteralPath (Join-Path $controlRoot 'requests.jsonl')){Copy-Item -LiteralPath (Join-Path $controlRoot 'requests.jsonl') -Destination (Join-Path $Output 'coordination-requests.jsonl')}
 Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
 [ordered]@{kind=$Kind;dataRoute=$DataRoute;requestedRounds=$Rounds;rows=@($rows);evidenceLevel=$(if($DataRoute -eq 'host'){'RealIO-over-overlay'}else{'PhysicalWAN-attempt'});actualWintun=$true;physicalNatSuccessClaimed=$false;metadataViaSshForward=[bool]$MetadataViaSshForward;publicCoordinatorModified=$false;businessRelay=$false;stableServiceChanged=$false;loadRequested=[bool]$MeasureLoad}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $Output 'scope.json')
}
