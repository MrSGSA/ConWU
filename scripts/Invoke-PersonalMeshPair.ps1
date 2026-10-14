#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Bundle,[Parameter(Mandatory)][string]$ControlServerDll,[Parameter(Mandatory)][string]$Output,
 [string]$SshTarget='Administrator@10.129.129.1',[string]$HostKeyAlias='10.126.126.2',
 [string]$LocalIp='10.129.129.2',[string]$PeerIp='10.129.129.1',
 [string]$RemoteDirectory='E:/Codex_Workspace/Streamlink/personal-v3-harness',
 [ValidateSet('tcp','udp')][string]$Kind='udp',[ValidateSet('host','public')][string]$DataRoute='host',
 [ValidateRange(1,5)][int]$Rounds=5,[switch]$MeasureLoad,[switch]$MetadataViaSshForward)
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
$server=[Diagnostics.Process]::Start($info);$rule='StreamLink-Personal-Control-'+[guid]::NewGuid().ToString('N')
$rows=[Collections.Generic.List[object]]::new();$remote=$null;$local=$null;$forward=$null
try{
 New-NetFirewallRule -Name $rule -DisplayName $rule -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $LocalIp -RemoteAddress $PeerIp -LocalPort $port | Out-Null
 $ready=[Diagnostics.Stopwatch]::StartNew();$coord=Join-Path $controlRoot 'coordination.json'
 while(-not(Test-Path -LiteralPath $coord)){if($server.HasExited -or $ready.Elapsed.TotalSeconds -gt 20){throw 'Isolated pinned HTTPS coordination not ready'};Start-Sleep -Milliseconds 100}
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
  foreach($n in @($a,$b)){$n.MeasureLoad=[bool]$MeasureLoad;$n.CaptureBroker=$Kind -eq 'tcp';$n.LifetimeSeconds=if($MeasureLoad){110}elseif($DataRoute -eq 'public'){90}else{40}
   if($DataRoute -eq 'public'){$n.Profile.TcpStun=@('stun.space4sgsa.com:3478');$n.Profile.UdpStun=@('stun.space4sgsa.com:3478')}
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
  if($local.ExitCode -or $remote.ExitCode -or $copied){throw 'Product Mesh/Wintun pair failed; evidence retained'}
  $local.Dispose();$local=$null;$remote.Dispose();$remote=$null
 }
}finally{
 foreach($p in @($local,$remote,$forward)){if($null -ne $p){try{if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit(5000)|Out-Null}}finally{$p.Dispose()}}}
 if(Test-Path -LiteralPath $controlRoot){Set-Content -LiteralPath (Join-Path $controlRoot 'stop') -Value stop}
 if(-not $server.WaitForExit(10000)){$server.Kill($true);$server.WaitForExit(5000)|Out-Null};$server.Dispose()
 if(Test-Path -LiteralPath (Join-Path $controlRoot 'requests.jsonl')){Copy-Item -LiteralPath (Join-Path $controlRoot 'requests.jsonl') -Destination (Join-Path $Output 'coordination-requests.jsonl')}
 Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
 [ordered]@{kind=$Kind;dataRoute=$DataRoute;requestedRounds=$Rounds;rows=@($rows);evidenceLevel=$(if($DataRoute -eq 'host'){'RealIO-over-overlay'}else{'PhysicalWAN-attempt'});actualWintun=$true;physicalNatSuccessClaimed=$false;metadataViaSshForward=[bool]$MetadataViaSshForward;publicCoordinatorModified=$false;businessRelay=$false;stableServiceChanged=$false;loadRequested=[bool]$MeasureLoad}|ConvertTo-Json -Depth 7|Set-Content (Join-Path $Output 'scope.json')
}
