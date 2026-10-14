#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Bundle,[Parameter(Mandatory)][string]$Output,
 [string]$SshTarget='Administrator@10.129.129.1',[string]$HostKeyAlias='10.126.126.2',
 [string]$LocalIp='10.129.129.2',[string]$PeerIp='10.129.129.1',
 [string]$RemoteDirectory='E:/Codex_Workspace/Streamlink/personal-v3-endpoint',
 [ValidateSet('so','learn-local','learn-remote')][string]$Scenario='so',[ValidateRange(1,30)][int]$Rounds=30)
$ErrorActionPreference='Stop'
$Bundle=[IO.Path]::GetFullPath($Bundle);$Output=[IO.Path]::GetFullPath($Output)
if(Test-Path -LiteralPath $Output){throw 'Fresh evidence directory required'}
if($RemoteDirectory -notmatch '^[A-Za-z]:/[A-Za-z0-9_./-]+$'){throw 'Remote staging path rejected'}
New-Item -ItemType Directory -Path $Output | Out-Null
$ssh=@('-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o',"HostKeyAlias=$HostKeyAlias",'-o','ConnectTimeout=5')
$tag='v3-'+[guid]::NewGuid().ToString('N');$configs=Join-Path $Bundle $tag
& (Join-Path $Bundle 'StreamLink.EndpointPoc.exe') --prepare-router-network $configs
if($LASTEXITCODE){throw 'Private fixture generation failed'}
$a=Get-Content -LiteralPath (Join-Path $configs 'local-private.json') -Raw|ConvertFrom-Json
$b=Get-Content -LiteralPath (Join-Path $configs 'remote-private.json') -Raw|ConvertFrom-Json
foreach($n in @($a,$b)){$n.Rounds=$Rounds;$n.SourceLearning=$Scenario -ne 'so';$n.Binary='udp2raw-native.exe'}
$a.LocalIp=$LocalIp;$a.PeerIp=$PeerIp;$b.LocalIp=$PeerIp;$b.PeerIp=$LocalIp
$a.BasePort=46400;$a.PeerBasePort=46500;$b.BasePort=46500;$b.PeerBasePort=46400
$a.ReflectorPort=46391;$a.PeerReflectorPort=46392;$b.ReflectorPort=46392;$b.PeerReflectorPort=46391
$a.ControlPort=$b.ControlPort=46390
$a.LocalAnnouncementOffset=if($Scenario -eq 'learn-remote'){8}else{0};$a.PeerAnnouncementOffset=if($Scenario -eq 'learn-local'){8}else{0}
$b.LocalAnnouncementOffset=$a.PeerAnnouncementOffset;$b.PeerAnnouncementOffset=$a.LocalAnnouncementOffset
$a.Output="$tag-local-result.json";$b.Output="$tag-remote-result.json"
$localConfig=Join-Path $Bundle "$tag-local.private.json";$remoteConfig=Join-Path $Bundle "$tag-remote.private.json"
$a|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $localConfig -Encoding utf8NoBOM
$b|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $remoteConfig -Encoding utf8NoBOM
$runner=Join-Path $Bundle 'Invoke-NativeRouterNetworkNode.ps1';Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Invoke-NativeRouterNetworkNode.ps1') -Destination $runner
& scp @ssh $remoteConfig $runner "${SshTarget}:$RemoteDirectory/"
if($LASTEXITCODE){throw 'Private remote fixture copy failed'}
function Encode([string]$t){[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($t))}
$remoteScript="& '$RemoteDirectory/Invoke-NativeRouterNetworkNode.ps1' -Configuration '$RemoteDirectory/$(Split-Path $remoteConfig -Leaf)'"
$encoded=Encode $remoteScript
$remote=Start-Process -FilePath ssh.exe -ArgumentList (@($ssh)+@($SshTarget,"powershell -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand $encoded")) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Output 'remote.log') -RedirectStandardError (Join-Path $Output 'remote-error.log')
try {
 $localEncoded=Encode "& '$($runner.Replace("'","''"))' -Configuration '$($localConfig.Replace("'","''"))'"
 $local=Start-Process -FilePath powershell.exe -ArgumentList "-NoProfile -NonInteractive -OutputFormat Text -EncodedCommand $localEncoded" -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Output 'local.log') -RedirectStandardError (Join-Path $Output 'local-error.log')
 try {if(-not $local.WaitForExit(420000)){$local.Kill();throw 'Local owned supervisor exceeded seven-minute deadline'};$localCode=$local.ExitCode}finally{$local.Dispose()}
 if(-not $remote.WaitForExit(30000)){throw 'Remote supervisor not finished after local exit; remote fixture has its own six-minute deadline'}
 & scp @ssh "${SshTarget}:$RemoteDirectory/$($b.Output)" (Join-Path $Output 'remote.json')
 $remoteCopy=$LASTEXITCODE
 if(Test-Path -LiteralPath (Join-Path $Bundle $a.Output)){Copy-Item -LiteralPath (Join-Path $Bundle $a.Output) -Destination (Join-Path $Output 'local.json')}
 [ordered]@{scenario=$Scenario;requestedRounds=$Rounds;localExit=$localCode;remoteExit=$remote.ExitCode;remoteResultCopy=$remoteCopy;evidenceLevel='RealIO-over-overlay';physicalNatCoverage=$false;stableServiceChanged=$false;
  hashes=@('StreamLink.Core.dll','StreamLink.EndpointPoc.dll','udp2raw-native.exe')|ForEach-Object{[ordered]@{file=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $Bundle $_)).Hash}}}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $Output 'scope.json')
 if($localCode -or $remote.ExitCode -or $remoteCopy){throw 'Pair failed; retained evidence, no unchanged-input retry'}
}finally {
 if(-not $remote.HasExited){$remote.Kill();$remote.WaitForExit(5000)|Out-Null}
 # Only disposable credentials generated above, never a user profile.
 foreach($p in @($localConfig,$remoteConfig,(Join-Path $configs 'local-private.json'),(Join-Path $configs 'remote-private.json'))){Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue}
}
