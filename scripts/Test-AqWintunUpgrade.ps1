#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$PreviousMsi,[Parameter(Mandatory)][string]$CandidateMsi,
      [Parameter(Mandatory)][string]$Harness,[Parameter(Mandatory)][string]$OutputDirectory,[switch]$UseInstalledPrevious)
$ErrorActionPreference='Stop'
function ProductApp([string]$Folder){$current=Join-Path $Folder 'ConWU.exe';if(Test-Path -LiteralPath $current){return $current};return (Join-Path $Folder 'StreamLink.exe')}
$PreviousMsi=[IO.Path]::GetFullPath($PreviousMsi);$CandidateMsi=[IO.Path]::GetFullPath($CandidateMsi);$Harness=[IO.Path]::GetFullPath($Harness)
$old=Get-Content ($PreviousMsi+'.json') -Raw|ConvertFrom-Json;$new=Get-Content ($CandidateMsi+'.json') -Raw|ConvertFrom-Json
$instance=[string]$new.validationInstance;$guid=[guid]::Empty
if(-not [guid]::TryParseExact($instance,'N',[ref]$guid) -or $guid -eq [guid]::Empty -or $old.validationInstance -cne $instance){throw 'Both MSI packages must use the same explicit isolated instance'}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Fresh evidence directory required'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$service='StreamLink-Validation-'+$instance
if((Get-Service $service -ErrorAction SilentlyContinue) -and -not $UseInstalledPrevious){throw 'This test starts from an uninstalled isolated instance'}
$data=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('StreamLink-Validation/'+$instance)
$rows=[Collections.Generic.List[object]]::new();$held=$null
function Daily { @(Get-CimInstance Win32_Service -Filter "Name='StreamLink' OR Name='StreamLink-PersonalFeature'" | Sort-Object Name | Select-Object Name,State,ProcessId,PathName)|ConvertTo-Json -Compress }
$dailyBefore=Daily
$interfacesBefore=@(Get-NetAdapter -IncludeHidden|ForEach-Object InterfaceGuid)
function Check([bool]$Ok,[string]$Name){$rows.Add(@{name=$Name;status=$(if($Ok){'Pass'}else{'Fail'})});if(-not $Ok){throw $Name}}
function Msi([string]$Operation,[string]$Package,[string]$Label,[switch]$Fail){
 $log=Join-Path $OutputDirectory ($Label+'.log')
 $p=Start-Process msiexec.exe -ArgumentList @($Operation,('"'+$Package+'"'),'/qn','/norestart','/l*v',('"'+$log+'"')) -WindowStyle Hidden -PassThru
 if(-not $p.WaitForExit(300000)){throw ('MSI timed out; process retained: '+$p.Id)}
 $rows.Add(@{name=$Label;exit=$p.ExitCode;expectedFailure=[bool]$Fail})
 Check $(if($Fail){$p.ExitCode -eq 1603}else{$p.ExitCode -eq 0}) ($Label+' exit (no reboot success allowed)')
 Check ((Daily) -eq $dailyBefore) ($Label+' daily service PID/path preserved')
 Write-Output ($Label+' completed: '+$p.ExitCode)
}
function Ready([string]$Label,[switch]$ServiceOnly){
 $path=Join-Path $OutputDirectory ($Label+'.json')
 $runtime=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('StreamLink-Validation/'+$instance+'/msi/app')
 if($ServiceOnly){
  $p=Start-Process (ProductApp $runtime) -ArgumentList @('--validation-instance',$instance,'--acceptance-status',('"'+$path+'"')) -WindowStyle Hidden -PassThru
  if(-not $p.WaitForExit(30000) -or $p.ExitCode){throw 'Restored service status unavailable'}
 }else{
  & $Harness --wintun-installer $instance ready $path > (Join-Path $OutputDirectory ($Label+'-harness.log')) 2>&1
  if($LASTEXITCODE){throw ('Actual installed Wintun did not become ready: '+$Label)}
 }
 $state=Get-Content $path -Raw|ConvertFrom-Json
 if($ServiceOnly){
  Check ($state.Ok -and $state.ServiceReady) ($Label+' prior service ready; external owner still prevents cleanup')
  $state|Add-Member profileHash $state.ProfileSha256
 }else{Check ($state.Ok -and $state.ServiceReady -and $state.status.Adapter.Loaded) ($Label+' real official adapter opened')}
 $manifest=Get-Content (Join-Path $runtime 'manifest.json') -Raw|ConvertFrom-Json
 $binary=(Get-FileHash (Join-Path $runtime 'StreamLink.Service.dll')).Hash
 Check ($binary -eq ($manifest.files|Where-Object path -eq 'StreamLink.Service.dll').sha256) ($Label+' installed service matches bundle manifest')
 $state|Add-Member release $manifest.version
 $state|Add-Member sourceCommit $manifest.sourceCommit
 $state|Add-Member serviceHash $binary
 return $state
}
try {
 if(-not(Test-Path (Join-Path $data 'profile.dpapi'))){
  & $Harness --wintun-installer $instance seed (Join-Path $OutputDirectory 'seed.json')
  if($LASTEXITCODE){throw 'Seed failed'}
 }
 if(-not $UseInstalledPrevious){Msi '/i' $PreviousMsi 'install-previous'}
 $before=Ready 'previous-ready'
 $interfacesBefore=@($interfacesBefore|Where-Object {[guid]$_ -notin @($before.actualInterfaces|ForEach-Object {[guid]$_})})
 $interfacesBefore|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'foreign-interfaces-before.json')
 Check ($before.sourceCommit -eq $old.sourceCommit -and $before.release -eq $old.version) 'baseline is the supplied old binary, not a newer service'
 # The previous release does not have the new identity lease. Retain that
 # lease externally so candidate maintenance must refuse and roll back.
 $marker=Join-Path $OutputDirectory 'held-identity'
 $held=Start-Process $Harness -ArgumentList @('--wintun-installer',$instance,'hold-identity',('"'+$marker+'"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput ($marker+'.stdout') -RedirectStandardError ($marker+'.stderr')
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not(Test-Path $marker)){if($held.HasExited -or $watch.Elapsed.TotalSeconds -gt 15){throw 'Could not establish external identity lease'};Start-Sleep -Milliseconds 100}
 Msi '/i' $CandidateMsi 'blocked-update' -Fail
 $restored=Ready 'rollback-ready' -ServiceOnly
 Check ($restored.release -eq $before.release -and $restored.serviceHash -eq $before.serviceHash -and $restored.profileHash -eq $before.profileHash) 'failed cleanup restores previous binary and unchanged profile'
 Set-Content ($marker+'.release') 'release'
 Check ($held.WaitForExit(10000) -and $held.ExitCode -eq 0) 'external fixture lease released'
 $held.Dispose();$held=$null
 Msi '/i' $CandidateMsi 'upgrade'
 $updated=Ready 'candidate-ready'
 Check ($updated.release -eq $new.version -and $updated.sourceCommit -eq $new.sourceCommit -and $updated.profileHash -eq $before.profileHash -and $updated.identity.Guid -eq $before.identity.Guid) 'upgrade retains profile and exclusive adapter ownership scope'
 foreach($round in 1..2){
  Msi '/famus' $CandidateMsi ('repair-'+$round)
  $state=Ready ('repair-'+$round+'-ready')
  Check ($state.profileHash -eq $before.profileHash -and $state.identity.Guid -eq $before.identity.Guid) ('repair '+$round+' retains enabled network ownership')
 }
 $journal=Join-Path $data 'wintun-upgrade.jsonl'
 Check (Test-Path $journal) 'installed cleanup produced protected journal'
 Copy-Item -LiteralPath $journal -Destination $OutputDirectory
 Check ((Get-Content (Join-Path $OutputDirectory 'upgrade.log') -Raw).Contains('Prior service process exit proven')) 'MSI proves old process exit before replacement'
 Msi '/x' $CandidateMsi 'uninstall'
 Check (-not(Get-Service $service -ErrorAction SilentlyContinue)) 'isolated service removed'
 $interfacesAfter=@(Get-NetAdapter -IncludeHidden|ForEach-Object InterfaceGuid)
 $interfacesAfter|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'interfaces-after.json')
 Check (@($interfacesBefore|Where-Object {$_ -notin $interfacesAfter}).Count -eq 0) 'all pre-existing interface identities retained'
 @{status='Pass';instance=$instance;steps=$rows.ToArray();previousSha256=(Get-FileHash $PreviousMsi).Hash;candidateSha256=(Get-FileHash $CandidateMsi).Hash;
 scope='Actual isolated installed old-to-new MSI update, cleanup failure rollback, two repairs, official Wintun reopen, no reboot, no daily network disruption';
 limits='No physical WAN streaming; shared-driver removal deliberately skipped while foreign devices exist. Failure rollback proves file/profile/service restoration; adapter readiness while an external owner still blocks cleanup is not claimed. Successful candidate upgrade and repairs require a real opened adapter.'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputDirectory 'result.json')
}catch{
 @{status='Fail';instance=$instance;error=$_.Exception.ToString();steps=$rows.ToArray()}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputDirectory 'result.json')
 throw
}finally{
 if($held){Set-Content ($marker+'.release') 'release';$held.WaitForExit(10000)|Out-Null;$held.Dispose()}
}
