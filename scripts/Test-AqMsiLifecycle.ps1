#requires -Version 7.0
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$Msi,
 [Parameter(Mandatory)][string]$ValidationInstance,
 [Parameter(Mandatory)][string]$OutputDirectory,
 [string]$FaultMsi,
 [string]$LegacyBundle
)
$ErrorActionPreference='Stop'
$id=[guid]::Empty
if(-not[guid]::TryParseExact($ValidationInstance,'N',[ref]$id) -or $id -eq [guid]::Empty){throw 'An isolated canonical validation GUID is required'}
$Msi=[IO.Path]::GetFullPath($Msi)
if($FaultMsi){$FaultMsi=[IO.Path]::GetFullPath($FaultMsi)}
foreach($package in @($Msi,$FaultMsi)|Where-Object {$_}){
 if((Get-Content -LiteralPath ($package+'.json') -Raw|ConvertFrom-Json).validationInstance -cne $ValidationInstance){throw 'MSI must be built for this isolated instance'}
}
if($LegacyBundle){$LegacyBundle=[IO.Path]::GetFullPath($LegacyBundle)}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a fresh MSI evidence directory'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$service='StreamLink-Validation-'+$ValidationInstance
$install=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('StreamLink-Validation/'+$ValidationInstance+'/msi')
$runtime=Join-Path $install 'app'
$data=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('StreamLink-Validation/'+$ValidationInstance)
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$rows=[Collections.Generic.List[object]]::new()
function DailySnapshot {
 @(Get-CimInstance Win32_Service -Filter "Name='StreamLink' OR Name='StreamLink-PersonalFeature'"|Sort-Object Name|Select-Object Name,State,ProcessId,PathName)|ConvertTo-Json -Compress
}
$dailyBefore=DailySnapshot
function Check([bool]$Condition,[string]$Name){
 $rows.Add([ordered]@{name=$Name;status=$(if($Condition){'Pass'}else{'Fail'})})
 if(-not $Condition){throw $Name}
}
function MsiRun([string]$Operation,[string]$Package,[string]$Label,[switch]$ExpectedFailure){
 $log=Join-Path $OutputDirectory ($Label+'.log')
 $p=Start-Process msiexec.exe -ArgumentList @($Operation,('"'+$Package+'"'),'/qn','/norestart','/l*v',('"'+$log+'"')) -WindowStyle Hidden -PassThru
 if(-not $p.WaitForExit(300000)){throw ('MSI timeout; process and log retained: '+$p.Id)}
 $rows.Add([ordered]@{name=$Label;exit=$p.ExitCode;expectedFailure=[bool]$ExpectedFailure;log=$Label+'.log'})
 Check $(if($ExpectedFailure){$p.ExitCode -ne 0}else{$p.ExitCode -eq 0}) ($Label+' exit matches expectation')
 Check ((DailySnapshot) -eq $dailyBefore) ($Label+' preserves daily services')
}
function App([string]$Folder,[string[]]$Arguments){
 $quoted=(@('--validation-instance',$ValidationInstance)+$Arguments|ForEach-Object{if($_.Contains('"')){throw 'Quote in test argument'};'"'+$_+'"'}) -join ' '
 $p=Start-Process (Join-Path $Folder 'StreamLink.exe') -ArgumentList $quoted -WindowStyle Hidden -PassThru
 if(-not $p.WaitForExit(60000)){throw 'Owned app operation timed out'}
 if($p.ExitCode){throw ('Owned app failed: '+($Arguments -join ' '))}
}
function State([string]$Folder,[string]$Label){
 $path=Join-Path $OutputDirectory ($Label+'.json')
 App $Folder @('--acceptance-status',$path)
 $state=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 Check ($state.Ok -and $state.ServiceReady) ($Label+' authenticated service ready')
 return $state
}
function Same([object]$Before,[object]$After,[string]$Label){
 Check ($Before.ProfileSha256 -eq $After.ProfileSha256 -and $Before.Network -eq $After.Network -and $Before.UiSid -eq $After.UiSid -and -not $After.NetworkEnabled) ($Label+' preserves profile, network identity and SID; remains disabled')
}
function StartTray([string]$Label,[switch]$Manual){
 $trayArguments=@('--validation-instance',$ValidationInstance)
 if(-not $Manual){$trayArguments+='--startup'}
 & (Join-Path $PSScriptRoot 'Invoke-AqOrdinaryUser.ps1') -Executable (Join-Path $install 'StreamLink.exe') -Arguments $trayArguments -OutputDirectory (Join-Path $OutputDirectory $Label)|Out-Null
 $launch=Get-Content (Join-Path $OutputDirectory ($Label+'/launch-result.json')) -Raw|ConvertFrom-Json
 Check ($launch.exit -eq 0 -and $launch.admin -eq $false -and -not $launch.error) ($Label+' ordinary launcher')
 $watch=[Diagnostics.Stopwatch]::StartNew()
 do {
  $processes=@(Get-CimInstance Win32_Process -Filter "Name='StreamLink.exe' OR Name='StreamLink.Web.exe'"|Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($runtime+'\',[StringComparison]::OrdinalIgnoreCase)})
  if(@($processes|Where-Object Name -eq 'StreamLink.Web.exe').Count){break}
  Start-Sleep -Milliseconds 200
 }while($watch.Elapsed.TotalSeconds -lt 15)
 Check (@($processes|Where-Object Name -eq 'StreamLink.exe').Count -eq 1 -and @($processes|Where-Object Name -eq 'StreamLink.Web.exe').Count -eq 1) ($Label+' real tray and Web processes started')
 return ,@($processes.ProcessId)
}
function Gone([uint32[]]$Pids,[string]$Label){
 Check (@($Pids|Where-Object {Get-Process -Id $_ -ErrorAction SilentlyContinue}).Count -eq 0) ($Label+' prior UI and Web exited')
}
function DistinctPolicy {
 & sc.exe failure $service 'reset=' '1234' 'actions=' 'restart/7000' > $null
 if($LASTEXITCODE){throw 'Could not set owned recovery fixture'}
 & sc.exe description $service 'AQ original recovery description' > $null
 if($LASTEXITCODE){throw 'Could not set owned description fixture'}
}
function FailurePolicy {
 $failure=(& sc.exe qfailure $service | Out-String).Trim()
 if($LASTEXITCODE){throw 'Could not query owned recovery fixture'}
 $description=(& sc.exe qdescription $service | Out-String).Trim()
 if($LASTEXITCODE){throw 'Could not query owned description fixture'}
 return $failure+"`n"+$description
}
function Uninstall([string]$Label){
 $profile=if(Test-Path (Join-Path $data 'profile.dpapi')){(Get-FileHash (Join-Path $data 'profile.dpapi')).Hash}else{''}
 $ui=StartTray ($Label+'-tray') -Manual
 MsiRun '/x' $Msi $Label
 Gone $ui $Label
 Check (-not(Get-Service -Name $service -ErrorAction SilentlyContinue)) ($Label+' removes owned service')
 Check (-not(Test-Path (Join-Path $runtime 'StreamLink.Service.exe'))) ($Label+' removes program')
 Check ((Test-Path (Join-Path $data 'profile.dpapi')) -and (Get-FileHash (Join-Path $data 'profile.dpapi')).Hash -eq $profile) ($Label+' retains protected configuration')
 Check (-not(Test-Path ('HKLM:\Software\StreamLink\Validation\'+$ValidationInstance))) ($Label+' removes MSI registration')
 # Get-ItemPropertyValue terminates on a missing value; absence is success here.
 Check ($null -eq ([Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',$service,$null))) ($Label+' removes owned login startup entry')
}
try {
 $preUi=@()
 if(Test-Path (Join-Path $install 'StreamLink.exe')){$preUi=StartTray 'before-update'}
 MsiRun '/i' $Msi 'install-or-upgrade'
 $startup=Get-ItemPropertyValue -LiteralPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $service
 Check ($startup -eq ('"'+(Join-Path $install 'StreamLink.exe')+'" --validation-instance '+$ValidationInstance+' --startup')) 'MSI owns the exact quoted login startup command'
 $shell=New-Object -ComObject WScript.Shell
 foreach($folder in @([Environment]::GetFolderPath('CommonDesktopDirectory'),(Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'StreamLink'))){
  $link=Join-Path $folder ('StreamLink Validation '+$ValidationInstance.Substring(0,8)+'.lnk')
  Check (Test-Path -LiteralPath $link) 'installed application shortcut exists'
  $shortcut=$shell.CreateShortcut($link)
  Check ($shortcut.TargetPath -eq (Join-Path $install 'StreamLink.exe') -and $shortcut.Arguments.Trim() -eq ('--validation-instance '+$ValidationInstance) -and $shortcut.IconLocation.Length -gt 0) 'shortcut targets actual launcher with icon and isolated arguments'
 }
 if($preUi.Count){Gone $preUi 'upgrade'}
 # Restart before any acceptance-status call: the first UI request is from an
 # ordinary InteractiveToken process, without an administrator priming it.
 Restart-Service -Name $service
 $node=(Get-Command node.exe).Source
 & (Join-Path $PSScriptRoot 'Invoke-AqOrdinaryUser.ps1') -Executable $node -Arguments @((Join-Path $repo 'scripts/Test-AqPublishedPanel.cjs'),$runtime,$ValidationInstance,(Join-Path $OutputDirectory 'ordinary-browser')) -OutputDirectory (Join-Path $OutputDirectory 'ordinary-browser-launch')|Out-Null
 $launch=Get-Content (Join-Path $OutputDirectory 'ordinary-browser-launch/launch-result.json') -Raw|ConvertFrom-Json
 Check ($launch.exit -eq 0 -and $launch.admin -eq $false -and -not $launch.error) 'cold service ordinary UI first request'
 Check ((Get-Content (Join-Path $OutputDirectory 'ordinary-browser/browser.json') -Raw|ConvertFrom-Json).status -eq 'Pass') 'actual published Web/ordinary token/SCM persistence'
 App $runtime @('--acceptance-create-network')
 $before=State $runtime 'before-repair'
 $pids=StartTray 'before-repair-tray'
 MsiRun '/fomus' $Msi 'repair'
 Gone $pids 'repair'
 Same $before (State $runtime 'after-repair') 'repair'
 if($FaultMsi){
  DistinctPolicy
  $policy=FailurePolicy
  $image=(Get-CimInstance Win32_Service -Filter "Name='$service'").PathName
  $hash=(Get-FileHash (Join-Path $runtime 'StreamLink.Service.dll')).Hash
  MsiRun '/i' $FaultMsi 'failed-update' -ExpectedFailure
  Same $before (State $runtime 'after-failed-update') 'failed update rollback'
  Check ((Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -eq $image -and (Get-FileHash (Join-Path $runtime 'StreamLink.Service.dll')).Hash -eq $hash) 'failed update restores ImagePath and original binary'
  Check ((FailurePolicy) -eq $policy) 'failed update restores SCM failure actions and description'
 }
 App $runtime @('--acceptance-disable-startup')
 $startupBefore=State $runtime 'startup-disabled'
 MsiRun '/fomus' $Msi 'repair-startup-disabled'
 Same $startupBefore (State $runtime 'startup-disabled-after-repair') 'disabled startup repair'
 Check ((Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$service)).Start -eq 3) 'repair preserves explicitly disabled automatic service startup'
 App $runtime @('--startup')
 Check (@(Get-CimInstance Win32_Process -Filter "Name='StreamLink.exe' OR Name='StreamLink.Web.exe'"|Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($runtime+'\',[StringComparison]::OrdinalIgnoreCase)}).Count -eq 0) 'disabled login startup exits without tray or Web processes'
 Uninstall 'uninstall'
 if($LegacyBundle){
  App $LegacyBundle @('--install','--ui-user-account',[Security.Principal.WindowsIdentity]::GetCurrent().Name)
  $manual=State $LegacyBundle 'manual-ready'
  $oldImage=(Get-CimInstance Win32_Service -Filter "Name='$service'").PathName
  if($FaultMsi){
   DistinctPolicy
   $policy=FailurePolicy
   MsiRun '/i' $FaultMsi 'failed-manual-takeover' -ExpectedFailure
   Same $manual (State $LegacyBundle 'manual-restored') 'manual takeover rollback'
   Check ((Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -eq $oldImage) 'manual rollback restores original service path'
   Check ((FailurePolicy) -eq $policy) 'manual rollback restores SCM failure actions and description'
  }
  MsiRun '/i' $Msi 'manual-takeover'
  Same $manual (State $runtime 'manual-migrated') 'manual migration'
  Uninstall 'migration-uninstall'
 }
 Check ((DailySnapshot) -eq $dailyBefore) 'all daily service PIDs and paths unchanged'
 [ordered]@{status='Pass';validationInstance=$ValidationInstance;msiSha256=(Get-FileHash $Msi).Hash;steps=$rows.ToArray();scope='Real isolated Windows Installer lifecycle; ordinary-token browser and UI; no physical networking or cross-account claims'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8NoBOM
}catch{
 [ordered]@{status='Fail';error=$_.Exception.Message;validationInstance=$ValidationInstance;steps=$rows.ToArray()}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8NoBOM
 throw
}
