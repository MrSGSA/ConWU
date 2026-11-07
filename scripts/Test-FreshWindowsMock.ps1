#requires -Version 7.0
$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Install-ConwuFreshWindows.ps1'))
$source=[regex]::Replace($source,"(?m)^if\(-not \(\[Security\.Principal\.WindowsPrincipal\].*?\}\s*$",'# test admin stub',1)
$source=$source.Replace('$installer=New-Object -ComObject WindowsInstaller.Installer', '$installer=$global:fakeInstaller')
$replacement='function MsiProperty([string]$path,[string]$property) { if($property -eq "UpgradeCode"){return $global:testUpgrade};if($path -like "*candidate*"){return "{11111111-1111-1111-1111-111111111111}"};return "{22222222-2222-2222-2222-222222222222}" }'
$source=[regex]::Replace($source,'(?s)function MsiProperty\(.*?\r?\n\}',$replacement,1)
if($source.Contains('WindowsIdentity]::GetCurrent') -or $source.Contains('New-Object -ComObject WindowsInstaller.Installer')){throw '模拟隔离失败'}
$root=Join-Path ([IO.Path]::GetTempPath()) ('conwu-fresh-mock-'+[guid]::NewGuid().ToString('N'))
$env:ProgramData=Join-Path $root 'data';$env:ProgramFiles=Join-Path $root 'program'
$data=Join-Path $env:ProgramData 'StreamLink-PersonalFeature';$install=Join-Path $env:ProgramFiles 'StreamLink';$backup=Join-Path $root 'backups'
foreach($dir in @($data,(Join-Path $install 'app'),$backup)){New-Item -ItemType Directory -Path $dir -Force|Out-Null}
Set-Content -LiteralPath (Join-Path $data 'profile.dpapi') -Value 'old data'
$candidate=Join-Path $root 'candidate.msi';$previous=Join-Path $root 'previous.msi';$maintenanceDir=Join-Path $root 'candidate-runtime';New-Item -ItemType Directory -Path $maintenanceDir|Out-Null;$maintenance=Join-Path $maintenanceDir 'ConWU.exe'
foreach($file in @($candidate,$previous,$maintenance)){Set-Content -LiteralPath $file -Value $file};$candidateManifest=Join-Path $maintenanceDir 'manifest.json';@{version='1.1';sourceCommit=('a'*40);files=@(@{path='ConWU.exe';sha256=(Get-FileHash $maintenance).Hash})}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $candidateManifest
$global:testUpgrade='{AD076018-A9B8-47F5-B098-97479A363416}';$global:testService='StreamLink-PersonalFeature';$global:testData=$data;$global:testInstall=$install;
$global:events=[Collections.Generic.List[string]]::new();$global:svc='Running';$global:oldPresent=$true;$global:newPresent=$false
$global:fakeInstaller=[pscustomobject]@{};$global:fakeInstaller|Add-Member ScriptMethod ProductState {param($id) if($id -like '*11111111*'){if($global:newPresent){return 5}else{return 2}};if($global:oldPresent){return 5};return 2}
function icacls.exe {$global:LASTEXITCODE=0}
function Get-CimInstance {param($ClassName,$Filter) [pscustomobject]@{Name=$global:testService;State=$global:svc;StartMode='Auto';PathName=('"'+(Join-Path $global:testInstall 'app\StreamLink.Service.exe')+'"')}}
function Get-Service {param($Name,$ErrorAction) $o=[pscustomobject]@{Status=$global:svc};$o|Add-Member ScriptMethod WaitForStatus {param($a,$b)};return $o}
function Stop-Service {param($Name,$ErrorAction) $global:events.Add('stop');$global:svc='Stopped'}
function Start-Service {param($Name,$ErrorAction) $global:events.Add('start');$global:svc='Running'}
function Set-Service {param($Name,$StartupType) $global:events.Add('startup:'+ $StartupType)}
function Start-Process {param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru,[switch]$Wait)
 if($FilePath -like '*maintenance-runtime*ConWU.exe'){if($ArgumentList[0] -eq '--validation-instance'){if($ArgumentList[1] -ne $global:testValidation){throw 'validation 参数不符'};$global:events.Add('validation-scope');$ArgumentList=$ArgumentList[2..($ArgumentList.Count-1)]};$action=$ArgumentList[1];$report=$ArgumentList[2].Trim('"');$global:events.Add('maintenance:'+ $action);@{Schema=1;Instance=$global:testService;DataRoot=$global:testData;ServiceStopped=$true;Scopes=@();Released=($action -eq 'release');Error=''}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $report}
 else{$action=$ArgumentList[0];$arg=$ArgumentList[1];if($action -eq '/x'){$global:events.Add('uninstall-candidate');$global:newPresent=$false}elseif($arg -like '*candidate.msi*'){$global:events.Add('install-candidate');$global:newPresent=$true;$global:oldPresent=$false;@{version='1.1';sourceCommit=('b'*40);files=@(@{path='dummy';sha256=('0'*64)})}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $global:testInstall 'app\manifest.json')}else{$global:events.Add('install-previous');if($global:newPresent){throw '模拟拒绝直接降级'};$global:oldPresent=$true}}
 $o=[pscustomobject]@{ExitCode=0;Id=123};$o|Add-Member ScriptMethod WaitForExit {param($ms) return $true};return $o
}
$script=[ScriptBlock]::Create($source)
try {& $script -CandidateMsi $candidate -CandidateHash (Get-FileHash $candidate).Hash -RollbackMsi $previous -RollbackHash (Get-FileHash $previous).Hash -MaintenanceExe $maintenance -MaintenanceHash (Get-FileHash $maintenance).Hash -ExpectedManifestHash (Get-FileHash $candidateManifest).Hash -ExpectedCommit ('a'*40) -BackupParent $backup;throw '模拟失败未触发'}
catch {if($_.Exception.Message -notmatch '切换失败，已恢复原数据和服务'){throw}}
$remove=$global:events.IndexOf('uninstall-candidate');$restore=$global:events.IndexOf('install-previous')
if($remove -lt 0 -or $restore -le $remove -or $global:newPresent -or -not $global:oldPresent){throw ('候选卸载和旧包恢复顺序错误：'+($global:events -join ','))}
if((Get-Content -Raw (Join-Path $data 'profile.dpapi')).Trim() -ne 'old data' -or $global:svc -ne 'Running'){throw '旧数据或服务未恢复'}
if($global:events.IndexOf('maintenance:release') -lt $global:events.IndexOf('stop')){throw '维护释放发生在停服前'}
$global:testValidation=[guid]::NewGuid().ToString('N');$global:testUpgrade='{'+([guid]::ParseExact($global:testValidation,'N')).ToString('D')+'}';$global:testService='StreamLink-Validation-'+$global:testValidation
$global:testData=Join-Path $env:ProgramData ('StreamLink-Validation\'+$global:testValidation);$global:testInstall=Join-Path $env:ProgramFiles ('StreamLink-Validation\'+$global:testValidation+'\msi')
New-Item -ItemType Directory -Path $global:testData,(Join-Path $global:testInstall 'app') -Force|Out-Null;Set-Content -LiteralPath (Join-Path $global:testData 'profile.dpapi') -Value 'validation only'
$global:events.Clear();$global:svc='Running';$global:oldPresent=$true;$global:newPresent=$false
try {& $script -CandidateMsi $candidate -CandidateHash (Get-FileHash $candidate).Hash -RollbackMsi $previous -RollbackHash (Get-FileHash $previous).Hash -MaintenanceExe $maintenance -MaintenanceHash (Get-FileHash $maintenance).Hash -ExpectedManifestHash (Get-FileHash $candidateManifest).Hash -ExpectedCommit ('a'*40) -BackupParent $backup -ValidationInstance $global:testValidation;throw '模拟失败未触发'}catch {if($_.Exception.Message -notmatch '切换失败，已恢复原数据和服务'){throw}}
if(-not $global:events.Contains('validation-scope') -or (Get-Content -Raw (Join-Path $global:testData 'profile.dpapi')).Trim() -ne 'validation only' -or (Get-Content -Raw (Join-Path $data 'profile.dpapi')).Trim() -ne 'old data'){throw 'validation 模拟未隔离生产数据或维护参数错误'}
Write-Output 'PASS 模拟 Windows MSI 降级顺序、旧数据和服务恢复及 validation 实例隔离；没有操作真实服务。'
