#requires -Version 7.0
$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Install-ConwuFreshWindows.ps1'))
$source=[regex]::Replace($source,"(?m)^if\(-not \(\[Security\.Principal\.WindowsPrincipal\].*?\}\s*$",'# test admin stub',1)
$source=$source.Replace('$installer=New-Object -ComObject WindowsInstaller.Installer', '$installer=$global:fakeInstaller')
$source=[regex]::Replace($source,'(?s)if\(-not \(''ConwuInstallerProductState'' -as \[type\]\)\).*?function Get-MsiProductState\(\[string\]\$product\) \{.*?\r?\n\}', 'function Get-MsiProductState([string]$product) { if($global:badCandidateState -and $product -like "*11111111*"){throw "无法确认 MSI 产品状态：-2"}; return $global:fakeInstaller.ProductState($product) }',1)
if($source.Contains('MsiQueryProductStateW')){throw '模拟产品状态替换失败'}
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
$global:events=[Collections.Generic.List[string]]::new();$global:svc='Running';$global:svcMode='Auto';$global:oldPresent=$true;$global:newPresent=$false
$global:fakeInstaller=[pscustomobject]@{};$global:fakeInstaller|Add-Member ScriptMethod ProductState {param($id) if($id -like '*11111111*'){if($global:newPresent){return 5}else{return 2}};if($global:oldPresent){return 5};return 2}
function icacls.exe {$global:LASTEXITCODE=0}
function Get-CimInstance {param($ClassName,$Filter) [pscustomobject]@{Name=$global:testService;State=$global:svc;StartMode=$global:svcMode;PathName=('"'+(Join-Path $global:testInstall 'app\StreamLink.Service.exe')+'"')}}
function Get-Service {param($Name,$ErrorAction) $o=[pscustomobject]@{Status=$global:svc};$o|Add-Member ScriptMethod WaitForStatus {param($a,$b)};return $o}
function Stop-Service {param($Name,$ErrorAction) $global:events.Add('stop');$global:svc='Stopped'}
function Start-Service {param($Name,$ErrorAction) $global:events.Add('start');$global:svc='Running'}
function Set-Service {param($Name,$StartupType) $global:events.Add('startup:'+ $StartupType);$global:svcMode=if($StartupType -eq 'Automatic'){'Auto'}else{$StartupType}}
function Get-NetAdapter {param([switch]$IncludeHidden) if($null -ne $global:adapterGuidRows){return $global:adapterGuidRows};[pscustomobject]@{InterfaceGuid=$global:guardGuid.ToString('B').ToUpperInvariant();InterfaceDescription='StreamLink Tunnel'}}
function Get-PnpDevice {param([switch]$PresentOnly,$InstanceId,$ErrorAction) [pscustomobject]@{InstanceId=$InstanceId}}
function Start-Process {param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru,[switch]$Wait)
 if($FilePath -like '*maintenance-runtime*ConWU.exe'){
  if($ArgumentList[0] -eq '--validation-instance'){if($ArgumentList[1] -ne $global:testValidation){throw 'validation 参数不符'};$global:events.Add('validation-scope');$ArgumentList=$ArgumentList[2..($ArgumentList.Count-1)]}
  if($ArgumentList[0] -eq '--driver-guard'){
   $global:guardScope=$ArgumentList[2];$global:guardReport=$ArgumentList[3].Trim('"');$global:guardStop=$ArgumentList[4].Trim('"');$global:guardGuid=[guid]::NewGuid();$global:guardStarted=[DateTime]::UtcNow;$global:events.Add('guard-start')
   @{Status='Ready';Scope=$global:guardScope;Instance=$global:testService;DataRoot=$global:testData;InterfaceGuid=$global:guardGuid;ProcessId=321;StartedAt=$global:guardStarted.ToString('O')}|ConvertTo-Json|Set-Content -LiteralPath $global:guardReport
   $o=[pscustomobject]@{ExitCode=0;Id=321;HasExited=$false;StartTime=$global:guardStarted};$o|Add-Member ScriptMethod Refresh {}; $o|Add-Member ScriptMethod WaitForExit {param($ms) if(Test-Path -LiteralPath $global:guardStop){@{Status='Stopped';Scope=$global:guardScope;ProcessId=321;StartedAt=$global:guardStarted.ToString('O')}|ConvertTo-Json|Set-Content -LiteralPath ($global:guardReport+'.stopped');$global:events.Add('guard-stop');return $true};return $false};return $o
  }
  $action=$ArgumentList[1];$report=$ArgumentList[2].Trim('"');$global:events.Add('maintenance:'+ $action);@{Schema=1;Instance=$global:testService;DataRoot=$global:testData;ServiceStopped=$true;Scopes=@();Released=($action -eq 'release');Error=''}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $report
 }
 else{$action=$ArgumentList[0];$arg=$ArgumentList[1];if($global:simulateTimeout){$global:events.Add('msi-pending');$o=[pscustomobject]@{ExitCode=0;Id=456};$o|Add-Member ScriptMethod WaitForExit {param($ms) return $false};return $o};if($action -eq '/x'){$global:events.Add('uninstall-candidate');$global:newPresent=$false}elseif($arg -like '*candidate.msi*'){$global:events.Add('install-candidate');$global:newPresent=$true;$global:oldPresent=$false;@{version='1.1';sourceCommit=('b'*40);files=@(@{path='dummy';sha256=('0'*64)})}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $global:testInstall 'app\manifest.json')}else{$global:events.Add('install-previous');if($global:newPresent){throw '模拟拒绝直接降级'};$global:oldPresent=$true;$global:svc='Running';$global:svcMode='Auto';$global:events.Add('previous-auto-start')}}
 $o=[pscustomobject]@{ExitCode=0;Id=123};$o|Add-Member ScriptMethod WaitForExit {param($ms) return $true};return $o
}
$script=Join-Path $root 'mocked-fresh.ps1';[IO.File]::WriteAllText($script,$source,[Text.UTF8Encoding]::new($false))
try {& $script -CandidateMsi $candidate -CandidateHash (Get-FileHash $candidate).Hash -RollbackMsi $previous -RollbackHash (Get-FileHash $previous).Hash -MaintenanceExe $maintenance -MaintenanceHash (Get-FileHash $maintenance).Hash -ExpectedManifestHash (Get-FileHash $candidateManifest).Hash -ExpectedCommit ('a'*40) -BackupParent $backup;throw '模拟失败未触发'}
catch {$global:failureMessage=$_.Exception.Message;if($_.Exception.Message -notmatch '切换失败，已恢复原数据和服务'){throw}}
$remove=$global:events.IndexOf('uninstall-candidate');$restore=$global:events.IndexOf('install-previous')
if($remove -lt 0 -or $restore -le $remove -or $global:newPresent -or -not $global:oldPresent){throw ('候选卸载和旧包恢复顺序错误：'+($global:events -join ',')+'；'+$global:failureMessage)}
if((Get-Content -Raw (Join-Path $data 'profile.dpapi')).Trim() -ne 'old data' -or $global:svc -ne 'Running'){throw '旧数据或服务未恢复'}
if($global:events.IndexOf('maintenance:release') -lt $global:events.IndexOf('stop')){throw '维护释放发生在停服前'}
if($global:events.IndexOf('guard-start') -gt $global:events.IndexOf('install-candidate') -or $global:events.IndexOf('guard-stop') -le $restore){throw '保护网卡未贯穿安装和回退'}
$global:events.Clear();$global:svc='Stopped';$global:svcMode='Manual';$global:oldPresent=$true;$global:newPresent=$false
try {& $script -CandidateMsi $candidate -CandidateHash (Get-FileHash $candidate).Hash -RollbackMsi $previous -RollbackHash (Get-FileHash $previous).Hash -MaintenanceExe $maintenance -MaintenanceHash (Get-FileHash $maintenance).Hash -ExpectedManifestHash (Get-FileHash $candidateManifest).Hash -ExpectedCommit ('a'*40) -BackupParent $backup;throw '模拟失败未触发'}catch {if($_.Exception.Message -notmatch '切换失败，已恢复原数据和服务'){throw}}
if($global:events.IndexOf('previous-auto-start') -lt 0 -or $global:events.LastIndexOf('stop') -le $global:events.IndexOf('previous-auto-start') -or $global:svc -ne 'Stopped' -or $global:svcMode -ne 'Manual' -or (Get-Content -Raw (Join-Path $data 'profile.dpapi')).Trim() -ne 'old data'){throw '原停止服务回退后状态或启动类型未恢复'}
$global:events.Clear();$global:svc='Running';$global:svcMode='Auto';$global:oldPresent=$true;$global:newPresent=$false;$global:badCandidateState=$true
try {& $script -CandidateMsi $candidate -CandidateHash (Get-FileHash $candidate).Hash -RollbackMsi $previous -RollbackHash (Get-FileHash $previous).Hash -MaintenanceExe $maintenance -MaintenanceHash (Get-FileHash $maintenance).Hash -ExpectedManifestHash (Get-FileHash $candidateManifest).Hash -ExpectedCommit ('a'*40) -BackupParent $backup;throw '异常状态未触发'}catch {if($_.Exception.Message -notmatch '卸载候选版本失败'){throw}}
if($global:events.Contains('guard-stop') -or $global:events.Contains('install-previous') -or $global:events.Contains('uninstall-candidate')){throw '未知产品状态未保留保护或错误启动恢复'}
$held=@(Get-ChildItem -LiteralPath (Split-Path $data) -Directory|Where-Object {$_.Name -like ((Split-Path $data -Leaf)+'.preinstall-*')});if($held.Count -ne 1){throw '模拟隔离旧数据无法唯一确认'}
Move-Item -LiteralPath $data -Destination (Join-Path $root 'failed-mock-data');Move-Item -LiteralPath $held[0].FullName -Destination $data
$global:badCandidateState=$false
$global:testValidation=[guid]::NewGuid().ToString('N');$global:testUpgrade='{'+([guid]::ParseExact($global:testValidation,'N')).ToString('D')+'}';$global:testService='StreamLink-Validation-'+$global:testValidation
$global:testData=Join-Path $env:ProgramData ('StreamLink-Validation\'+$global:testValidation);$global:testInstall=Join-Path $env:ProgramFiles ('StreamLink-Validation\'+$global:testValidation+'\msi')
New-Item -ItemType Directory -Path $global:testData,(Join-Path $global:testInstall 'app') -Force|Out-Null;Set-Content -LiteralPath (Join-Path $global:testData 'profile.dpapi') -Value 'validation only'
$global:events.Clear();$global:svc='Running';$global:oldPresent=$true;$global:newPresent=$false
try {& $script -CandidateMsi $candidate -CandidateHash (Get-FileHash $candidate).Hash -RollbackMsi $previous -RollbackHash (Get-FileHash $previous).Hash -MaintenanceExe $maintenance -MaintenanceHash (Get-FileHash $maintenance).Hash -ExpectedManifestHash (Get-FileHash $candidateManifest).Hash -ExpectedCommit ('a'*40) -BackupParent $backup -ValidationInstance $global:testValidation;throw '模拟失败未触发'}catch {if($_.Exception.Message -notmatch '切换失败，已恢复原数据和服务'){throw}}
if(-not $global:events.Contains('validation-scope') -or (Get-Content -Raw (Join-Path $global:testData 'profile.dpapi')).Trim() -ne 'validation only' -or (Get-Content -Raw (Join-Path $data 'profile.dpapi')).Trim() -ne 'old data'){throw 'validation 模拟未隔离生产数据或维护参数错误'}
$global:events.Clear();$global:simulateTimeout=$true;$global:svc='Running';$global:oldPresent=$true;$global:newPresent=$false
[IO.File]::WriteAllText($script,$source.Replace('AddMilliseconds(900000)','AddMilliseconds(5)'),[Text.UTF8Encoding]::new($false))
try {& $script -CandidateMsi $candidate -CandidateHash (Get-FileHash $candidate).Hash -RollbackMsi $previous -RollbackHash (Get-FileHash $previous).Hash -MaintenanceExe $maintenance -MaintenanceHash (Get-FileHash $maintenance).Hash -ExpectedManifestHash (Get-FileHash $candidateManifest).Hash -ExpectedCommit ('a'*40) -BackupParent $backup -ValidationInstance $global:testValidation;throw '模拟超时未触发'}catch {if($_.Exception.Message -notmatch 'MSI 尚在运行'){throw}}
if(-not $global:events.Contains('msi-pending') -or $global:events.Contains('guard-stop') -or $global:events.Contains('uninstall-candidate') -or (Test-Path -LiteralPath $global:guardStop)){throw 'MSI 未定状态没有保留保护网卡或启动了回退'}
Write-Output 'PASS 模拟 Windows MSI 降级顺序、validation 隔离及超时保留 guard；没有操作真实服务。'
# Exercise the real guard predicate with actual CIM string formats, typed GUIDs,
# malformed unrelated rows and missing/duplicate ownership; no MSI is launched.
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
$definition=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'AssertDriverGuard'},$true)
if($parseErrors.Count -or -not $definition){throw '无法提取正式保护检查函数'}
$checkGuard=[scriptblock]::Create($definition.Extent.Text+"`nAssertDriverGuard")
$guardInfo=Get-Content -Raw -LiteralPath $global:guardReport|ConvertFrom-Json
$fixtureGuardStart=[DateTime]$guardInfo.StartedAt
$guardScope=$global:guardScope;$guardStarted=$fixtureGuardStart.ToString('O');$serviceName=$global:testService;$data=$global:testData;$evidence=$root
$guard=[pscustomobject]@{HasExited=$false;Id=321;StartTime=$fixtureGuardStart};$guard|Add-Member ScriptMethod Refresh {}
$junk=@([pscustomobject]@{InterfaceGuid=$null},[pscustomobject]@{InterfaceGuid='not-a-guid'},[pscustomobject]@{InterfaceGuid=[guid]::NewGuid().ToString('B')})
foreach($representation in @($global:guardGuid,$global:guardGuid.ToString('B').ToUpperInvariant(),$global:guardGuid.ToString('D').ToLowerInvariant())){
 $global:adapterGuidRows=$junk+@([pscustomobject]@{InterfaceGuid=$representation;InterfaceDescription='StreamLink Tunnel'})
 & $checkGuard
}
foreach($invalidRows in @(@($junk),@([pscustomobject]@{InterfaceGuid=$global:guardGuid.ToString('B')},[pscustomobject]@{InterfaceGuid=$global:guardGuid.ToString('D')}))){
 $global:adapterGuidRows=$invalidRows;$rejected=$false
 try{& $checkGuard}catch{if($_.Exception.Message -notmatch '保护网卡接口不可确认'){throw};$rejected=$true}
 if(-not $rejected){throw '缺失或重复的保护 GUID 被接受'}
}
$guardInfo.InterfaceGuid='invalid-guid';$rejected=$false
try{& $checkGuard}catch{if($_.Exception.Message -notmatch '保护网卡 GUID 无效'){throw};$rejected=$true}
if(-not $rejected){throw '无效保护报告 GUID 被接受'}
$global:adapterGuidRows=$null
Write-Output 'PASS 真实CIM格式、大小写、Guid对象及无效/重复/缺失GUID的所有权检查。'
