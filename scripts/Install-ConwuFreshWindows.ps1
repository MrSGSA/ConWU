#requires -Version 7.0
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$CandidateMsi,[Parameter(Mandatory)][string]$CandidateHash,
 [Parameter(Mandatory)][string]$RollbackMsi,[Parameter(Mandatory)][string]$RollbackHash,
 [Parameter(Mandatory)][string]$MaintenanceExe,[Parameter(Mandatory)][string]$MaintenanceHash,[Parameter(Mandatory)][string]$ExpectedManifestHash,[Parameter(Mandatory)][string]$ExpectedCommit,
 [Parameter(Mandatory)][string]$BackupParent,[string]$ValidationInstance
)
$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw '必须以管理员身份运行。'}
$serviceName='StreamLink-PersonalFeature'
$data=[IO.Path]::GetFullPath((Join-Path $env:ProgramData $serviceName))
$install=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'StreamLink'))
$expectedUpgrade='{AD076018-A9B8-47F5-B098-97479A363416}'
$maintenancePrefix=@()
if($ValidationInstance){
 $validationGuid=[guid]::Empty
 if(-not [guid]::TryParseExact($ValidationInstance,'N',[ref]$validationGuid) -or $validationGuid -eq [guid]::Empty){throw 'ValidationInstance 必须是非零的 32 位 GUID。'}
 $serviceName='StreamLink-Validation-'+$ValidationInstance
 $data=[IO.Path]::GetFullPath((Join-Path $env:ProgramData ('StreamLink-Validation\'+$ValidationInstance)))
 $install=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles ('StreamLink-Validation\'+$ValidationInstance+'\msi')))
 $expectedUpgrade='{'+$validationGuid.ToString('D')+'}'
 $maintenancePrefix=@('--validation-instance',$ValidationInstance)
}
$parent=[IO.Path]::GetFullPath($BackupParent)
foreach($v in @($CandidateMsi,$RollbackMsi,$MaintenanceExe)) {if(-not (Test-Path -LiteralPath $v -PathType Leaf)){throw '候选或回退文件不存在。'}}
if(-not (Test-Path -LiteralPath $parent -PathType Container)){throw '备份父目录必须已经存在。'}
foreach($p in @($data,$install,$parent)) {
 $item=Get-Item -LiteralPath $p -Force
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "拒绝重解析点：$p"}
}
foreach($p in @($data,$install)){if($parent.Equals($p,[StringComparison]::OrdinalIgnoreCase) -or $parent.StartsWith($p+'\',[StringComparison]::OrdinalIgnoreCase)){throw '备份不能位于产品目录内。'}}
foreach($pair in @(@($CandidateMsi,$CandidateHash),@($RollbackMsi,$RollbackHash),@($MaintenanceExe,$MaintenanceHash))) {
 if($pair[1] -notmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ine $pair[1]){throw '文件哈希不匹配。'}
}
$service=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if(-not $service -or -not $service.PathName.TrimStart('"').StartsWith($install+'\',[StringComparison]::OrdinalIgnoreCase)){throw '服务不存在或不属于预期的 ConWU 安装。'}
# Reject junctions anywhere inside the product data rather than following them
# during backup or rename; other applications are never traversed.
if(@(Get-ChildItem -LiteralPath $data -Force -Recurse | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw '产品数据包含链接，无法安全备份。'}
$installer=New-Object -ComObject WindowsInstaller.Installer
if(-not ('ConwuInstallerProductState' -as [type])){Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class ConwuInstallerProductState { [DefaultDllImportSearchPaths(DllImportSearchPath.System32)] [DllImport("msi.dll", CharSet=CharSet.Unicode, ExactSpelling=true)] public static extern int MsiQueryProductStateW(string product); }'}
function Get-MsiProductState([string]$product) {
 $state=[ConwuInstallerProductState]::MsiQueryProductStateW($product)
 if($state -notin @(-1,1,2,3,4,5)){throw "无法确认 MSI 产品状态：$state"}
 return $state
}
function MsiProperty([string]$path,[string]$property) {
 $db=$installer.OpenDatabase([IO.Path]::GetFullPath($path),0)
 $view=$db.OpenView(('SELECT `Value` FROM `Property` WHERE `Property`=''{0}''' -f $property))
 [void]$view.Execute();$row=$view.Fetch();if(-not $row){throw "MSI 缺少 $property"};$value=$row.StringData(1)
 if($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)){throw "MSI 的 $property 为空或无效"};return $value
}
$candidateProduct=MsiProperty $CandidateMsi 'ProductCode';$oldProduct=MsiProperty $RollbackMsi 'ProductCode'
$candidateUpgrade=MsiProperty $CandidateMsi 'UpgradeCode';$oldUpgrade=MsiProperty $RollbackMsi 'UpgradeCode'
if($candidateUpgrade -ine $expectedUpgrade -or $oldUpgrade -ine $expectedUpgrade -or $candidateProduct -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or $oldProduct -notmatch '^\{[0-9A-Fa-f-]{36}\}$'){throw 'MSI 产品身份不匹配。'}
if($candidateProduct -ieq $oldProduct){throw '候选和回退 MSI 的产品代码相同，无法安全区分卸载目标。'}
if((Get-MsiProductState $oldProduct) -notin @(3,4,5)){throw '指定的回退 MSI 与当前安装产品不匹配。'}
if($ExpectedCommit -notmatch '^[a-fA-F0-9]{40}$'){throw '需要候选完整源码提交标识。'}
function VerifyRuntime([string]$folder) {
 $folder=[IO.Path]::GetFullPath($folder);$manifestPath=Join-Path $folder 'manifest.json'
 if($ExpectedManifestHash -notmatch '^[a-fA-F0-9]{64}$' -or -not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -ine $ExpectedManifestHash){throw '候选运行目录清单哈希不符。'}
 if(@(Get-ChildItem -LiteralPath $folder -Force -Recurse | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw '候选运行目录包含链接。'}
 $manifest=Get-Content -Raw -LiteralPath $manifestPath|ConvertFrom-Json
 if($manifest.sourceCommit -ine $ExpectedCommit -or -not $manifest.files){throw '候选运行目录提交或文件清单无效。'}
 $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($file in $manifest.files){$target=[IO.Path]::GetFullPath((Join-Path $folder $file.path));if(-not $target.StartsWith($folder+'\',[StringComparison]::OrdinalIgnoreCase) -or -not $names.Add($target) -or -not (Test-Path -LiteralPath $target -PathType Leaf) -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $file.sha256){throw '候选运行目录文件与清单不一致。'}}
 foreach($file in Get-ChildItem -LiteralPath $folder -File -Recurse -Force){if($file.FullName -ine $manifestPath -and -not $names.Contains($file.FullName)){throw '候选运行目录存在未列入清单的文件。'}}
 if(-not $names.Contains((Join-Path $folder 'ConWU.exe'))){throw '候选清单不含维护程序。'}
}
$maintenanceRuntime=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($MaintenanceExe))
if([IO.Path]::GetFileName($MaintenanceExe) -ine 'ConWU.exe'){throw '维护程序必须是候选运行目录中的 ConWU.exe。'}
VerifyRuntime $maintenanceRuntime
$evidence=Join-Path $parent ('conwu-fresh-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $evidence -ErrorAction Stop|Out-Null
& icacls.exe $evidence /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if($LASTEXITCODE){throw '无法保护备份目录 ACL。'}
Copy-Item -LiteralPath $CandidateMsi -Destination (Join-Path $evidence 'candidate.msi')
Copy-Item -LiteralPath $RollbackMsi -Destination (Join-Path $evidence 'previous.msi')
Copy-Item -LiteralPath $maintenanceRuntime -Destination (Join-Path $evidence 'maintenance-runtime') -Recurse -Force
VerifyRuntime (Join-Path $evidence 'maintenance-runtime')
$quarantine=$data+'.preinstall-'+[guid]::NewGuid().ToString('N')
if(Test-Path -LiteralPath $quarantine){throw '隔离目标已存在。'}
$wasRunning=$service.State -eq 'Running';$startMode=$service.StartMode
$service|Select-Object Name,State,StartMode,PathName|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'service-before.json') -Encoding utf8NoBOM
$stopped=$false;$moved=$false;$installed=$false;$indeterminate=$false
$guard=$null;$guardInfo=$null;$guardScope=[guid]::NewGuid().ToString('N');$guardReport=Join-Path $evidence 'driver-guard.json';$guardStop=Join-Path $evidence 'driver-guard.stop'
function StartDriverGuard {
 $guardArgs=$maintenancePrefix+@('--driver-guard','hold',$guardScope,('"'+$guardReport+'"'),('"'+$guardStop+'"'))
 $startedGuard=Start-Process -FilePath (Join-Path $evidence 'maintenance-runtime\ConWU.exe') -ArgumentList $guardArgs -WindowStyle Hidden -PassThru
 $until=[DateTime]::UtcNow.AddSeconds(45)
 while(-not (Test-Path -LiteralPath $guardReport) -and [DateTime]::UtcNow -lt $until){$startedGuard.Refresh();if($startedGuard.HasExited){break};Start-Sleep -Milliseconds 200}
 if(-not (Test-Path -LiteralPath $guardReport)){$script:indeterminate=$true;throw "保护网卡未确认启动；PID $($startedGuard.Id)，证据：$evidence"}
 $guardJson=Get-Content -Raw -LiteralPath $guardReport;$info=$guardJson|ConvertFrom-Json
 if($info.Status -ne 'Ready'){$startedGuard.Refresh();if(-not $startedGuard.HasExited){$script:indeterminate=$true};throw "保护网卡未就绪；PID $($startedGuard.Id)，证据：$evidence"}
 return @{process=$startedGuard;info=$info;started=[Text.Json.JsonDocument]::Parse($guardJson).RootElement.GetProperty('StartedAt').GetString()}
}
function AssertDriverGuard {
 if(-not $guard -or -not $guardInfo){throw '保护网卡尚未就绪。'}
 $guard.Refresh()
 if($guard.HasExited -or $guardInfo.Status -ne 'Ready' -or $guardInfo.Scope -cne $guardScope -or $guardInfo.Instance -ine $serviceName -or [IO.Path]::GetFullPath($guardInfo.DataRoot) -ine $data -or $guardInfo.ProcessId -ne $guard.Id -or $guard.StartTime.ToUniversalTime().Ticks -ne [DateTimeOffset]::Parse($guardStarted).UtcTicks){throw "保护网卡进程或代次不符；证据：$evidence"}
 $guardInterface=[guid]::Empty
 if(-not [guid]::TryParse([string]$guardInfo.InterfaceGuid,[ref]$guardInterface) -or $guardInterface -eq [guid]::Empty){throw "保护网卡 GUID 无效；证据：$evidence"}
 $interfaces=@(Get-NetAdapter -IncludeHidden|Where-Object {$adapterInterface=[guid]::Empty;[guid]::TryParse([string]$_.InterfaceGuid,[ref]$adapterInterface) -and $adapterInterface -eq $guardInterface})
 if($interfaces.Count -ne 1){throw "保护网卡接口不可确认；证据：$evidence"}
 $instance='SWD\WINTUN\'+$guardInterface.ToString('B').ToUpperInvariant()
 $present=@(Get-PnpDevice -PresentOnly -InstanceId $instance -ErrorAction Stop)
 if($present.Count -ne 1 -or $present[0].InstanceId -ine $instance){throw "保护网卡 PnP 实例不在场；证据：$evidence"}
}
function StopDriverGuard {
 AssertDriverGuard
 $stream=[IO.File]::Open($guardStop,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$stream.Dispose()
 if(-not $guard.WaitForExit(90000) -or $guard.ExitCode -ne 0 -or -not (Test-Path -LiteralPath ($guardReport+'.stopped'))){throw "保护网卡未确认释放；PID $($guard.Id)，证据：$evidence"}
 $doneJson=Get-Content -Raw -LiteralPath ($guardReport+'.stopped');$done=$doneJson|ConvertFrom-Json
 $doneStarted=[Text.Json.JsonDocument]::Parse($doneJson).RootElement.GetProperty('StartedAt').GetString()
 if($done.Status -ne 'Stopped' -or $done.Scope -cne $guardScope -or $done.ProcessId -ne $guard.Id -or $doneStarted -cne $guardStarted){throw "保护网卡释放报告不符；证据：$evidence"}
}
function RunMsi([string[]]$arguments,[string]$log) {
 AssertDriverGuard
 $args=@($arguments)+@('/qn','/norestart','/l*v',('"'+$log+'"'))
 $process=Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -WindowStyle Hidden -PassThru
 $until=[DateTime]::UtcNow.AddMilliseconds(900000)
 while(-not $process.WaitForExit(250)){
  try{AssertDriverGuard}catch{$script:indeterminate=$true;throw "保护网卡失效而 MSI 仍可能运行（PID $($process.Id)）；请检查 $evidence。"}
  if([DateTime]::UtcNow -ge $until){$script:indeterminate=$true;throw "MSI 尚在运行（PID $($process.Id)），禁止并发恢复；请检查 $log。"}
 }
 try{AssertDriverGuard}catch{$script:indeterminate=$true;throw "MSI 已结束但保护网卡失效，请检查 $evidence。"}
 if($process.ExitCode -eq 3010){$script:indeterminate=$true;throw 'MSI 要求重启；状态未确认，禁止自动并发恢复。'}
 if($process.ExitCode -ne 0){throw "MSI 失败，退出码 $($process.ExitCode)。"}
}
function Maintenance([string]$action) {
 $report=Join-Path $evidence ("adapter-$action.json")
 $p=Start-Process -FilePath (Join-Path $evidence 'maintenance-runtime\ConWU.exe') -ArgumentList ($maintenancePrefix+@('--adapter-maintenance',$action,('"'+$report+'"'))) -WindowStyle Hidden -Wait -PassThru
 if($p.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $report)){throw "适配器 $action 未完成。"}
 $r=Get-Content -Raw -LiteralPath $report|ConvertFrom-Json
 if($r.Schema -ne 1 -or $r.Instance -ine $serviceName -or [IO.Path]::GetFullPath($r.DataRoot) -ine $data -or $r.ServiceStopped -ne $true -or $r.Error -or ($action -eq 'release' -and $r.Released -ne $true)){throw "适配器 $action 报告未通过校验。"}
}
function RestoreServiceMode {
 if(-not $wasRunning -and (Get-Service -Name $serviceName).Status -ne 'Stopped'){Stop-Service -Name $serviceName -ErrorAction Stop;(Get-Service -Name $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))}
 if($wasRunning -and $startMode -eq 'Disabled'){Set-Service -Name $serviceName -StartupType Manual}
 elseif($startMode -eq 'Disabled'){Set-Service -Name $serviceName -StartupType Disabled}
 elseif($startMode -eq 'Auto'){Set-Service -Name $serviceName -StartupType Automatic}
 else{Set-Service -Name $serviceName -StartupType Manual}
 if($wasRunning -and (Get-Service -Name $serviceName).Status -ne 'Running'){Start-Service -Name $serviceName -ErrorAction Stop;(Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(60))}
 if($wasRunning -and $startMode -eq 'Disabled'){Set-Service -Name $serviceName -StartupType Disabled}
}
$mutex=[Threading.Mutex]::new($false,('Global\ConwuFreshInstallTransaction-'+$serviceName))
if(-not $mutex.WaitOne(0)){$mutex.Dispose();throw '另一个全新安装任务正在运行。'}
try {
 $guardState=StartDriverGuard;$guard=$guardState.process;$guardInfo=$guardState.info;$guardStarted=$guardState.started;AssertDriverGuard
 Copy-Item -LiteralPath $data -Destination (Join-Path $evidence 'data-before-stop') -Recurse -Force
 if($wasRunning){Stop-Service -Name $serviceName -ErrorAction Stop;(Get-Service -Name $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))}
 if((Get-Service -Name $serviceName).Status -ne 'Stopped'){throw '服务尚未停止。'}
 $stopped=$true
 Copy-Item -LiteralPath $data -Destination (Join-Path $evidence 'data-stopped') -Recurse -Force
 Maintenance 'inspect';Maintenance 'release'
 Move-Item -LiteralPath $data -Destination $quarantine
 $moved=$true
 New-Item -ItemType Directory -Path $data|Out-Null
 RunMsi @('/i',('"'+[IO.Path]::GetFullPath($CandidateMsi)+'"')) (Join-Path $evidence 'candidate-install.log')
 $installed=$true
 VerifyRuntime (Join-Path $install 'app')
 RestoreServiceMode
 $indeterminate=$true;StopDriverGuard;$indeterminate=$false
 'installed'|Set-Content -LiteralPath (Join-Path $evidence 'result.txt')
 Write-Output "全新安装完成。旧数据：$quarantine；备份：$evidence"
} catch {
 $original=$_
 if($indeterminate){'msi-indeterminate'|Set-Content -LiteralPath (Join-Path $evidence 'result.txt');throw $original}
 $restoreErrors=[Collections.Generic.List[string]]::new()
 if($stopped){
  $safeToRestore=$true
  try {$currentService=Get-Service -Name $serviceName -ErrorAction SilentlyContinue;if($currentService -and $currentService.Status -ne 'Stopped'){Stop-Service -Name $serviceName -ErrorAction Stop;(Get-Service -Name $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))}}catch{$safeToRestore=$false;$restoreErrors.Add('停止新服务：'+$_.Exception.Message)}
  if(-not $safeToRestore){$restoreErrors|Set-Content -LiteralPath (Join-Path $evidence 'rollback-errors.txt');throw "切换失败且新服务未停止，已保留旧数据，未执行恢复：$evidence；$($original.Exception.Message)"}
  try {if((Get-MsiProductState $candidateProduct) -in @(3,4,5)){RunMsi @('/x',$candidateProduct) (Join-Path $evidence 'candidate-remove.log')}}catch{$restoreErrors.Add('查询或卸载候选 MSI：'+$_.Exception.Message)}
  if($restoreErrors.Count){$restoreErrors|Set-Content -LiteralPath (Join-Path $evidence 'rollback-errors.txt');throw "卸载候选版本失败，保留旧数据未恢复：$evidence；$($original.Exception.Message)"}
  if($moved){try {if(Test-Path -LiteralPath $data){Move-Item -LiteralPath $data -Destination (Join-Path $evidence 'failed-new-data')};Move-Item -LiteralPath $quarantine -Destination $data}catch{$restoreErrors.Add('恢复数据：'+$_.Exception.Message)}}
  if($restoreErrors.Count){$restoreErrors|Set-Content -LiteralPath (Join-Path $evidence 'rollback-errors.txt');throw "恢复旧数据失败，未安装回退 MSI：$evidence；$($original.Exception.Message)"}
  try {if((Get-MsiProductState $oldProduct) -notin @(3,4,5)){RunMsi @('/i',('"'+[IO.Path]::GetFullPath((Join-Path $evidence 'previous.msi'))+'"')) (Join-Path $evidence 'previous-install.log')}}catch{$restoreErrors.Add('恢复旧 MSI：'+$_.Exception.Message)}
  try {RestoreServiceMode}catch{$restoreErrors.Add('恢复服务状态：'+$_.Exception.Message)}
 }
 if($restoreErrors.Count){$restoreErrors|Set-Content -LiteralPath (Join-Path $evidence 'rollback-errors.txt');throw "切换失败且自动恢复不完整：$evidence；原始错误：$($original.Exception.Message)"}
 if($guardInfo -and $guardInfo.Status -eq 'Ready'){try{StopDriverGuard}catch{$_|Out-String|Set-Content -LiteralPath (Join-Path $evidence 'guard-cleanup-error.txt');throw "旧数据已恢复，但保护网卡未确认释放：$evidence"}}
 'rolled-back'|Set-Content -LiteralPath (Join-Path $evidence 'result.txt');throw "切换失败，已恢复原数据和服务；备份：$evidence；$($original.Exception.Message)"
} finally { $mutex.ReleaseMutex();$mutex.Dispose() }
