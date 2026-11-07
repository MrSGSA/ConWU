#requires -Version 7.0
#requires -RunAsAdministrator
param([Parameter(Mandatory)][string]$Runtime,[Parameter(Mandatory)][string]$Evidence)
$ErrorActionPreference='Stop';$Runtime=[IO.Path]::GetFullPath($Runtime);$Evidence=[IO.Path]::GetFullPath($Evidence)
if(Test-Path -LiteralPath $Evidence){throw '证据目录必须不存在'}
New-Item -ItemType Directory -Path $Evidence|Out-Null
& icacls.exe $Evidence /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
if($LASTEXITCODE){throw '无法保护证据目录'}
function Snapshot { @(Get-NetAdapter -IncludeHidden|Sort-Object InterfaceGuid|Select-Object Name,InterfaceGuid,InterfaceDescription,Status)|ConvertTo-Json -Compress }
$before=Snapshot;$before|Set-Content -LiteralPath (Join-Path $Evidence 'adapters-before.json')
$instance=[guid]::NewGuid().ToString('N');$scope=[guid]::NewGuid().ToString('N');$exe=Join-Path $Runtime 'ConWU.exe';$report=Join-Path $Evidence 'guard.json';$stop=Join-Path $Evidence 'guard.stop';$unsafe=Join-Path $Evidence 'inherited';New-Item -ItemType Directory -Path $unsafe|Out-Null
$bad=Start-Process -FilePath $exe -ArgumentList @('--validation-instance',$instance,'--driver-guard','hold',$scope,('"'+(Join-Path $unsafe 'ready.json')+'"'),('"'+(Join-Path $unsafe 'stop')+'"')) -WindowStyle Hidden -PassThru
if(-not $bad.WaitForExit(15000) -or $bad.ExitCode -eq 0){throw '非私有目录 guard 未安全拒绝'}
$weak=Join-Path $Evidence 'weak';New-Item -ItemType Directory -Path $weak|Out-Null
& icacls.exe $weak /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-1-0:(OI)(CI)M'|Out-Null
if($LASTEXITCODE){throw '无法构造弱 DACL 夹具'}
$bad=Start-Process -FilePath $exe -ArgumentList @('--validation-instance',$instance,'--driver-guard','hold',$scope,('"'+(Join-Path $weak 'ready.json')+'"'),('"'+(Join-Path $weak 'stop')+'"')) -WindowStyle Hidden -PassThru
if(-not $bad.WaitForExit(15000) -or $bad.ExitCode -eq 0){throw '允许其他主体写入的 guard 目录未安全拒绝'}
$launcher=Join-Path $Evidence 'launcher.ps1';$pidFile=Join-Path $Evidence 'guard.pid'
@'
param($Exe,$Instance,$Scope,$Report,$Stop,$PidFile)
$p=Start-Process -FilePath $Exe -ArgumentList @('--validation-instance',$Instance,'--driver-guard','hold',$Scope,('"'+$Report+'"'),('"'+$Stop+'"')) -WindowStyle Hidden -PassThru
[IO.File]::WriteAllText($PidFile,[string]$p.Id)
'@ | Set-Content -LiteralPath $launcher
$parent=Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile','-File',('"'+$launcher+'"'),('"'+$exe+'"'),$instance,$scope,('"'+$report+'"'),('"'+$stop+'"'),('"'+$pidFile+'"')) -WindowStyle Hidden -PassThru
if(-not $parent.WaitForExit(15000) -or $parent.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $pidFile)){throw '短父进程启动 guard 失败'}
$process=Get-Process -Id ([int](Get-Content -Raw -LiteralPath $pidFile)) -ErrorAction Stop
$deadline=[DateTime]::UtcNow.AddSeconds(60);while(-not (Test-Path -LiteralPath $report) -and [DateTime]::UtcNow -lt $deadline){$process.Refresh();if($process.HasExited){break};Start-Sleep -Milliseconds 250}
if(-not (Test-Path -LiteralPath $report)){throw "guard 未报告，保留 PID $($process.Id)"}
$r=Get-Content -Raw -LiteralPath $report|ConvertFrom-Json;if($r.Status -ne 'Ready' -or $r.Scope -cne $scope -or $r.ProcessId -ne $process.Id){throw "guard 未就绪，保留 PID $($process.Id)"}
$expected='SWD\WINTUN\'+([guid]$r.InterfaceGuid).ToString('B').ToUpperInvariant();if(-not (Get-PnpDevice -PresentOnly -InstanceId $expected -ErrorAction SilentlyContinue)){throw "guard PnP 未出现：$expected；保留 PID $($process.Id)"}
$target=Join-Path $Evidence 'invalid-target';New-Item -ItemType File -Path $target|Out-Null
New-Item -ItemType SymbolicLink -Path $stop -Target $target|Out-Null;Start-Sleep -Seconds 2;$process.Refresh();if($process.HasExited){throw '非法 stop 链接导致 guard 退出'}
Remove-Item -LiteralPath $stop;[IO.File]::Open($stop,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None).Dispose()
if(-not $process.WaitForExit(90000) -or -not (Test-Path -LiteralPath ($report+'.stopped'))){throw "guard 未确认释放；PID $($process.Id)"}
$stopped=Get-Content -Raw -LiteralPath ($report+'.stopped')|ConvertFrom-Json
if($stopped.Status -ne 'Stopped' -or $stopped.Scope -cne $scope -or $stopped.ProcessId -ne $r.ProcessId -or $stopped.StartedAt -ne $r.StartedAt){throw 'guard 释放报告身份不匹配'}
if(Get-PnpDevice -PresentOnly -InstanceId $expected -ErrorAction SilentlyContinue){throw "guard PnP 仍 present：$expected"}
$after=@(Get-NetAdapter -IncludeHidden|Where-Object {$_.InterfaceGuid -ne [guid]$r.InterfaceGuid}|Sort-Object InterfaceGuid|Select-Object Name,InterfaceGuid,InterfaceDescription,Status)|ConvertTo-Json -Compress;$after|Set-Content -LiteralPath (Join-Path $Evidence 'adapters-after.json')
if($before -cne $after){throw '外部网卡清单有变化'}
@{status='Pass';scope=$scope;interfaceGuid=$r.InterfaceGuid;instance=$instance;checks=@('private DACL','short parent exited','invalid stop ignored','owned PnP absent','external inventory unchanged')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Evidence 'result.json')
