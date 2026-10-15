#requires -Version 7.0
# InteractiveToken/LUA test runner. Arguments must never contain credentials or
# launch tickets: only fixture paths and validation IDs are persisted here.
param([Parameter(Mandatory)][string]$Executable,[string[]]$Arguments,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$taskId='StreamLink-UI-Test-'+[guid]::NewGuid().ToString('N')
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a fresh ordinary-user evidence directory'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$argumentsFile=Join-Path $OutputDirectory 'launch.json'
@{exe=[IO.Path]::GetFullPath($Executable);args=$Arguments}|ConvertTo-Json|Set-Content -LiteralPath $argumentsFile -Encoding utf8NoBOM
$runner=Join-Path $OutputDirectory 'run.ps1'
@'
$ErrorActionPreference='Stop'
try{
 $settings=Get-Content (Join-Path $PSScriptRoot 'launch.json') -Raw|ConvertFrom-Json
 $argsText=if($settings.args){($settings.args|ForEach-Object{if($_.Contains('"')){throw 'Quoted test argument refused'};'"'+$_+'"'}) -join ' '}else{''}
 $start=@{FilePath=$settings.exe;WindowStyle='Hidden';PassThru=$true}
 if($argsText){$start.ArgumentList=$argsText}
 $p=Start-Process @start
 if(-not $p.WaitForExit(120000)){$p.Kill($true);throw 'Owned test timeout'}
 @{exit=$p.ExitCode;admin=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}|ConvertTo-Json|Set-Content (Join-Path $PSScriptRoot 'launch-result.json')
}catch{@{error=$_.Exception.Message}|ConvertTo-Json|Set-Content (Join-Path $PSScriptRoot 'launch-result.json')}
'@|Set-Content -LiteralPath $runner -Encoding utf8NoBOM
$scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect();$root=$scheduler.GetFolder('\');$definition=$scheduler.NewTask(0)
$definition.RegistrationInfo.Description='Temporary ordinary-token isolated StreamLink UI test; removed by test runner'
$definition.Principal.UserId=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$definition.Principal.LogonType=3;$definition.Principal.RunLevel=0
$definition.Settings.Hidden=$true;$definition.Settings.ExecutionTimeLimit='PT3M';$definition.Settings.DisallowStartIfOnBatteries=$false;$definition.Settings.StopIfGoingOnBatteries=$false
$action=$definition.Actions.Create(0);$action.Path=(Join-Path $PSHOME 'pwsh.exe');$action.Arguments='-NoProfile -WindowStyle Hidden -File "'+$runner+'"';$action.WorkingDirectory=$OutputDirectory
try{
 $task=$root.RegisterTaskDefinition($taskId,$definition,6,$definition.Principal.UserId,$null,3);$task.Run($null)|Out-Null
 $watch=[Diagnostics.Stopwatch]::StartNew();while(-not(Test-Path (Join-Path $OutputDirectory 'launch-result.json'))){if($watch.Elapsed.TotalSeconds -gt 140){throw 'Ordinary task did not finish'};Start-Sleep -Milliseconds 100}
 Get-Content (Join-Path $OutputDirectory 'launch-result.json') -Raw
}finally{try{$root.DeleteTask($taskId,0)}catch{}}
