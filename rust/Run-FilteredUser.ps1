param([Parameter(Mandatory)][string]$EncodedCommand,[Parameter(Mandatory)][string]$WorkingDirectory)
$ErrorActionPreference='Stop'
$taskName='ConWU-Validation-User-'+[guid]::NewGuid().ToString('N')
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$EncodedCommand) -WorkingDirectory $WorkingDirectory
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
try {
 $null=Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings
 Start-ScheduledTask -TaskName $taskName
 $deadline=[datetime]::UtcNow.AddMinutes(4)
 do {
  Start-Sleep -Milliseconds 300
  $info=Get-ScheduledTaskInfo -TaskName $taskName
  $state=(Get-ScheduledTask -TaskName $taskName).State
  if([datetime]::UtcNow -gt $deadline){throw 'Ordinary user check timed out'}
 } while($info.LastRunTime.Year -lt 2020 -or $state -eq 'Running' -or $state -eq 'Queued')
 exit [int]$info.LastTaskResult
} finally {
 Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
