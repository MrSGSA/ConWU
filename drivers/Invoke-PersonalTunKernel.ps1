#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Package,[Parameter(Mandatory)][string]$Probe,
 [Parameter(Mandatory)][string]$HostMachineGuid,[Parameter(Mandatory)][string]$DeviceInstance,
 [switch]$AuthorizedRecoverableLab,[switch]$RecoveryConfirmed)
$ErrorActionPreference='Stop'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$machine=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
$cs=Get-CimInstance Win32_ComputerSystem
if(-not $admin -or -not $AuthorizedRecoverableLab -or -not $RecoveryConfirmed -or $machine -eq $HostMachineGuid -or
 $HostMachineGuid -notmatch '^[0-9a-fA-F-]{36}$' -or $cs.Model -notmatch 'Virtual Machine|VMware|VirtualBox|KVM|Standard PC'){
 throw 'Run only inside an explicitly authorized recoverable Windows guest; daily host is rejected before device I/O.'
}
if($DeviceInstance -notmatch '^ROOT\\STREAMLINKTUN\\[A-Za-z0-9_&-]+$'){throw 'Exact owned guest device required'}
$Package=[IO.Path]::GetFullPath($Package);$Probe=[IO.Path]::GetFullPath($Probe)
& (Join-Path $PSScriptRoot 'Manage-PersonalTun.ps1') -Package $Package -Action Status |Out-Null
$identity=Get-Content (Join-Path $Package 'package-identity.json') -Raw|ConvertFrom-Json
if((Get-AuthenticodeSignature (Join-Path $Package 'StreamLinkTun.cat')).Status -ne 'Valid'){throw 'Guest catalog must already be signed and trusted. No trust or boot policy is changed.'}
$adapter=@(Get-CimInstance Win32_NetworkAdapter|Where-Object PNPDeviceID -eq $DeviceInstance)
$driver=@(Get-CimInstance Win32_SystemDriver -Filter "Name='StreamLinkTun'")
if($adapter.Count -ne 1 -or $driver.Count -ne 1 -or $driver[0].State -ne 'Running'){throw 'Actual selected research device is not uniquely loaded'}
$image=$driver[0].PathName
if($image.StartsWith('\SystemRoot\')){$image=Join-Path $env:WINDIR $image.Substring(12)}
if($image.StartsWith('\??\')){$image=$image.Substring(4)}
if((Get-FileHash -LiteralPath $image).Hash -ne ($identity.Files|Where-Object Name -eq 'StreamLinkTun.sys').Sha256){throw 'Loaded image differs from tested package'}
$index=[uint32]$adapter[0].InterfaceIndex
if(@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.IPAddress -like '10.254.242.*' -or $_.InterfaceIndex -eq $index}).Count){throw 'Lab test subnet/interface is already configured; no existing address or route is changed'}
$run=[guid]::NewGuid();$root=Join-Path $env:ProgramData "StreamLink-TunLab\$run"
New-Item -ItemType Directory -Path $root -Force|Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));Set-Acl -LiteralPath $root -AclObject $acl
$plan=Join-Path $root 'lab-plan.json';$result=Join-Path $root 'kernel-result.json'
[ordered]@{RunId=$run;GuestMachineGuid=$machine;HostMachineGuid=$HostMachineGuid;InterfaceIndex=$index;
 PackageHash=(Get-FileHash (Join-Path $Package 'package-identity.json')).Hash;AuthorizedRecoverableLab=$true;RecoveryConfirmed=$true}|ConvertTo-Json|Set-Content $plan
$process=$null;$address=$null
try{
 & verifier.exe /query > (Join-Path $root 'verifier-before.txt')
 $address=New-NetIPAddress -InterfaceIndex $index -IPAddress '10.254.242.1' -PrefixLength 24 -PolicyStore ActiveStore
 $process=Start-Process -FilePath $Probe -ArgumentList @('--run',"`"$plan`"","`"$result`"") -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $root 'stdout.log') -RedirectStandardError (Join-Path $root 'stderr.log')
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not $process.WaitForExit(1000)){if($watch.Elapsed.TotalSeconds -gt 90){$process.Kill($true);$process.WaitForExit(5000)|Out-Null;throw 'Owned kernel test watchdog expired; preserve dump/Verifier/event evidence. No automatic rerun.'}}
 if($process.ExitCode -or -not(Test-Path $result)){throw 'Actual kernel probe failed; inspect fixed evidence directory'}
}finally{
 if($process){if(-not $process.HasExited){$process.Kill($true);$process.WaitForExit(5000)|Out-Null};$process.Dispose()}
 if($address){$address|Remove-NetIPAddress -Confirm:$false}
 Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue|
  Select-Object TimeCreated,Id,LevelDisplayName,Message|ConvertTo-Json -Depth 4|Set-Content (Join-Path $root 'code-integrity.json')
 & verifier.exe /querysettings > (Join-Path $root 'verifier-query.txt')
 & verifier.exe /query > (Join-Path $root 'verifier-after.txt')
}
Write-Output "Evidence retained in $root. Kernel IO alone is not a complete gate: collect standard-user denial and a booted, targeted Verifier run. No product approval was issued."
