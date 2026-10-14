#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([ValidateSet('Status','InstallLab','RemoveLab')][string]$Action='Status',
 [Parameter(Mandatory)][string]$Package,[string]$DevCon,[string]$DeviceInstance,
 [switch]$AuthorizedRecoverableLab,[switch]$RecoveryConfirmed,[string]$Output)
$ErrorActionPreference='Stop'
function File-Sha256([string]$Path){$stream=[IO.File]::OpenRead($Path);$hash=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','')}finally{$stream.Dispose();$hash.Dispose()}}
$Package=[IO.Path]::GetFullPath($Package)
$identityFile=Join-Path $Package 'package-identity.json'
if(-not(Test-Path -LiteralPath $identityFile -PathType Leaf)){throw 'Missing exact package identity'}
$identity=Get-Content -LiteralPath $identityFile -Raw|ConvertFrom-Json
if($identity.SchemaVersion -ne 1 -or $identity.Architecture -ne 'win-x64' -or $identity.DescriptorAbi -ne 2 -or $identity.UserAbi -ne 1 -or $identity.Mtu -ne 1280 -or $identity.HardwareId -ne 'ROOT\StreamLinkTun' -or $identity.ServiceName -ne 'StreamLinkTun'){throw 'Package ABI/model mismatch'}
$names=@('StreamLinkTun.sys','StreamLinkTun.inf','StreamLinkTun.cat','streamlink-tun-research.dll')
if(@($identity.Files).Count -ne 4 -or @($identity.Files|Select-Object -ExpandProperty Name -Unique).Count -ne 4){throw 'Package file set is not unique'}
foreach($entry in $identity.Files){
 if($entry.Name -cnotin $names -or $entry.Sha256 -notmatch '^[0-9A-Fa-f]{64}$'){throw 'Package member outside allow-list'}
 $p=Join-Path $Package $entry.Name
 if((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked driver member rejected'}
 if((File-Sha256 $p) -ne $entry.Sha256){throw 'Driver member hash mismatch'}
}
$cat=Get-AuthenticodeSignature -LiteralPath (Join-Path $Package 'StreamLinkTun.cat')
$devices=@(Get-CimInstance Win32_PnPEntity -OperationTimeoutSec 8 | Where-Object {$_.Service -eq 'StreamLinkTun' -and $_.PNPDeviceID -like 'ROOT\STREAMLINKTUN\*'})
$report=[ordered]@{schemaVersion=1;utc=[DateTime]::UtcNow;action=$Action;packageHash=(File-Sha256 $identityFile);sourceCommit=$identity.SourceCommit;
 catalogSignature=[string]$cat.Status;signatureValid=$cat.Status -eq 'Valid';devices=@($devices|Select-Object PNPDeviceID,Service,ConfigManagerErrorCode,Status);
 driverLoaded=@(Get-CimInstance Win32_SystemDriver -OperationTimeoutSec 8|Where-Object Name -eq 'StreamLinkTun'|Select-Object Name,State,PathName);
 kernelIo='NotTested';kernelGate='BlockedExternal';securityPolicyChanged=$false;productFallback='official-wintun';statusOnly=$Action -eq 'Status'}
if($Output){if(Test-Path -LiteralPath $Output){throw 'Fresh evidence path required'};$report|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $Output -Encoding UTF8}
if($Action -eq 'Status'){$report|ConvertTo-Json -Depth 6;return}
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $admin -or -not $AuthorizedRecoverableLab -or -not $RecoveryConfirmed){throw 'Kernel operations require admin, explicit recoverable-lab authorization and a confirmed recovery route. Daily machines are not authorized by this script.'}
if(-not $DevCon -or -not(Test-Path -LiteralPath $DevCon -PathType Leaf)){throw 'Provide Microsoft WDK devcon.exe; no arbitrary downloaded device manager is bundled'}
$toolSignature=Get-AuthenticodeSignature -LiteralPath $DevCon
if($toolSignature.Status -ne 'Valid' -or $toolSignature.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'Microsoft WDK tool signature not verified'}
if($Action -eq 'InstallLab'){
 if($cat.Status -ne 'Valid'){throw 'Unsigned/untrusted catalog rejected; no device was created. Obtain approved signing; do not disable security policy.'}
 if($devices.Count){throw 'Owned device already exists; inspect it, never create a second instance automatically'}
 if($PSCmdlet.ShouldProcess('ROOT\StreamLinkTun on explicitly authorized lab','Create exactly one root adapter and install current signed INF')){
  & $DevCon install (Join-Path $Package 'StreamLinkTun.inf') 'ROOT\StreamLinkTun'
  if($LASTEXITCODE -notin @(0,1)){throw 'OS rejected installation; preserve CodeIntegrity/SetupAPI evidence; do not change policy and retry'}
  if($LASTEXITCODE -eq 1){Write-Warning 'WDK reports reboot required; no automatic restart performed'}
 }
}else{
 if(-not $DeviceInstance -or $DeviceInstance -notmatch '^ROOT\\STREAMLINKTUN\\[A-Za-z0-9_&-]+$'){throw 'An exact owned device instance is required, not a wildcard/hardware ID'}
 $owned=@($devices|Where-Object PNPDeviceID -eq $DeviceInstance)
 if($owned.Count -ne 1){throw 'Exact instance does not uniquely belong to StreamLinkTun; no removal performed'}
 if($PSCmdlet.ShouldProcess($DeviceInstance,'Remove only the selected owned lab adapter; retain shared drivers and profiles')){
  & $DevCon remove "@$DeviceInstance"
  if($LASTEXITCODE -notin @(0,1)){throw 'Owned-device removal failed'}
 }
}
