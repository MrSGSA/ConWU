#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory)][string]$Package,[Parameter(Mandatory)][string]$KernelResult,
 [Parameter(Mandatory)][string]$PermissionResult,[Parameter(Mandatory)][string]$VerifierEvidence,
 [Parameter(Mandatory)][string]$OutputRoot,[string]$TargetMachineGuid,
 [string]$TargetDeviceInstance,[switch]$AuthorizeTarget,[ValidateRange(1,30)][int]$Days=7)
$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required for protected gate publication'}
function Protected-Input([string]$p){
 $item=Get-Item -LiteralPath $p
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked evidence rejected'}
 $acl=Get-Acl -LiteralPath $p;$allowed=@('S-1-5-18','S-1-5-32-544')
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Evidence owner is not SYSTEM/Administrators'}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  $write=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and $rule.IdentityReference.Value -notin $allowed){throw 'Evidence writable by a non-administrative identity'}
 }
}
foreach($p in @($KernelResult,$PermissionResult,$VerifierEvidence)){Protected-Input $p}
$k=Get-Content -LiteralPath $KernelResult -Raw|ConvertFrom-Json;$p=Get-Content -LiteralPath $PermissionResult -Raw|ConvertFrom-Json;$v=Get-Content -LiteralPath $VerifierEvidence -Raw|ConvertFrom-Json
$hash=(Get-FileHash -LiteralPath (Join-Path $Package 'package-identity.json')).Hash
& (Join-Path $PSScriptRoot 'Manage-PersonalTun.ps1') -Package $Package -Action Status|Out-Null
if((Get-AuthenticodeSignature -LiteralPath (Join-Path $Package 'StreamLinkTun.cat')).Status -ne 'Valid'){throw 'Sign and refreeze package before publishing gates'}
if($k.tool -ne 'StreamLink.TunKernelTests' -or $k.evidenceLevel -ne 'DriverKernelIO' -or $k.status -ne 'Pass' -or
 $k.kernelIo -ne 'Pass' -or $k.cancellation -ne 'Pass' -or $k.cleanup -ne 'Pass' -or $k.PackageHash -ne $hash -or
 $p.permissions -ne 'Pass' -or $p.admin -ne $false -or $p.openError -ne 5 -or $p.PackageHash -ne $hash -or $p.machine -ne $k.machine -or $p.RunId -ne $k.RunId){throw 'Actual kernel/standard-user evidence does not match this exact package/run'}
if($v.schemaVersion -ne 1 -or $v.packageHash -ne $hash -or $v.machine -ne $k.machine -or $v.driver -ne 'StreamLinkTun.sys' -or
 $v.bootedWithVerifier -ne $true -or $v.result -ne 'Pass' -or $v.operatorReviewed -ne $true -or -not $v.rawFiles){throw 'Booted targeted Verifier run and explicit operator review required, not a NotTested template'}
$base=Split-Path -Parent ([IO.Path]::GetFullPath($VerifierEvidence))
foreach($file in $v.rawFiles){
 if($file.path -notmatch '^[A-Za-z0-9_.-]+$' -or $file.sha256 -notmatch '^[0-9A-Fa-f]{64}$'){throw 'Invalid Verifier evidence member'}
 $at=Join-Path $base $file.path;Protected-Input $at
 if((Get-FileHash -LiteralPath $at).Hash -ne $file.sha256){throw 'Verifier raw evidence hash mismatch'}
}
$OutputRoot=[IO.Path]::GetFullPath($OutputRoot)
if(Test-Path -LiteralPath $OutputRoot){throw 'Fresh protected output required; prior approvals are never overwritten'}
if($AuthorizeTarget -and ($TargetMachineGuid -notmatch '^[0-9a-fA-F-]{36}$' -or $TargetDeviceInstance -notmatch '^ROOT\\STREAMLINKTUN\\[A-Za-z0-9_&-]+$')){throw 'Exact authorized target identity required'}
if(-not $PSCmdlet.ShouldProcess($OutputRoot,'Publish verified kernel gate and optional exact-target approval')){return}
New-Item -ItemType Directory -Path $OutputRoot|Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));Set-Acl -LiteralPath $OutputRoot -AclObject $acl
$gate=Join-Path $OutputRoot 'kernel-gate.json'
[ordered]@{schemaVersion=2;evidenceLevel='DriverKernelIO';packageHash=$hash;kernelIo='Pass';cancellation='Pass';permissions='Pass';cleanup='Pass';verifier='Pass';guestMachine=$k.machine;
 rawInputs=@($KernelResult,$PermissionResult,$VerifierEvidence|ForEach-Object{@{file=(Split-Path $_ -Leaf);sha256=(Get-FileHash -LiteralPath $_).Hash}});publicApproval=$false}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $gate
if($AuthorizeTarget){[ordered]@{SchemaVersion=1;MachineGuid=$TargetMachineGuid;PackageHash=$hash;DeviceInstanceId=$TargetDeviceInstance;Purpose='personal-target-after-kernel-gate';ExpiresUtc=[DateTimeOffset]::UtcNow.AddDays($Days);KernelEvidenceSha256=(Get-FileHash -LiteralPath $gate).Hash}|ConvertTo-Json|Set-Content (Join-Path $OutputRoot 'target-approval.json')}
Write-Output 'Gate fixed. Guest evidence is not host coverage: product still requires trusted catalog and exact loaded target device/image.'
