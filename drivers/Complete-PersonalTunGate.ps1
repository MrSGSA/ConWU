#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory)][string]$Package,[Parameter(Mandatory)][string]$KernelResult,
 [Parameter(Mandatory)][string]$PermissionResult,[Parameter(Mandatory)][string]$VerifierEvidence,
 [Parameter(Mandatory)][string]$OutputRoot,[string]$TargetMachineGuid,
 [string]$TargetDeviceInstance,[switch]$AuthorizeTarget,[ValidateRange(1,30)][int]$Days=7)
$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required for protected gate publication'}
function Protected-Input([string]$p){
 $at=[IO.Path]::GetFullPath($p);if($at.StartsWith('\\')){throw 'Local protected evidence required'};$first=$true
 $allowed=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
 while($at){
  $item=Get-Item -LiteralPath $at;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked evidence or ancestor rejected'}
  $acl=Get-Acl -LiteralPath $at
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Evidence/ancestor owner is not a trusted system administrator'}
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
   $write=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
   if($first){$write=$write -bor [Security.AccessControl.FileSystemRights]::AppendData}
   if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and $rule.IdentityReference.Value -notin $allowed){throw 'Evidence or ancestor can be replaced by a non-administrative identity'}
  }
  $first=$false;$at=[IO.Path]::GetDirectoryName($at)
 }
}
foreach($p in @($KernelResult,$PermissionResult,$VerifierEvidence)){Protected-Input $p}
$k=Get-Content -LiteralPath $KernelResult -Raw|ConvertFrom-Json;$p=Get-Content -LiteralPath $PermissionResult -Raw|ConvertFrom-Json;$v=Get-Content -LiteralPath $VerifierEvidence -Raw|ConvertFrom-Json
$hash=(Get-FileHash -LiteralPath (Join-Path $Package 'package-identity.json')).Hash
& (Join-Path $PSScriptRoot 'Manage-PersonalTun.ps1') -Package $Package -Action Status|Out-Null
if((Get-AuthenticodeSignature -LiteralPath (Join-Path $Package 'StreamLinkTun.cat')).Status -ne 'Valid'){throw 'Sign and refreeze package before publishing gates'}
. (Join-Path $PSScriptRoot 'Assert-PersonalTunCatalog.ps1');Assert-PersonalTunCatalog $Package -KernelPolicy
. (Join-Path $PSScriptRoot 'Assert-PersonalTunEvidence.ps1')
Assert-PersonalTunEvidence $k $p $v $hash (Get-FileHash -LiteralPath $KernelResult).Hash
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
