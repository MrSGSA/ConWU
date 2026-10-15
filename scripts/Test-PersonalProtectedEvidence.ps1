param([Parameter(Mandatory)][string]$Output)
$ErrorActionPreference='Stop';if(Test-Path -LiteralPath $Output){throw 'Fresh evidence required'}
. (Join-Path $PSScriptRoot '../drivers/Assert-PersonalTunProtectedInput.ps1')
$parent=[Environment]::GetFolderPath('CommonApplicationData');$name='StreamLink-GateAudit-'+[guid]::NewGuid().ToString('N');$root=Join-Path $parent $name
$rows=[Collections.Generic.List[object]]::new();$status='Fail'
function Protect([string]$Path,[switch]$File){
 $acl=if($File){[Security.AccessControl.FileSecurity]::new()}else{[Security.AccessControl.DirectorySecurity]::new()};$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $rule=if($File){[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow')}
   else{[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')}
  $acl.AddAccessRule($rule)
 }
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));Set-Acl -LiteralPath $Path -AclObject $acl
}
function Refuse([string]$Path,[string]$Label){
 $refused=$false;try{Assert-PersonalTunProtectedInput $Path}catch{$refused=$true}
 if(-not $refused){throw "Unsafe evidence accepted: $Label"};$rows.Add(@{test=$Label;rejected=$true})
}
try{
 New-Item -ItemType Directory -Path $root|Out-Null;Protect $root
 $file=Join-Path $root 'evidence.json';'synthetic ACL test, no gate approval'|Set-Content -LiteralPath $file;Protect $file -File
 Assert-PersonalTunProtectedInput $file;$rows.Add(@{test='protected leaf under actual default ProgramData ancestors';accepted=$true})
 $acl=Get-Acl -LiteralPath $file;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Write','Allow'));Set-Acl -LiteralPath $file -AclObject $acl
 Refuse $file 'user-writable leaf';Protect $file -File
 $weak=Join-Path $root 'weak';New-Item -ItemType Directory -Path $weak|Out-Null;Protect $weak
 $inside=Join-Path $weak 'protected.json';'synthetic'|Set-Content $inside;Protect $inside -File
 $acl=Get-Acl -LiteralPath $weak;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'DeleteSubdirectoriesAndFiles','Allow'));Set-Acl -LiteralPath $weak -AclObject $acl
 Refuse $inside 'replaceable ancestor despite protected leaf';$status='Pass'
}finally{
 @{status=$status;checks=$rows.Count;rows=$rows;scope='Actual own temporary files/ACLs and read-only default ancestors. No trust policy, driver, service or existing directory ACL changed.'}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $Output
 if(Test-Path -LiteralPath $root){$resolved=[IO.Path]::GetFullPath($root)
  if($resolved -ne [IO.Path]::GetFullPath((Join-Path $parent $name)) -or -not $resolved.StartsWith([IO.Path]::GetFullPath($parent)+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or (Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Owned ACL test cleanup boundary rejected'}
  Remove-Item -LiteralPath $resolved -Recurse -Force
 }
}
