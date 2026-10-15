function Assert-PersonalTunProtectedInput([string]$Path) {
 $at=[IO.Path]::GetFullPath($Path);if($at.StartsWith('\\')){throw 'Local protected evidence required'};$first=$true
 $allowed=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
 while($at){
  $item=Get-Item -LiteralPath $at -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked evidence or ancestor rejected'}
  $acl=Get-Acl -LiteralPath $at
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Evidence/ancestor owner is not a trusted system administrator'}
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
   if($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly){continue}
   # CreateFiles/CreateDirectories on an ancestor permits siblings, not the
   # replacement of an existing protected component. DELETE_CHILD does.
   $write=[Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
   if($first){$write=$write -bor [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData}
   if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and $rule.IdentityReference.Value -notin $allowed){throw 'Evidence or ancestor can be replaced by a non-administrative identity'}
  }
  $first=$false;$at=[IO.Path]::GetDirectoryName($at)
 }
}
