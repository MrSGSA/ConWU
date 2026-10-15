#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory)][string]$Package)
$ErrorActionPreference='Stop';$Package=[IO.Path]::GetFullPath($Package)
$identity=Join-Path $Package 'package-identity.json';$v=Get-Content -LiteralPath $identity -Raw|ConvertFrom-Json
if($v.SchemaVersion -ne 1 -or $v.HardwareId -ne 'ROOT\StreamLinkTun' -or $v.SourceCommit -notmatch '^[a-f0-9]{40}$'){throw 'Original complete package identity required'}
$names=@('StreamLinkTun.sys','StreamLinkTun.inf','StreamLinkTun.cat','streamlink-tun-research.dll')
if(@($v.Files|Select-Object -ExpandProperty Name -Unique).Count -ne 4 -or @($v.Files|Where-Object Name -notin $names).Count){throw 'Exact package allow-list required'}
foreach($name in $names){if((Get-Item -LiteralPath (Join-Path $Package $name)).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked member rejected'}}
if((Get-AuthenticodeSignature -LiteralPath (Join-Path $Package 'StreamLinkTun.cat')).Status -ne 'Valid'){throw 'Catalog is not signed/trusted; no identity changed'}
. (Join-Path $PSScriptRoot 'Assert-PersonalTunCatalog.ps1')
Assert-PersonalTunCatalog $Package -KernelPolicy
$backup=$identity+'.unsigned-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffff')
if($PSCmdlet.ShouldProcess($identity,'Back up unsigned identity and refreeze exact signed package; old approvals become invalid')){
 Copy-Item -LiteralPath $identity -Destination $backup
 foreach($file in $v.Files){$file.Sha256=(Get-FileHash -LiteralPath (Join-Path $Package $file.Name)).Hash}
 $temp=$identity+'.new';$v|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $temp -Encoding utf8NoBOM;Move-Item -LiteralPath $temp -Destination $identity -Force
 Write-Output 'Signed package hash is new. Rebuild bundle manifest and all gates/target approvals; unsigned approvals cannot be reused.'
}
