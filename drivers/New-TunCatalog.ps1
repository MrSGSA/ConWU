[CmdletBinding()]
param([Parameter(Mandatory)][string]$Package,[Parameter(Mandatory)][string]$Inf2Cat,[Parameter(Mandatory)][string]$InfVerif,[string]$Os='10_GE_X64')
$ErrorActionPreference='Stop'
$Package=[IO.Path]::GetFullPath($Package)
foreach($p in @($Inf2Cat,$InfVerif,(Join-Path $Package 'StreamLinkTun.sys'),(Join-Path $Package 'StreamLinkTun.inf'))){if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw "Missing build input: $p"}}
if(Test-Path -LiteralPath (Join-Path $Package 'StreamLinkTun.cat')){throw 'Do not overwrite a frozen catalog; use a new build directory'}
& $InfVerif /v /w (Join-Path $Package 'StreamLinkTun.inf')
if($LASTEXITCODE){throw 'INF validation failed'}
& $Inf2Cat "/driver:$Package" "/os:$Os" /verbose
if($LASTEXITCODE){throw 'PnP catalog signability failed'}
if(-not(Test-Path -LiteralPath (Join-Path $Package 'StreamLinkTun.cat'))){throw 'Catalog was not produced'}
Write-Output 'Unsigned PnP catalog generated. No signing, device creation, loading or policy changes performed.'
