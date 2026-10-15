# Read-only check shared by lab installation, gate publication and signed freeze.
function Assert-PersonalTunCatalog([string]$Package,[switch]$KernelPolicy) {
 if(-not ('StreamLink.ResearchAdapters.CatalogTrust' -as [type])){Add-Type -LiteralPath (Join-Path $PSScriptRoot 'CatalogTrust.cs') -ErrorAction Stop}
 [StreamLink.ResearchAdapters.CatalogTrust]::RequirePackage($Package)
 if($KernelPolicy){
  $tool=Get-Command signtool.exe -ErrorAction SilentlyContinue
  $path=if($tool){$tool.Source}else{$null}
  if(-not $path){
   $kits=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
   if(Test-Path -LiteralPath $kits){$path=Get-ChildItem -LiteralPath $kits -Directory|Sort-Object Name -Descending|ForEach-Object {Join-Path $_.FullName 'x64/signtool.exe'}|Where-Object {Test-Path -LiteralPath $_}|Select-Object -First 1}
  }
  if(-not $path){throw 'Microsoft SDK signtool required to verify kernel policy; no approval or package changed'}
  $signature=Get-AuthenticodeSignature -LiteralPath $path
  if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'Untrusted signature verification tool rejected'}
  foreach($member in @('StreamLinkTun.sys','StreamLinkTun.inf')){
   & $path verify /kp /v /c (Join-Path $Package 'StreamLinkTun.cat') (Join-Path $Package $member)
   if($LASTEXITCODE -ne 0){throw "Exact catalog member/kernel policy rejected: $member"}
  }
 }
}
