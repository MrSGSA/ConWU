param([Parameter(Mandatory)][string]$Catalog,[Parameter(Mandatory)][string]$TrustedSys,
 [Parameter(Mandatory)][string]$TrustedInf,[Parameter(Mandatory)][string]$OtherMember,[Parameter(Mandatory)][string]$Output)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Output){throw 'Fresh evidence required'}
Add-Type -LiteralPath (Join-Path $PSScriptRoot '../drivers/CatalogTrust.cs') -ErrorAction Stop
$rows=[Collections.Generic.List[object]]::new();$status='Fail'
try{
 foreach($member in @($TrustedSys,$TrustedInf)){
  [StreamLink.ResearchAdapters.CatalogTrust]::RequireMember($Catalog,$member)
  $rows.Add(@{member=(Split-Path $member -Leaf);accepted=$true})
 }
 $rejected=$false;$reason=''
 try{[StreamLink.ResearchAdapters.CatalogTrust]::RequireMember($Catalog,$OtherMember)}catch{
  $reason=$_.Exception.ToString();$rejected=$reason -match 'Current member is not trusted in the exact catalog'
 }
 if(-not $rejected){throw 'Non-member did not produce a catalog membership rejection'}
 $rows.Add(@{member=(Split-Path $OtherMember -Leaf);accepted=$false;reason=$reason});$status='Pass'
}finally{
 @{status=$status;checks=$rows.Count;rows=$rows;catalogHash=(Get-FileHash -LiteralPath $Catalog).Hash;scope='Actual Windows catalog membership verification on an official driver. No self-TUN signed/load claim.'}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $Output
}
