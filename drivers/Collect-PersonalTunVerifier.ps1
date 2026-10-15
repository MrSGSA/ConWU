#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RunRoot,[switch]$OperatorReviewed)
$ErrorActionPreference='Stop';$RunRoot=[IO.Path]::GetFullPath($RunRoot)
$result=Join-Path $RunRoot 'verifier-evidence.json'
if(Test-Path -LiteralPath $result){throw 'Never overwrite a Verifier run result'}
$k=Get-Content -LiteralPath (Join-Path $RunRoot 'kernel-result.json') -Raw|ConvertFrom-Json
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$before=Get-Content -LiteralPath (Join-Path $RunRoot 'verifier-before.txt') -Raw
$after=Get-Content -LiteralPath (Join-Path $RunRoot 'verifier-after.txt') -Raw
$settings=Get-Content -LiteralPath (Join-Path $RunRoot 'verifier-query.txt') -Raw
. (Join-Path $PSScriptRoot 'Read-PersonalTunEvents.ps1')
$system=Read-PersonalTunEvents 'System' $boot @(1001);$events=@($system.events)
$system|ConvertTo-Json -Depth 6|Set-Content (Join-Path $RunRoot 'system-bugcheck-events.json')
$ci=Get-Content -LiteralPath (Join-Path $RunRoot 'code-integrity.json') -Raw|ConvertFrom-Json
$active=$before -match 'StreamLinkTun\.sys' -and $after -match 'StreamLinkTun\.sys' -and $settings -match 'StreamLinkTun\.sys'
$pass=$active -and $k.status -eq 'Pass' -and $events.Count -eq 0 -and $OperatorReviewed -and $system.status -eq 'Observed' -and $ci.status -eq 'Observed'
$raw=@('kernel-result.json','lab-plan.json','verifier-before.txt','verifier-after.txt','verifier-query.txt','system-bugcheck-events.json','code-integrity.json')
foreach($name in $raw){if(-not(Test-Path -LiteralPath (Join-Path $RunRoot $name))){throw 'Missing actual Verifier/CodeIntegrity evidence'}}
[ordered]@{schemaVersion=2;packageHash=$k.PackageHash;machine=$k.machine;RunId=$k.RunId;PlanSha256=$k.PlanSha256;collectedUtc=[DateTimeOffset]::UtcNow;driver='StreamLinkTun.sys';bootedWithVerifier=$active;
 result=$(if($pass){'Pass'}else{'NotProven'});operatorReviewed=[bool]$OperatorReviewed;lastBoot=$boot;systemBugchecks=$events.Count;SystemLogRead=$system.status;CodeIntegrityRead=$ci.status;
 rawFiles=@($raw|ForEach-Object{@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $RunRoot $_)).Hash}});
 scope='Actual active Verifier query before/after same guest kernel test and System bugchecks. Operator must inspect settings, dumps, NDIS/IRQL evidence. Not host or HLK certification.'}|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $result
Get-Content -LiteralPath $result
