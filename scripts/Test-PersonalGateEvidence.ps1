param([Parameter(Mandatory)][string]$Output)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Output){throw 'Fresh evidence required'}
. (Join-Path $PSScriptRoot '../drivers/Assert-PersonalTunEvidence.ps1')
$stamp=[DateTimeOffset]::UtcNow;$hash='A'*64;$kernelHash='B'*64;$planHash='C'*64;$id=[guid]::NewGuid().ToString()
$k=@{schemaVersion=2;tool='StreamLink.TunKernelTests';evidenceLevel='DriverKernelIO';status='Pass';kernelIo='Pass';cancellation='Pass';cleanup='Pass';PackageHash=$hash;RunId=$id;PlanSha256=$planHash;DeviceInstance='ROOT\STREAMLINKTUN\0000';InterfaceIndex=123;device='\\.\StreamLinkTun-123';machine='isolated-synthetic-guest';StartedUtc=$stamp.AddSeconds(-10);FinishedUtc=$stamp.AddSeconds(-5)}
$k.cleanupCoverage='CancellationJoined+PendingLastHandleClose+OwnedProcessExit+Reopen'
$p=@{schemaVersion=2;tool=$k.tool;evidenceLevel=$k.evidenceLevel;permissions='Pass';admin=$false;openError=5;PackageHash=$hash;machine=$k.machine;RunId=$id;PlanSha256=$planHash;DeviceInstance=$k.DeviceInstance;InterfaceIndex=123;device=$k.device}
$v=@{schemaVersion=2;packageHash=$hash;machine=$k.machine;RunId=$id;PlanSha256=$planHash;driver='StreamLinkTun.sys';bootedWithVerifier=$true;result='Pass';operatorReviewed=$true;systemBugchecks=0;SystemLogRead='Observed';CodeIntegrityRead='Observed';lastBoot=$stamp.AddMinutes(-2);collectedUtc=$stamp;
 rawFiles=@('kernel-result.json','lab-plan.json','verifier-before.txt','verifier-after.txt','verifier-query.txt','system-bugcheck-events.json','code-integrity.json'|ForEach-Object {@{path=$_;sha256=$(if($_ -eq 'kernel-result.json'){$kernelHash}elseif($_ -eq 'lab-plan.json'){$planHash}else{'D'*64})}})}
$rows=[Collections.Generic.List[object]]::new()
function Test-Case([string]$Name,[scriptblock]$Change,[bool]$Expected){
 $kk=$k|ConvertTo-Json -Depth 6|ConvertFrom-Json;$pp=$p|ConvertTo-Json -Depth 6|ConvertFrom-Json;$vv=$v|ConvertTo-Json -Depth 6|ConvertFrom-Json
 & $Change $kk $pp $vv;$accepted=$true;$errorText=''
 try{Assert-PersonalTunEvidence $kk $pp $vv $hash $kernelHash}catch{$accepted=$false;$errorText=$_.Exception.Message}
 if($accepted -ne $Expected){throw "Evidence contract failed: $Name"}
 $rows.Add(@{name=$Name;expected=$Expected;accepted=$accepted;reason=$errorText})
}
Test-Case 'same run and exact evidence' {} $true
Test-Case 'Verifier from another run' {param($a,$b,$c)$c.RunId=[guid]::NewGuid().ToString()} $false
Test-Case 'Verifier binds a different kernel result' {param($a,$b,$c)$c.rawFiles[0].sha256='E'*64} $false
Test-Case 'permission on different device' {param($a,$b,$c)$b.device='\\.\StreamLinkTun-124'} $false
Test-Case 'modified standard-user plan copy' {param($a,$b,$c)$b.PlanSha256='E'*64} $false
Test-Case 'kernel test before verifier boot' {param($a,$b,$c)$c.lastBoot=$stamp} $false
Test-Case 'missing required raw member' {param($a,$b,$c)$c.rawFiles=$c.rawFiles[0..5]} $false
Test-Case 'duplicate raw member' {param($a,$b,$c)$c.rawFiles[1].path='kernel-result.json'} $false
Test-Case 'old result schema' {param($a,$b,$c)$b.schemaVersion=1} $false
Test-Case 'non-kernel evidence' {param($a,$b,$c)$a.evidenceLevel='Model'} $false
Test-Case 'actual cancellation incomplete' {param($a,$b,$c)$a.cancellation='NotProven'} $false
Test-Case 'unreadable system log is not zero bugchecks proof' {param($a,$b,$c)$c.SystemLogRead='Unknown'} $false
@{status='Pass';checks=$rows.Count;rows=$rows;scope='Synthetic gate matching regression only. No approval published, no driver or Verifier enabled.'}|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $Output
