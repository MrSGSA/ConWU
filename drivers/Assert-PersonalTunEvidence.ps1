function Assert-PersonalTunEvidence($Kernel,$Permission,$Verifier,[string]$PackageHash,[string]$KernelSha256) {
 $k=$Kernel;$p=$Permission;$v=$Verifier
 if($k.schemaVersion -ne 2 -or $k.tool -ne 'StreamLink.TunKernelTests' -or $k.evidenceLevel -ne 'DriverKernelIO' -or $k.status -ne 'Pass' -or
  $k.kernelIo -ne 'Pass' -or $k.cancellation -ne 'Pass' -or $k.cleanup -ne 'Pass' -or
  $k.cleanupCoverage -ne 'CancellationJoined+PendingLastHandleClose+OwnedProcessExit+Reopen' -or $k.PackageHash -ne $PackageHash -or
  $k.RunId -notmatch '^[0-9a-fA-F-]{36}$' -or [guid]$k.RunId -eq [guid]::Empty -or $k.PlanSha256 -notmatch '^[0-9A-Fa-f]{64}$' -or
  $k.DeviceInstance -notmatch '^ROOT\\STREAMLINKTUN\\[A-Za-z0-9_&-]+$' -or $k.InterfaceIndex -lt 1 -or $k.device -ne "\\.\StreamLinkTun-$($k.InterfaceIndex)"){
  throw 'Actual kernel evidence does not prove this exact package/run/device'
 }
 if($p.schemaVersion -ne 2 -or $p.tool -ne $k.tool -or $p.evidenceLevel -ne 'DriverKernelIO' -or $p.permissions -ne 'Pass' -or
  $p.admin -ne $false -or $p.openError -ne 5 -or $p.PackageHash -ne $PackageHash -or $p.machine -ne $k.machine -or $p.RunId -ne $k.RunId -or
  $p.PlanSha256 -ne $k.PlanSha256 -or $p.DeviceInstance -ne $k.DeviceInstance -or $p.InterfaceIndex -ne $k.InterfaceIndex -or $p.device -ne $k.device){
  throw 'Standard-user denial must use the exact kernel-test plan and device'
 }
 if($v.schemaVersion -ne 2 -or $v.packageHash -ne $PackageHash -or $v.machine -ne $k.machine -or $v.RunId -ne $k.RunId -or
  $v.PlanSha256 -ne $k.PlanSha256 -or $v.driver -ne 'StreamLinkTun.sys' -or $v.bootedWithVerifier -ne $true -or
  $v.result -ne 'Pass' -or $v.operatorReviewed -ne $true -or $v.systemBugchecks -ne 0 -or $v.SystemLogRead -ne 'Observed' -or $v.CodeIntegrityRead -ne 'Observed'){
  throw 'Targeted Verifier evidence must come from this same run, plan and guest'
 }
 $required=@('kernel-result.json','lab-plan.json','verifier-before.txt','verifier-after.txt','verifier-query.txt','system-bugcheck-events.json','code-integrity.json')
 if(@($v.rawFiles).Count -ne $required.Count -or @($v.rawFiles.path|Select-Object -Unique).Count -ne $required.Count -or @($v.rawFiles.path|Where-Object {$_ -cnotin $required}).Count){throw 'Exact Verifier raw evidence file set required'}
 if(($v.rawFiles|Where-Object path -ceq 'kernel-result.json').sha256 -ne $KernelSha256 -or
  ($v.rawFiles|Where-Object path -ceq 'lab-plan.json').sha256 -ne $k.PlanSha256){throw 'Verifier raw inputs do not bind the supplied kernel result and plan'}
 try {
  $boot=[DateTimeOffset]::Parse($v.lastBoot);$start=[DateTimeOffset]::Parse($k.StartedUtc);$end=[DateTimeOffset]::Parse($k.FinishedUtc);$collected=[DateTimeOffset]::Parse($v.collectedUtc)
 }catch{throw 'Verifier/current-boot and kernel run timestamps required'}
 if($start -lt $boot -or $end -lt $start -or $collected -lt $end -or $collected -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Kernel run is not within the recorded Verifier boot'}
}
