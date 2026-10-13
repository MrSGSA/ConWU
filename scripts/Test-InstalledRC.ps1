param([Parameter(Mandatory)][string]$Bundle,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
$Bundle=[IO.Path]::GetFullPath($Bundle)
$scope=[guid]::NewGuid().ToString('N');$service='StreamLink-Validation-'+$scope
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if(-not $OutputDirectory){$OutputDirectory=Join-Path $repo ('artifacts/installed-rc-'+$scope)}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory);New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$profileRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('StreamLink-Validation/'+$scope)
$installRoot=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('StreamLink-Validation/'+$scope)
$rows=[Collections.Generic.List[object]]::new();$failure='';$original=$null
function Snapshot-Live {
    $item=Get-CimInstance Win32_Service -Filter "Name='StreamLink'"
    if($item){[ordered]@{Name=$item.Name;State=$item.State;ProcessId=$item.ProcessId;PathName=$item.PathName}}else{$null}
}
function Invoke-App([string]$Folder,[string[]]$AppArgs,[switch]$ExpectedFailure){
    $arguments=@('--validation-instance',$scope)+$AppArgs
    if($arguments|Where-Object {$_.Contains('"')}){throw 'Invalid quoted argument'}
    $quoted=($arguments|ForEach-Object {'"'+$_+'"'}) -join ' '
    $process=Start-Process -FilePath (Join-Path $Folder 'StreamLink.exe') -ArgumentList $quoted -WindowStyle Hidden -Wait -PassThru
    $rows.Add(@{operation=($AppArgs -join ' ');exit=$process.ExitCode;expectedFailure=[bool]$ExpectedFailure})
    if($ExpectedFailure){if($process.ExitCode -eq 0){throw 'Expected installer failure did not occur'}}elseif($process.ExitCode){throw 'Candidate app operation failed; inspect its exact installer log'}
}
function Read-Status([string]$Folder,[string]$Label){
    $path=Join-Path $OutputDirectory ($Label+'.json');Invoke-App $Folder @('--acceptance-status',$path)
    $state=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    if(-not $state.Ok -or -not $state.ServiceReady){throw 'Service failed local authenticated readiness'}
    return $state
}
function Rehash([string]$Folder){
    $path=Join-Path $Folder 'manifest.json';$manifest=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    foreach($file in $manifest.files){$actual=Get-Item -LiteralPath (Join-Path $Folder $file.path);$file.length=$actual.Length;$file.sha256=(Get-FileHash -LiteralPath $actual.FullName).Hash}
    $manifest|Add-Member NoteProperty acceptanceMutation 'intentional isolated runtimeconfig fault; not the immutable release artifact' -Force
    $manifest|ConvertTo-Json -Depth 15|Set-Content -LiteralPath $path -Encoding utf8
}
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Real service acceptance needs an administrator; no UAC/security bypass will be attempted'}
    if(Get-Service -Name $service -ErrorAction SilentlyContinue){throw 'Fresh validation GUID unexpectedly registered'}
    $original=Snapshot-Live
    $good=Join-Path $OutputDirectory 'good';$bad=Join-Path $OutputDirectory 'fault'
    Copy-Item -LiteralPath $Bundle -Destination $good -Recurse;Copy-Item -LiteralPath $Bundle -Destination $bad -Recurse
    # Only this copied fault fixture is modified; the fixed bundle stays intact.
    'intentionally invalid runtime JSON'|Set-Content -LiteralPath (Join-Path $bad 'StreamLink.Service.runtimeconfig.json') -Encoding utf8
    Rehash $bad
    Invoke-App $good @('--install')
    $initial=Read-Status $good 'initial-ready'
    Invoke-App $good @('--acceptance-create-network')
    $paired=Read-Status $good 'paired-disabled'
    if($paired.NetworkEnabled -or -not $paired.Network){throw 'Pair fixture unexpectedly enables networking'}
    $old=(Get-CimInstance Win32_Service -Filter "Name='$service'").PathName
    Invoke-App $bad @('--install') -ExpectedFailure
    $restored=Read-Status $good 'restored-ready'
    if($restored.ProfileSha256 -ne $paired.ProfileSha256 -or $restored.Network -ne $paired.Network -or $restored.UiSid -ne $paired.UiSid){throw 'Same-network rollback changed protected configuration or UI authorization'}
    if((Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -ne $old){throw 'Old ImagePath was not restored'}
    Copy-Item -LiteralPath (Join-Path $bad 'install-error.log') -Destination (Join-Path $OutputDirectory 'candidate-failure-restored.txt')
    # A running prior process stays alive while its next-start ImagePath is
    # intentionally made invalid; this tests candidate + old-restart failure.
    $missing=Join-Path $installRoot 'deliberately-missing-service.exe';if(Test-Path -LiteralPath $missing){throw 'Missing-service fixture unexpectedly exists'}
    & sc.exe config $service 'binPath=' $missing > (Join-Path $OutputDirectory 'double-fault-config.txt')
    if($LASTEXITCODE){throw 'Could not prepare owned double-failure fixture'}
    Invoke-App $bad @('--install') -ExpectedFailure
    $errorText=Get-Content -LiteralPath (Join-Path $bad 'install-error.log') -Raw
    if(-not $errorText.Contains('恢复也未全部完成')){throw 'Double failure was not reported distinctly'}
    Copy-Item -LiteralPath (Join-Path $bad 'install-error.log') -Destination (Join-Path $OutputDirectory 'double-failure.txt')
    & sc.exe config $service 'binPath=' $old > (Join-Path $OutputDirectory 'restore-fixture-config.txt')
    if($LASTEXITCODE){throw 'Could not restore owned fixture ImagePath'}
    & sc.exe start $service > (Join-Path $OutputDirectory 'restore-fixture-start.txt')
    if($LASTEXITCODE){throw 'Could not restart owned fixture'}
    $controller=[ServiceProcess.ServiceController]::new($service);try{$controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30))}finally{$controller.Dispose()}
    $final=Read-Status $good 'final-ready'
    if($final.ProfileSha256 -ne $paired.ProfileSha256 -or $final.UiSid -ne $paired.UiSid){throw 'Double failure recovery changed persisted authorization/config'}
    Invoke-App $good @('--uninstall')
}catch{$failure=$_.Exception.ToString()}
finally {
    # Cleanup only the exact generated instance; never uninstall shared drivers.
    try {
        if(Get-Service -Name $service -ErrorAction SilentlyContinue){
            & sc.exe stop $service > (Join-Path $OutputDirectory 'cleanup-stop.txt')
            $controller=[ServiceProcess.ServiceController]::new($service);try{$controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(55))}finally{$controller.Dispose()}
            & sc.exe delete $service > (Join-Path $OutputDirectory 'cleanup-delete.txt');if($LASTEXITCODE){throw 'Owned service deletion failed'}
        }
        foreach($owned in @($profileRoot,$installRoot)){
            $resolved=[IO.Path]::GetFullPath($owned)
            if((Split-Path -Leaf $resolved) -ne $scope -or (Split-Path -Leaf (Split-Path -Parent $resolved)) -ne 'StreamLink-Validation'){throw 'Cleanup containment check failed'}
            if(Test-Path -LiteralPath $resolved){if((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Refusing linked cleanup target'};Remove-Item -LiteralPath $resolved -Recurse -Force}
        }
        $after=Snapshot-Live
        if(($original|ConvertTo-Json -Compress) -ne ($after|ConvertTo-Json -Compress)){throw 'Live production service state/PID/ImagePath changed; verify separately'}
    }catch{if($failure){$failure+='; cleanup: '+$_.Exception.Message}else{$failure=$_.Exception.ToString()}}
    $manifest=Get-Content -LiteralPath (Join-Path $Bundle 'manifest.json') -Raw|ConvertFrom-Json
    [ordered]@{status=$(if($failure){'Fail'}else{'Pass'});sourceCommit=$manifest.sourceCommit;version=$manifest.version;scope='Actual complete Windows candidate, SCM/PID-verified RPC and protected DPAPI; unique service/pipe/profile/install directories. Same RC baseline and intentional copied-runtime fault; not 0.5.6 migration, two-device business or unlogged boot evidence.';validationInstance=$service;networkEnabled=$false;results=$rows;failure=$failure;liveServiceUnchanged=($original|ConvertTo-Json -Compress) -eq ($after|ConvertTo-Json -Compress);sharedDriversUninstalled=$false}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding utf8
}
if($failure){throw $failure}
Write-Output (Join-Path $OutputDirectory 'result.json')
