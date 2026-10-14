#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$RunFullCore,
    [switch]$AllowIsolatedAdapterTest,
    [string]$Components,
    [ValidateRange(1,100)][int]$AdapterRounds=100
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $IsWindows){throw 'This verifier requires Windows. Linux sanitizer tests are a separate evidence level.'}
if($AllowIsolatedAdapterTest -and -not $Components){throw 'Explicit adapter tests require the exact rebuilt/fixed -Components directory.'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root ('artifacts/rc2-sourcefix-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a NEW evidence directory; previous results will not be overwritten.'}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$results=[Collections.Generic.List[object]]::new()
$completed=$false;$failure='';$before=@();$after=@();$fixed=$false
function Snapshot-Inputs {
    # Actual bytes, not just a mutable git HEAD. Generated outputs and this
    # evidence directory are excluded; source, scripts, projects and lock files
    # are retained. All final receipts also identify the loaded binary hashes.
    @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
        $rel=[IO.Path]::GetRelativePath($root,$_.FullName).Replace('\','/')
        $rel -notmatch '(^|/)(\.git|\.vs|bin|obj|out|artifacts|__pycache__)(/|$)' -and
        -not $_.FullName.StartsWith($OutputDirectory+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
    } | Sort-Object FullName | ForEach-Object {
        [pscustomobject]@{path=[IO.Path]::GetRelativePath($root,$_.FullName).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
}
function Run-Checked([string]$Name,[string]$Exe,[string[]]$Arguments,[int]$TimeoutSeconds=300) {
    $watch=[Diagnostics.Stopwatch]::StartNew();$exit=$null;$errorText='';$timedOut=$false;$proc=$null
    $stdout=$null;$stderr=$null
    try {
        $info=[Diagnostics.ProcessStartInfo]::new($Exe)
        $info.WorkingDirectory=$root;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        foreach($a in $Arguments){$info.ArgumentList.Add($a)}
        $proc=[Diagnostics.Process]::Start($info)
        $stdout=$proc.StandardOutput.ReadToEndAsync();$stderr=$proc.StandardError.ReadToEndAsync()
        if(-not $proc.WaitForExit($TimeoutSeconds*1000)) {
            $timedOut=$true
            # Only the process tree spawned by this invocation, never an
            # installed StreamLink/foreign process. No service/driver removal.
            $proc.Kill($true)
            if(-not $proc.WaitForExit(5000)){throw 'Owned test child did not exit after watchdog termination; investigate manually.'}
        }
        $exit=$proc.ExitCode
        if($stdout.Wait(5000)){[IO.File]::WriteAllText((Join-Path $OutputDirectory ($Name+'.stdout.log')),$stdout.Result)}else{throw 'stdout did not finish draining'}
        if($stderr.Wait(5000)){[IO.File]::WriteAllText((Join-Path $OutputDirectory ($Name+'.stderr.log')),$stderr.Result)}else{throw 'stderr did not finish draining'}
        if($timedOut){throw 'Test process deadline exceeded (containment only; not a changed pass criterion)'}
        if($exit -ne 0){throw "Exit code $exit"}
    } catch {$errorText=$_.Exception.ToString()}
    finally {
        if($null -ne $proc){
            try{if(-not $proc.HasExited){$proc.Kill($true);[void]$proc.WaitForExit(5000)}}catch{$errorText+="`nOwned-child cleanup: $_"}
            $proc.Dispose()
        }
        $results.Add([pscustomobject]@{name=$Name;status=$(if($errorText){'Fail'}else{'Pass'});command=@($Exe)+$Arguments;exitCode=$exit;timedOut=$timedOut;elapsedMs=$watch.ElapsedMilliseconds;error=$errorText})
        $results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'steps.partial.json') -Encoding utf8
    }
    if($errorText){throw "$Name failed; see evidence logs. $errorText"}
}
Push-Location $root
try {
    $before=Snapshot-Inputs
    ConvertTo-Json -InputObject $before -Depth 4 | Set-Content (Join-Path $OutputDirectory 'inputs-before.json') -Encoding utf8
    Run-Checked 'dotnet-info' 'dotnet' @('--info') 30
    Run-Checked 'app-build' 'dotnet' @('build','src/StreamLink.App/StreamLink.csproj','-c','Release') 600
    Run-Checked 'portable-patch-draft-policy' 'dotnet' @('run','--project','tests/StreamLink.Rc2PortableTests','-c','Release') 300
    Run-Checked 'control-atomic-patch-and-boundary' 'dotnet' @('run','--project','tests/StreamLink.ControlTests','-c','Release') 300
    Run-Checked 'research-read-cancel-lock-order' 'dotnet' @('run','--project','tests/StreamLink.Rc2ResearchTests','-c','Release') 180
    Run-Checked 'adapter-contracts-no-driver' 'dotnet' @('run','--project','tests/StreamLink.AdapterContractTests','-c','Release') 300
    Run-Checked 'watchdog-negative-no-driver' 'dotnet' @('run','--project','tests/StreamLink.AdapterContractTests','-c','Release','--no-build','--','--lifecycle-watchdog-selftest',(Join-Path $OutputDirectory 'watchdog.json')) 30
    if($RunFullCore){
        # No StartAt: a tail-only pass cannot be labelled the full core suite.
        Run-Checked 'full-existing-core' 'pwsh' @('-NoProfile','-File','scripts/Invoke-TraversalValidation.ps1','-Profile','Local','-OutputDirectory',(Join-Path $OutputDirectory 'core')) 10800
    } else {$results.Add([pscustomobject]@{name='full-existing-core';status='NotRun';reason='Explicit -RunFullCore not supplied; targeted tests are not the complete core gate'})}
    if($AllowIsolatedAdapterTest){
        $componentsPath=[IO.Path]::GetFullPath($Components)
        foreach($f in @('streamlink-tun.dll','wintun.dll')){if(-not(Test-Path (Join-Path $componentsPath $f))){throw "Missing fixed component: $f"}}
        Run-Checked 'official-adapter-isolated-iterations' 'dotnet' @('run','--project','tests/StreamLink.AdapterContractTests','-c','Release','--no-build','--','--native-lifecycle',$componentsPath,'--output',(Join-Path $OutputDirectory 'wintun-isolated.json'),'--rounds',"$AdapterRounds") ($AdapterRounds*40+60)
    } else {$results.Add([pscustomobject]@{name='official-adapter-isolated-iterations';status='NotRun';reason='Requires explicit consent and a rebuilt/fixed components directory; no driver is loaded by default'})}
    $completed=$true
} catch {$failure=$_.Exception.ToString()}
finally {
    try {
        $after=Snapshot-Inputs
        ConvertTo-Json -InputObject $after -Depth 4 | Set-Content (Join-Path $OutputDirectory 'inputs-after.json') -Encoding utf8
        $fixed=(ConvertTo-Json -InputObject $before -Compress -Depth 4) -ceq (ConvertTo-Json -InputObject $after -Compress -Depth 4)
    } catch {$failure+="`nInput provenance failure: $_"}
    $binaries=@(Get-ChildItem src,tests -Recurse -File -Filter 'StreamLink*.dll' | Where-Object {$_.FullName -match '[\\/]bin[\\/]'} | ForEach-Object {
        [pscustomobject]@{path=[IO.Path]::GetRelativePath($root,$_.FullName);sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    [pscustomobject]@{
        schemaVersion=1;status=$(if($completed -and $fixed -and -not $failure){'Pass'}else{'Fail'});fixedSourceBytes=$fixed
        results=$results;failure=$failure;binaries=$binaries;formalReleaseAllowed=$false
        scope='Local Windows source-fix verification; explicit options only. No deployment, cross-account UAC, real WAN, quality or release claim.'
        remainingGates=@('Actual standard user A/admin B installation and admin C upgrade','Official same-process lifetime/leak root cause and installed service gate','Prior legacy authentication timeout root cause','Real FakeTCP off/on coverage','Current fixed package quality and live upgrade','Research SYS build/Verifier/signed isolated kernel validation','8 Windows and remaining release gates')
    } | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8
    Pop-Location
}
if(-not $completed -or -not $fixed -or $failure){throw "Source-fix verification incomplete/failed: $OutputDirectory"}
Write-Output "Requested local checks passed on unchanged input bytes. Not a release approval: $OutputDirectory"
