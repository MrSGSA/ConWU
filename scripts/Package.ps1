param([string]$EasyTierDirectory='C:\Program Files\easytier-manager-pro\resource',[switch]$SkipBuild,[string]$NativeBinary='out/native/udp2raw-native.exe',[string]$ReleaseVersion='0.5.6',[switch]$IncludeLegacy)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if($ReleaseVersion -notmatch '^\d+\.\d+\.\d+$') {throw 'ReleaseVersion must be a three-part numeric version'}
    $commit=(& git rev-parse HEAD).Trim()
    if($LASTEXITCODE -ne 0 -or @(& git status --porcelain).Count -ne 0) {throw 'Commit the exact candidate source before packaging; working tree must be clean'}
    $verification=Join-Path $root ("artifacts\release-verification-$releaseVersion.json")
    if(Test-Path -LiteralPath $verification) {
        $summary=Get-Content -LiteralPath $verification -Raw | ConvertFrom-Json
        if($summary.sourceCommit -ne $commit -or $summary.version -ne "$releaseVersion-preview" -or
            $summary.releaseLevel -ne 'development-candidate' -or $summary.releaseGate -ne 'NotPassed') {
            throw 'Verification summary does not match this exact candidate source/version/release level'
        }
    }
    $nativePath=[IO.Path]::GetFullPath((Join-Path $root $NativeBinary))
    if($nativePath -ne [IO.Path]::GetFullPath((Join-Path $root 'out/native/udp2raw-native.exe'))) {throw 'Only the production native build output can be packaged'}
    $receipt=Join-Path $root "out/package-build-$releaseVersion.json"
    function Build-Files {
        $paths=@($nativePath, (Join-Path $root 'out/native/streamlink-tun.dll'))
        foreach($folder in @("out/app-$releaseVersion","out/service-$releaseVersion")) {
            $paths += @(Get-ChildItem -LiteralPath (Join-Path $root $folder) -File -Recurse | ForEach-Object FullName)
        }
        foreach($path in $paths) { [ordered]@{path=[IO.Path]::GetRelativePath($root,$path);sha256=(Get-FileHash -LiteralPath $path).Hash} }
    }
    if(-not $SkipBuild) {
        & .\scripts\Build.ps1 -Test
        & dotnet run --project tests/StreamLink.Tests -c Release
        if($LASTEXITCODE -ne 0) {throw 'Core regression failed'}
        & dotnet run --project tests/StreamLink.PairingTests -c Release
        if($LASTEXITCODE -ne 0) {throw 'Pairing regression failed'}
        & dotnet run --project tests/StreamLink.WindowsTests -c Release
        if($LASTEXITCODE -ne 0) {throw 'Windows lifecycle/feedback regression failed'}
        & dotnet run --project tests/StreamLink.ConnectionTests -c Release
        if($LASTEXITCODE -ne 0) {throw 'Connection scheduling regression failed'}
        & dotnet run --project tests/StreamLink.MeshConnectionTests -c Release
        if($LASTEXITCODE -ne 0) {throw 'TCP selection / mesh recovery regression failed'}
        & dotnet run --project tests/StreamLink.MeshConnectionTests -c Release --no-build -- --network-wake-only (Join-Path $root "artifacts/network-wake-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'SCM resume / network notification and retained legacy resource regression failed'}
        & dotnet run --project tests/StreamLink.MappingTests -c Release -- --tcp-mapping-wake-only (Join-Path $root "artifacts/tcp-mapping-wake-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Same held TCP helper refresh / explicit gateway candidate regression failed'}
        & python tests/legacy_wire_loopback.py --output (Join-Path $root "artifacts/legacy-native-wire-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Actual compatibility native injection report / failed sink isolation regression failed'}
        & dotnet run --project tests/StreamLink.LegacyWireTests -c Release -- --native-report (Join-Path $root "artifacts/legacy-native-wire-$releaseVersion.json") --output (Join-Path $root "artifacts/legacy-parent-wire-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Compatibility native report parser / parent resource ledger regression failed'}
        & dotnet run --project tests/StreamLink.LegacyControlTests -c Release -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --output (Join-Path $root "artifacts/legacy-native-control-$releaseVersion.json") --rounds 30
        if($LASTEXITCODE -ne 0) {throw 'Compatibility native authorization / shared control admission / full IP datagram regression failed'}
        & dotnet run --project tests/StreamLink.HelperLedgerTests -c Release -- --output (Join-Path $root "artifacts/kernel-helper-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Kernel helper and explicit compatibility resource accounting regression failed'}
        # Fail short resource/freshness checks before the long load diagnostics.
        # Every case still runs on this exact committed source; no gate is skipped.
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/tcp-endpoint-pool-$releaseVersion.json") --pool-only
        if($LASTEXITCODE -ne 0) {throw 'Shared TCP source observation / cancellation isolation regression failed'}
        & dotnet run --project tests/StreamLink.TcpObserverTests -c Release -- --output (Join-Path $root "artifacts/tcp-observer-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Authenticated TCP observation regression failed'}
        & dotnet run --project tests/StreamLink.ManagedPathTests -c Release -- --output (Join-Path $root "artifacts/managed-recovery-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Managed/legacy recovery observation and nomination regression failed'}
        & dotnet run --project tests/StreamLink.ManagedPathTests -c Release --no-build -- --feedback-only --output (Join-Path $root "artifacts/delivery-feedback-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Same-path receipt authentication/range/history/budget regression failed'}
        & dotnet run --project tests/StreamLink.ManagedPathTests -c Release --no-build -- --standby-only --output (Join-Path $root "artifacts/standby-router-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Retained standby phase / later nomination / rollback regression failed'}
        & dotnet run --project tests/StreamLink.ManagedPathTests -c Release --no-build -- --diagnostic-control-only --output (Join-Path $root "artifacts/diagnostic-control-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Bounded diagnostic control parser regression failed'}
        & dotnet run --project tests/StreamLink.ManagedPathTests -c Release --no-build -- --diagnostic-readiness-only --output (Join-Path $root "artifacts/diagnostic-readiness-$releaseVersion.json")
        if($LASTEXITCODE -ne 0){throw 'Diagnostic allowance readiness/fairness/expiry regression failed'}
        & dotnet run --project tests/StreamLink.ManagedPathTests -c Release --no-build -- --diagnostic-session-model-only --output (Join-Path $root "artifacts/diagnostic-session-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Diagnostic common lifetime/role/duplicate/loss/cancel regression failed'}
        foreach($case in @('quality-assessment','quality-agreement')){
            & dotnet run --project tests/StreamLink.ManagedPathTests -c Release --no-build -- "--$case-only" --output (Join-Path $root "artifacts/$case-$releaseVersion.json")
            if($LASTEXITCODE -ne 0){throw "$case regression failed"}
        }
        foreach($case in @('relative-quality','relative-session')){
            & dotnet run --project tests/StreamLink.ManagedPathTests -c Release --no-build -- "--$case-only" --output (Join-Path $root "artifacts/$case-$releaseVersion.json")
            if($LASTEXITCODE -ne 0){throw "$case regression failed"}
        }
        & dotnet run --project tests/StreamLink.MeshTests -c Release
        if($LASTEXITCODE -ne 0) {throw 'Mesh regression failed'}
        & dotnet run --project tests/StreamLink.TraversalTests -c Release
        if($LASTEXITCODE -ne 0) {throw 'Traversal foundation regression failed'}
        & dotnet run --project tests/StreamLink.TraversalTests -c Release --no-build -- --enhancement (Join-Path $root "artifacts/enhancement-admission-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Cross-protocol heavy admission / cooldown / cancellation regression failed'}
        & dotnet run --project tests/StreamLink.TraversalTests -c Release --no-build -- --probability-smoke (Join-Path $root "artifacts/udp-exploration-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Experimental UDP shared-source / winning-path regression failed'}
        & dotnet run --project tests/StreamLink.TraversalTests -c Release --no-build -- --probability-boundaries (Join-Path $root "artifacts/udp-exploration-boundaries-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Experimental UDP authentication / resource budget regression failed'}
        & dotnet run --project tests/StreamLink.TraversalTests -c Release --no-build -- --probability-model (Join-Path $root "artifacts/udp-exploration-model-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Uniform port-set intersection model regression failed'}
        & dotnet run --project tests/StreamLink.EgressTests -c Release -- (Join-Path $root "artifacts/egress-correctness-$releaseVersion.json") --correctness-only
        if($LASTEXITCODE -ne 0) {throw 'Egress lifecycle / same-socket / queue regression failed'}
        & dotnet run --project tests/StreamLink.PredictionTests -c Release -- --output (Join-Path $root "artifacts/prediction-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Conditional port prediction regression failed'}
        & dotnet run --project tests/StreamLink.EndpointPoc -c Release -- --port-window-wide (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --output (Join-Path $root "artifacts/native-port-window-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Native bounded port-window regression failed'}
        & dotnet run --project tests/StreamLink.EndpointPoc -c Release --no-build -- --tcp-prflx (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/tcp-source-learning-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Bounded native TCP source-learning mechanism regression failed'}
        & dotnet run --project tests/StreamLink.MeshTraversalTests -c Release -- --output (Join-Path $root "artifacts/prediction-control-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Signed prediction control regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 2 --output (Join-Path $root "artifacts/prediction-runner-$releaseVersion.json") --prediction-runner-only
        if($LASTEXITCODE -ne 0) {throw 'Formal predicted FakeTCP Runner regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/tcp-source-runner-$releaseVersion.json") --source-only
        if($LASTEXITCODE -ne 0) {throw 'Signed TCP source-learning product admission / same-IP member isolation regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/udp-exploration-runner-$releaseVersion.json") --exploration-only
        if($LASTEXITCODE -ne 0) {throw 'Formal UDP exploration source continuity / signed role / shared budget regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/delivery-feedback-runner-$releaseVersion.json") --feedback-only
        if($LASTEXITCODE -ne 0) {throw 'Formal native/UDP bilateral delivery-feedback admission/receipt regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/standby-native-runner-$releaseVersion.json") --standby-only
        if($LASTEXITCODE -ne 0) {throw 'Formal retained native standby / independent source / old permission regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/standby-udp-runner-$releaseVersion.json") --udp-standby-only
        if($LASTEXITCODE -ne 0) {throw 'Formal same-socket UDP standby continuity / failure preservation regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/diagnostic-udp-product-$releaseVersion.json") --diagnostic-runner-only
        if($LASTEXITCODE -ne 0) {throw 'Formal diagnostic same-socket/negotiation/receipt product regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/diagnostic-native-product-$releaseVersion.json") --native-diagnostic-runner-only
        if($LASTEXITCODE -ne 0) {throw 'Formal native diagnostic grant/receipt/common completion regression failed'}
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/diagnostic-business-protection-$releaseVersion.json") --diagnostic-busy-only
        if($LASTEXITCODE -ne 0) {throw 'Formal diagnostic abort on real application business regression failed'}
        foreach($case in @('quality-udp-retain','quality-native-benefit','quality-native-fault')){
            & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/$case-$releaseVersion.json") "--$case-only"
            if($LASTEXITCODE -ne 0){throw "Formal $case regression failed"}
        }
        foreach($case in @('relative-quality-udp','relative-quality-native')){
            & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/$case-$releaseVersion.json") "--$case-only"
            if($LASTEXITCODE -ne 0){throw "Formal $case regression failed"}
        }
        & dotnet run --project tests/StreamLink.MeshRunnerTraversalTests -c Release --no-build -- --native (Join-Path $root 'out/native/udp2raw-protocol-test.exe') --rounds 1 --output (Join-Path $root "artifacts/network-scope-$releaseVersion.json") --network-only
        if($LASTEXITCODE -ne 0) {throw 'Network epoch / stale candidate / retained path ownership regression failed'}
        & dotnet run --project tests/StreamLink.MeshTests -c Release -- --raw out/native/udp2raw-protocol-test.exe
        if($LASTEXITCODE -ne 0) {throw 'Native multi-client protocol regression failed'}
        if($IncludeLegacy) { & dotnet run --project tests/StreamLink.MappingTests -c Release -- (Join-Path $EasyTierDirectory 'easytier-core.exe') } else { & dotnet run --project tests/StreamLink.MappingTests -c Release }
        if($LASTEXITCODE -ne 0) {throw 'Router discovery regression failed'}
        & dotnet run --project tests/StreamLink.RenderingTests -c Release -- (Join-Path $root "artifacts/rendering-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Desktop rendering regression failed'}
        & .\scripts\Test-Coordination.ps1
        foreach($project in @('StreamLink.App','StreamLink.Service')) {
            $dest=switch($project) {'StreamLink.App' {"out/app-$releaseVersion"} 'StreamLink.Service' {"out/service-$releaseVersion"}}
            & dotnet publish (Join-Path 'src' $project) -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false "-p:Version=$releaseVersion" -o $dest
            if($LASTEXITCODE -ne 0) {throw "Publish failed: $project"}
        }
        [ordered]@{sourceCommit=$commit;version=$releaseVersion;configuration='Release, self-contained win-x64';dotnetSdk=(& dotnet --version).Trim();powershell=$PSVersionTable.PSVersion.ToString();os=[Environment]::OSVersion.VersionString;cmakeCacheSha256=(Get-FileHash -LiteralPath 'out/native/CMakeCache.txt').Hash;compileCommandsSha256=(Get-FileHash -LiteralPath 'out/native/compile_commands.json').Hash;files=@(Build-Files)} | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath $receipt
    } else {
        if(-not(Test-Path -LiteralPath $receipt)) {throw 'SkipBuild requires an existing verified build receipt'}
        $prior=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        if($prior.sourceCommit -ne $commit -or $prior.version -ne $releaseVersion) {throw 'Published outputs do not match this source/version'}
        $actual=@(Build-Files)
        if($actual.Count -ne $prior.files.Count) {throw 'Published file list has changed'}
        foreach($file in $actual) {
            $expected=@($prior.files | Where-Object path -eq $file.path)
            if($expected.Count -ne 1 -or $expected[0].sha256 -ne $file.sha256) {throw "Published file changed: $($file.path)"}
        }
    }
    $nativeInfo = (& $nativePath --native-info | ConvertFrom-Json)
    if($LASTEXITCODE -ne 0 -or $nativeInfo.backend -ne 'windivert' -or $nativeInfo.wireProtocol -ne 'udp2raw-http-c4995ea') {throw 'Not a production WinDivert FakeTCP/HTTP backend'}
    foreach($dll in @("out/app-$releaseVersion/StreamLink.dll","out/service-$releaseVersion/StreamLink.Service.dll")) {
        if([Reflection.AssemblyName]::GetAssemblyName((Join-Path $root $dll)).Version.ToString(3) -ne $releaseVersion) {throw "Published assembly version mismatch: $dll"}
    }
    $downloads=Join-Path $root 'out\downloads'
    New-Item -ItemType Directory -Path $downloads -Force | Out-Null
    $wd=Join-Path $downloads 'WinDivert-2.2.2-A'
    if(-not(Test-Path (Join-Path $wd 'x64\WinDivert.dll'))) {
        Invoke-WebRequest 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile (Join-Path $downloads 'WinDivert-2.2.2-A.zip')
        Expand-Archive -LiteralPath (Join-Path $downloads 'WinDivert-2.2.2-A.zip') -DestinationPath $downloads -Force
    }
    $wt=Join-Path $downloads 'wintun'
    if(-not(Test-Path (Join-Path $wt 'LICENSE.txt'))) {
        Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile (Join-Path $downloads 'wintun-0.14.1.zip')
        Expand-Archive -LiteralPath (Join-Path $downloads 'wintun-0.14.1.zip') -DestinationPath $downloads -Force
    }
    if((Get-AuthenticodeSignature (Join-Path $wd 'x64\WinDivert64.sys')).Status -ne 'Valid') {throw 'WinDivert driver signature is not valid'}
    if((Get-FileHash (Join-Path $wt 'bin\amd64\wintun.dll')).Hash -ne 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE') {throw 'Unexpected official Wintun binary'}
    $version=$null
    if($IncludeLegacy) {
    $version=& (Join-Path $EasyTierDirectory 'easytier-core.exe') --version
    if($version -notmatch '2\.6\.4-8428a89d') {throw 'This preview requires the tested EasyTier 2.6.4-8428a89d build'}
    }
    $stage=Join-Path $root ('out\release-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,6))
    $components=Join-Path $stage 'components'; $licenses=Join-Path $stage 'licenses'
    New-Item -ItemType Directory -Path $components,$licenses -Force | Out-Null
    foreach($published in @("out/app-$releaseVersion","out/service-$releaseVersion")) {
        foreach($file in Get-ChildItem -LiteralPath $published -File -Recurse) {
            $relative=[IO.Path]::GetRelativePath((Join-Path $root $published),$file.FullName)
            if($file.Extension -eq '.pdb' -or $relative -match '^(cs|de|es|fr|it|ja|ko|pl|pt-BR|ru|tr|zh-Hant)[\\/]') {continue}
            $target=Join-Path $stage $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            if(Test-Path $target) {if((Get-FileHash $target).Hash -ne (Get-FileHash $file.FullName).Hash){throw "Conflicting shared dependency: $relative"}} else {Copy-Item -LiteralPath $file.FullName -Destination $target}
        }
    }
    Copy-Item -LiteralPath $NativeBinary -Destination $components\udp2raw-native.exe
    Copy-Item (Join-Path $wd 'x64\WinDivert.dll'),(Join-Path $wd 'x64\WinDivert64.sys') $components
    Copy-Item (Join-Path $wt 'bin\amd64\wintun.dll') $components
    Copy-Item -LiteralPath 'out/native/streamlink-tun.dll' -Destination $components
    if($IncludeLegacy) {foreach($name in @('easytier-core.exe','easytier-cli.exe')) {Copy-Item -LiteralPath (Join-Path $EasyTierDirectory $name) -Destination $components}}
    Copy-Item .\LICENSE $licenses\StreamLink-MIT.txt
    Copy-Item .\transport\udp2raw\LICENSE.md $licenses\udp2raw-MIT.txt
    Copy-Item (Join-Path $wd 'LICENSE') $licenses\WinDivert-LGPL.txt
    Copy-Item (Join-Path $wt 'LICENSE.txt') $licenses\Wintun.txt
    $nuget=(Join-Path $env:USERPROFILE '.nuget\packages')
    Copy-Item (Join-Path $nuget 'microsoft.netcore.app.runtime.win-x64\10.0.12\LICENSE.TXT') $licenses\dotnet-runtime.txt
    Copy-Item (Join-Path $nuget 'microsoft.netcore.app.runtime.win-x64\10.0.12\THIRD-PARTY-NOTICES.TXT') $licenses\dotnet-third-party-notices.txt
    Copy-Item (Join-Path $nuget 'microsoft.windowsdesktop.app.runtime.win-x64\10.0.12\LICENSE') $licenses\dotnet-windowsdesktop.txt
    Copy-Item (Join-Path $nuget 'microsoft.extensions.hosting.windowsservices\10.0.12\THIRD-PARTY-NOTICES.TXT') $licenses\dotnet-windowsservices-notices.txt
    $sources=Join-Path $stage 'sources'
    New-Item -ItemType Directory -Path $sources -Force | Out-Null
    if($IncludeLegacy) {
    $etSource=Join-Path $downloads 'EasyTier-8428a89d.zip'
    if(-not(Test-Path $etSource)) {
        if(Test-Path '..\research-sources\easytier\.git') {
            & git -C ..\research-sources\easytier archive --format=zip --prefix=easytier/ "--output=$etSource" 8428a89d2dabc94c97d370ec607c6ca142473626
            if($LASTEXITCODE -ne 0) {throw 'EasyTier source archive failed'}
        } else {Invoke-WebRequest 'https://codeload.github.com/EasyTier/EasyTier/zip/8428a89d2dabc94c97d370ec607c6ca142473626' -OutFile $etSource}
    }
    Copy-Item $etSource $sources
    $etArchive=[IO.Compression.ZipFile]::OpenRead($etSource)
    try {
        $licenseEntry=$etArchive.Entries | Where-Object {$_.FullName -match '^[^/]+/LICENSE$'} | Select-Object -First 1
        if(-not $licenseEntry) {throw 'EasyTier source license missing'}
        [IO.Compression.ZipFileExtensions]::ExtractToFile($licenseEntry,(Join-Path $licenses 'EasyTier-LGPL-3.0.txt'),$true)
    } finally {$etArchive.Dispose()}
    }
    $wdSource=Join-Path $downloads 'WinDivert-v2.2.2-source.zip'
    if(-not(Test-Path $wdSource)) {Invoke-WebRequest 'https://codeload.github.com/basil00/WinDivert/zip/refs/tags/v2.2.2' -OutFile $wdSource}
    Copy-Item $wdSource $sources
    Copy-Item .\docs\native-mesh-0.4.txt $stage\使用说明.txt
    Copy-Item .\docs\native-mesh-0.4-dependencies.txt $stage\第三方组件.txt
    Copy-Item .\docs\native-mesh-0.4.txt $stage\原生多机网络说明.txt
    $releaseNotes = Join-Path $root "docs/releases/v$releaseVersion-preview.md"
    if(Test-Path $releaseNotes) {Copy-Item -LiteralPath $releaseNotes -Destination $stage\版本更新说明.md}
    $releaseText = Join-Path $root "docs/releases/v$releaseVersion-preview.txt"
    if(Test-Path $releaseText) {Copy-Item -LiteralPath $releaseText -Destination $stage\版本更新说明.txt}
    Copy-Item .\docs\初版实测报告-20261010.md $stage\历史实测报告-0.2.md
    Copy-Item .\docs\发现服务运维.txt $stage\发现服务运维.txt
    Copy-Item .\docs\execution-status-20261011.md $stage\开发验收状态.md
    Copy-Item .\docs\StreamLink-Codex-Execution-Plan-20261011.md $stage\开发验收规格.md
    Copy-Item -LiteralPath $receipt -Destination $stage\构建来源.json
    if(Test-Path $verification) {Copy-Item $verification $stage\验证摘要.json}
    $preview=Start-Process -FilePath (Join-Path $stage 'StreamLink.exe') -ArgumentList @('--preview',(Join-Path $root 'artifacts\desktop-preview.png')) -WindowStyle Hidden -PassThru -Wait
    if($preview.ExitCode -ne 0) {throw 'Desktop preview failed'}
    Copy-Item .\artifacts\desktop-preview.png $stage\界面预览.png
    $files=@(Get-ChildItem -LiteralPath $stage -File -Recurse | ForEach-Object {
        [ordered]@{path=[IO.Path]::GetRelativePath($stage,$_.FullName);length=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    [ordered]@{version="$releaseVersion-preview";built=(Get-Date -Format o);sourceCommit=$commit;sourceDirty=$false;releaseLevel='development-candidate';releaseGate='NotPassed';architecture='win-x64';networkBackend='native-wintun';meshProtocol=4;easytier=$version;native=$nativeInfo;files=$files} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding UTF8
    $preflight=Join-Path $root "artifacts/bundle-preflight-$releaseVersion.json"
    $verify=Start-Process -FilePath (Join-Path $stage 'StreamLink.exe') -ArgumentList @('--verify-bundle',('"'+$preflight+'"')) -WindowStyle Hidden -PassThru -Wait
    if($verify.ExitCode -ne 0 -or (Get-Content -LiteralPath $preflight -Raw | ConvertFrom-Json).status -ne 'Pass') {throw 'Packaged executable rejected the actual bundle'}
    $release=Join-Path $root 'artifacts\releases'
    New-Item -ItemType Directory -Path $release -Force | Out-Null
    $zip=Join-Path $release "StreamLink-$releaseVersion-win-x64-preview.zip"
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force -CompressionLevel Optimal
    & git archive --format=zip "--output=$(Join-Path $release "StreamLink-$releaseVersion-source.zip")" $commit
    if($LASTEXITCODE -ne 0) {throw 'Committed source archive failed'}
    Get-FileHash -LiteralPath $zip,(Join-Path $release "StreamLink-$releaseVersion-source.zip") | Select-Object Hash,Path | ConvertTo-Json | Set-Content (Join-Path $release "sha256-$releaseVersion.json") -Encoding UTF8
    [ordered]@{stage=$stage;zip=$zip;manifest=(Join-Path $stage 'manifest.json')} | ConvertTo-Json | Set-Content (Join-Path $release 'latest.json') -Encoding UTF8
    Write-Output "Packaged: $zip"
} finally {Pop-Location}
