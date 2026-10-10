param([string]$EasyTierDirectory='C:\Program Files\easytier-manager-pro\resource',[switch]$SkipBuild,[string]$NativeBinary='out/native/udp2raw-native.exe',[string]$ReleaseVersion='0.3.1')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
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
        & dotnet run --project tests/StreamLink.RenderingTests -c Release -- (Join-Path $root "artifacts/rendering-$releaseVersion.json")
        if($LASTEXITCODE -ne 0) {throw 'Desktop rendering regression failed'}
        & .\scripts\Test-Coordination.ps1
        foreach($project in @('StreamLink.App','StreamLink.Service')) {
            $dest=switch($project) {'StreamLink.App' {"out/app-$releaseVersion"} 'StreamLink.Service' {"out/service-$releaseVersion"}}
            & dotnet publish (Join-Path 'src' $project) -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false "-p:Version=$releaseVersion" -o $dest
            if($LASTEXITCODE -ne 0) {throw "Publish failed: $project"}
        }
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
    $version=& (Join-Path $EasyTierDirectory 'easytier-core.exe') --version
    if($version -notmatch '2\.6\.4-8428a89d') {throw 'This preview requires the tested EasyTier 2.6.4-8428a89d build'}
    $stage=Join-Path $root ('out\release-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
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
    foreach($name in @('easytier-core.exe','easytier-cli.exe')) {Copy-Item -LiteralPath (Join-Path $EasyTierDirectory $name) -Destination $components}
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
    $wdSource=Join-Path $downloads 'WinDivert-v2.2.2-source.zip'
    if(-not(Test-Path $wdSource)) {Invoke-WebRequest 'https://codeload.github.com/basil00/WinDivert/zip/refs/tags/v2.2.2' -OutFile $wdSource}
    Copy-Item $wdSource $sources
    Copy-Item .\docs\初版使用说明.md $stage\使用说明.md
    Copy-Item .\docs\发布依赖说明.txt $stage\第三方组件.txt
    Copy-Item .\docs\releases\0.3-development.md $stage\本版验证说明.md
    $releaseNotes = Join-Path $root "docs/releases/v$releaseVersion-preview.md"
    if(Test-Path $releaseNotes) {Copy-Item -LiteralPath $releaseNotes -Destination $stage\版本更新说明.md}
    Copy-Item .\docs\初版实测报告-20261010.md $stage\历史实测报告-0.2.md
    Copy-Item .\docs\发现服务运维.txt $stage\发现服务运维.txt
    $verification=Join-Path $root ("artifacts\release-verification-$releaseVersion.json")
    if(Test-Path $verification) {Copy-Item $verification $stage\验证摘要.json}
    $preview=Start-Process -FilePath (Join-Path $stage 'StreamLink.exe') -ArgumentList @('--preview',(Join-Path $root 'artifacts\desktop-preview.png')) -WindowStyle Hidden -PassThru -Wait
    if($preview.ExitCode -ne 0) {throw 'Desktop preview failed'}
    Copy-Item .\artifacts\desktop-preview.png $stage\界面预览.png
    $files=@(Get-ChildItem -LiteralPath $stage -File -Recurse | ForEach-Object {
        [ordered]@{path=[IO.Path]::GetRelativePath($stage,$_.FullName);length=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    })
    [ordered]@{version="$releaseVersion-preview";built=(Get-Date -Format o);architecture='win-x64';easytier=$version;files=$files} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding UTF8
    $release=Join-Path $root 'artifacts\releases'
    New-Item -ItemType Directory -Path $release -Force | Out-Null
    $zip=Join-Path $release "StreamLink-$releaseVersion-win-x64-preview.zip"
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force -CompressionLevel Optimal
    $sourceStage=Join-Path $stage 'source-stage'
    New-Item -ItemType Directory -Path $sourceStage -Force | Out-Null
    $sourceFiles=@(& rg --files --hidden -g '!out/**' -g '!artifacts/**' -g '!.git/**' -g '!**/bin/**' -g '!**/obj/**' -g '!**/__pycache__/**' -g '!**/*.private.json' -g '!**/*.pfx' -g '!**/*.pem' -g '!**/*.key' -g '!**/*.dpapi' -g '!**/.env')
    foreach($relative in $sourceFiles) {
        $to=Join-Path $sourceStage $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $root $relative) -Destination $to
    }
    Compress-Archive -Path (Join-Path $sourceStage '*') -DestinationPath (Join-Path $release "StreamLink-$releaseVersion-source.zip") -Force -CompressionLevel Optimal
    Get-FileHash -LiteralPath $zip,(Join-Path $release "StreamLink-$releaseVersion-source.zip") | Select-Object Hash,Path | ConvertTo-Json | Set-Content (Join-Path $release "sha256-$releaseVersion.json") -Encoding UTF8
    [ordered]@{stage=$stage;zip=$zip;manifest=(Join-Path $stage 'manifest.json')} | ConvertTo-Json | Set-Content (Join-Path $release 'latest.json') -Encoding UTF8
    Write-Output "Packaged: $zip"
} finally {Pop-Location}
