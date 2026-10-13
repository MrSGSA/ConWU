param([string]$Version='1.0.0-rc1')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try{
    if($Version -notmatch '^1\.0\.0-rc[1-9][0-9]*$'){throw 'This pipeline packages explicit RC candidates only'}
    $commit=(& git rev-parse HEAD).Trim()
    if(@(& git status --porcelain).Count){throw 'Commit the exact complete candidate tree before packaging'}
    $root=[IO.Path]::GetFullPath((Join-Path $repo '../releases'))
    $candidate=Join-Path $root "StreamLink-$Version-$($commit.Substring(0,8))"
    if(Test-Path -LiteralPath $candidate){throw 'Fixed candidate already exists; never overwrite its evidence'}
    $stage=New-Item -ItemType Directory -Path (Join-Path $candidate 'windows') -Force
    $artifacts=New-Item -ItemType Directory -Path (Join-Path $repo "artifacts/package-$Version-$($commit.Substring(0,8))") -Force
    & git archive --format=zip "--output=$candidate/StreamLink-$Version-source.zip" $commit
    if($LASTEXITCODE){throw 'Exact committed source archive failed'}
    & ./scripts/Build.ps1 -Test *> (Join-Path $artifacts.FullName 'native-build.txt')
    if($LASTEXITCODE){throw 'Native build failed'}
    foreach($project in @('StreamLink.App','StreamLink.Service')){
        $output=Join-Path $repo "out/rc-publish-$Version-$project"
        & dotnet publish "src/$project" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false "-p:StreamLinkReleaseVersion=$Version" -o $output *> (Join-Path $artifacts.FullName "$project-publish.txt")
        if($LASTEXITCODE){throw "Publish failed: $project"}
        foreach($file in Get-ChildItem -LiteralPath $output -File -Recurse){
            $relative=[IO.Path]::GetRelativePath($output,$file.FullName)
            if($file.Extension -eq '.pdb' -or $relative -match '^(cs|de|es|fr|it|ja|ko|pl|pt-BR|ru|tr|zh-Hant)[\\/]'){continue}
            $target=Join-Path $stage.FullName $relative;New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force|Out-Null
            if(Test-Path -LiteralPath $target){if((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash){throw "Conflicting shared publish file: $relative"}}else{Copy-Item -LiteralPath $file.FullName -Destination $target}
        }
    }
    $components=New-Item -ItemType Directory -Path (Join-Path $stage.FullName 'components') -Force
    $wd=Join-Path $repo 'out/downloads/WinDivert-2.2.2-A';$wt=Join-Path $repo 'out/downloads/wintun'
    if((Get-AuthenticodeSignature -LiteralPath "$wd/x64/WinDivert64.sys").Status -ne 'Valid'){throw 'Official WinDivert kernel signature must validate'}
    if((Get-FileHash -LiteralPath "$wt/bin/amd64/wintun.dll").Hash -ne 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'){throw 'Official Wintun binary hash mismatch'}
    Copy-Item out/native/udp2raw-native.exe,out/native/streamlink-tun.dll,"$wd/x64/WinDivert.dll","$wd/x64/WinDivert64.sys","$wt/bin/amd64/wintun.dll" -Destination $components.FullName
    $native=& ./out/native/udp2raw-native.exe --native-info|ConvertFrom-Json
    if($LASTEXITCODE -or $native.backend -ne 'windivert' -or $native.wireProtocol -ne 'udp2raw-http-c4995ea'){throw 'Wrong production native backend/profile'}
    $licenses=New-Item -ItemType Directory -Path (Join-Path $stage.FullName 'licenses') -Force
    Copy-Item LICENSE -Destination "$($licenses.FullName)/StreamLink-MIT.txt"
    Copy-Item transport/udp2raw/LICENSE.md -Destination "$($licenses.FullName)/udp2raw-license.txt"
    Copy-Item "$wd/LICENSE" -Destination "$($licenses.FullName)/WinDivert-license.txt"
    Copy-Item "$wt/LICENSE.txt" -Destination "$($licenses.FullName)/Wintun-license.txt"
    Copy-Item transport/udp2raw/libev/LICENSE -Destination "$($licenses.FullName)/libev-license.txt"
    Copy-Item docs/licenses/* -Destination $licenses.FullName
    foreach($crypto in @('lib/aes_faster_c/aes.cpp','lib/md5.cpp','lib/pbkdf2-sha1.cpp','lib/pbkdf2-sha256.cpp')){
        $header=(Get-Content -LiteralPath (Join-Path transport/udp2raw $crypto) -TotalCount 30)-join "`n"
        $header|Set-Content (Join-Path $licenses.FullName (([IO.Path]::GetFileName($crypto))+'.copyright-header.txt')) -Encoding utf8
    }
    $sources=New-Item -ItemType Directory -Path (Join-Path $stage.FullName 'sources') -Force
    Copy-Item out/downloads/WinDivert-v2.2.2-source.zip -Destination $sources.FullName
    Copy-Item (Join-Path $candidate "StreamLink-$Version-source.zip") -Destination $sources.FullName
    Copy-Item docs/implementation-1.0/task-status.json -Destination "$($stage.FullName)/task-status.json"
    @"
StreamLink $Version 开发候选；业务仅P2P，不经过服务器或成员中继。
普通权限启动 StreamLink.exe 读取指定SID受限接口；安装、配对与高级设置从管理员入口操作。
公共协调服务器尚未预配置，请自行填写可信HTTPS协调地址。
本包未获发布者签名；文件hash只证明完整性。必过Gate未全通过，不能当1.0正式发布。
默认官方Wintun/WinDivert；自研驱动不在运行组件内，不会自动加载。
缺校园网NAT4、八台真机、未登录冷启动等证据见task-status.json；历史Fail保留。
安装/回滚会中断本软件当前连接；不卸载其他软件共享的驱动。回滚后保留当前DPAPI配置，不能恢复旧撤销目录。
"@ |Set-Content "$($stage.FullName)/使用说明.txt" -Encoding utf8
    @'
$ErrorActionPreference='Stop'
$exe=Join-Path $PSScriptRoot 'StreamLink.exe'
$process=Start-Process -FilePath $exe -ArgumentList '--install' -Verb RunAs -PassThru -Wait
if($process.ExitCode){throw 'Installation failed; inspect local installer error and rollback outcome'}
'@|Set-Content "$($stage.FullName)/Install-Service.ps1" -Encoding utf8
    & ./scripts/Write-RcSbom.ps1 -Directory $stage.FullName -Version $Version -Commit $commit -Assets @('src/StreamLink.App/obj/project.assets.json','src/StreamLink.Service/obj/project.assets.json') -Native
    $files=@(Get-ChildItem -LiteralPath $stage.FullName -File -Recurse|ForEach-Object{[ordered]@{path=[IO.Path]::GetRelativePath($stage.FullName,$_.FullName).Replace('\','/');length=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
    [ordered]@{schemaVersion=2;version=$Version;sourceCommit=$commit;sourceDirty=$false;architecture='win-x64';tunAbi=2;meshProtocol=4;releaseLevel='development-candidate';releaseGate='NotPassed';provenance=@{publisherSignature='UnsignedCandidate';officialDrivers='WinDivert Authenticode valid; pinned Wintun SHA256';hashesAreNotSourceAuthentication=$true};native=$native;files=$files}|ConvertTo-Json -Depth 12|Set-Content "$($stage.FullName)/manifest.json" -Encoding utf8
    $preflight=Join-Path $artifacts.FullName 'bundle-preflight.json'
    $process=Start-Process -FilePath "$($stage.FullName)/StreamLink.exe" -ArgumentList @('--verify-bundle',$preflight) -WindowStyle Hidden -Wait -PassThru
    if($process.ExitCode){throw 'Actual published app rejected its complete bundle'}
    $coord=Join-Path $candidate 'coordination-linux-x64'
    & dotnet publish src/StreamLink.Discovery -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=false "-p:StreamLinkReleaseVersion=$Version" -o $coord *> (Join-Path $artifacts.FullName 'coordination-publish.txt')
    if($LASTEXITCODE){throw 'Coordination publish failed'}
    [ordered]@{version=$Version;sourceCommit=$commit;businessRelay=$false;deployment='PreparedOnlyNotDeployed';listen='http://127.0.0.1:42861';stateDirectory='owner must explicitly configure persistent STREAMLINK_DISCOVERY_DATA';cloudflareOriginIsHttp=$true}|ConvertTo-Json|Set-Content (Join-Path $coord 'deployment.json') -Encoding utf8
    Copy-Item LICENSE -Destination (Join-Path $coord 'LICENSE-StreamLink.txt')
    & ./scripts/Write-RcSbom.ps1 -Directory $coord -Version $Version -Commit $commit -Assets @('src/StreamLink.Discovery/obj/project.assets.json')
    $driver=New-Item -ItemType Directory -Path (Join-Path $candidate 'driver-research') -Force
    Copy-Item drivers,transport/tun-native,src/StreamLink.ResearchAdapters,docs/driver-validation -Destination $driver.FullName -Recurse
    if(Test-Path out/driver-research){Copy-Item out/driver-research -Destination $driver.FullName -Recurse}
    'Research-only unsigned outputs. No kernel loading or default replacement permitted before independent driver Gate.'|Set-Content (Join-Path $driver.FullName 'RESEARCH-ONLY.txt')
    foreach($folder in @($stage.FullName,$coord,$driver.FullName)){Compress-Archive -LiteralPath $folder -DestinationPath ($folder+'.zip') -CompressionLevel Optimal}
    Copy-Item $artifacts.FullName -Destination (Join-Path $candidate 'build-evidence') -Recurse
    $hashes=Get-ChildItem -LiteralPath $candidate -File|Where-Object Extension -eq '.zip'|Get-FileHash -Algorithm SHA256|Select-Object @{Name='file';Expression={Split-Path $_.Path -Leaf}},Hash
    [ordered]@{version=$Version;sourceCommit=$commit;releaseGate='NotPassed';signature='UnsignedCandidate';files=@($hashes)}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $candidate 'artifact-hashes.json') -Encoding utf8
    Write-Output $candidate
}finally{Pop-Location}
