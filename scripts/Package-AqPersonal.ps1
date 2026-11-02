#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputRoot,[Parameter(Mandatory)][string]$DependencyCache,
      [string]$Version='1.0.3',[string]$MsiVersion='1.0.23',[switch]$PublicationApproved)
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try {
 $stable=$Version -match '^1\.0\.[1-9][0-9]*$'
 if(-not $stable -and $Version -notmatch '^1\.0\.0-aq1-personal\.[1-9][0-9]*$' -and $Version -notmatch '^1\.0\.1-rc\.[1-9][0-9]*$'){throw 'Supported release or candidate version required'}
 if($MsiVersion -notmatch '^1\.0\.([1-9][0-9]{0,4})$' -or [int]$Matches[1] -gt 65535){throw 'Explicit monotonic MSI version required'}
 $fileVersion=$MsiVersion+'.0'
 $commit=(& git rev-parse HEAD).Trim()
 if($LASTEXITCODE -or @(& git status --porcelain).Count){throw 'Commit and freeze the exact candidate first'}
 $candidate=Join-Path ([IO.Path]::GetFullPath($OutputRoot)) "StreamLink-$Version-$($commit.Substring(0,8))"
 if(Test-Path -LiteralPath $candidate){throw 'A frozen candidate cannot be overwritten'}
 $stage=Join-Path $candidate 'windows';$runtime=Join-Path $stage 'app';$logs=Join-Path $candidate 'build-evidence'
 New-Item -ItemType Directory -Path $stage,$runtime,$logs -Force|Out-Null
 & git archive --format=zip "--output=$candidate/StreamLink-$Version-source.zip" $commit
 if($LASTEXITCODE){throw 'Exact source archive failed'}
 & ./scripts/Build.ps1 -Test -FileVersion $fileVersion *> (Join-Path $logs 'native-build.log')
 if($LASTEXITCODE){throw 'Native build failed'}
 foreach($project in @('StreamLink.App','StreamLink.Service','StreamLink.Web')) {
  $published=Join-Path $repo "out/aq-publish-$Version-$project"
  & dotnet publish "src/$project" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:RuntimeFrameworkVersion=10.0.12 -p:StreamLinkPersonalFeature=true "-p:StreamLinkReleaseVersion=$Version" "-p:FileVersion=$fileVersion" -o $published *> (Join-Path $logs "$project-publish.log")
  if($LASTEXITCODE){throw "Publish failed: $project"}
  $destination=if($project -eq 'StreamLink.Web'){Join-Path $runtime 'web'}else{$runtime}
  foreach($file in Get-ChildItem -LiteralPath $published -File -Recurse) {
   $relative=[IO.Path]::GetRelativePath($published,$file.FullName)
   if($file.Extension -eq '.pdb' -or $relative -match '^(cs|de|es|fr|it|ja|ko|pl|pt-BR|ru|tr|zh-Hant)[\\/]'){continue}
   $target=Join-Path $destination $relative
   New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force|Out-Null
   if(Test-Path -LiteralPath $target){if((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash){throw "Shared publish conflict: $relative"}}
   else{Copy-Item -LiteralPath $file.FullName -Destination $target}
  }
 }
 Copy-Item -LiteralPath out/native/streamlink-launcher.exe -Destination (Join-Path $stage 'StreamLink.exe')
 $components=Join-Path $runtime 'components';New-Item -ItemType Directory -Path $components|Out-Null
 $wd=Join-Path $DependencyCache 'WinDivert-2.2.2-A';$wt=Join-Path $DependencyCache 'wintun'
 if((Get-AuthenticodeSignature -LiteralPath "$wd/x64/WinDivert64.sys").Status -ne 'Valid'){throw 'Official WinDivert signature invalid'}
 if((Get-FileHash -LiteralPath "$wt/bin/amd64/wintun.dll").Hash -ne 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'){throw 'Pinned official Wintun mismatch'}
 Copy-Item -LiteralPath out/native/udp2raw-native.exe,out/native/streamlink-tun.dll,"$wd/x64/WinDivert.dll","$wd/x64/WinDivert64.sys","$wt/bin/amd64/wintun.dll" -Destination $components
 $native=& ./out/native/udp2raw-native.exe --native-info|ConvertFrom-Json
 if($LASTEXITCODE -or $native.backend -ne 'windivert' -or $native.wireProtocol -ne 'udp2raw-http-c4995ea'){throw 'Wrong raw backend/profile'}
 if(Get-ChildItem $stage -Recurse -File|Where-Object Name -match 'ResearchAdapters|StreamLinkTun|easytier|Lucky'){throw 'Excluded product component present'}
 Copy-Item -LiteralPath docs/aq1/使用与回退.txt -Destination $runtime
 Copy-Item -LiteralPath docs/aq1/安装与更新.txt -Destination (Join-Path $stage '使用说明.txt')
 Copy-Item -LiteralPath docs/aq1/实机测试.txt,docs/aq1/已有入口与新版界面.txt -Destination $stage
 Copy-Item -LiteralPath docs/aq1/run-plan.json -Destination $runtime
 $licenses=Join-Path $runtime 'licenses';New-Item -ItemType Directory -Path $licenses|Out-Null
 Copy-Item LICENSE -Destination "$licenses/StreamLink-MIT.txt"
 Copy-Item transport/udp2raw/LICENSE.md -Destination "$licenses/udp2raw-license.txt"
 Copy-Item "$wd/LICENSE" -Destination "$licenses/WinDivert-license.txt"
 Copy-Item "$wt/LICENSE.txt" -Destination "$licenses/Wintun-license.txt"
 Copy-Item transport/udp2raw/libev/LICENSE -Destination "$licenses/libev-license.txt"
 Copy-Item docs/licenses/* -Destination $licenses
 $sources=Join-Path $runtime 'sources';New-Item -ItemType Directory -Path $sources|Out-Null
 Copy-Item -LiteralPath (Join-Path $candidate "StreamLink-$Version-source.zip"),(Join-Path $DependencyCache 'WinDivert-v2.2.2-source.zip') -Destination $sources
 & ./scripts/Write-RcSbom.ps1 -Directory $runtime -Version $Version -Commit $commit -Assets @('src/StreamLink.App/obj/project.assets.json','src/StreamLink.Service/obj/project.assets.json','src/StreamLink.Web/obj/project.assets.json') -Native
 $files=@(Get-ChildItem -LiteralPath $runtime -File -Recurse|ForEach-Object{[ordered]@{path=[IO.Path]::GetRelativePath($runtime,$_.FullName).Replace('\','/');length=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
 [ordered]@{schemaVersion=2;version=$Version;sourceCommit=$commit;sourceDirty=$false;architecture='win-x64';tunAbi=2;meshProtocol=4;personalContract='AQ-1-personal';releaseLevel=$(if($stable){'stable'}else{'engineering-candidate'});releaseGate='NotPassed';
  provenance=@{publisherSignature='UnsignedCandidate';officialDrivers='WinDivert Authenticode valid; pinned Wintun SHA256';hashesAreNotSourceAuthentication=$true};
  msiVersion=$MsiVersion;researchDrivers='OutOfScopeByUserDecision';businessProfile='FakeTcpHttpDatagram';controlProtocol='HTTPS';directControl='authenticated MeshLink, no coordinator';directInvitationVersion=2;directShortPairing=1;webHost='restricted loopback + SID-authenticated IPC';native=$native;files=$files}|ConvertTo-Json -Depth 12|Set-Content (Join-Path $runtime 'manifest.json') -Encoding utf8NoBOM
 [ordered]@{schemaVersion=1;version=$Version;sourceCommit=$commit;entryPoint='StreamLink.exe';runtimeDirectory='app';runtimeManifest='app/manifest.json';runtimeManifestSha256=(Get-FileHash (Join-Path $runtime 'manifest.json')).Hash;launcherSha256=(Get-FileHash (Join-Path $stage 'StreamLink.exe')).Hash;installer='MSI';profileDirectory='%ProgramData%/StreamLink-PersonalFeature'}|ConvertTo-Json|Set-Content (Join-Path $stage 'layout-manifest.json') -Encoding utf8NoBOM
 $p=Start-Process -FilePath (Join-Path $runtime 'StreamLink.exe') -ArgumentList @('--verify-bundle',"`"$(Join-Path $logs 'bundle-preflight.json')`"") -WindowStyle Hidden -Wait -PassThru
 if($p.ExitCode){throw 'Actual app rejected bundle'}
 $coord=Join-Path $candidate 'coordination-linux-x64'
 & dotnet publish src/StreamLink.Discovery -c Release -r linux-x64 --self-contained true -p:RuntimeFrameworkVersion=10.0.12 "-p:StreamLinkReleaseVersion=$Version" -o $coord *> (Join-Path $logs 'coordination-publish.log')
 if($LASTEXITCODE){throw 'Coordination publish failed'}
 Copy-Item -LiteralPath LICENSE,scripts/Deploy-PersonalCoordination.sh,docs/aq1/协调服务.txt -Destination $coord
 [ordered]@{sourceCommit=$commit;businessRelay=$false;deployment='PreparedOnlyNotDeployed';oldServiceUnchanged=$true;nativeSynObservation='Included, requires explicit authenticated observer configuration and CAP_NET_RAW'}|ConvertTo-Json|Set-Content (Join-Path $coord 'deployment.json')
 & ./scripts/Build-Msi.ps1 -BundleRoot $stage -OutputPath (Join-Path $candidate "StreamLink-$Version-x64.msi") -MsiVersion $MsiVersion
 foreach($folder in @($stage,$coord)){Compress-Archive -LiteralPath $folder -DestinationPath ($folder+'.zip') -CompressionLevel Optimal}
 $hashes=@(Get-ChildItem -LiteralPath $candidate -File|Where-Object Extension -in '.zip','.msi'|ForEach-Object{[ordered]@{file=$_.Name;bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
 [ordered]@{version=$Version;sourceCommit=$commit;publicReleaseApproved=[bool]$PublicationApproved;releaseGate='NotPassed';files=$hashes}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $candidate 'artifact-hashes.json') -Encoding utf8NoBOM
 Write-Output $candidate
} finally {Pop-Location}
