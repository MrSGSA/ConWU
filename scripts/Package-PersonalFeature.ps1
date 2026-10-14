#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputRoot,[Parameter(Mandatory)][string]$DependencyCache,
 [Parameter(Mandatory)][string]$WdkRoot,[Parameter(Mandatory)][string]$Inf2Cat,
 [string]$Version='1.0.0-personal-feature.2')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try{
 if($Version -notmatch '^1\.0\.0-personal-feature\.[1-9][0-9]*$'){throw 'Personal feature version required'}
 $commit=(& git rev-parse HEAD).Trim()
 if($LASTEXITCODE -or @(& git status --porcelain).Count){throw 'Freeze and commit the exact complete candidate tree first'}
 $candidate=Join-Path ([IO.Path]::GetFullPath($OutputRoot)) "StreamLink-$Version-$($commit.Substring(0,8))"
 if(Test-Path -LiteralPath $candidate){throw 'Never overwrite a fixed personal candidate'}
 $stage=Join-Path $candidate 'windows';$logs=Join-Path $candidate 'build-evidence'
 New-Item -ItemType Directory -Path $stage,$logs -Force|Out-Null
 & git archive --format=zip "--output=$candidate/StreamLink-$Version-source.zip" $commit
 if($LASTEXITCODE){throw 'Exact source archive failed'}
 & ./scripts/Build.ps1 -Test *> (Join-Path $logs 'native-build.log')
 if($LASTEXITCODE){throw 'Native build failed'}
 foreach($project in @('StreamLink.App','StreamLink.Service')){
  $published=Join-Path $repo "out/personal-publish-$Version-$project"
  & dotnet publish "src/$project" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:StreamLinkPersonalFeature=true "-p:StreamLinkReleaseVersion=$Version" -o $published *> (Join-Path $logs "$project-publish.log")
  if($LASTEXITCODE){throw "Publish failed: $project"}
  foreach($file in Get-ChildItem -LiteralPath $published -File -Recurse){
   $relative=[IO.Path]::GetRelativePath($published,$file.FullName)
   if($file.Extension -eq '.pdb' -or $relative -match '^(cs|de|es|fr|it|ja|ko|pl|pt-BR|ru|tr|zh-Hant)[\\/]'){continue}
   $target=Join-Path $stage $relative;New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force|Out-Null
   if(Test-Path -LiteralPath $target){if((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash){throw "Shared publish conflict: $relative"}}else{Copy-Item -LiteralPath $file.FullName -Destination $target}
  }
 }
 $components=Join-Path $stage 'components';New-Item -ItemType Directory -Path $components|Out-Null
 $wd=Join-Path $DependencyCache 'WinDivert-2.2.2-A';$wt=Join-Path $DependencyCache 'wintun'
 if((Get-AuthenticodeSignature -LiteralPath "$wd/x64/WinDivert64.sys").Status -ne 'Valid'){throw 'Official WinDivert signature invalid'}
 if((Get-FileHash -LiteralPath "$wt/bin/amd64/wintun.dll").Hash -ne 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'){throw 'Pinned official Wintun mismatch'}
 Copy-Item -LiteralPath out/native/udp2raw-native.exe,out/native/streamlink-tun.dll,"$wd/x64/WinDivert.dll","$wd/x64/WinDivert64.sys","$wt/bin/amd64/wintun.dll" -Destination $components
 $native=& ./out/native/udp2raw-native.exe --native-info|ConvertFrom-Json
 if($LASTEXITCODE -or $native.backend -ne 'windivert' -or $native.wireProtocol -ne 'udp2raw-http-c4995ea'){throw 'Wrong raw backend/profile'}
 $driverOutput="out/personal-driver-$($commit.Substring(0,8))"
 & ./drivers/Build-Research.ps1 -WdkRoot $WdkRoot -Output $driverOutput -TunOnly *> (Join-Path $logs 'tun-build.log')
 $tun=Join-Path $repo "$driverOutput/tun"
 & ./drivers/New-TunCatalog.ps1 -Package $tun -Inf2Cat $Inf2Cat -InfVerif (Join-Path $WdkRoot 'tools/10.0.26100.0/x64/infverif.exe') *> (Join-Path $logs 'tun-catalog.log')
 $self=Join-Path $components 'self-tun';New-Item -ItemType Directory -Path $self|Out-Null
 $members=@('StreamLinkTun.sys','StreamLinkTun.inf','StreamLinkTun.cat','streamlink-tun-research.dll')
 foreach($name in $members){Copy-Item -LiteralPath (Join-Path $tun $name) -Destination (Join-Path $self $name)}
 [ordered]@{SchemaVersion=1;SourceCommit=$commit;Architecture='win-x64';DescriptorAbi=2;UserAbi=1;Mtu=1280;HardwareId='ROOT\StreamLinkTun';ServiceName='StreamLinkTun';
  Files=@($members|ForEach-Object{[ordered]@{Name=$_;Sha256=(Get-FileHash -LiteralPath (Join-Path $self $_)).Hash}})}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $self 'package-identity.json') -Encoding utf8NoBOM
 $scripts=Join-Path $stage 'tools';New-Item -ItemType Directory -Path $scripts|Out-Null
 Copy-Item -LiteralPath drivers/Manage-PersonalTun.ps1,drivers/Invoke-PersonalTunKernel.ps1,drivers/Complete-PersonalTunGate.ps1,drivers/Collect-PersonalTunVerifier.ps1,drivers/Freeze-SignedTunPackage.ps1,scripts/Get-PersonalHostPreflight.ps1 -Destination $scripts
 $kernelTool=Join-Path $repo "out/personal-publish-$Version-kernel-tool"
 & dotnet publish tests/StreamLink.TunKernelTests -c Release -r win-x64 --self-contained true "-p:StreamLinkReleaseVersion=$Version" -o $kernelTool *> (Join-Path $logs 'kernel-tool-publish.log')
 if($LASTEXITCODE){throw 'Actual kernel test tool publish failed'}
 # Reuse the exact .NET runtime already in the Windows bundle instead of
 # adding a second full runtime under tools. The research ZIP remains standalone.
 foreach($file in Get-ChildItem -LiteralPath $kernelTool -File){
  if($file.Extension -eq '.pdb'){continue}
  $target=Join-Path $stage $file.Name
  if(Test-Path -LiteralPath $target){if((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash){throw "Kernel tool runtime conflict: $($file.Name)"}}
  else{Copy-Item -LiteralPath $file.FullName -Destination $target}
 }
 Copy-Item -LiteralPath docs/personal-v3 -Destination (Join-Path $stage 'docs') -Recurse
 Copy-Item -LiteralPath docs/personal-v3/使用与回退.md -Destination (Join-Path $stage '使用与回退.md')
 @'
$ErrorActionPreference='Stop'
$exe=Join-Path $PSScriptRoot 'StreamLink.exe'
$p=Start-Process -FilePath $exe -ArgumentList '--install-ui' -Verb RunAs -PassThru -Wait
if($p.ExitCode){throw 'Personal service install failed; stable StreamLink service was not selected'}
'@|Set-Content (Join-Path $stage 'Install-PersonalService.ps1') -Encoding UTF8
 $licenses=Join-Path $stage 'licenses';New-Item -ItemType Directory -Path $licenses|Out-Null
 Copy-Item LICENSE -Destination "$licenses/StreamLink-MIT.txt"
 Copy-Item transport/udp2raw/LICENSE.md -Destination "$licenses/udp2raw-license.txt"
 Copy-Item "$wd/LICENSE" -Destination "$licenses/WinDivert-license.txt"
 Copy-Item "$wt/LICENSE.txt" -Destination "$licenses/Wintun-license.txt"
 Copy-Item transport/udp2raw/libev/LICENSE -Destination "$licenses/libev-license.txt"
 Copy-Item docs/licenses/* -Destination $licenses
 $sources=Join-Path $stage 'sources';New-Item -ItemType Directory -Path $sources|Out-Null
 Copy-Item -LiteralPath (Join-Path $candidate "StreamLink-$Version-source.zip"),(Join-Path $DependencyCache 'WinDivert-v2.2.2-source.zip') -Destination $sources
 & ./scripts/Write-RcSbom.ps1 -Directory $stage -Version $Version -Commit $commit -Assets @('src/StreamLink.App/obj/project.assets.json','src/StreamLink.Service/obj/project.assets.json') -Native
 $files=@(Get-ChildItem -LiteralPath $stage -File -Recurse|ForEach-Object{[ordered]@{path=[IO.Path]::GetRelativePath($stage,$_.FullName).Replace('\','/');length=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
 [ordered]@{schemaVersion=2;version=$Version;sourceCommit=$commit;sourceDirty=$false;architecture='win-x64';tunAbi=2;meshProtocol=4;personalContract='personal-feature-acceptance-v3';releaseLevel='personal-partial-candidate';releaseGate='NotPassed';
  provenance=@{publisherSignature='UnsignedCandidate';officialDrivers='WinDivert Authenticode valid; pinned Wintun SHA256';hashesAreNotSourceAuthentication=$true};
  selfTun=@{built=$true;catalogGenerated=$true;signed=$false;loadedOnPersonalHosts=$false;kernelGate='BlockedExternal';automaticLoading=$false};native=$native;files=$files}|ConvertTo-Json -Depth 12|Set-Content (Join-Path $stage 'manifest.json') -Encoding utf8NoBOM
 $p=Start-Process -FilePath (Join-Path $stage 'StreamLink.exe') -ArgumentList @('--verify-bundle',"`"$(Join-Path $logs 'bundle-preflight.json')`"") -WindowStyle Hidden -Wait -PassThru
 if($p.ExitCode){throw 'Actual personal app rejected the complete bundle'}
 $coord=Join-Path $candidate 'coordination-linux-x64'
 & dotnet publish src/StreamLink.Discovery -c Release -r linux-x64 --self-contained true "-p:StreamLinkReleaseVersion=$Version" -o $coord *> (Join-Path $logs 'coordination-publish.log')
 if($LASTEXITCODE){throw 'Matching coordination publish failed'}
 Copy-Item -LiteralPath LICENSE,scripts/Deploy-PersonalCoordination.sh,docs/personal-v3/协调部署.md -Destination $coord
 [ordered]@{sourceCommit=$commit;businessRelay=$false;deployment='PreparedOnlyNotDeployed';listen='http://127.0.0.1:42863';separateService='streamlink-personal-v3.service';oldServiceUnchanged=$true}|ConvertTo-Json|Set-Content (Join-Path $coord 'deployment.json')
 $research=Join-Path $candidate 'tun-research';New-Item -ItemType Directory -Path $research|Out-Null
 Copy-Item -LiteralPath $self,drivers/StreamLink.Tun,transport/tun-native,src/StreamLink.ResearchAdapters,drivers/Build-Research.ps1,drivers/New-TunCatalog.ps1,drivers/Manage-PersonalTun.ps1,drivers/Invoke-PersonalTunKernel.ps1,drivers/Complete-PersonalTunGate.ps1,drivers/Collect-PersonalTunVerifier.ps1,drivers/Freeze-SignedTunPackage.ps1,docs/personal-v3/driver-gates.md,docs/personal-v3/PF2-驱动实验流程.md -Destination $research -Recurse
 Copy-Item -LiteralPath $kernelTool -Destination (Join-Path $research 'tun-kernel-probe') -Recurse
 Copy-Item -LiteralPath (Join-Path $stage 'StreamLink.ResearchAdapters.dll') -Destination $research
 foreach($folder in @($stage,$coord,$research)){Compress-Archive -LiteralPath $folder -DestinationPath ($folder+'.zip') -CompressionLevel Optimal}
 $hashes=@(Get-ChildItem -LiteralPath $candidate -File -Filter '*.zip'|ForEach-Object{[ordered]@{file=$_.Name;bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
 [ordered]@{version=$Version;sourceCommit=$commit;publicReleaseApproved=$false;releaseGate='NotPassed';files=$hashes}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $candidate 'artifact-hashes.json') -Encoding utf8NoBOM
 Write-Output $candidate
}finally{Pop-Location}
