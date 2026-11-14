#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputRoot,[Parameter(Mandatory)][string]$DependencyCache,
      [string]$Version='1.2.0',[string]$MsiVersion='1.2.3',[ValidateSet('high','mszip')][string]$Compression='high',[switch]$PublicationApproved)
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try {
 $stable=$Version -match '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
 if(-not $stable -and $Version -notmatch '^1\.0\.0-aq1-personal\.[1-9][0-9]*$' -and $Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-(rc|preview)\.[1-9][0-9]*$'){throw 'Supported release or candidate version required'}
 if($MsiVersion -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$' -or [int]$Matches[1] -gt 255 -or [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 65535){throw 'Explicit monotonic MSI version required'}
 $fileVersion=$MsiVersion+'.0'
 $commit=(& git rev-parse HEAD).Trim()
 if($LASTEXITCODE -or @(& git status --porcelain --untracked-files=no).Count -or @(& git ls-files --others --exclude-standard -- src transport installer packaging).Count){throw 'Commit and freeze all package inputs first; unrelated untracked research is excluded'}
 $candidate=Join-Path ([IO.Path]::GetFullPath($OutputRoot)) "ConWU-$Version-$($commit.Substring(0,8))"
 if(Test-Path -LiteralPath $candidate){throw 'A frozen candidate cannot be overwritten'}
 $stage=Join-Path $candidate 'windows';$runtime=Join-Path $stage 'app';$logs=Join-Path $candidate 'build-evidence'
 New-Item -ItemType Directory -Path $stage,$runtime,$logs -Force|Out-Null
 & git archive --format=zip "--output=$candidate/ConWU-$Version-source.zip" $commit
 if($LASTEXITCODE){throw 'Exact source archive failed'}
 & ./scripts/Build.ps1 -Test -FileVersion $fileVersion *> (Join-Path $logs 'native-build.log')
 if($LASTEXITCODE){throw 'Native build failed'}
 foreach($project in @('ConWU.App','ConWU.Service','ConWU.Web')) {
  $published=Join-Path $repo "out/aq-publish-$Version-$project"
  & dotnet publish "src/$project" -f $(if($project -eq 'ConWU.Web'){'net10.0'}else{'net10.0-windows'}) -c Release -r win-x64 --self-contained true -m:1 -nr:false -p:UseSharedCompilation=false -p:NuGetAudit=false -p:PublishSingleFile=false -p:RuntimeFrameworkVersion=10.0.12 -p:StreamLinkPersonalFeature=true "-p:StreamLinkReleaseVersion=$Version" "-p:FileVersion=$fileVersion" -o $published *> (Join-Path $logs "$project-publish.log")
  if($LASTEXITCODE){throw "Publish failed: $project"}
  $destination=if($project -eq 'ConWU.Web'){Join-Path $runtime 'web'}else{$runtime}
  foreach($file in Get-ChildItem -LiteralPath $published -File -Recurse) {
   $relative=[IO.Path]::GetRelativePath($published,$file.FullName)
   if($file.Extension -eq '.pdb' -or $relative -match '^(cs|de|es|fr|it|ja|ko|pl|pt-BR|ru|tr|zh-Hant)[\\/]'){continue}
   $target=Join-Path $destination $relative
   New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force|Out-Null
   if(Test-Path -LiteralPath $target){if((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash){throw "Shared publish conflict: $relative"}}
   else{Copy-Item -LiteralPath $file.FullName -Destination $target}
  }
 }
 Copy-Item -LiteralPath out/native/conwu-launcher.exe -Destination (Join-Path $stage 'ConWU.exe')
 $components=Join-Path $runtime 'components';New-Item -ItemType Directory -Path $components|Out-Null
 $wd=Join-Path $DependencyCache 'WinDivert-2.2.2-A';$wt=Join-Path $DependencyCache 'wintun'
 if((Get-AuthenticodeSignature -LiteralPath "$wd/x64/WinDivert64.sys").Status -ne 'Valid'){throw 'Official WinDivert signature invalid'}
 if((Get-FileHash -LiteralPath "$wt/bin/amd64/wintun.dll").Hash -ne 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'){throw 'Pinned official Wintun mismatch'}
 Copy-Item -LiteralPath out/native/udp2raw-native.exe,out/native/conwu-tun.dll,out/native/conwu-updater.exe,"$wd/x64/WinDivert.dll","$wd/x64/WinDivert64.sys","$wt/bin/amd64/wintun.dll" -Destination $components
 Copy-Item -LiteralPath out/phantun-native/x86_64-pc-windows-msvc/release/conwu-phantun.exe,out/phantun-native/x86_64-pc-windows-msvc/release/conwu-raw.exe -Destination $components
 $phantun=& (Join-Path $components 'conwu-phantun.exe') --conwu-info|ConvertFrom-Json
 if($LASTEXITCODE -or $phantun.component -ne 'ConWU.Phantun' -or $phantun.abi -ne 1){throw 'Wrong Phantun component/ABI'}
 $raw=& (Join-Path $components 'conwu-raw.exe') --conwu-info|ConvertFrom-Json
 if($LASTEXITCODE -or $raw.component -ne 'ConWU.RawCarriers' -or $raw.abi -ne 1){throw 'Wrong Mimic/TCPRAW component/ABI'}
 $native=& ./out/native/udp2raw-native.exe --native-info|ConvertFrom-Json
 if($LASTEXITCODE -or $native.backend -ne 'windivert' -or $native.wireProtocol -ne 'udp2raw-http-c4995ea'){throw 'Wrong raw backend/profile'}
 if(Get-ChildItem $stage -Recurse -File|Where-Object Name -match 'ResearchAdapters|StreamLinkTun|easytier|Lucky'){throw 'Excluded product component present'}
 Copy-Item -LiteralPath docs/ConWU-使用说明.txt -Destination (Join-Path $runtime '使用与回退.txt')
 Copy-Item -LiteralPath docs/ConWU-使用说明.txt -Destination (Join-Path $stage '使用说明.txt')
 Copy-Item -LiteralPath docs/ConWU-入口与配置.md -Destination (Join-Path $stage '入口与配置.md')
 $licenses=Join-Path $runtime 'licenses';New-Item -ItemType Directory -Path $licenses|Out-Null
 Copy-Item LICENSE -Destination "$licenses/ConWU-MIT.txt"
 Copy-Item transport/udp2raw/LICENSE.md -Destination "$licenses/udp2raw-license.txt"
 Copy-Item "$wd/LICENSE" -Destination "$licenses/WinDivert-license.txt"
 Copy-Item "$wt/LICENSE.txt" -Destination "$licenses/Wintun-license.txt"
 Copy-Item transport/udp2raw/libev/LICENSE -Destination "$licenses/libev-license.txt"
 Copy-Item docs/licenses/* -Destination $licenses
 & py -3 scripts/Write-PhantunNotices.py --directory $runtime
 if($LASTEXITCODE){throw 'Phantun dependency notices failed'}
 $sources=Join-Path $runtime 'sources';New-Item -ItemType Directory -Path $sources|Out-Null
 Copy-Item -LiteralPath (Join-Path $candidate "ConWU-$Version-source.zip"),(Join-Path $DependencyCache 'WinDivert-v2.2.2-source.zip') -Destination $sources
 & ./scripts/Write-RcSbom.ps1 -Directory $runtime -Version $Version -Commit $commit -Assets @('src/ConWU.App/obj/project.assets.json','src/ConWU.Service/obj/project.assets.json','src/ConWU.Web/obj/project.assets.json') -Native
 $files=@(Get-ChildItem -LiteralPath $runtime -File -Recurse|ForEach-Object{[ordered]@{path=[IO.Path]::GetRelativePath($runtime,$_.FullName).Replace('\','/');length=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
 [ordered]@{schemaVersion=2;version=$Version;sourceCommit=$commit;sourceDirty=$false;architecture='win-x64';tunAbi=2;meshProtocol=4;personalContract='AQ-1-personal';releaseLevel=$(if($stable){'stable'}else{'engineering-candidate'});releaseGate='PackagePreflightOnly';releaseVerification="ConWU-$Version-verification.json";
  provenance=@{publisherSignature='UnsignedCandidate';officialDrivers='WinDivert Authenticode valid; pinned Wintun SHA256';hashesAreNotSourceAuthentication=$true};
  product='ConWU';businessTransports=@('faketcp','phantun','mimic','tcpraw','tcp','https');rawCarriers='Mimic zero-padding + TCPRAW kernel handshake; experimental datagram paths; separate GPL-2.0-only component';phantunCarrier='Phantun TCP-format datagrams; MeshLink AEAD; native ABI 1';httpsCarrier='TCP + TLS 1.2/1.3 + WebSocket; approved persistent SPKI pin';streamFlowLanes=1;streamFlowDefault='off';streamFlowConnections=3;streamFlowCompatibility='approved member negotiation; primary connection fallback';streamGuestRole='outbound connection to host, bidirectional data';autoGuestSettings=1;pkarrDiscovery='autonomous signed endpoint discovery; initial approved invitation; HTTPS gateways; no synchronized NAT exchange';discoveryPolicyVersion=1;integratedCoordinator=1;defaultCoordinatorRoleVersion=1;pairingUi='16-symbol compact direct code with local approval';networkEntryIdentity=1;signedDnsDiscovery=0;dnsPublisher='Not included; external HTTPS/TXT subscriptions supported';
  msiVersion=$MsiVersion;researchDrivers='OutOfScopeByUserDecision';businessProfile='FakeTcpHttpDatagram';controlProtocol='HTTPS';directControl='authenticated MeshLink, no coordinator';directInvitationVersion=2;compactDirectCodeVersion=1;directShortPairing=1;peerMetadataReplication=1;equalMembership=0;pairNetworks=1;nodeIdentity=1;workspaceVersion=2;sharedConfigurationLibrary=1;sharedReceiverFrame='CNW1';freshInstallRequiredFrom='legacy single-network configurations only';maximumStoredNetworks=16;maximumEnabledNetworks=8;networkModel='independent two-device networks; creator approves the guest; bidirectional data; no inter-network forwarding';coordinatedNetworks='shared integrated HTTPS discovery; coordinator does not enroll itself; no business relay';webHost='restricted loopback + SID-authenticated IPC';native=$native;files=$files}|ConvertTo-Json -Depth 12|Set-Content (Join-Path $runtime 'manifest.json') -Encoding utf8NoBOM
 [ordered]@{schemaVersion=1;version=$Version;sourceCommit=$commit;entryPoint='ConWU.exe';runtimeDirectory='app';runtimeManifest='app/manifest.json';runtimeManifestSha256=(Get-FileHash (Join-Path $runtime 'manifest.json')).Hash;launcherSha256=(Get-FileHash (Join-Path $stage 'ConWU.exe')).Hash;installer='MSI';profileDirectory='%ProgramData%/StreamLink-PersonalFeature'}|ConvertTo-Json|Set-Content (Join-Path $stage 'layout-manifest.json') -Encoding utf8NoBOM
 $p=Start-Process -FilePath (Join-Path $runtime 'ConWU.exe') -ArgumentList @('--verify-bundle',"`"$(Join-Path $logs 'bundle-preflight.json')`"") -WindowStyle Hidden -Wait -PassThru
 if($p.ExitCode){throw 'Actual app rejected bundle'}
 # Linux member/coordinator uses the same integrated host, packaged by
 # Package-UnifiedLinux.ps1. Do not ship a second coordinator-only application.
 & ./scripts/Build-Msi.ps1 -BundleRoot $stage -OutputPath (Join-Path $candidate "ConWU-$Version-x64.msi") -MsiVersion $MsiVersion -Compression $Compression
 Compress-Archive -LiteralPath $stage -DestinationPath ($stage+'.zip') -CompressionLevel Optimal
 $hashes=@(Get-ChildItem -LiteralPath $candidate -File|Where-Object Extension -in '.zip','.msi'|ForEach-Object{[ordered]@{file=$_.Name;bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
 [ordered]@{version=$Version;sourceCommit=$commit;publicReleaseApproved=[bool]$PublicationApproved;releaseGate='PackagePreflightOnly';releaseVerification="ConWU-$Version-verification.json";files=$hashes}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $candidate 'artifact-hashes.json') -Encoding utf8NoBOM
 Write-Output $candidate
} finally {Pop-Location}
