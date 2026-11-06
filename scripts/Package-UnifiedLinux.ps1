#requires -Version 7.0
param([Parameter(Mandatory)][string]$OutputDirectory,[string]$Version='1.0.6-rc.6',[string]$Distro='ArchLinux')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try {
 if(@(& git status --porcelain).Count){throw 'Freeze the candidate source before packaging'}
 $commit=(& git rev-parse HEAD).Trim()
 $out=[IO.Path]::GetFullPath($OutputDirectory)
 if(Test-Path -LiteralPath $out){throw 'Use a fresh package directory'}
 $bundle=Join-Path $out "StreamLink-$Version-linux-x64"
 $runtime=Join-Path $bundle 'runtime'
 New-Item -ItemType Directory -Path $runtime -Force|Out-Null
 & dotnet publish src/StreamLink.Host -c Release -r linux-x64 --self-contained true -p:RuntimeFrameworkVersion=10.0.12 -p:StreamLinkPersonalFeature=true "-p:StreamLinkReleaseVersion=$Version" -o $runtime *> (Join-Path $out 'publish.log')
 if($LASTEXITCODE){throw 'Linux managed publish failed'}
 $linuxRepo=(& wsl -d $Distro -- wslpath -a $repo).Trim()
 & wsl -d $Distro -- cmake -S $linuxRepo -B "$linuxRepo/out/linux-native" -G Ninja -DCMAKE_BUILD_TYPE=Release -DSTREAMLINK_LINUX_STATIC=ON *> (Join-Path $out 'native-configure.log')
 if($LASTEXITCODE){throw 'Linux native configure failed'}
 & wsl -d $Distro -- cmake --build "$linuxRepo/out/linux-native" --parallel 4 *> (Join-Path $out 'native-build.log')
 if($LASTEXITCODE){throw 'Linux native build failed'}
 New-Item -ItemType Directory -Path (Join-Path $runtime 'components')|Out-Null
 Copy-Item -LiteralPath out/linux-native/udp2raw-native -Destination (Join-Path $runtime 'components/udp2raw-native')
 Copy-Item -Path packaging/linux/* -Destination $bundle
 Copy-Item -LiteralPath LICENSE -Destination $bundle
 Copy-Item -LiteralPath transport/udp2raw/LICENSE.md -Destination (Join-Path $bundle 'udp2raw-LICENSE.md')
 New-Item -ItemType Directory -Path (Join-Path $bundle 'licenses')|Out-Null
 Copy-Item -LiteralPath transport/udp2raw/libev/LICENSE -Destination (Join-Path $bundle 'licenses/libev-LICENSE')
 Copy-Item -Path docs/licenses/* -Destination (Join-Path $bundle 'licenses')
 & git archive --format=zip "--output=$bundle/source-$commit.zip" $commit
 if($LASTEXITCODE){throw 'Source archive failed'}
 [ordered]@{version=$Version;sourceCommit=$commit;architecture='linux-x64';runtime='self-contained .NET 10.0.12';native='static Linux raw IPv4';adapter='Linux kernel TUN';business='FakeTCP + HTTP';control='HTTPS';memberAndCoordinatorRoles='independent';web='loopback 47821, private UID-authenticated login';settings='/var/lib/streamlink';status='candidate';validation='See accompanying evidence; physical WAN streaming is not claimed'}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $bundle 'manifest.json') -Encoding utf8NoBOM
 $checks=Get-ChildItem -LiteralPath $bundle -File -Recurse|Sort-Object FullName|ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()+'  '+[IO.Path]::GetRelativePath($bundle,$_.FullName).Replace('\','/') }
 [IO.File]::WriteAllText((Join-Path $bundle 'SHA256SUMS'),($checks -join "`n")+"`n")
 $linuxBundle=(& wsl -d $Distro -- wslpath -a $bundle).Trim()
 & wsl -d $Distro -- chmod 755 "$linuxBundle/install.sh" "$linuxBundle/uninstall.sh" "$linuxBundle/runtime/streamlink" "$linuxBundle/runtime/components/udp2raw-native"
 & wsl -d $Distro -- tar -czf "$linuxBundle.tar.gz" -C ([IO.Path]::GetDirectoryName($linuxBundle).Replace('\','/')) ([IO.Path]::GetFileName($bundle))
 if($LASTEXITCODE){throw 'Linux archive failed'}
 Get-FileHash -LiteralPath "$bundle.tar.gz" | Format-List
} finally {Pop-Location}
