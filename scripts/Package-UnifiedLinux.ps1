#requires -Version 7.0
param([Parameter(Mandatory)][string]$OutputDirectory,[string]$Version='1.1.0-preview.8',[string]$Distro='ArchLinux')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try {
 if(@(& git status --porcelain).Count){throw 'Freeze the candidate source before packaging'}
 $commit=(& git rev-parse HEAD).Trim()
 $out=[IO.Path]::GetFullPath($OutputDirectory)
 if(Test-Path -LiteralPath $out){throw 'Use a fresh package directory'}
 $bundle=Join-Path $out "ConWU-$Version-linux-x64"
 $runtime=Join-Path $bundle 'runtime'
 New-Item -ItemType Directory -Path $runtime -Force|Out-Null
 & dotnet publish src/StreamLink.Host -c Release -r linux-x64 --self-contained true -p:RuntimeFrameworkVersion=10.0.12 -p:StreamLinkPersonalFeature=true "-p:StreamLinkReleaseVersion=$Version" -o $runtime *> (Join-Path $out 'publish.log')
 if($LASTEXITCODE){throw 'Linux managed publish failed'}
 # Preserve the old service ExecStart and rollback target without a second host.
 $compatCommand=@'
#!/bin/sh
exec "$(dirname -- "$(readlink -f -- "$0")")/conwu" "$@"
'@
 [IO.File]::WriteAllText((Join-Path $runtime 'streamlink'),$compatCommand.Replace("`r`n","`n")+"`n",[Text.UTF8Encoding]::new($false))
 $linuxRepo=(& wsl -d $Distro -- wslpath -a $repo.Replace('\','/')).Trim()
 if($LASTEXITCODE -or -not $linuxRepo.StartsWith('/')){throw 'Cannot resolve repository path in WSL'}
 & wsl -d $Distro -- cmake -S $linuxRepo -B "$linuxRepo/out/linux-native" -G Ninja -DCMAKE_BUILD_TYPE=Release -DSTREAMLINK_LINUX_STATIC=ON *> (Join-Path $out 'native-configure.log')
 if($LASTEXITCODE){throw 'Linux native configure failed'}
 & wsl -d $Distro -- cmake --build "$linuxRepo/out/linux-native" --parallel 4 *> (Join-Path $out 'native-build.log')
 if($LASTEXITCODE){throw 'Linux native build failed'}
 New-Item -ItemType Directory -Path (Join-Path $runtime 'components')|Out-Null
 Copy-Item -LiteralPath out/linux-native/udp2raw-native -Destination (Join-Path $runtime 'components/udp2raw-native')
 Copy-Item -Path packaging/linux/* -Destination $bundle
 # Earlier Windows-produced packages carried a CRLF systemd unit. Accept that
 # exact old format when upgrading, but always ship LF for future operations.
 $unitPath=Join-Path $bundle 'streamlink.service'
 [IO.File]::WriteAllText($unitPath,[IO.File]::ReadAllText($unitPath).Replace("`r`n","`n"),[Text.UTF8Encoding]::new($false))
 Copy-Item -LiteralPath docs/ConWU-入口与配置.md -Destination (Join-Path $bundle '入口与配置.md')
 Copy-Item -LiteralPath docs/aq1/协调服务可靠性与迁移-20261106.md -Destination (Join-Path $bundle '协调服务可靠性与迁移.md')
 $readme=Join-Path $bundle 'README.md'
 $readmeText=[IO.File]::ReadAllText($readme).Replace('../../docs/ConWU-入口与配置.md','入口与配置.md').Replace('../../docs/aq1/协调服务可靠性与迁移-20261106.md','协调服务可靠性与迁移.md')
 [IO.File]::WriteAllText($readme,$readmeText,[Text.UTF8Encoding]::new($false))
 Copy-Item -LiteralPath LICENSE -Destination $bundle
 Copy-Item -LiteralPath transport/udp2raw/LICENSE.md -Destination (Join-Path $bundle 'udp2raw-LICENSE.md')
 New-Item -ItemType Directory -Path (Join-Path $bundle 'licenses')|Out-Null
 Copy-Item -LiteralPath transport/udp2raw/libev/LICENSE -Destination (Join-Path $bundle 'licenses/libev-LICENSE')
 Copy-Item -Path docs/licenses/* -Destination (Join-Path $bundle 'licenses')
 & git archive --format=zip "--output=$bundle/source-$commit.zip" $commit
 if($LASTEXITCODE){throw 'Source archive failed'}
 [ordered]@{version=$Version;sourceCommit=$commit;architecture='linux-x64';runtime='self-contained .NET 10.0.12';native='static Linux raw IPv4';adapter='one Linux kernel TUN per network';topology='one host and one guest per network; multiple networks per device';business='FakeTCP + HTTP; no automatic UDP fallback or relay';wireCompatibility='pairwise directory and shared-entry frame require matching new peers';control='per-configuration HTTPS coordination or approved direct invitation';memberAndCoordinatorRoles='independent';autoGuestSettings=1;pkarrDiscovery='autonomous signed endpoint discovery; initial approved invitation; HTTPS gateways; no synchronized NAT exchange';discoveryPolicyVersion=1;web='loopback 47821; opt-in password-authenticated /admin/ on the coordination domain or separate loopback 47823';settings='/var/lib/streamlink; protected device profile and networks/<configuration-id>';status='candidate';validation='See accompanying evidence; physical WAN streaming is not claimed'}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $bundle 'manifest.json') -Encoding utf8NoBOM
 $checks=Get-ChildItem -LiteralPath $bundle -File -Recurse|Sort-Object FullName|ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()+'  '+[IO.Path]::GetRelativePath($bundle,$_.FullName).Replace('\','/') }
 [IO.File]::WriteAllText((Join-Path $bundle 'SHA256SUMS'),($checks -join "`n")+"`n")
 $linuxBundle=(& wsl -d $Distro -- wslpath -a $bundle.Replace('\','/')).Trim()
 if($LASTEXITCODE -or -not $linuxBundle.StartsWith('/')){throw 'Cannot resolve package path in WSL'}
 & wsl -d $Distro -- chmod 755 "$linuxBundle/install.sh" "$linuxBundle/uninstall.sh" "$linuxBundle/fresh-install.sh" "$linuxBundle/runtime/conwu" "$linuxBundle/runtime/streamlink" "$linuxBundle/runtime/components/udp2raw-native"
 & wsl -d $Distro -- tar -czf "$linuxBundle.tar.gz" -C ([IO.Path]::GetDirectoryName($linuxBundle).Replace('\','/')) ([IO.Path]::GetFileName($bundle))
 if($LASTEXITCODE){throw 'Linux archive failed'}
 Get-FileHash -LiteralPath "$bundle.tar.gz" | Format-List
} finally {Pop-Location}
