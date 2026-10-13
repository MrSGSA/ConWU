param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$Version,[Parameter(Mandatory)][string]$Commit,[Parameter(Mandatory)][string[]]$Assets,[switch]$Native)
$ErrorActionPreference='Stop'
$packages=@{};$folders=@{}
foreach($path in $Assets){
    $assetsJson=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    foreach($folder in $assetsJson.packageFolders.PSObject.Properties.Name){$folders[$folder]=$true}
    foreach($entry in $assetsJson.libraries.PSObject.Properties){if($entry.Value.type -eq 'package'){$packages[$entry.Name]=$entry.Value}}
}
$licenses=New-Item -ItemType Directory -Path (Join-Path $Directory 'licenses/nuget') -Force
$rows=[Collections.Generic.List[object]]::new()
foreach($name in ($packages.Keys|Sort-Object)){
    $parts=$name.Split('/');$id='SPDXRef-Package-'+($name -replace '[^A-Za-z0-9.-]','-');$declared='NOASSERTION'
    foreach($folder in $folders.Keys){
        $installed=Join-Path $folder $packages[$name].path
        if(-not(Test-Path -LiteralPath $installed)){continue}
        $target=New-Item -ItemType Directory -Path (Join-Path $licenses.FullName ($name -replace '/','-')) -Force
        foreach($notice in Get-ChildItem -LiteralPath $installed -File|Where-Object Name -match '^(LICENSE|COPYING|THIRD[-.]PARTY[-.]NOTICES|NOTICE)(\..*)?$'){
            Copy-Item -LiteralPath $notice.FullName -Destination $target.FullName
        }
        $nuspec=Get-ChildItem -LiteralPath $installed -File -Filter '*.nuspec'|Select-Object -First 1
        if($nuspec){[xml]$xml=Get-Content -LiteralPath $nuspec.FullName -Raw;$license=$xml.SelectSingleNode('//*[local-name()="license"]');if($license -and $license.type -eq 'expression'){$declared=$license.InnerText}}
        break
    }
    $rows.Add([ordered]@{SPDXID=$id;name=$parts[0];versionInfo=$parts[1];downloadLocation="https://www.nuget.org/packages/$($parts[0])/$($parts[1])";filesAnalyzed=$false;licenseConcluded='NOASSERTION';licenseDeclared=$declared;copyrightText='NOASSERTION';externalRefs=@(@{referenceCategory='PACKAGE-MANAGER';referenceType='purl';referenceLocator="pkg:nuget/$($parts[0])@$($parts[1])"})})
}
if($Native){
    foreach($item in @(
        @('WinDivert','2.2.2','https://github.com/basil00/WinDivert','LGPL-3.0-only'),
        @('Wintun','0.14.1','https://www.wintun.net/','NOASSERTION'),
        @('udp2raw-http-StreamLink',$Commit,'NOASSERTION','NOASSERTION'),
        @('PolarSSL-vendored-crypto','1.3.x-vendored','NOASSERTION','GPL-2.0-or-later'),
        @('libev','vendored','NOASSERTION','BSD-2-Clause OR GPL-2.0-or-later'),
        @('MinGW-GCC-runtime','build-toolchain','NOASSERTION','GPL-3.0-or-later WITH GCC-exception-3.1'),
        @('winpthreads','build-toolchain','NOASSERTION','NOASSERTION')
    )){$rows.Add([ordered]@{SPDXID='SPDXRef-Native-'+$item[0];name=$item[0];versionInfo=$item[1];downloadLocation=$item[2];filesAnalyzed=$false;licenseConcluded='NOASSERTION';licenseDeclared=$item[3];copyrightText='NOASSERTION'})}
}
$root=[ordered]@{SPDXID='SPDXRef-StreamLink';name='StreamLink';versionInfo=$Version;downloadLocation='NOASSERTION';filesAnalyzed=$false;licenseConcluded='NOASSERTION';licenseDeclared='MIT';copyrightText='Copyright (c) 2026 StreamLink contributors';sourceInfo="Exact committed source: $Commit; native crypto keeps its original GPL notices, not covered by the top-level MIT declaration."}
$fileRows=[Collections.Generic.List[object]]::new();$relationships=[Collections.Generic.List[object]]::new()
$relationships.Add(@{spdxElementId='SPDXRef-DOCUMENT';relationshipType='DESCRIBES';relatedSpdxElement='SPDXRef-StreamLink'})
foreach($item in $rows){$relationships.Add(@{spdxElementId='SPDXRef-StreamLink';relationshipType='DEPENDS_ON';relatedSpdxElement=$item.SPDXID})}
$index=0
foreach($file in Get-ChildItem -LiteralPath $Directory -File -Recurse|Sort-Object FullName){
    if($file.Name -in @('sbom.spdx.json','manifest.json')){continue}
    $id='SPDXRef-File-'+(++$index);$relative=[IO.Path]::GetRelativePath($Directory,$file.FullName).Replace('\','/')
    $fileRows.Add(@{SPDXID=$id;fileName='./'+$relative;checksums=@(@{algorithm='SHA256';checksumValue=(Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant()});licenseConcluded='NOASSERTION';licenseInfoInFiles=@('NOASSERTION');copyrightText='NOASSERTION'})
    $relationships.Add(@{spdxElementId='SPDXRef-StreamLink';relationshipType='CONTAINS';relatedSpdxElement=$id})
}
$now=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
[ordered]@{spdxVersion='SPDX-2.3';dataLicense='CC0-1.0';SPDXID='SPDXRef-DOCUMENT';name="StreamLink-$Version";documentNamespace="https://github.com/MrSGSA/StreamLink/sbom/$Commit/$([guid]::NewGuid())";creationInfo=@{created=$now;creators=@('Tool: StreamLink Package-RC')};packages=@($root)+$rows.ToArray();files=$fileRows.ToArray();relationships=$relationships.ToArray();annotations=@(@{annotationType='OTHER';annotator='Tool: StreamLink Package-RC';annotationDate=$now;comment='Package identities and license expressions from the actual post-publish assets/nuspec; file SHA256 for integrity. SBOM and manifest exclude themselves to avoid circular hashes. Compiler runtime version/provenance and full legal compatibility remain independently reviewed; no publisher signature claim.'})}|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $Directory 'sbom.spdx.json') -Encoding utf8
