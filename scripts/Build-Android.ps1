param(
    [string]$AndroidSdkDirectory=$env:ANDROID_HOME,
    [string]$JavaSdkDirectory=$env:JAVA_HOME,
    [string]$Version='1.4.0-preview.2',
    [int]$VersionCode=2,
    [string]$OutputDirectory,
    [switch]$DevelopmentSigning
)
$ErrorActionPreference='Stop'
$repoRoot=Split-Path -Parent $PSScriptRoot
if(-not $DevelopmentSigning){throw 'This preview packager requires -DevelopmentSigning. Production signing must use a separately protected release keystore.'}
if($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$' -or $VersionCode -lt 1){throw 'Invalid Android application version'}
foreach($sdkLocation in @($AndroidSdkDirectory,$JavaSdkDirectory)){
    if(-not $sdkLocation -or -not (Test-Path -LiteralPath $sdkLocation -PathType Container)){throw 'Pass existing AndroidSdkDirectory and JavaSdkDirectory paths'}
}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $repoRoot "artifacts/android-$Version"}
$packageRoot=[IO.Path]::GetFullPath($OutputDirectory)
if((Test-Path -LiteralPath $packageRoot) -and (Get-ChildItem -LiteralPath $packageRoot -Force | Select-Object -First 1)){throw 'Use an empty output directory; verified packages are not overwritten'}
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
Push-Location $repoRoot
try{
    & dotnet build src/ConWU.Android/ConWU.Android.csproj -c Release -t:SignAndroidPackage `
        -p:StreamLinkPersonalFeature=true "-p:StreamLinkReleaseVersion=$Version" `
        "-p:ApplicationDisplayVersion=$Version" "-p:ApplicationVersion=$VersionCode" `
        "-p:AndroidSdkDirectory=$AndroidSdkDirectory" "-p:JavaSdkDirectory=$JavaSdkDirectory" `
        -p:AndroidKeyStore=false -v:minimal
    if($LASTEXITCODE -ne 0){throw 'Android build or signing failed'}
    $apk=Join-Path $repoRoot 'src/ConWU.Android/bin/Release/net10.0-android/io.github.mrsgsa.conwu-Signed.apk'
    if(-not (Test-Path -LiteralPath $apk -PathType Leaf)){throw 'Signed APK missing'}
    $name="ConWU-$Version-android-universal.apk"
    $destination=Join-Path $packageRoot $name
    Copy-Item -LiteralPath $apk -Destination $destination
    $hash=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $packageRoot 'SHA256SUMS.txt'),"$hash  $name`n")
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs/Android使用.md') -Destination (Join-Path $packageRoot '使用说明.md')
    $manifest=@{version=$Version;versionCode=$VersionCode;platform='android';minimumApi=26;architectures=@('arm64-v8a','x86_64');signing='Android SDK development key';productionSigned=$false;sha256=$hash;file=$name}
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $packageRoot 'package.json') -Encoding utf8NoBOM
    Write-Output "Preview APK: $destination"
}finally{Pop-Location}
