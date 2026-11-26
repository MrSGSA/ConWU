param(
    [Parameter(Mandatory)][string]$MoonlightSource,
    [Parameter(Mandatory)][string]$MoonlightBuild,
    [Parameter(Mandatory)][string]$Sdl3Runtime,
    [Parameter(Mandatory)][string]$QtBin,
    [Parameter(Mandatory)][string]$Output
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$source = (Resolve-Path -LiteralPath $MoonlightSource).Path
$build = (Resolve-Path -LiteralPath $MoonlightBuild).Path
$qt = (Resolve-Path -LiteralPath $QtBin).Path
$sdl3 = (Resolve-Path -LiteralPath $Sdl3Runtime).Path
if (!(Test-Path -LiteralPath $sdl3 -PathType Leaf) -or [IO.Path]::GetFileName($sdl3) -ine 'SDL3.dll') {
    throw 'Sdl3Runtime 必须指向应用 ConWU 焦点补丁后构建的 SDL3.dll'
}
$destination = [IO.Path]::GetFullPath($Output)
$outRoot = [IO.Path]::Combine($root, 'out')
if (!$destination.StartsWith($outRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $destination)) {
    throw 'Projection 运行目录必须是 out 内的新目录'
}
$parent = (Resolve-Path -LiteralPath (Split-Path -Parent $destination)).Path
while ($parent -ne $root) {
    $item = Get-Item -LiteralPath $parent -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Projection 输出路径含重解析点 $parent"
    }
    $parent = Split-Path -Parent $parent
}

$env:TEMP = Join-Path $outRoot 'tmp'
$env:TMP = $env:TEMP
$null = New-Item -ItemType Directory -Path $env:TEMP -Force
$null = New-Item -ItemType Directory -Path $destination
$player = Join-Path $destination 'ConWU-Moonlight.exe'
Copy-Item -LiteralPath (Join-Path $build 'app/release/Moonlight.exe') -Destination $player
Copy-Item -LiteralPath (Join-Path $build 'AntiHooking/release/AntiHooking.dll') -Destination $destination
$libraries = Join-Path $source 'libs/windows/lib/x64'
$dependencies = @(
    'avcodec-63.dll', 'avutil-61.dll', 'swscale-10.dll', 'dav1d.dll',
    'libcrypto-3-x64.dll', 'libssl-3-x64.dll', 'SDL2.dll', 'SDL2_ttf.dll',
    'opus.dll', 'libplacebo-374.dll', 'discord-rpc.dll'
)
foreach ($file in $dependencies) {
    Copy-Item -LiteralPath (Join-Path $libraries $file) -Destination $destination
}
Copy-Item -LiteralPath $sdl3 -Destination $destination

& (Join-Path $qt 'windeployqt.exe') --verbose 0 --release --no-translations --no-compiler-runtime --qmldir (Join-Path $source 'app') $player
if ($LASTEXITCODE -ne 0) {
    throw "Qt 运行库部署失败 $LASTEXITCODE"
}
foreach ($file in 'platforms/qwindows.dll','Qt6Core.dll','Qt6Quick.dll','Qt6Network.dll') {
    if (!(Test-Path -LiteralPath (Join-Path $destination $file) -PathType Leaf)) {
        throw "Projection 运行库缺少 $file"
    }
}
$destination
