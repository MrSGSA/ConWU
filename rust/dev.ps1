param([Parameter(ValueFromRemainingArguments=$true)][string[]]$CargoArguments)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path $PSScriptRoot -Parent
$env:CARGO_HOME='D:\Codex\cache\cargo-rust-rewrite'
$env:CARGO_HTTP_PROXY='http://127.0.0.1:7897'
$env:TEMP=Join-Path $projectRoot 'out\tmp'
$env:TMP=$env:TEMP
$null=New-Item -ItemType Directory -Force $env:TEMP
if($IsWindows -or $env:OS -eq 'Windows_NT') {
    $compiler='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207'
    $sdk='C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0'
    $env:PATH="$compiler\bin\Hostx64\x64;"+$env:PATH
    $env:LIB="$compiler\lib\x64;$sdk\um\x64;$sdk\ucrt\x64"
}
Push-Location $projectRoot
try { & cargo @CargoArguments; exit $LASTEXITCODE } finally { Pop-Location }
