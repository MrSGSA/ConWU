param([switch]$Test, [string]$Compiler,[string]$FileVersion='1.0.0.0')
$ErrorActionPreference = 'Stop'
if($FileVersion -notmatch '^\d+\.\d+\.\d+\.\d+$'){throw 'Four-part numeric file version required'}
$root = Split-Path -Parent $PSScriptRoot
if (-not $Compiler) {
    $found = Get-Command g++.exe -ErrorAction SilentlyContinue
    if ($found) { $Compiler = $found.Source }
    elseif (Test-Path -LiteralPath 'C:\Program Files\mingw64\bin\g++.exe') {
        $Compiler = 'C:\Program Files\mingw64\bin\g++.exe'
    } else { throw 'Install the MinGW-w64 x64 development compiler or pass -Compiler.' }
}
Push-Location $root
try {
    & cmake -S . -B out/native -G Ninja "-DCMAKE_CXX_COMPILER=$($Compiler.Replace('\','/'))" -DCMAKE_BUILD_TYPE=Release "-DSTREAMLINK_PACKAGE_FILE_VERSION=$FileVersion"
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
    & cmake --build out/native --parallel 4
    if ($LASTEXITCODE -ne 0) { throw 'Native build failed.' }
    & ./scripts/Build-Phantun.ps1 -Test:$Test
    if ($LASTEXITCODE -ne 0) { throw 'Phantun build failed.' }
    & .\out\native\udp2raw-native.exe --native-info
    if ($LASTEXITCODE -ne 0) { throw 'Native capability query failed.' }
    if ($Test) {
        & py -3 tests/protocol_loopback.py
        if ($LASTEXITCODE -ne 0) { throw 'Protocol regression tests failed.' }
    }
} finally { Pop-Location }
