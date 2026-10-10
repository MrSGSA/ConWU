param([switch]$Test, [string]$Compiler)
$ErrorActionPreference = 'Stop'
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
    & cmake -S . -B out/native -G Ninja "-DCMAKE_CXX_COMPILER=$($Compiler.Replace('\','/'))" -DCMAKE_BUILD_TYPE=Release
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
    & cmake --build out/native --parallel 4
    if ($LASTEXITCODE -ne 0) { throw 'Native build failed.' }
    & .\out\native\udp2raw-native.exe --native-info
    if ($LASTEXITCODE -ne 0) { throw 'Native capability query failed.' }
    if ($Test) {
        & py -3 tests/protocol_loopback.py
        if ($LASTEXITCODE -ne 0) { throw 'Protocol regression tests failed.' }
    }
} finally { Pop-Location }
