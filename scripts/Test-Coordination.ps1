param([string]$Port='42869')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
& dotnet build (Join-Path $root 'tests\ConWU.PairingTests') -c Release --nologo -v quiet
if($LASTEXITCODE -ne 0){throw 'Coordination test build failed'}
& dotnet build (Join-Path $root 'tests\ConWU.MeshTests') -c Release --nologo -v quiet
if($LASTEXITCODE -ne 0){throw 'Mesh coordination test build failed'}
$testRoot=Join-Path $root ('out\coordination-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$rsa=[Security.Cryptography.RSA]::Create(2048)
try {
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=StreamLink isolated test',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddDays(1))
    $password=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
    $pfx=Join-Path $testRoot 'test.private.pfx'
    [IO.File]::WriteAllBytes($pfx,$certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,$password))
    $pin=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificate.RawData))
    $start=[Diagnostics.ProcessStartInfo]::new('dotnet')
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.WindowStyle='Hidden'
    $start.ArgumentList.Add((Join-Path $root 'src\ConWU.Discovery\bin\Release\net10.0\ConWU.Discovery.dll'))
    $start.Environment['ASPNETCORE_URLS']="https://127.0.0.1:$Port"
    $start.Environment['ASPNETCORE_Kestrel__Certificates__Default__Path']=$pfx
    $start.Environment['ASPNETCORE_Kestrel__Certificates__Default__Password']=$password
    $start.Environment['STREAMLINK_DISCOVERY_DATA']=(Join-Path $testRoot 'data')
    $start.Environment['STREAMLINK_TRUST_CLOUDFLARE']='0'
    $process=[Diagnostics.Process]::Start($start)
    try {
        Start-Sleep -Seconds 2
        if($process.HasExited){throw 'Isolated coordination backend exited'}
        & dotnet run --project (Join-Path $root 'tests\ConWU.PairingTests') -c Release --no-build -- --server "https://127.0.0.1:$Port/" --pin $pin --exercise-limits
        if($LASTEXITCODE -ne 0){throw 'Isolated HTTPS coordination tests failed'}
        & dotnet run --project (Join-Path $root 'tests\ConWU.MeshTests') -c Release --no-build -- --server "https://127.0.0.1:$Port/" --pin $pin
        if($LASTEXITCODE -ne 0){throw 'Isolated HTTPS mesh tests failed'}
    } finally { if(-not $process.HasExited){$process.Kill($true);$process.WaitForExit()}; $process.Dispose() }
} finally { $rsa.Dispose(); if($certificate){$certificate.Dispose()} }
