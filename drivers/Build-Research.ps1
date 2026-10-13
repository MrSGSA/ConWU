param([string]$WdkRoot='out/driver-deps/wdk-x64/c',[string]$SdkRoot='C:/Program Files (x86)/Windows Kits/10',[string]$KitVersion='10.0.26100.0',[string]$Output='out/driver-research')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $repo
$wdk=[IO.Path]::GetFullPath($WdkRoot);$destination=[IO.Path]::GetFullPath($Output)
if(-not $destination.StartsWith($repo+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Research outputs must stay inside this repository'}
$vs=& 'C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe' -latest -products '*' -property installationPath
$msvc=Get-ChildItem (Join-Path $vs 'VC/Tools/MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
if(-not $msvc){throw 'MSVC x64 Build Tools unavailable'}
$bin=Join-Path $msvc.FullName 'bin/Hostx64/x64';$kitInclude=Join-Path $wdk "Include/$KitVersion";$sdkInclude=Join-Path $SdkRoot "Include/$KitVersion";$kernelLib=Join-Path $wdk "Lib/$KitVersion/km/x64"
if(-not (Test-Path -LiteralPath (Join-Path $kitInclude 'km/ndis.h'))){throw 'Matching WDK kernel headers unavailable; do not substitute a user-mode SDK'}
$tun=New-Item -ItemType Directory -Path (Join-Path $destination 'tun') -Force
$kernelArgs=@('/nologo','/kernel','/GS','/guard:cf','/W4','/WX','/wd4324','/TC','/Zl','/D_AMD64_','/DAMD64','/D_WIN64','/DWINNT','/DNDIS630_MINIPORT=1','/DNDIS_MINIPORT_DRIVER=1','/D_WIN32_WINNT=0x0A00','/DNTDDI_VERSION=0x0A00000C','/I',"$kitInclude/km",'/I',"$kitInclude/km/crt",'/I',"$sdkInclude/shared",'/I',"$($msvc.FullName)/include",'/c','drivers/StreamLink.Tun/driver.c',"/Fo$($tun.FullName)/driver.obj")
& "$bin/cl.exe" @kernelArgs
if($LASTEXITCODE){throw "Kernel compilation failed: $LASTEXITCODE"}
& "$bin/link.exe" /nologo /driver /subsystem:native /entry:GsDriverEntry /nodefaultlib /machine:x64 /incremental:no /dynamicbase /nxcompat /guard:cf "/out:$($tun.FullName)/StreamLinkTun.sys" "$($tun.FullName)/driver.obj" "/libpath:$kernelLib" ndis.lib ntoskrnl.lib hal.lib wmilib.lib BufferOverflowFastFailK.lib
if($LASTEXITCODE){throw "Kernel link failed: $LASTEXITCODE"}
Copy-Item -LiteralPath drivers/StreamLink.Tun/StreamLinkTun.inf -Destination $tun.FullName
& "$bin/cl.exe" /nologo /LD /MT /EHsc /GS /guard:cf /W4 /WX /I "$($msvc.FullName)/include" /I "$sdkInclude/shared" /I "$sdkInclude/um" /I "$sdkInclude/ucrt" transport/tun-native/user_api.cpp "/Fo$($tun.FullName)/user_api.obj" /link "/out:$($tun.FullName)/streamlink-tun-research.dll" "/implib:$($tun.FullName)/user_api.lib" "/libpath:$($msvc.FullName)/lib/x64" "/libpath:$SdkRoot/Lib/$KitVersion/um/x64" "/libpath:$SdkRoot/Lib/$KitVersion/ucrt/x64" kernel32.lib iphlpapi.lib ws2_32.lib /dynamicbase /nxcompat /guard:cf
if($LASTEXITCODE){throw "Research user API build failed: $LASTEXITCODE"}
$capture=New-Item -ItemType Directory -Path (Join-Path $destination 'capture') -Force
$captureArgs=$kernelArgs|Where-Object {$_ -ne 'drivers/StreamLink.Tun/driver.c' -and $_ -notlike '/Fo*'}
& "$bin/cl.exe" @captureArgs 'drivers/StreamLink.CapturePoC/driver.c' "/Fo$($capture.FullName)/capture.obj"
if($LASTEXITCODE){throw "Capture research compilation failed: $LASTEXITCODE"}
& "$bin/link.exe" /nologo /driver /subsystem:native /entry:GsDriverEntry /nodefaultlib /machine:x64 /incremental:no /dynamicbase /nxcompat /guard:cf "/out:$($capture.FullName)/StreamLinkCaptureResearch.sys" "$($capture.FullName)/capture.obj" "/libpath:$kernelLib" fwpkclnt.lib wdmsec.lib ntoskrnl.lib hal.lib BufferOverflowFastFailK.lib
if($LASTEXITCODE){throw "Capture research link failed: $LASTEXITCODE"}
Write-Output 'Research compilation only. No signing, installation, network changes or default-driver substitution performed.'
Get-FileHash -LiteralPath "$($tun.FullName)/StreamLinkTun.sys","$($tun.FullName)/streamlink-tun-research.dll" -Algorithm SHA256
