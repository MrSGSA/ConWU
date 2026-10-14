param([Parameter(Mandatory)][string]$Output)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Output){throw 'Use a new read-only inventory output; prior evidence is not overwritten'}
# Read-only inventory. Never alter boot policy, trust stores, services or devices.
$observations=[ordered]@{}
function Observe([string]$Name,[scriptblock]$Read) {
    try { $observations[$Name]=[ordered]@{state='Observed';value=(& $Read);error=$null} }
    catch { $observations[$Name]=[ordered]@{state='Unknown';value=$null;error=$_.Exception.Message} }
}
Observe 'os' { Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 8 | Select-Object Caption,Version,BuildNumber,OSArchitecture }
Observe 'identity' {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    [ordered]@{name=$identity.Name;administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);session=[Diagnostics.Process]::GetCurrentProcess().SessionId}
}
Observe 'secureBoot' { Confirm-SecureBootUEFI }
Observe 'deviceGuard' {
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -OperationTimeoutSec 8 |
        Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning,CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus
}
Observe 'bootPolicy' {
    $text=& bcdedit.exe /enum '{current}' 2>&1
    if($LASTEXITCODE -ne 0){throw "BCDEdit read failed: $LASTEXITCODE"}
    [ordered]@{raw=($text -join "`n");scope='Current boot entry read only; missing flags do not imply an observed explicit policy value'}
}
Observe 'streamlinkServices' {
    @(Get-CimInstance Win32_Service -OperationTimeoutSec 8 | Where-Object Name -like '*StreamLink*' | ForEach-Object {
        $binary=if($_.PathName -match '^"([^"]+)"'){$Matches[1]}elseif($_.PathName -match '^(.*?\.exe)(?:\s|$)'){$Matches[1]}else{$null}
        [ordered]@{name=$_.Name;state=$_.State;startMode=$_.StartMode;processId=$_.ProcessId;binary=$binary;account=$_.StartName}
    })
}
Observe 'runningComponents' {
    @(Get-Process -ErrorAction SilentlyContinue | Where-Object ProcessName -match '^(StreamLink\.|StreamLink$|udp2raw|easytier|vmware-vmx|vmwp)' |
        ForEach-Object { [ordered]@{name=$_.ProcessName;pid=$_.Id;path=$_.Path;fileVersion=$_.FileVersion} })
}
Observe 'drivers' {
    @(Get-CimInstance Win32_SystemDriver -OperationTimeoutSec 8 | Where-Object Name -match 'StreamLink|WinDivert|Wintun' |
        Select-Object Name,State,StartMode,PathName)
}
Observe 'selfTunDevices' {
    @(Get-CimInstance Win32_PnPEntity -OperationTimeoutSec 8 | Where-Object { $_.Service -eq 'StreamLinkTun' -or $_.PNPDeviceID -like 'ROOT\STREAMLINKTUN\*' } |
        Select-Object Name,PNPDeviceID,Service,Status,ConfigManagerErrorCode,HardwareID)
}
Observe 'adapters' {
    @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object Name,InterfaceDescription,ifIndex,Status,DriverVersion)
}
Observe 'overlayAddresses' {
    @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -like '10.12[679].*' } |
        Select-Object IPAddress,PrefixLength,InterfaceIndex,InterfaceAlias)
}
Observe 'componentListeners' {
    $componentPids=@(Get-Process -ErrorAction SilentlyContinue | Where-Object ProcessName -match '^(StreamLink\.|StreamLink$|udp2raw|easytier)' | Select-Object -ExpandProperty Id)
    [ordered]@{
        tcp=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $componentPids -contains $_.OwningProcess } | Select-Object LocalAddress,LocalPort,OwningProcess)
        udp=@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $componentPids -contains $_.OwningProcess } | Select-Object LocalAddress,LocalPort,OwningProcess)
    }
}
Observe 'hypervInventory' {
    if(-not(Get-Command Get-VM -ErrorAction SilentlyContinue)){throw 'Hyper-V inventory cmdlet unavailable; no inference about VMware or other labs'}
    @(Get-VM -ErrorAction Stop | Select-Object Name,State,Generation)
}
Observe 'codeSigningCertificateMetadata' {
    @(Get-ChildItem Cert:\LocalMachine\My,Cert:\CurrentUser\My -CodeSigningCert -ErrorAction Stop |
        Select-Object Subject,Issuer,Thumbprint,NotAfter,HasPrivateKey)
}
$result=[ordered]@{schemaVersion=1;scope='personal-feature-v3 read-only host inventory';time=(Get-Date -Format o);computer=$env:COMPUTERNAME;observations=$observations;changesMade=$false;driverLoadAuthorized=$false}
$destination=[IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
[IO.File]::WriteAllText($destination,($result | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
Write-Output "Read-only inventory saved: $destination"
