#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$LegacyRoot,[Parameter(Mandatory)][string]$RustRoot)
$ErrorActionPreference='Stop'
function Read-Private([string]$Path,[string]$Entropy='') {
    $bytes=[IO.File]::ReadAllBytes($Path)
    try {
        if($Path.EndsWith('.dpapi') -or $Path.EndsWith('.protected')) {
            $plain=[Security.Cryptography.ProtectedData]::Unprotect($bytes,[Text.Encoding]::UTF8.GetBytes($Entropy),[Security.Cryptography.DataProtectionScope]::LocalMachine)
        } elseif($bytes.Length -gt 4 -and [Text.Encoding]::ASCII.GetString($bytes,0,4) -eq 'CWD1') {
            $plain=[Security.Cryptography.ProtectedData]::Unprotect($bytes[4..($bytes.Length-1)],$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
        } else {$plain=$bytes}
        return ([Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json -Depth 100)
    } finally {
        [Array]::Clear($bytes,0,$bytes.Length)
        if($plain){[Array]::Clear($plain,0,$plain.Length)}
    }
}
function Equal-Value($Left,$Right) {
    return ($Left | ConvertTo-Json -Depth 100 -Compress) -ceq ($Right | ConvertTo-Json -Depth 100 -Compress)
}
function Require([bool]$Value,[string]$Label) {if(-not $Value){throw ('迁移核对失败：'+$Label)}}
$device=Read-Private (Join-Path $LegacyRoot 'profile.dpapi') 'StreamLink-profile-v2'
$database=Read-Private (Join-Path $RustRoot 'database.private.json')
Require ($database.nodePrivate -ceq $device.NodeSigningPrivate) '设备签名身份'
Require ($database.deviceName -ceq $device.DeviceName) '设备名称'
Require ($database.deviceSettings.autoStart -eq $device.AutoStart) '开机启动偏好'
Require ($database.deviceSettings.uuTakeover.enabled -eq $device.UuTakeover.Enabled) 'UU功能开关'
$count=0
foreach($folder in Get-ChildItem -LiteralPath (Join-Path $LegacyRoot 'networks') -Directory) {
    $info=Get-Content -LiteralPath (Join-Path $folder.FullName 'network-info.json') -Raw | ConvertFrom-Json
    if($info.Removed -or $info.PendingEnrollment){continue}
    $old=Read-Private (Join-Path $folder.FullName 'profile.dpapi') 'StreamLink-profile-v2'
    if(-not $old.Mesh){continue}
    $matching=@($database.networks | Where-Object id -CEQ $info.Id)
    Require ($matching.Count -eq 1) '网络编号及独立性'
    $network=$matching[0]
    $adapterOwner=if($old.AdapterScope){$old.AdapterScope}elseif($old.Device){$old.Device}else{$old.Mesh.Self.Device}
    Require ($network.legacyAdapter.owner -ceq $adapterOwner -and $network.legacyAdapter.network -ceq $old.Mesh.Pair.Network -and $network.legacyAdapter.slot -eq $old.Mesh.Self.Slot) '虚拟网卡所有权及回退作用域'
    foreach($field in @('OwnerKey','OwnerPrivate','SigningPrivate','ExchangePrivate','IntroducerSlot')) {
        Require (Equal-Value $old.Mesh.$field $network.profile.$field) ('网络身份 '+$field)
    }
    foreach($field in @('Network','Secret','Service','CertificatePin','Mode','TransportKeyPin')) {
        Require (Equal-Value $old.Mesh.Pair.$field $network.profile.Pair.$field) ('配对身份 '+$field)
    }
    foreach($field in @('Slot','Device','SigningKey','ExchangeKey','Signature','VirtualIp')) {
        Require (Equal-Value $old.Mesh.Self.$field $network.profile.Self.$field) ('成员身份 '+$field)
    }
    foreach($field in @('Revision','NextSlot','Signature','Closed','ReservedAddresses')) {
        Require (Equal-Value $old.Mesh.Directory.$field $network.profile.Directory.$field) ('成员目录 '+$field)
    }
    Require ($old.Mesh.Directory.Members.Count -eq $network.profile.Directory.Members.Count) '目录成员数量'
    $wasEnabled=if($null -eq $old.Enabled){$true}else{[bool]$old.Enabled}
    Require ($wasEnabled -eq $network.enabled -and [bool]$old.ConnectionPaused -eq $network.paused) '启动及断开状态'
    Require ($old.PkarrSeed -ceq $network.pkarrSeed -and $old.PkarrSequence -eq $network.pkarrSequence) 'PKARR发布身份及高水位'
    $settings=if($old.SavedNetworkSettings){$old.SavedNetworkSettings}else{$old}
    foreach($field in @('PathSelection','ConnectionSource','ListenPort','SourcePort','StreamFlowLanes','TcpStun','EntryRefreshSeconds','PortControlMapping','RequestedVirtualIp')) {
        Require (Equal-Value $settings.$field $network.settings.$field) ('网络设置 '+$field)
    }
    $count++
}
Require ($count -eq @($database.networks).Count) '网络集合'
[ordered]@{Networks=$count;DeviceIdentityPreserved=$true;PairingAndMemberKeysPreserved=$true;DirectoryAndRevocationPreserved=$true;NetworkSettingsPreserved=$true;PkarrIdentityAndSequencePreserved=$true;ServiceStarted=$false} | ConvertTo-Json
