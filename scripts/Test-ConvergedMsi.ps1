#requires -Version 7.0
param([Parameter(Mandatory)][string]$Msi,[Parameter(Mandatory)][string]$UpgradeMsi,[Parameter(Mandatory)][string]$ValidationInstance,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$instanceGuid=[guid]::Empty
if(-not [guid]::TryParseExact($ValidationInstance,'N',[ref]$instanceGuid)-or $instanceGuid -eq [guid]::Empty){throw 'Canonical isolated instance required'}
foreach($package in @($Msi,$UpgradeMsi)){if((Get-Content -LiteralPath ($package+'.json') -Raw|ConvertFrom-Json).validationInstance -cne $ValidationInstance){throw 'Only matching isolated validation MSIs are allowed'}}
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$service='StreamLink-Validation-'+$ValidationInstance
$data=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('StreamLink-Validation/'+$ValidationInstance)
$install=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('StreamLink-Validation/'+$ValidationInstance+'/msi')
if(Get-Service -Name $service -ErrorAction SilentlyContinue){throw 'Use a new isolated validation instance'}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$rows=[Collections.Generic.List[object]]::new();$daily=Get-CimInstance Win32_Service -Filter "Name='StreamLink-PersonalFeature' OR Name='StreamLink'"|Select-Object Name,State,ProcessId,PathName|ConvertTo-Json -Compress
function Check([bool]$condition,[string]$name){$rows.Add([ordered]@{name=$name;passed=$condition});if(-not $condition){throw $name}}
function ExecuteMsi([string]$verb,[string]$package,[string]$label){
 $process=Start-Process msiexec.exe -ArgumentList @($verb,('"'+[IO.Path]::GetFullPath($package)+'"'),'/qn','/norestart','/l*v',('"'+(Join-Path $OutputDirectory ($label+'.log'))+'"')) -WindowStyle Hidden -PassThru
 if(-not $process.WaitForExit(180000)){throw "Owned MSI did not finish: $($process.Id)"};Check ($process.ExitCode -eq 0) "$label exit"
 $current=Get-CimInstance Win32_Service -Filter "Name='StreamLink-PersonalFeature' OR Name='StreamLink'"|Select-Object Name,State,ProcessId,PathName|ConvertTo-Json -Compress
 Check ($current -eq $daily) "$label preserves daily services"
}
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
function PrivateJson([string]$relative,[string]$entropy){
 $raw=[IO.File]::ReadAllBytes((Join-Path $data $relative))
 $plain=[Security.Cryptography.ProtectedData]::Unprotect($raw,[Text.Encoding]::UTF8.GetBytes($entropy),[Security.Cryptography.DataProtectionScope]::LocalMachine)
 return [Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json -Depth 64
}
function ConfigurationFingerprint {
 $profile=PrivateJson 'profile.dpapi' 'StreamLink-profile-v2'
 $catalog=PrivateJson 'connection-configurations.protected' 'ConWU-private-document-v1'
 $networks=@(Get-ChildItem -LiteralPath (Join-Path $data 'networks') -Filter network-info.json -File -Recurse|Sort-Object FullName|ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json})
 $networkProfiles=@(Get-ChildItem -LiteralPath (Join-Path $data 'networks') -Filter profile.dpapi -File -Recurse|Sort-Object FullName|ForEach-Object { $relative=[IO.Path]::GetRelativePath($data,$_.FullName);$value=PrivateJson $relative 'StreamLink-profile-v2';[ordered]@{device=$value.Device;scope=$value.AdapterScope;mesh=$value.Mesh;enabled=$value.Enabled;settings=$value.SavedNetworkSettings;created=$value.NetworkCreatedHere;established=$value.NetworkEstablishedAt} })
 $content=[ordered]@{device=$profile.Device;identity=$profile.NodeSigningPrivate;name=$profile.DeviceName;level=$profile.LogLevel;startup=$profile.AutoStart;coordinator=$profile.Coordinator;catalog=$catalog;references=$networks;networks=$networkProfiles}|ConvertTo-Json -Depth 64 -Compress
 return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($content)))
}
$installed=$false
try{
 ExecuteMsi '/i' $Msi 'install';$installed=$true
 Check ((Get-Service -Name $service).Status -eq 'Running') 'isolated service runs'
 Stop-Service -Name $service
 & dotnet (Join-Path $repo 'tests/StreamLink.MeshConnectionTests/bin/Release/net10.0-windows/StreamLink.MeshConnectionTests.dll') --seed-configuration-upgrade $ValidationInstance > (Join-Path $OutputDirectory 'seed.log')
 if($LASTEXITCODE){throw 'Configuration fixture failed'}
 Start-Service -Name $service
 $before=ConfigurationFingerprint
 ExecuteMsi '/fomus' $Msi 'repair'
 Check ((ConfigurationFingerprint) -eq $before) 'repair preserves shared configuration, network references, identity and device settings'
 ExecuteMsi '/i' $UpgradeMsi 'major-upgrade'
 Check ((Get-Service -Name $service).Status -eq 'Running') 'upgraded service runs'
 Check ((ConfigurationFingerprint) -eq $before) 'major upgrade preserves shared configuration and per-network references'
 ExecuteMsi '/x' $UpgradeMsi 'uninstall';$installed=$false
 Check (-not (Get-Service -Name $service -ErrorAction SilentlyContinue)) 'uninstall removes only the validation service'
 Check ((ConfigurationFingerprint) -eq $before) 'uninstall retains settings and network credentials for later reinstall'
 Check (-not (Test-Path -LiteralPath (Join-Path $install 'app/ConWU.exe'))) 'uninstall removes owned application files'
 [ordered]@{status='Pass';scope='isolated MSI install, repair, major upgrade and uninstall; no business network';validationInstance=$ValidationInstance;checks=$rows}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding utf8
 Write-Output 'PASS 隔离 MSI 安装、修复、升级保留配置和卸载'
}catch{
 [ordered]@{status='Fail';error=$_.Exception.Message;validationInstance=$ValidationInstance;checks=$rows}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding utf8
 throw
}finally{if($installed){try{ExecuteMsi '/x' $UpgradeMsi 'cleanup-upgrade'}catch{};if(Get-Service -Name $service -ErrorAction SilentlyContinue){try{ExecuteMsi '/x' $Msi 'cleanup-original'}catch{}}}}
