#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OldMsi,[Parameter(Mandatory)][string]$NewMsi,
      [Parameter(Mandatory)][string]$ValidationInstance,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
function ProductApp([string]$Folder){$current=Join-Path $Folder 'ConWU.exe';if(Test-Path -LiteralPath $current){return $current};return (Join-Path $Folder 'ConWU.exe')}
$id=[guid]::Empty
if(-not [guid]::TryParseExact($ValidationInstance,'N',[ref]$id) -or $id -eq [guid]::Empty){throw 'Isolated validation GUID required'}
$OldMsi=[IO.Path]::GetFullPath($OldMsi);$NewMsi=[IO.Path]::GetFullPath($NewMsi)
foreach($package in @($OldMsi,$NewMsi)){
 if((Get-Content -LiteralPath ($package+'.json') -Raw|ConvertFrom-Json).validationInstance -cne $ValidationInstance){throw 'Both packages must own this exact isolated instance'}
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Fresh evidence directory required'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$name='StreamLink-Validation-'+$ValidationInstance
$runtime=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('StreamLink-Validation/'+$ValidationInstance+'/msi/app')
$data=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('StreamLink-Validation/'+$ValidationInstance)
$rows=[Collections.Generic.List[object]]::new();$failure=$null;$installed=$null
function Daily { @(Get-CimInstance Win32_Service -Filter "Name='StreamLink' OR Name='StreamLink-PersonalFeature'"|Sort-Object Name|Select-Object Name,State,ProcessId,PathName)|ConvertTo-Json -Compress }
$dailyBefore=Daily
function Msi([string]$operation,[string]$package,[string]$label){
 $process=Start-Process msiexec.exe -ArgumentList @($operation,('"'+$package+'"'),'/qn','/norestart','/l*v',('"'+(Join-Path $OutputDirectory ($label+'.log'))+'"')) -WindowStyle Hidden -PassThru
 if(-not $process.WaitForExit(900000)){throw ('Owned MSI still running: '+$process.Id)}
 $rows.Add(@{name=$label;exit=$process.ExitCode})
 if($process.ExitCode -ne 0){throw ($label+' MSI exit '+$process.ExitCode)}
 if((Daily) -cne $dailyBefore){throw 'Daily service changed during isolated upgrade'}
}
function App([string]$argument){
 $process=Start-Process (ProductApp $runtime) -ArgumentList @('--validation-instance',$ValidationInstance,$argument) -WindowStyle Hidden -PassThru
 if(-not $process.WaitForExit(30000) -or $process.ExitCode){throw ('Owned acceptance operation failed: '+$argument)}
}
function Call([hashtable]$body){
 $pipe=[IO.Pipes.NamedPipeClientStream]::new('.',$name+'-Control-v2',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
 $deadline=[Threading.CancellationTokenSource]::new(12000)
 function ReadExact([int]$count){$buffer=[byte[]]::new($count);$offset=0;while($offset -lt $count){$read=$pipe.ReadAsync($buffer,$offset,$count-$offset,$deadline.Token).GetAwaiter().GetResult();if($read -eq 0){throw 'Owned control pipe ended'};$offset+=$read};return ,$buffer}
 try{
  $pipe.Connect(5000);$payload=[Text.Encoding]::UTF8.GetBytes(($body|ConvertTo-Json -Depth 48 -Compress))
  $pipe.Write([BitConverter]::GetBytes([int]$payload.Length));$pipe.Write($payload);$pipe.Flush()
  $length=[BitConverter]::ToInt32((ReadExact 4),0);if($length -lt 1 -or $length -gt 65536){throw 'Owned reply exceeds wire bound'}
  $reply=[Text.Encoding]::UTF8.GetString((ReadExact $length))|ConvertFrom-Json;$pipe.WriteByte(1);$pipe.Flush()
  if(-not $reply.Ok){throw 'Owned control operation rejected'}
  return $reply
 }finally{$pipe.Dispose();$deadline.Dispose()}
}
function Digest($value){[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 48 -Compress))))}
function Snapshot {
 $reply=Call @{Command='status'};$p=$reply.Profile;$cfg=$p.SavedNetworkSettings
 if($null -eq $cfg){
  $service=$p.CoordinationService;$pin=$p.CoordinationPin;$direct=[bool]$p.DirectMode
  if($p.Mesh){$direct=[bool]$p.Mesh.Pair.Direct;if(-not $direct){$service=$p.Mesh.Pair.Service;$pin=$p.Mesh.Pair.CertificatePin}}
  $cfg=@{Service=$service;CertificatePin=$pin;ManualEndpoint=$p.ManualEndpoint;PathSelection=$p.PathSelection;ConnectionSource=$p.ConnectionSource;DirectMode=$direct;ExistingEntries=$p.ExistingEntries;EntryRefreshSeconds=$p.EntryRefreshSeconds;RequestedVirtualIp=$p.RequestedVirtualIp;TcpStun=$p.TcpStun;UdpStun=$p.UdpStun;ListenPort=$p.ListenPort;SourcePort=$p.SourcePort;AllowManualQualityRequests=$p.AllowManualQualityRequests}
 }
 $settings=[ordered]@{deviceName=$p.DeviceName;logLevel=$p.LogLevel;autoStart=$p.AutoStart;service=$cfg.Service;pin=$cfg.CertificatePin;manual=$cfg.ManualEndpoint;protocol=$cfg.PathSelection;source=$cfg.ConnectionSource;direct=$cfg.DirectMode;
  entries=@($cfg.ExistingEntries|ForEach-Object{[ordered]@{slot=$_.PeerSlot;source=$_.Source}});refresh=$cfg.EntryRefreshSeconds;requestedIp=$cfg.RequestedVirtualIp;tcp=@($cfg.TcpStun);udp=@($cfg.UdpStun);listen=$cfg.ListenPort;sourcePort=$cfg.SourcePort;quality=$cfg.AllowManualQualityRequests}
 # Compare persisted credentials and signed membership, not newly introduced
 # computed convenience properties such as IsDecentralized / CanManage.
 $m=$p.Mesh;$identity=[ordered]@{device=$p.Device;pair=$p.Pair;mesh=if($m){[ordered]@{pair=$m.Pair;ownerKey=$m.OwnerKey;ownerPrivate=$m.OwnerPrivate;self=$m.Self;signing=$m.SigningPrivate;exchange=$m.ExchangePrivate;directory=$m.Directory;introducer=if($null -eq $m.IntroducerSlot){1}else{$m.IntroducerSlot}}}else{$null}}
 [ordered]@{settingsSha256=(Digest $settings);identitySha256=(Digest $identity);uiSidSha256=(Digest (Get-Content -LiteralPath (Join-Path $data 'ui-user.sid') -Raw));serviceStart=(Get-ItemPropertyValue ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name) -Name Start);productVersion=(Get-Item (Join-Path $runtime 'ConWU.Service.dll')).VersionInfo.ProductVersion;serviceHash=(Get-FileHash (Join-Path $runtime 'ConWU.Service.dll')).Hash}
}
try{
 Msi '/i' $OldMsi 'install-old';$installed=$OldMsi
 App '--acceptance-create-network'
 $profile=(Call @{Command='status'}).Profile
 $profile.DeviceName='Upgrade Preserved Device';$profile.LogLevel='debug';$profile.ConnectionSource='existing'
 $profile.CoordinationService='https://example.com/';$profile.EntryRefreshSeconds=1800;$profile.RequestedVirtualIp='10.42.43.9'
 $profile.ListenPort=45220;$profile.SourcePort=45221;$profile.AllowManualQualityRequests=$true
 $profile.ExistingEntries=@(@{PeerSlot=0;Source='203.0.113.42:45220'},@{PeerSlot=-1;Source='https://entries.example.com/streamlink?token=fixture-only'},@{PeerSlot=8;Source='203.0.113.88:45220'})
 $profile.TcpStun=@('stun.example.com:3478','stun-alt.example.com:3478');$profile.UdpStun=@('stun.example.net:3478')
 $null=Call @{Command='save';Profile=$profile}
 App '--acceptance-disable-startup'
 $before=Snapshot;$before|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'before.json') -Encoding utf8NoBOM
 Msi '/i' $NewMsi 'upgrade-new';$installed=$NewMsi
 $after=Snapshot;$after|ConvertTo-Json|Set-Content (Join-Path $OutputDirectory 'after.json') -Encoding utf8NoBOM
 foreach($field in @('settingsSha256','identitySha256','uiSidSha256','serviceStart')){
  $same=$before[$field] -ceq $after[$field];$rows.Add(@{name=('upgrade preserves '+$field);status=if($same){'Pass'}else{'Fail'}})
  if(-not $same){throw ('Upgrade changed '+$field)}
 }
 if($before.serviceHash -eq $after.serviceHash -or $before.productVersion -eq $after.productVersion){throw 'Upgrade did not install the new frozen service payload'}
 $rows.Add(@{name='actual old-to-new payload changed while user settings and identity remained stable';status='Pass'})
}catch{$failure=$_.Exception.Message}finally{
 # A 3010 result is a failed no-reboot acceptance check, but the new product
 # may already be fully installed. Query both owned products rather than
 # attempting to remove the superseded MSI and leaving the new instance behind.
 $installer=New-Object -ComObject WindowsInstaller.Installer
 foreach($owned in @($NewMsi,$OldMsi)|Select-Object -Unique){
  try{
   $database=$installer.OpenDatabase($owned,0);$view=$database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductCode''');$view.Execute();$record=$view.Fetch();$product=$record.StringData(1);$view.Close()
   if($installer.ProductState($product) -eq 5){Msi '/x' $owned 'uninstall-owned'}
  }catch{$failure=if($failure){$failure+'; cleanup: '+$_.Exception.Message}else{$_.Exception.Message}}
 }
 if((Daily) -cne $dailyBefore){$failure='Daily service changed during isolated upgrade test'}
}
$result=[ordered]@{status=if($null -eq $failure){'Pass'}else{'Fail'};error=$failure;validationInstance=$ValidationInstance;oldVersion=$before.productVersion;newVersion=$after.productVersion;steps=$rows.ToArray();scope='Actual isolated previous-release-to-candidate Windows Installer upgrade; complete settings-page value fingerprint, network identity and UI account; no daily networking changed'}
$result|ConvertTo-Json -Depth 7|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8NoBOM
$result|ConvertTo-Json -Depth 7
if($failure){throw $failure}
