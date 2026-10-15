#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$BundleRoot,[Parameter(Mandatory)][string]$OutputPath,[string]$ValidationInstance,[string]$MsiVersion,[ValidateSet('high','mszip')][string]$Compression='high')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'));$BundleRoot=[IO.Path]::GetFullPath($BundleRoot);$OutputPath=[IO.Path]::GetFullPath($OutputPath)
$manifest=Get-Content -LiteralPath (Join-Path $BundleRoot 'app/manifest.json') -Raw|ConvertFrom-Json
if(-not $MsiVersion){if($manifest.version -notmatch '^1\.0\.0-aq1-personal\.([1-9][0-9]*)$'){throw 'Personal version required'};$MsiVersion='1.0.'+$Matches[1]}
if($MsiVersion -notmatch '^1\.0\.([1-9][0-9]{0,4})$' -or [int]$Matches[1] -gt 65535){throw 'Invalid MSI version'}
$wix=Join-Path $repo 'out/wix-tools/wix.exe';if(-not(Test-Path -LiteralPath $wix)){throw 'Install pinned WiX 6.0.2 in out/wix-tools first (build dependency only)'}
$service='StreamLink-PersonalFeature';$productName='StreamLink';$upgrade='AD076018-A9B8-47F5-B098-97479A363416';$directory='<Directory Id="INSTALLFOLDER" Name="StreamLink" />';$validationArgs='';$registryKey='Software\StreamLink\Installation'
if($ValidationInstance){
 $guid=[guid]::Empty;if(-not[guid]::TryParseExact($ValidationInstance,'N',[ref]$guid) -or $guid -eq [guid]::Empty){throw 'Canonical isolated validation GUID required'}
 $service='StreamLink-Validation-'+$ValidationInstance;$productName='StreamLink Validation '+$ValidationInstance.Substring(0,8);$upgrade=$guid.ToString('D');$validationArgs='--validation-instance '+$ValidationInstance+' ';$registryKey='Software\StreamLink\Validation\'+$ValidationInstance
 $directory='<Directory Id="ValidationParent" Name="StreamLink-Validation"><Directory Id="ValidationId" Name="'+$ValidationInstance+'"><Directory Id="INSTALLFOLDER" Name="msi" /></Directory></Directory>'
}
$work=Join-Path (Split-Path -Parent $OutputPath) ('msi-build-'+[IO.Path]::GetFileNameWithoutExtension($OutputPath));New-Item -ItemType Directory -Path $work -Force|Out-Null
$file=Join-Path $work 'Package.wxs'
$xml=[xml]@'
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs" xmlns:ui="http://wixtoolset.org/schemas/v4/wxs/ui">
 <Package Name="StreamLink" Manufacturer="StreamLink" Version="1.0.3" UpgradeCode="AD076018-A9B8-47F5-B098-97479A363416" Language="2052" Scope="perMachine" InstallerVersion="500">
  <MajorUpgrade Schedule="afterInstallExecute" DowngradeErrorMessage="已安装较新的 StreamLink，请使用相同或更新版本的安装包。" />
  <MediaTemplate EmbedCab="yes" CompressionLevel="high" />
  <Property Id="ARPPRODUCTICON" Value="AppIcon" />
  <Property Id="MSIRESTARTMANAGERCONTROL" Value="DisableShutdown" />
  <Property Id="REBOOT" Value="ReallySuppress" />
  <Property Id="REINSTALLMODE" Value="amus" />
  <Property Id="STREAMLINK_TRANSACTION" Secure="yes" />
  <Property Id="WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT" Value="启动 StreamLink" />
  <Property Id="WIXUI_EXITDIALOGOPTIONALCHECKBOX" Value="1" />
  <Icon Id="AppIcon" SourceFile="ICON" />
  <Binary Id="InstallerActions" SourceFile="ACTIONS" />
  <StandardDirectory Id="ProgramFiles64Folder" />
  <StandardDirectory Id="ProgramMenuFolder"><Directory Id="ApplicationMenuFolder" Name="StreamLink" /></StandardDirectory>
  <StandardDirectory Id="DesktopFolder" />
  <Feature Id="MainFeature" Title="StreamLink" Level="1" />
  <CustomAction Id="SetArpLocation" Property="ARPINSTALLLOCATION" Value="[INSTALLFOLDER]" />
  <CustomAction Id="NewTransaction" BinaryRef="InstallerActions" DllEntry="NewTransaction" Execute="immediate" Return="check" />
  <CustomAction Id="SetPrepare" Property="PrepareUpgrade" Value="CAD" />
  <CustomAction Id="PrepareUpgrade" BinaryRef="InstallerActions" DllEntry="PrepareUpgrade" Execute="deferred" Impersonate="no" Return="check" />
  <CustomAction Id="SetRollback" Property="RollbackUpgrade" Value="CAD" />
  <CustomAction Id="RollbackUpgrade" BinaryRef="InstallerActions" DllEntry="RollbackUpgrade" Execute="rollback" Impersonate="no" Return="check" />
  <CustomAction Id="SetCommit" Property="CommitUpgrade" Value="CAD" />
  <CustomAction Id="CommitUpgrade" BinaryRef="InstallerActions" DllEntry="CommitUpgrade" Execute="commit" Impersonate="no" Return="ignore" />
  <CustomAction Id="SetClose" Property="CloseClients" Value="CAD" />
  <CustomAction Id="CloseClients" BinaryRef="InstallerActions" DllEntry="CloseClients" Execute="deferred" Impersonate="no" Return="check" />
  <CustomAction Id="RollbackAuthorization" FileRef="ServiceUiExe" ExeCommand="ARGS--msi-rollback &quot;[STREAMLINK_TRANSACTION]&quot;" Execute="rollback" Impersonate="no" Return="check" />
  <CustomAction Id="ConfigureAuthorization" FileRef="ServiceUiExe" ExeCommand="ARGS--msi-configure &quot;[UserSID]&quot; &quot;[STREAMLINK_TRANSACTION]&quot;" Execute="deferred" Impersonate="no" Return="check" />
  <CustomAction Id="CommitAuthorization" FileRef="ServiceUiExe" ExeCommand="ARGS--msi-commit &quot;[STREAMLINK_TRANSACTION]&quot;" Execute="commit" Impersonate="no" Return="ignore" />
  <CustomAction Id="VerifyReady" FileRef="ServiceUiExe" ExeCommand="ARGS--msi-ready" Execute="deferred" Impersonate="no" Return="check" />
  <CustomAction Id="LaunchApp" FileRef="LauncherExe" ExeCommand="ARGS" Execute="immediate" Impersonate="yes" Return="asyncNoWait" />
  <InstallExecuteSequence>
   <Custom Action="SetArpLocation" After="CostFinalize" />
   <Custom Action="NewTransaction" After="InstallInitialize" Condition="NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="SetRollback" Before="RollbackUpgrade" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="RollbackUpgrade" Before="SetPrepare" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="SetPrepare" Before="PrepareUpgrade" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="PrepareUpgrade" Before="StopServices" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="SetClose" Before="CloseClients" Condition="REMOVE ~= &quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="CloseClients" Before="StopServices" Condition="REMOVE ~= &quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="RollbackAuthorization" After="InstallServices" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="ConfigureAuthorization" After="RollbackAuthorization" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="VerifyReady" After="StartServices" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="CommitAuthorization" After="VerifyReady" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="SetCommit" After="CommitAuthorization" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
   <Custom Action="CommitUpgrade" After="SetCommit" Condition="NOT (REMOVE ~= &quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE" />
  </InstallExecuteSequence>
  <ui:WixUI Id="WixUI_Minimal" />
  <WixVariable Id="WixUILicenseRtf" Value="LICENSE" />
  <UI><Publish Dialog="ExitDialog" Control="Finish" Event="DoAction" Value="LaunchApp" Condition="WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 AND NOT Installed" /></UI>
 </Package>
</Wix>
'@
$ns='http://wixtoolset.org/schemas/v4/wxs';$manager=[Xml.XmlNamespaceManager]::new($xml.NameTable);$manager.AddNamespace('w',$ns)
function Node([string]$name,[hashtable]$attributes){$n=$xml.CreateElement($name,$ns);foreach($entry in $attributes.GetEnumerator()){if([string]$entry.Value -ne ''){$n.SetAttribute($entry.Key,[string]$entry.Value)}};return ,$n}
$package=$xml.DocumentElement.FirstChild;$package.SetAttribute('Name',$productName);$package.SetAttribute('Version',$MsiVersion);$package.SetAttribute('UpgradeCode',$upgrade)
$xml.SelectSingleNode('//w:MediaTemplate',$manager).SetAttribute('CompressionLevel',$Compression)
$programs=$xml.SelectSingleNode('//w:StandardDirectory[@Id="ProgramFiles64Folder"]',$manager)
$fragment=$xml.CreateDocumentFragment();$fragment.InnerXml=$directory.Replace('<Directory ','<Directory xmlns="'+$ns+'" ');$programs.AppendChild($fragment)|Out-Null
$install=$xml.SelectSingleNode('//w:Directory[@Id="INSTALLFOLDER"]',$manager);$feature=$xml.SelectSingleNode('//w:Feature',$manager)
$dirs=@{''=$install}
$all=@(Get-ChildItem -LiteralPath $BundleRoot -File -Recurse|Sort-Object FullName)
foreach($item in $all){
 $relative=[IO.Path]::GetRelativePath($BundleRoot,$item.FullName).Replace('\','/');$parent=[IO.Path]::GetDirectoryName($relative).Replace('\','/')
 if(-not $dirs.ContainsKey($parent)){
  $at='';$node=$install
  foreach($part in $parent.Split('/',[StringSplitOptions]::RemoveEmptyEntries)){$at=if($at){$at+'/'+$part}else{$part};if(-not $dirs.ContainsKey($at)){$id='D'+[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($at))).Substring(0,20);$child=Node 'Directory' @{Id=$id;Name=$part};$node.AppendChild($child)|Out-Null;$dirs[$at]=$child};$node=$dirs[$at]}
 }
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($relative))).Substring(0,24);$componentId='C'+$hash;$fileId='F'+$hash
 if($relative -eq 'StreamLink.exe'){$fileId='LauncherExe'}elseif($relative -eq 'app/StreamLink.exe'){$fileId='ServiceUiExe'}elseif($relative -eq 'app/StreamLink.Service.exe'){$fileId='ServiceExe'}
 $component=Node 'Component' @{Id=$componentId;Guid='*';Bitness='always64'};$fileNode=Node 'File' @{Id=$fileId;Source=$item.FullName;KeyPath='yes'};$component.AppendChild($fileNode)|Out-Null
 if($fileId -eq 'ServiceExe'){
  $serviceNode=Node 'ServiceInstall' @{Id='InstallNetworkService';Name=$service;DisplayName='StreamLink Personal Network';Type='ownProcess';Start='auto';ErrorControl='normal';Account='LocalSystem';Vital='yes';Arguments=$validationArgs.Trim()};$component.AppendChild($serviceNode)|Out-Null
  $component.AppendChild((Node 'ServiceControl' @{Id='ControlNetworkService';Name=$service;Start='install';Stop='both';Remove='uninstall';Wait='yes'}))|Out-Null
 }
 if($fileId -eq 'LauncherExe'){
  foreach($value in @(@('ProductCode','[ProductCode]'),@('InstallLocation','[INSTALLFOLDER]'))){$component.AppendChild((Node 'RegistryValue' @{Root='HKLM';Key=$registryKey;Name=$value[0];Type='string';Value=$value[1]}))|Out-Null}
  $component.AppendChild((Node 'Shortcut' @{Id='StartMenuApp';Directory='ApplicationMenuFolder';Name=$productName;WorkingDirectory='INSTALLFOLDER';Arguments=$validationArgs.Trim();Icon='AppIcon';Advertise='no'}))|Out-Null
  $component.AppendChild((Node 'Shortcut' @{Id='DesktopApp';Directory='DesktopFolder';Name=$productName;WorkingDirectory='INSTALLFOLDER';Arguments=$validationArgs.Trim();Icon='AppIcon';Advertise='no'}))|Out-Null
  $component.AppendChild((Node 'Shortcut' @{Id='StartMenuUninstall';Directory='ApplicationMenuFolder';Name='卸载 '+$productName;Target='[SystemFolder]msiexec.exe';Arguments='/x [ProductCode]';Icon='AppIcon';Advertise='no'}))|Out-Null
  $component.AppendChild((Node 'RemoveFolder' @{Id='RemoveApplicationMenu';Directory='ApplicationMenuFolder';On='uninstall'}))|Out-Null
 }
 $dirs[$parent].AppendChild($component)|Out-Null;$feature.AppendChild((Node 'ComponentRef' @{Id=$componentId}))|Out-Null
}
foreach($node in $xml.SelectNodes('//*')){foreach($attr in @($node.Attributes)){
 if($attr.Value -eq 'ICON'){$attr.Value=Join-Path $repo 'src/StreamLink.App/Assets/streamlink.ico'}elseif($attr.Value -eq 'ACTIONS'){$attr.Value=Join-Path $repo 'out/native/streamlink-installer-actions.dll'}elseif($attr.Value -eq 'CAD'){$attr.Value='[INSTALLFOLDER]|'+$service+'|[STREAMLINK_TRANSACTION]'}elseif($attr.Value.StartsWith('ARGS')){$attr.Value=$validationArgs+$attr.Value.Substring(4)}elseif($attr.Value -eq 'LICENSE'){$attr.Value=Join-Path $work 'License.rtf'}
}}
$notice="StreamLink 个人试用候选`n安装与更新会关闭原 StreamLink 界面，仅重启个人后台；保留配对、设备配置及旧版服务。卸载保留个人配置和共享驱动。`nStreamLink 使用 MIT 许可证。第三方组件分别遵守 app/licenses 和 app/sources 中的许可证及源码说明。`n`n"+(Get-Content -LiteralPath (Join-Path $repo 'LICENSE') -Raw)
$rtf=[Text.StringBuilder]::new('{\rtf1\ansi\deff0 {\fonttbl {\f0 Microsoft YaHei;}}\f0\fs20 ')
foreach($character in $notice.ToCharArray()){
 $code=[int]$character
 if($character -eq "`n"){[void]$rtf.Append('\par ')}elseif($character -eq "`r"){continue}elseif($code -gt 127){$signed=if($code -gt 32767){$code-65536}else{$code};[void]$rtf.Append('\u'+[string]$signed+'?')}elseif($character -in '\','{','}'){[void]$rtf.Append('\'+$character)}else{[void]$rtf.Append($character)}
}
[void]$rtf.Append('}');$rtf.ToString()|Set-Content (Join-Path $work 'License.rtf') -Encoding ascii
$xml.Save($file)
& $wix build -arch x64 -culture zh-cn -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -o $OutputPath $file > (Join-Path $work 'wix-build.log') 2>&1
if($LASTEXITCODE){throw ('MSI build failed: '+(Join-Path $work 'wix-build.log'))}
[ordered]@{version=$manifest.version;msiVersion=$MsiVersion;sourceCommit=$manifest.sourceCommit;service=$service;validationInstance=$ValidationInstance;upgradeCode=$upgrade;publisherSignature='UnsignedCandidate';sha256=(Get-FileHash -LiteralPath $OutputPath).Hash;files=$all.Count}|ConvertTo-Json|Set-Content ($OutputPath+'.json') -Encoding utf8NoBOM
Write-Output $OutputPath
