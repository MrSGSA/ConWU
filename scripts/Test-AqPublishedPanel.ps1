param([Parameter(Mandatory)][string]$Bundle,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$Bundle=[IO.Path]::GetFullPath($Bundle);$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Fresh evidence required'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$scope=[guid]::NewGuid().ToString('N');$service='StreamLink-Validation-'+$scope;$failure='';$after=$null
function Snapshot {Get-CimInstance Win32_Service -Filter "Name='StreamLink'"|Select-Object Name,State,ProcessId,PathName|ConvertTo-Json -Compress}
function App([string[]]$Arguments){
 $argsText=(@('--validation-instance',$scope)+$Arguments|ForEach-Object{'"'+$_+'"'}) -join ' '
 $p=Start-Process -FilePath (Join-Path $Bundle 'StreamLink.exe') -ArgumentList $argsText -WindowStyle Hidden -PassThru
 if(-not $p.WaitForExit(90000)){$p.Kill();throw 'Owned installer timeout'}
 if($p.ExitCode){throw "Installer/status exit $($p.ExitCode)"}
}
$before=Snapshot
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 App @('--install','--ui-user-account',$identity.Name)
 & node (Join-Path $PSScriptRoot 'Test-AqPublishedPanel.cjs') $Bundle $scope $OutputDirectory > (Join-Path $OutputDirectory 'browser.log') 2>&1
 if($LASTEXITCODE){throw 'Published panel test failed'}
 App @('--acceptance-status',(Join-Path $OutputDirectory 'service-after-browser.json'))
 $state=Get-Content (Join-Path $OutputDirectory 'service-after-browser.json') -Raw|ConvertFrom-Json
 if(-not $state.ServiceReady -or $state.NetworkEnabled){throw 'Service state changed unexpectedly'}
 App @('--uninstall')
}catch{$failure=$_.Exception.ToString()}
finally {
 try {
  if(Get-Service -Name $service -ErrorAction SilentlyContinue){
   & sc.exe stop $service > (Join-Path $OutputDirectory 'cleanup-stop.txt')
   $controller=[ServiceProcess.ServiceController]::new($service);try{$controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(55))}finally{$controller.Dispose()}
   & sc.exe delete $service > (Join-Path $OutputDirectory 'cleanup-delete.txt');if($LASTEXITCODE){throw 'Owned service deletion failed'}
  }
  foreach($base in @([Environment]::GetFolderPath('CommonApplicationData'),[Environment]::GetFolderPath('ProgramFiles'))){
   $target=[IO.Path]::GetFullPath((Join-Path $base "StreamLink-Validation/$scope"))
   if((Split-Path -Leaf $target) -ne $scope -or (Split-Path -Leaf (Split-Path -Parent $target)) -ne 'StreamLink-Validation'){throw 'Containment check failed'}
   if(Test-Path -LiteralPath $target){if((Get-Item -LiteralPath $target).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked target refused'};Remove-Item -LiteralPath $target -Recurse -Force}
  }
  $after=Snapshot;if($before -ne $after){throw 'Stable service changed'}
 }catch{$failure+='; cleanup: '+$_.Exception.Message}
 $manifest=Get-Content (Join-Path $Bundle 'manifest.json') -Raw|ConvertFrom-Json
 [ordered]@{status=$(if($failure){'Fail'}else{'Pass'});sourceCommit=$manifest.sourceCommit;failure=$failure;service=$service;liveServiceUnchanged=($before -eq $after);ordinaryUserVerified=$false;networkEnabled=$false}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $OutputDirectory 'result.json') -Encoding utf8NoBOM
}
if($failure){throw $failure}
