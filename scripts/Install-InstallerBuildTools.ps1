#requires -Version 7.0
$ErrorActionPreference='Stop'
Push-Location ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')))
try {
 if(-not(Test-Path -LiteralPath out/wix-tools/wix.exe)){& dotnet tool install wix --version 6.0.2 --tool-path out/wix-tools --allow-roll-forward;if($LASTEXITCODE){throw 'WiX installation failed'}}
 foreach($extension in @('WixToolset.UI.wixext','WixToolset.Util.wixext')){& ./out/wix-tools/wix.exe extension add ($extension+'/6.0.2');if($LASTEXITCODE){throw 'WiX extension installation failed'}}
}finally{Pop-Location}
