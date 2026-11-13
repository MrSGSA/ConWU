#requires -Version 7.0
param([ValidateSet('Windows','Linux')][string]$Platform='Windows',[string]$Cargo,[switch]$Test,[switch]$Offline)
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$extension=if([OperatingSystem]::IsWindows()){'.exe'}else{''}
if(-not $Cargo){
 $found=Get-Command ('cargo'+$extension) -ErrorAction SilentlyContinue
 if($found){$Cargo=$found.Source}else{$Cargo=Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe'}
}
if(-not(Test-Path -LiteralPath $Cargo)){throw 'Install Rust 1.85 or newer, or pass -Cargo.'}
$rustc=Join-Path (Split-Path -Parent $Cargo) ('rustc'+$extension)
if(-not(Test-Path -LiteralPath $rustc)){throw 'The selected Cargo needs its matching rustc executable.'}
$target=if($Platform -eq 'Linux'){'x86_64-unknown-linux-musl'}else{'x86_64-pc-windows-msvc'}
$prior=@{};foreach($name in @('CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER')){$prior[$name]=[Environment]::GetEnvironmentVariable($name)}
Push-Location -LiteralPath (Join-Path $repo 'transport/phantun')
try{
 $sysroot=(& $rustc --print sysroot).Trim();if($LASTEXITCODE){throw 'Cannot query the Rust sysroot.'}
 if(-not(Test-Path -LiteralPath (Join-Path $sysroot "lib/rustlib/$target/lib"))){throw "Install the Rust target first: rustup target add $target"}
 [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR',(Join-Path $repo 'out/phantun-native'),'Process')
 [Environment]::SetEnvironmentVariable('CARGO_BUILD_JOBS','4','Process')
 if($Platform -eq 'Linux'){
  $hostLine=& $rustc -vV|Where-Object {$_ -like 'host: *'}
  $hostTarget=$hostLine.Substring(6).Trim()
  $linker=Join-Path $sysroot "lib/rustlib/$hostTarget/bin/rust-lld$extension"
  if(-not(Test-Path -LiteralPath $linker)){throw 'The Rust LLVM linker is missing.'}
  [Environment]::SetEnvironmentVariable('CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER',$linker,'Process')
 }
 $arguments=@('build','--release','--locked','--target',$target);if($Offline){$arguments+='--offline'}
 & $Cargo @arguments;if($LASTEXITCODE){throw 'Phantun component build failed.'}
 if($Test){
  $arguments=@('test','--workspace','--locked');if($Offline){$arguments+='--offline'}
  & $Cargo @arguments;if($LASTEXITCODE){throw 'Phantun protocol regressions failed.'}
 }
 $file=Join-Path $repo ('out/phantun-native/'+$target+'/release/conwu-phantun'+$(if($Platform -eq 'Windows'){'.exe'}else{''}))
 if(-not(Test-Path -LiteralPath $file)){throw 'Phantun output is missing.'}
 $raw=Join-Path (Split-Path -Parent $file) ('conwu-raw'+$(if($Platform -eq 'Windows'){'.exe'}else{''}))
 if(-not(Test-Path -LiteralPath $raw)){throw 'Optional Mimic/TCPRAW output is missing.'}
 Write-Output $file
}finally{
 Pop-Location
 foreach($name in $prior.Keys){
  if($null -eq $prior[$name]){Remove-Item -LiteralPath ('Env:'+$name) -ErrorAction SilentlyContinue}
  else{[Environment]::SetEnvironmentVariable($name,$prior[$name],'Process')}
 }
}
