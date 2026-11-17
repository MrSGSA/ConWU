[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RuntimeDirectory)

$ErrorActionPreference = 'Stop'
$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$runtime = [IO.Path]::GetFullPath($RuntimeDirectory)
$setup = Join-Path $runtime 'xdp-setup.ps1'
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
    throw '随包的 Microsoft XDP 安装文件不完整。'
}

# netcfg -q may return 0 even when it prints "not installed". Check actual
# driver registration and bindings instead; this also catches partial installs.
$driver = Get-Service -Name xdp -ErrorAction SilentlyContinue
$bindings = @(Get-NetAdapterBinding -ComponentID ms_xdp -AllBindings -ErrorAction SilentlyContinue)
if (-not $driver -or $bindings.Count -eq 0) {
    & $setup -Install xdp -ErrorAction Stop
}
$driver = Get-Service -Name xdp -ErrorAction SilentlyContinue
if (-not $driver) { throw 'Microsoft XDP 驱动未能注册，请检查系统驱动安装日志。' }
if ($driver.Status -ne 'Running') { Start-Service -Name xdp -ErrorAction Stop }

$bindings = @(Get-NetAdapterBinding -ComponentID ms_xdp -AllBindings -ErrorAction SilentlyContinue)
$active = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name)
foreach ($binding in $bindings) {
    if (-not $binding.Enabled -and $active -contains $binding.Name) {
        $binding | Enable-NetAdapterBinding -Confirm:$false -ErrorAction Stop | Out-Null
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $env:WINDIR 'System32/drivers/xdp.sys'))) {
    throw 'Microsoft XDP 系统驱动文件缺失。'
}
$driver = Get-Service -Name xdp
if ($driver.Status -ne 'Running') { throw 'Microsoft XDP 驱动未运行。' }
Write-Output ('Microsoft XDP 已安装并运行；已启用绑定：' + @(
    Get-NetAdapterBinding -ComponentID ms_xdp -AllBindings -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled }
).Count)
