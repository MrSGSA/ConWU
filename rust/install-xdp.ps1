[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RuntimeDirectory,
    [string]$ProbeExecutable,
    [switch]$RequireMimic
)

$ErrorActionPreference = 'Stop'
$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$runtime = [IO.Path]::GetFullPath($RuntimeDirectory)
if (-not $ProbeExecutable) { $ProbeExecutable = Join-Path (Split-Path $runtime -Parent) 'conwu-raw.exe' }
if (-not (Test-Path -LiteralPath $ProbeExecutable -PathType Leaf)) { throw 'XDP 实际队列检查组件缺失。' }
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

# A running driver and an enabled binding can still leave AF_XDP unusable.
# Probe the actual rings without installing a rule or redirecting any traffic.
function Test-XdpQueue([uint32]$InterfaceIndex) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $ProbeExecutable
    $start.Arguments = '--xdp-probe ' + $InterfaceIndex
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        $null = $process.Start()
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
            $process.WaitForExit()
            return @{Ready=$false;Reason='等待 XDP 网卡队列检查超时'}
        }
        $line = @($output.Result -split "`r?`n" | Where-Object { $_.StartsWith('CONWU_RAW ') }) | Select-Object -Last 1
        if ($line) {
            $reply = $line.Substring(10) | ConvertFrom-Json
            if ($process.ExitCode -eq 0 -and $reply.event -eq 'xdp-probe' -and
                $reply.abi -eq 1 -and $reply.ready -eq $true -and
                $reply.interfaceIndex -eq $InterfaceIndex -and $reply.redirectionAttached -eq $false) {
                return @{Ready=$true;Queues=$reply.receiveQueues}
            }
            return @{Ready=$false;Reason=[string]$reply.reason}
        }
        return @{Ready=$false;Reason=('XDP 队列检查未返回结果：' + $errors.Result.Trim())}
    } finally {
        $process.Dispose()
    }
}
$physical = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
$primary = @(Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSObject.Properties.Name -contains 'IPAddress' } | Select-Object -ExpandProperty InterfaceIndex)
$preferred = @($physical | Where-Object { $primary -contains $_.ifIndex })
if ($preferred.Count) { $physical = $preferred }
$ready = 0
$failures = @()
foreach ($adapter in $physical) {
    $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_xdp -ErrorAction SilentlyContinue
    if (-not $binding -or -not $binding.Enabled) {
        $failures += ($adapter.Name + '：未启用 XDP 绑定')
        continue
    }
    $check = Test-XdpQueue $adapter.ifIndex
    # Repairs are limited to the installer maintenance window. Never reset a
    # binding while another ConWU raw process is still using the driver.
    $retryable = $check.Reason -match 'bind Generic.*0x80070(017|015|48f|4d5)'
    if (-not $check.Ready -and $retryable -and -not @(Get-Process -Name 'conwu-raw' -ErrorAction SilentlyContinue).Count) {
        Write-Output ('正在修复 XDP 网卡绑定：' + $adapter.Name)
        try {
            Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_xdp -Confirm:$false -ErrorAction Stop | Out-Null
        } finally {
            Enable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_xdp -Confirm:$false -ErrorAction Stop | Out-Null
        }
        for ($attempt = 0; $attempt -lt 3; $attempt++) {
            $check = Test-XdpQueue $adapter.ifIndex
            if ($check.Ready) { break }
            Start-Sleep -Milliseconds 500
        }
    }
    if ($check.Ready) {
        $ready++
        Write-Output ('XDP 实际收发队列已就绪：' + $adapter.Name + '，接收队列 ' + $check.Queues)
    } else {
        $failures += ($adapter.Name + '：' + $check.Reason)
    }
}
if ($failures.Count) {
    $message = 'XDP 网卡队列尚未就绪：' + ($failures -join '；')
    if ($RequireMimic -and -not $ready) { throw $message }
    Write-Warning $message
}
if (-not $physical.Count) { Write-Output '当前没有已连接的物理网卡，联网后再启用 Mimic。' }
Write-Output ('Microsoft XDP 已安装并运行；已启用绑定：' + @(
    Get-NetAdapterBinding -ComponentID ms_xdp -AllBindings -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled }
).Count)
