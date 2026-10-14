param([Parameter(Mandatory)][string]$Configuration)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$Configuration=[IO.Path]::GetFullPath($Configuration)
$folder=Split-Path -Parent $Configuration
$node=Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
$rule='StreamLink-NativeRouter-Poc-'+[guid]::NewGuid().ToString('N')
$ports=@([string]$node.ReflectorPort,[string]$node.ControlPort,('{0}-{1}' -f ($node.BasePort+1),($node.BasePort+$node.Rounds)))
try {
 New-NetFirewallRule -Name $rule -DisplayName $rule -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $node.LocalIp -RemoteAddress $node.PeerIp -LocalPort $ports | Out-Null
 & (Join-Path $folder 'StreamLink.EndpointPoc.exe') --router-network $Configuration
 $code=$LASTEXITCODE
 if($code -ne 0){throw "Isolated native Router failed: $code"}
} finally {
 Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
 # These generated per-run credentials are separate from every user profile.
 Remove-Item -LiteralPath $Configuration -Force -ErrorAction SilentlyContinue
}
