param([Parameter(Mandatory=$true)][string]$Probe)
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\resources'))
$ErrorActionPreference = 'Stop'
$manager = Join-Path $root 'claude-guard-manager.exe'
$hostAddress = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1 -ExpandProperty IPAddress
if (-not $hostAddress) { throw 'No host IPv4 address for local non-loopback control' }
function Test-Delivery([string]$Address, [string]$Protocol, [bool]$Allowed) {
    $ip = [Net.IPAddress]::Parse($Address)
    $server = $null
    try {
        if ($Protocol -eq 'tcp') {
            $server = [Net.Sockets.TcpListener]::new($ip, 0)
            $server.Start()
            $port = $server.LocalEndpoint.Port
        } else {
            $server = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new($ip, 0))
            $port = $server.Client.LocalEndPoint.Port
        }
        $result = & $probe $Protocol $Address $port
        $code = $LASTEXITCODE
        if (-not $Allowed) {
            if ($Protocol -eq 'tcp') {
                if ($code -ne 2 -or $result -notcontains 'AccessDenied') { throw "Expected kernel AccessDenied: $Address $Protocol -> $result ($code)" }
            } else {
                # UDP send may succeed while WFP discards the datagram; assert non-delivery.
                $server.Client.ReceiveTimeout = 1500
                $remote = [Net.IPEndPoint]::new($ip, 0)
                $timedOut = $false
                try { $null = $server.Receive([ref]$remote) }
                catch {
                    $cause = $_.Exception.GetBaseException()
                    if ($cause -is [Net.Sockets.SocketException] -and $cause.SocketErrorCode -eq 'TimedOut') { $timedOut = $true } else { throw }
                }
                if (-not $timedOut) { throw 'Blocked UDP payload reached the server' }
            }
        } else {
            if ($code -ne 0) { throw "Expected delivery: $Address $Protocol -> $result ($code)" }
            if ($Protocol -eq 'tcp') {
                if (-not $server.Pending()) { throw 'No accepted data connection' }
                $client = $server.AcceptTcpClient()
                try {
                    $client.ReceiveTimeout = 2000
                    $buffer = New-Object byte[] 64
                    $count = $client.GetStream().Read($buffer, 0, $buffer.Length)
                    $payload = [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
                } finally { $client.Dispose() }
            } else {
                $server.Client.ReceiveTimeout = 2000
                $remote = [Net.IPEndPoint]::new($ip, 0)
                $payload = [Text.Encoding]::ASCII.GetString($server.Receive([ref]$remote))
            }
            if ($payload -ne 'local-service-probe') { throw 'Payload mismatch' }
        }
        Write-Output "PASS $Protocol $Address allowed=$Allowed"
    } finally { if ($server) { if ($Protocol -eq 'tcp') { $server.Stop() } else { $server.Dispose() } } }
}
Test-Delivery $hostAddress 'tcp' $true
Test-Delivery $hostAddress 'udp' $true
try {
    & $manager install $probe local --apply
    if ($LASTEXITCODE) { throw 'Probe filter install failed' }
    & $manager verify $probe local
    if ($LASTEXITCODE) { throw 'Probe filter verification failed' }
    foreach ($address in @('127.0.0.1','127.0.0.2','::1')) {
        foreach ($protocol in @('tcp','udp')) { Test-Delivery $address $protocol $true }
    }
    Test-Delivery $hostAddress 'tcp' $false
    Test-Delivery $hostAddress 'udp' $false
} finally {
    & $manager remove $probe --apply
    if ($LASTEXITCODE) { throw 'Probe filters cleanup failed' }
}
Test-Delivery $hostAddress 'tcp' $true
Test-Delivery $hostAddress 'udp' $true
Write-Output 'LOCAL_SERVICES_KERNEL_PASS: 12 checks; isolated probe filters removed.'
