param([Parameter(Mandatory=$true)][string]$Probe)
$ErrorActionPreference = 'Stop'
$manager = Join-Path $env:ProgramFiles 'Clash Verge Auto Chain\resources\claude-guard-manager.exe'
$version = Join-Path $env:APPDATA ('Claude\claude-code\0.0.0-auto-chain-test-' + [Guid]::NewGuid().ToString('N'))
$binary = Join-Path $version 'claude.exe'
$statusPath = Join-Path $env:ProgramData 'ClashVergeAutoChainProtection\auto-chain-guard-status.json'
$listener = $null
try {
    New-Item -ItemType Directory -Path $version | Out-Null
    Copy-Item -LiteralPath $Probe -Destination $binary
    $deadline = (Get-Date).AddSeconds(100)
    do {
        Start-Sleep -Seconds 2
        $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
        $found = @($status.Results | Where-Object { $_.Path -eq $binary -and $_.Verified })
    } until ($found.Count -or (Get-Date) -gt $deadline)
    if (-not $found.Count) { throw 'Scheduled discovery did not protect the new path within 100 seconds.' }
    & $manager verify $binary local
    if ($LASTEXITCODE) { throw 'New version WFP rules were not verified.' }
    $address = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.AddressState -eq 'Preferred' -and $_.IPAddress -notmatch '^(127\.|169\.254\.)'
    } | Select-Object -First 1 -ExpandProperty IPAddress
    $result = & $binary tcp $address 9
    if ($LASTEXITCODE -ne 2 -or $result -notcontains 'AccessDenied') { throw 'New version direct traffic was not blocked.' }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    & $binary tcp 127.0.0.1 $listener.LocalEndpoint.Port
    if ($LASTEXITCODE -or -not $listener.Pending()) { throw 'New version cannot access a local service.' }
    $client = $listener.AcceptTcpClient()
    $client.Dispose()
    $task = Get-ScheduledTask -TaskName 'Clash Verge Auto Chain Claude Guard'
    if ($task.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) { throw 'Discovery task is not running as SYSTEM.' }
    'PASS: scheduled SYSTEM task discovered a new version; direct TCP blocked, loopback allowed.'
} finally {
    if ($listener) { $listener.Stop() }
    if (Test-Path -LiteralPath $binary) {
        & $manager remove $binary --apply
        if ($LASTEXITCODE) { throw 'Test filter cleanup failed; test executable retained.' }
        Remove-Item -LiteralPath $binary
        Remove-Item -LiteralPath $version
    }
}
