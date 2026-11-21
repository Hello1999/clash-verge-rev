<#
.SYNOPSIS
    Idempotent Windows system-level hardening for Anthropic / Claude egress and DNS protection.
    Supports -Action Audit (read-only), -Action Apply (backs up first, requires Administrator),
    and -Action Restore -BackupDirectory <path> (requires Administrator).
#>
param(
    [ValidateSet('Audit', 'Apply', 'Restore')]
    [string]$Action = 'Audit',
    [string]$BackupDirectory = '',
    [string]$UserHome = $env:USERPROFILE
)

$ErrorActionPreference = 'Stop'

$FirewallGroup = 'Claude Guard Hardening v3'
$NrptCommentTag = 'ClaudeGuardHardeningV3'
$NrptTargetDns = '198.18.0.2'
$BackupRoot = 'C:\ProgramData\ClashVergeAutoChainProtection\hardening-backups'

$AnthropicSuffixes = @(
    'claude.ai',
    'claude.com',
    'anthropic.com',
    'claudeusercontent.com',
    'anthropicusercontent.com',
    'anthropic.ai',
    'anthropic.team',
    'ant.dev',
    'antspace.dev',
    'chatbotclaude.com',
    'clau.de',
    'claude.app',
    'claude.dev',
    'claude.new',
    'claude.site',
    'claudeacademy.com',
    'claudemcpclient.com',
    'claudemcpcontent.com',
    'claudepages.dev',
    'claudestudio.com'
)

$AnthropicExactDomains = @(
    'servd-anthropic-website.b-cdn.net',
    'http-intake.logs.us5.datadoghq.com',
    'browser-intake-us5-datadoghq.com',
    'o1158394.ingest.us.sentry.io',
    'collector-pxvl48pwoc.px-cloud.net',
    'lupk8zyo.messenger.intercom-chat.com'
)

$AnthropicIPv4Cidrs = @(
    '160.79.104.0/21',
    '153.61.224.0/22',
    '153.61.208.0/20'
)

$AnthropicIPv6Cidrs = @(
    '2607:6bc0::/48'
)

# Non-overlapping remote IP ranges that block everything except loopback (127.0.0.0/8 and ::1).
$NonLoopbackIPv4 = @('0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255')
$NonLoopbackIPv6 = @('::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')

$BrowserPolicyKeys = @(
    'HKLM:\Software\Policies\Google\Chrome',
    'HKLM:\Software\Policies\Microsoft\Edge'
)

$ExpectedBrowserPolicies = [ordered]@{
    BuiltInDnsClientEnabled  = @{ Kind = 'DWord';  Value = 0 }
    DnsOverHttpsMode         = @{ Kind = 'String'; Value = 'off' }
    NetworkPredictionOptions = @{ Kind = 'DWord';  Value = 2 }
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-ExpectedNrptNamespaces {
    $ns = [Collections.Generic.List[string]]::new()
    foreach ($d in $AnthropicSuffixes) {
        # Include both exact apex domain and leading-dot suffix so both root and subdomains match reliably.
        $ns.Add($d)
        $ns.Add(".$d")
    }
    foreach ($h in $AnthropicExactDomains) {
        $ns.Add($h)
    }
    return @($ns)
}

function Get-ProtectedExecutables {
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Chrome & Edge (leave Firefox and other normal software untouched)
    foreach ($candidate in @(
        'C:\Program Files\Google\Chrome\Application\chrome.exe',
        'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
        (Join-Path $UserHome 'AppData\Local\Google\Chrome\Application\chrome.exe'),
        'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
        'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
        (Join-Path $UserHome 'AppData\Local\Microsoft\Edge\Application\msedge.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            [void]$paths.Add([IO.Path]::GetFullPath($candidate))
        }
    }

    # Claude Desktop AppX packages
    $appxPackages = if (Test-IsAdmin) {
        @(Get-AppxPackage -AllUsers -Name Claude -ErrorAction SilentlyContinue)
    } else {
        @(Get-AppxPackage -Name Claude -ErrorAction SilentlyContinue)
    }
    foreach ($pkg in $appxPackages) {
        $appRoot = Join-Path $pkg.InstallLocation 'app'
        if (Test-Path -LiteralPath $appRoot -PathType Container) {
            Get-ChildItem -LiteralPath $appRoot -Recurse -File -Filter '*.exe' -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$paths.Add($_.FullName) }
        }
    }

    # Claude CLI, NativeHost, and legacy locations
    $cliBin = Join-Path $UserHome '.local\bin\claude.exe'
    if (Test-Path -LiteralPath $cliBin -PathType Leaf) { [void]$paths.Add($cliBin) }

    foreach ($rel in @(
        '.local\share\claude\versions',
        'AppData\Roaming\Claude\claude-code',
        'AppData\Roaming\Claude\ChromeNativeHost',
        'AppData\Local\AnthropicClaude'
    )) {
        $dir = Join-Path $UserHome $rel
        if (Test-Path -LiteralPath $dir -PathType Container) {
            Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Extension -eq '.exe' -or $_.Name -match '^\d+\.\d+\.\d+$'
            } | ForEach-Object { [void]$paths.Add($_.FullName) }
        }
    }

    $nativeHostRoot = Join-Path $UserHome 'AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude-NativeHost'
    if (Test-Path -LiteralPath $nativeHostRoot -PathType Container) {
        Get-ChildItem -LiteralPath $nativeHostRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^\d+(\.\d+){2,3}$' -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
        } | ForEach-Object {
            $hostBin = Join-Path $_.FullName 'chrome-native-host.exe'
            if (Test-Path -LiteralPath $hostBin -PathType Leaf) { [void]$paths.Add($hostBin) }
        }
    }

    $legacy = Join-Path $env:ProgramData ((Split-Path $UserHome -Leaf) + '\AnthropicClaude')
    if (Test-Path -LiteralPath $legacy -PathType Container) {
        Get-ChildItem -LiteralPath $legacy -Recurse -File -Filter '*.exe' -ErrorAction SilentlyContinue |
            ForEach-Object { [void]$paths.Add($_.FullName) }
    }

    return @($paths | Sort-Object)
}

function Get-NonMetaAdapterAliases {
    $ipv4Aliases = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$ipv4Aliases.Add($_.InterfaceAlias) }

    return @(
        Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -ne 'Meta' -and
                $_.InterfaceDescription -notmatch 'Meta Tunnel|Wintun|Bluetooth' -and
                $_.Status -ne 'Not Present' -and
                $ipv4Aliases.Contains($_.Name)
            } |
            Select-Object -ExpandProperty Name |
            Sort-Object -Unique
    )
}

function Get-ShortHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant())))).Replace('-', '').Substring(0, 16)
    } finally {
        $sha.Dispose()
    }
}

function Ensure-FirewallBlockRule {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string[]]$RemoteAddress,
        [string]$Program = '',
        [string[]]$InterfaceAlias = @(),
        [string]$Description = ''
    )
    $existing = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-NetFirewallRule -Name $Name | Out-Null
    }
    $params = @{
        Name          = $Name
        DisplayName   = $DisplayName
        Group         = $FirewallGroup
        Direction     = 'Outbound'
        Action        = 'Block'
        Enabled       = 'True'
        Profile       = 'Any'
        Protocol      = 'Any'
        RemoteAddress = $RemoteAddress
        Description   = $Description
    }
    if ($Program) { $params.Program = $Program }
    if ($InterfaceAlias.Count -gt 0) { $params.InterfaceAlias = $InterfaceAlias }
    New-NetFirewallRule @params | Out-Null
}

function Invoke-Audit {
    $fwOwned = @(Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue)
    $hasIpV4 = [bool](Get-NetFirewallRule -Name 'ClaudeGuardV3-AnthropicIPv4-Block' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    $hasIpV6 = [bool](Get-NetFirewallRule -Name 'ClaudeGuardV3-AnthropicIPv6-Block' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    $nrptDnsRules = @($fwOwned | Where-Object { $_.Name -like 'ClaudeGuardV3-NrptDnsNonMeta-*' -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    $hasDnsLeakBlock = ($nrptDnsRules.Count -gt 0)

    $nrptRules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq $NrptCommentTag })
    $expectedNs = Get-ExpectedNrptNamespaces
    $presentNs = @($nrptRules | ForEach-Object { $_.Namespace } | Sort-Object -Unique)
    $missingNs = @($expectedNs | Where-Object { $presentNs -notcontains $_ })

    $browserStatus = @()
    foreach ($keyPath in $BrowserPolicyKeys) {
        $entry = [ordered]@{ Key = $keyPath; MissingOrMismatched = @() }
        $props = if (Test-Path -LiteralPath $keyPath) { Get-ItemProperty -LiteralPath $keyPath } else { $null }
        foreach ($kv in $ExpectedBrowserPolicies.GetEnumerator()) {
            $ok = $props -and ($props.PSObject.Properties.Name -contains $kv.Key) -and ($props.($kv.Key) -eq $kv.Value.Value)
            if (-not $ok) { $entry.MissingOrMismatched += "$($kv.Key) (want $($kv.Value.Value))" }
        }
        $browserStatus += [pscustomobject]$entry
    }

    $hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
    $hostsActive = @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' })
    $hostsAnthropic = @($hostsActive | Where-Object { $_ -match 'claude|anthropic|datadoghq|sentry\.io|b-cdn\.net|px-cloud\.net|intercom-chat\.com' })

    $exes = Get-ProtectedExecutables
    $missingExeRules = @()
    foreach ($exe in $exes) {
        $h = Get-ShortHash $exe
        $r4 = Get-NetFirewallRule -Name "ClaudeGuardV3-App-$h-IPv4" -ErrorAction SilentlyContinue
        $r6 = Get-NetFirewallRule -Name "ClaudeGuardV3-App-$h-IPv6" -ErrorAction SilentlyContinue
        if (-not ($r4 -and $r4.Enabled -eq 'True' -and $r6 -and $r6.Enabled -eq 'True')) {
            $missingExeRules += $exe
        }
    }

    [pscustomobject]@{
        Time                          = (Get-Date -Format o)
        Action                        = 'Audit'
        Administrator                 = (Test-IsAdmin)
        FirewallGroup                 = $FirewallGroup
        FirewallOwnedRuleCount        = $fwOwned.Count
        AnthropicIPv4BlockPresent     = $hasIpV4
        AnthropicIPv6BlockPresent     = $hasIpV6
        NrptNonMetaDnsBlockPresent    = $hasDnsLeakBlock
        ExpectedProtectedExeCount     = $exes.Count
        MissingProtectedExeRuleCount  = $missingExeRules.Count
        MissingProtectedExes          = $missingExeRules
        ExpectedNrptNamespaceCount    = $expectedNs.Count
        PresentNrptNamespaceCount     = $presentNs.Count
        MissingNrptNamespaceCount     = $missingNs.Count
        BrowserPolicyAudit            = $browserStatus
        HostsActiveEntryCount         = $hostsActive.Count
        HostsAnthropicConflictEntries = $hostsAnthropic
        NonMetaAdapters               = (Get-NonMetaAdapterAliases)
    } | ConvertTo-Json -Depth 5
}

function Invoke-Apply {
    if (-not (Test-IsAdmin)) {
        throw 'Administrator privileges are required for -Action Apply. No changes were made.'
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupDir = if ($BackupDirectory) { $BackupDirectory } else { Join-Path $BackupRoot "backup-$stamp" }
    if (Test-Path -LiteralPath $backupDir) {
        throw "Backup directory already exists: $backupDir"
    }
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

    # 1. Backup current state before any modification
    $fwBackup = Join-Path $backupDir 'windows-firewall.wfw'
    & netsh.exe advfirewall export "$fwBackup" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to export Windows Firewall backup.' }

    Copy-Item -LiteralPath 'C:\Windows\System32\drivers\etc\hosts' -Destination (Join-Path $backupDir 'hosts.bak') -Force

    $existingNrpt = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Select-Object Name, Namespace, NameServers, Comment)
    $existingNrpt | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $backupDir 'nrpt-before.json') -Encoding UTF8

    $regBackup = @()
    foreach ($keyPath in $BrowserPolicyKeys) {
        $keyObj = Get-Item -LiteralPath $keyPath -ErrorAction SilentlyContinue
        foreach ($kv in $ExpectedBrowserPolicies.GetEnumerator()) {
            $exists = [bool]($keyObj -and ($keyObj.GetValueNames() -contains $kv.Key))
            $regBackup += [pscustomobject]@{
                Key    = $keyPath
                Name   = $kv.Key
                Exists = $exists
                Kind   = if ($exists) { $keyObj.GetValueKind($kv.Key).ToString() } else { $null }
                Value  = if ($exists) { $keyObj.GetValue($kv.Key) } else { $null }
            }
        }
    }
    $regBackup | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $backupDir 'browser-policies-before.json') -Encoding UTF8

    # 2. System-wide Anthropic official IP block (TCP + UDP, Program=Any).
    # Safe with Clash Proxy + fake-ip TUN because verge-mihomo dials proxy server IPs, never Anthropic IPs directly.
    Ensure-FirewallBlockRule `
        -Name 'ClaudeGuardV3-AnthropicIPv4-Block' `
        -DisplayName 'Claude Guard v3 - Block direct outbound to Anthropic official IPv4 CIDRs' `
        -RemoteAddress $AnthropicIPv4Cidrs `
        -Description 'Blocks direct IPv4 (TCP/UDP) to Anthropic AS399358 ranges from all processes.'

    Ensure-FirewallBlockRule `
        -Name 'ClaudeGuardV3-AnthropicIPv6-Block' `
        -DisplayName 'Claude Guard v3 - Block direct outbound to Anthropic official IPv6 CIDR' `
        -RemoteAddress $AnthropicIPv6Cidrs `
        -Description 'Blocks direct IPv6 (TCP/UDP) to Anthropic 2607:6bc0::/48 from all processes.'

    # 3. Block NRPT target DNS (198.18.0.2) per non-Meta IPv4 adapter so queries never leak out physical NICs when Clash TUN is stopped.
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'ClaudeGuardV3-NrptDnsNonMeta-*' } |
        Remove-NetFirewallRule | Out-Null

    $nonMeta = Get-NonMetaAdapterAliases
    $appliedDnsBlocks = 0
    foreach ($alias in $nonMeta) {
        $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
        $h = Get-ShortHash $alias
        try {
            Ensure-FirewallBlockRule `
                -Name "ClaudeGuardV3-NrptDnsNonMeta-$h" `
                -DisplayName "Claude Guard v3 - Block NRPT DNS 198.18.0.2 on $alias" `
                -RemoteAddress @($NrptTargetDns) `
                -InterfaceAlias @($alias) `
                -Description "Drops 198.18.0.2 outbound on $alias when Clash TUN is stopped."
            $appliedDnsBlocks++
        } catch {
            if ($adapter -and $adapter.Status -eq 'Up') {
                throw "Failed to bind NRPT DNS leak block to active adapter '$alias': $($_.Exception.Message)"
            }
            Write-Warning "Skipped disconnected adapter '$alias' not registered in Windows Firewall: $($_.Exception.Message)"
        }
    }
    if ($appliedDnsBlocks -eq 0) {
        throw 'No non-Meta IPv4 network adapters accepted the NRPT DNS leak block.'
    }

    # 4. Defense-in-depth non-loopback Defender Firewall rules for all discovered Claude & Chrome/Edge binaries.
    $exes = Get-ProtectedExecutables
    foreach ($exe in $exes) {
        $h = Get-ShortHash $exe
        $leaf = [IO.Path]::GetFileName($exe)
        Ensure-FirewallBlockRule `
            -Name "ClaudeGuardV3-App-$h-IPv4" `
            -DisplayName "Claude Guard v3 - Loopback-only IPv4 ($leaf $h)" `
            -Program $exe `
            -RemoteAddress $NonLoopbackIPv4 `
            -Description "Blocks non-loopback IPv4 outbound (TCP/UDP) for $exe."
        Ensure-FirewallBlockRule `
            -Name "ClaudeGuardV3-App-$h-IPv6" `
            -DisplayName "Claude Guard v3 - Loopback-only IPv6 ($leaf $h)" `
            -Program $exe `
            -RemoteAddress $NonLoopbackIPv6 `
            -Description "Blocks non-loopback IPv6 outbound (TCP/UDP) for $exe."
    }

    # 5. Windows DNS NRPT rules for all 20 suffixes (apex + .suffix) and 6 exact Anthropic domains -> 198.18.0.2 (Clash TUN DNS).
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Comment -eq $NrptCommentTag } |
        ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }

    foreach ($ns in (Get-ExpectedNrptNamespaces)) {
        Add-DnsClientNrptRule -Namespace $ns -NameServers $NrptTargetDns -Comment $NrptCommentTag | Out-Null
    }

    # 6. Chrome & Edge HKLM DNS / Pre-resolution policies (preserves existing ProxySettings untouched).
    foreach ($keyPath in $BrowserPolicyKeys) {
        if (-not (Test-Path -LiteralPath $keyPath)) {
            New-Item -Path $keyPath -Force | Out-Null
        }
        foreach ($kv in $ExpectedBrowserPolicies.GetEnumerator()) {
            New-ItemProperty -LiteralPath $keyPath -Name $kv.Key -PropertyType $kv.Value.Kind -Value $kv.Value.Value -Force | Out-Null
        }
    }

    # Flush OS DNS cache so NRPT rules take effect immediately without restarting Clash.
    Clear-DnsClientCache

    Write-Host "HARDENING_APPLIED_SUCCESSFULLY. Backup saved at: $backupDir"
    Invoke-Audit
}

function Invoke-Restore {
    if (-not (Test-IsAdmin)) {
        throw 'Administrator privileges are required for -Action Restore. No changes were made.'
    }
    if (-not $BackupDirectory -or -not (Test-Path -LiteralPath $BackupDirectory -PathType Container)) {
        throw 'Specify a valid -BackupDirectory created by -Action Apply.'
    }

    # 1. Remove only our dedicated firewall rule group (never removes older user rule groups or WFP rules).
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule | Out-Null

    # 2. Remove only our tagged NRPT rules.
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Comment -eq $NrptCommentTag } |
        ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }

    # 3. Restore only the 3 Chrome/Edge registry values we touched (preserves ProxySettings).
    $regBackupFile = Join-Path $BackupDirectory 'browser-policies-before.json'
    if (Test-Path -LiteralPath $regBackupFile -PathType Leaf) {
        $entries = @(Get-Content -LiteralPath $regBackupFile -Raw | ConvertFrom-Json)
        foreach ($e in $entries) {
            if ($BrowserPolicyKeys -notcontains $e.Key) { throw "Unexpected key in backup: $($e.Key)" }
            if ($e.Exists) {
                New-ItemProperty -LiteralPath $e.Key -Name $e.Name -PropertyType $e.Kind -Value $e.Value -Force | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $e.Key -Name $e.Name -ErrorAction SilentlyContinue
            }
        }
    }

    Clear-DnsClientCache
    Write-Host "HARDENING_RESTORED_CLEANLY from $BackupDirectory. Existing WFP rules, Clash settings, and ProxySettings were preserved."
}

switch ($Action) {
    'Audit'   { Invoke-Audit }
    'Apply'   { Invoke-Apply }
    'Restore' { Invoke-Restore }
}
