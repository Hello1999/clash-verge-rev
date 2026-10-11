param([ValidateSet('Audit', 'Reconcile', 'Install', 'Uninstall')][string]$Action = 'Audit')
$ErrorActionPreference = 'Stop'
$taskName = 'Clash Verge Auto Chain Claude Guard'
$stateRoot = Join-Path $env:ProgramData 'ClashVergeAutoChainProtection'
$manager = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\resources\claude-guard-manager.exe'))
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Administrator rights are required to inspect or update WFP filters.' }

function Find-ClaudeApplications {
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($package in @(Get-AppxPackage -AllUsers -Name Claude)) {
        $root = Join-Path $package.InstallLocation 'app'
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.exe' | ForEach-Object { [void]$paths.Add($_.FullName) }
        }
    }
    $profiles = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables((Get-ItemProperty $_.PSPath).ProfileImagePath) })
    foreach ($homePath in $profiles) {
        $binary = Join-Path $homePath '.local\bin\claude.exe'
        if (Test-Path -LiteralPath $binary -PathType Leaf) { [void]$paths.Add($binary) }
        foreach ($relative in @('.local\share\claude\versions', 'AppData\Roaming\Claude\claude-code',
            'AppData\Roaming\Claude\ChromeNativeHost', 'AppData\Local\AnthropicClaude')) {
            $root = Join-Path $homePath $relative
            if (Test-Path -LiteralPath $root) {
                Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {
                    $_.Extension -eq '.exe' -or $_.Name -match '^\d+\.\d+\.\d+$'
                } | ForEach-Object { [void]$paths.Add($_.FullName) }
            }
        }
        $legacy = Join-Path $env:ProgramData ((Split-Path $homePath -Leaf) + '\AnthropicClaude')
        if (Test-Path -LiteralPath $legacy) {
            Get-ChildItem -LiteralPath $legacy -Recurse -File -Filter '*.exe' | ForEach-Object { [void]$paths.Add($_.FullName) }
        }
    }
    return @($paths | Sort-Object)
}

function Invoke-Guard([string]$Operation, [string]$Path) {
    # Windows PowerShell treats a native program's stderr as an ErrorRecord.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $arguments = @($Operation, $Path, 'local')
        if ($Operation -eq 'install') { $arguments += '--apply' }
        $output = & $manager @arguments 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output.Trim() }
    } finally { $ErrorActionPreference = $savedPreference }
}

if ($Action -eq 'Uninstall') {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    Write-Output 'Automatic discovery removed. Existing persistent blocking filters are retained.'
    exit 0
}
if (-not (Test-Path -LiteralPath $manager -PathType Leaf)) { throw 'Auto Chain guard manager is missing.' }

if ($Action -eq 'Install') {
    # A SYSTEM task must never execute a script from a user-writable installation.
    $installRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
    $programFiles = [Environment]::GetFolderPath('ProgramFiles').TrimEnd('\') + '\'
    if (-not $installRoot.StartsWith($programFiles, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Automatic guard installation requires an administrator-owned Program Files directory.'
    }
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $taskAction = New-ScheduledTaskAction -Execute $shell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Action Reconcile')
    $triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)))
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
}

$mutex = [Threading.Mutex]::new($false, 'Global\ClashVergeAutoChainClaudeGuard')
$locked = $false
try {
    try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Another Auto Chain guard check is still running.' }
    $results = @(foreach ($path in @(Find-ClaudeApplications)) {
        $check = Invoke-Guard 'verify' $path
        $changed = $false
        if ($check.ExitCode -ne 0 -and $Action -ne 'Audit') {
            $apply = Invoke-Guard 'install' $path
            if ($apply.ExitCode -ne 0) { throw "Cannot protect ${path}: $($apply.Output)" }
            $changed = $true
            $check = Invoke-Guard 'verify' $path
        }
        [pscustomobject]@{ Path = $path; Verified = ($check.ExitCode -eq 0); Changed = $changed; Details = $check.Output }
    })
    $report = [ordered]@{ Time = (Get-Date -Format o); Action = $Action; Results = $results }
    if ($Action -ne 'Audit') {
        if (-not (Test-Path -LiteralPath $stateRoot)) { New-Item -ItemType Directory -Path $stateRoot | Out-Null }
        $statusPath = Join-Path $stateRoot 'auto-chain-guard-status.json'
        $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ($statusPath + '.tmp') -Encoding UTF8
        Move-Item -LiteralPath ($statusPath + '.tmp') -Destination $statusPath -Force
    }
    $report | ConvertTo-Json -Depth 5
    if (@($results | Where-Object { -not $_.Verified }).Count) { exit 1 }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
