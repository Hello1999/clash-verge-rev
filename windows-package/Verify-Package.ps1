param([Parameter(Mandatory=$true)][string]$Installer)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$archiveTool = 'C:\Program Files\7-Zip\7z.exe'
if (-not (Test-Path -LiteralPath $archiveTool -PathType Leaf)) { throw '7-Zip is required for non-executing package inspection' }
$inspection = Join-Path $PSScriptRoot ('package-inspection\' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $inspection
& $archiveTool x $installerPath "-o$inspection" -y -bso0 -bsp0
if ($LASTEXITCODE -ne 0) { throw 'Cannot extract installer for inspection' }
$files = @(Get-ChildItem -LiteralPath $inspection -Recurse -File)
foreach ($forbidden in @('clash-verge.exe', 'clash-verge-service.exe', 'wfp-manager.exe', 'gateway.py',
    'browser_router_config.py', 'profiles.yaml', 'verge.yaml', 'config.yaml', '.clash-verge-service-owner-token')) {
    if ($files | Where-Object Name -eq $forbidden) { throw "Unexpected payload: $forbidden" }
}
$expected = @{
    'clash-verge-auto-chain.exe' = 'target\release\clash-verge-auto-chain.exe'
    'claude-guard-manager.exe' = 'src-tauri\resources\claude-guard-manager.exe'
    'clash-verge-service-auto-chain.exe' = 'src-tauri\resources\clash-verge-service-auto-chain.exe'
    'clash-verge-service-install.exe' = 'src-tauri\resources\clash-verge-service-install.exe'
    'clash-verge-service-uninstall.exe' = 'src-tauri\resources\clash-verge-service-uninstall.exe'
    'verge-mihomo.exe' = 'src-tauri\sidecar\verge-mihomo-x86_64-pc-windows-msvc.exe'
    'verge-mihomo-alpha.exe' = 'src-tauri\sidecar\verge-mihomo-alpha-x86_64-pc-windows-msvc.exe'
}
foreach ($entry in $expected.GetEnumerator()) {
    $matches = @($files | Where-Object Name -eq $entry.Key)
    if ($matches.Count -ne 1) { throw "Expected exactly one payload: $($entry.Key)" }
    $sourcePath = Join-Path $root $entry.Value
    $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
    if ($entry.Key -eq 'clash-verge-auto-chain.exe') {
        # Tauri patches the bundle marker for NSIS, then restores the unbundled build output.
        $bytes = [IO.File]::ReadAllBytes($sourcePath)
        $text = [Text.Encoding]::ASCII.GetString($bytes)
        $marker = '__TAURI_BUNDLE_TYPE_VAR_UNK'
        $offset = $text.IndexOf($marker, [StringComparison]::Ordinal)
        if ($offset -lt 0 -or $text.IndexOf($marker, $offset + 1, [StringComparison]::Ordinal) -ge 0) {
            throw 'Expected exactly one unbundled Tauri marker'
        }
        $replacement = [Text.Encoding]::ASCII.GetBytes('__TAURI_BUNDLE_TYPE_VAR_NSS')
        [Buffer]::BlockCopy($replacement, 0, $bytes, $offset, $replacement.Length)
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $sourceHash = [BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-', '') }
        finally { $hasher.Dispose() }
    }
    $packageHash = (Get-FileHash -LiteralPath $matches[0].FullName -Algorithm SHA256).Hash
    if ($sourceHash -ne $packageHash) { throw "Payload hash mismatch: $($entry.Key)" }
}
$main = @($files | Where-Object Name -eq 'clash-verge-auto-chain.exe')[0]
$guardScript = @($files | Where-Object Name -eq 'reconcile.ps1')
if ($guardScript.Count -ne 1) { throw 'Expected exactly one Claude guard task script' }
$guardSource = Join-Path $root 'src-tauri\packages\windows\claude-guard\reconcile.ps1'
if ((Get-FileHash $guardScript[0].FullName).Hash -ne (Get-FileHash $guardSource).Hash) { throw 'Claude guard script hash mismatch' }
$info = [Diagnostics.FileVersionInfo]::GetVersionInfo($main.FullName)
if ($info.ProductName -ne 'Clash Verge Auto Chain') { throw 'Incorrect executable product identity' }
[pscustomobject]@{
    Installer=$installerPath
    SHA256=(Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash
    Bytes=(Get-Item -LiteralPath $installerPath).Length
    ProductName=$info.ProductName
    ProductVersion=$info.ProductVersion
    VerifiedExecutables=$expected.Count
    PayloadFiles=$files.Count
    ClaudeGuardBundled=$true
    UserConfigurationBundled=$false
    InstallerExecuted=$false
    ExtractedTo=$inspection
} | ConvertTo-Json
