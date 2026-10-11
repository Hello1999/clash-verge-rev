$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual C++ build tools are required.' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$output = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\resources\claude-guard-manager.exe'))
$source = Join-Path $PSScriptRoot 'manager.cpp'
$object = Join-Path $env:TEMP ('auto-chain-guard-' + [Guid]::NewGuid().ToString('N') + '.obj')
$batch = [IO.Path]::ChangeExtension($object, '.cmd')
try {
    @("@echo off", "call `"$vcvars`"", 'if errorlevel 1 exit /b 1',
        "cl /nologo /std:c++17 /EHsc /W4 /WX /MT `"$source`" /Fo:`"$object`" /Fe:`"$output`"", 'exit /b %errorlevel%') | Set-Content -LiteralPath $batch -Encoding ASCII
    & cmd.exe /d /c $batch
    if ($LASTEXITCODE) { throw 'Auto Chain guard compilation failed.' }
} finally {
    foreach ($file in @($object, $batch)) { if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file } }
}
