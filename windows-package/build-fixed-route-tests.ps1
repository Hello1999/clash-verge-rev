$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$deps = Join-Path $root 'target\release\deps'
$yaml = Get-ChildItem -LiteralPath $deps -Filter 'libserde_yaml_ng-*.rlib' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $yaml) { throw 'Existing release dependencies are required' }
$compiler = Join-Path $env:USERPROFILE '.cargo\bin\rustc.exe'
$source = Join-Path $PSScriptRoot 'fixed-route-harness.rs'
& $compiler --edition=2024 --test $source --extern "serde_yaml_ng=$($yaml.FullName)" -L "dependency=$deps" -o (Join-Path $PSScriptRoot 'fixed-route-tests.exe')
if ($LASTEXITCODE) { throw 'Unit test compilation failed' }
& (Join-Path $PSScriptRoot 'fixed-route-tests.exe')
if ($LASTEXITCODE) { throw 'Unit tests failed' }
& $compiler --edition=2024 $source --extern "serde_yaml_ng=$($yaml.FullName)" -L "dependency=$deps" -o (Join-Path $PSScriptRoot 'fixed-route-harness.exe')
if ($LASTEXITCODE) { throw 'Fixture transformer compilation failed' }
