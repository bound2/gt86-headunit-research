param([string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin')
$ErrorActionPreference = 'Stop'
$headunitDiagRoot = Split-Path -Parent $PSScriptRoot
$headunitDiagClang = Join-Path $LlvmDirectory 'clang.exe'
if (-not (Test-Path -LiteralPath $headunitDiagClang -PathType Leaf)) { throw 'Missing host clang' }
$headunitDiagOutput = Join-Path $headunitDiagRoot ('build/qnx-diagnostic-host-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $headunitDiagOutput | Out-Null
$headunitDiagExecutable = Join-Path $headunitDiagOutput 'diagnostic-tests.exe'
$headunitDiagFlags = @('-std=c99', '-g', '-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror', '-DHEADUNIT_QNX_DIAGNOSTIC_TEST=1')
& $headunitDiagClang @headunitDiagFlags -I (Join-Path $headunitDiagRoot 'tests') `
    (Join-Path $headunitDiagRoot 'tests/qnx_network_diagnostic_tests.c') `
    (Join-Path $headunitDiagRoot 'src/carplay/qnx_network_diagnostic.c') -o $headunitDiagExecutable
if ($LASTEXITCODE -ne 0) { throw 'Host diagnostic sanitizer compilation failed' }
$headunitDiagResource = & $headunitDiagClang --print-resource-dir
if ($LASTEXITCODE -ne 0) { throw 'Host LLVM resource lookup failed' }
$headunitDiagSavedPath = $env:Path
try {
    Remove-Item Env:PATH
    $env:Path = (Join-Path $headunitDiagResource 'lib/windows') + ';' + $headunitDiagSavedPath
    & $headunitDiagExecutable
    if ($LASTEXITCODE -ne 0) { throw 'Host diagnostic sanitizer test failed' }
} finally { $env:Path = $headunitDiagSavedPath }
Write-Output 'Host API-model checks only; QNX SDK branch and installed-unit execution remain unverified.'
