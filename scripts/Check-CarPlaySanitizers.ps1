param(
    [string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin'
)
$ErrorActionPreference = 'Stop'
$headunitRoot = Split-Path -Parent $PSScriptRoot
$headunitClang = Join-Path $LlvmDirectory 'clang.exe'
$headunitClangCpp = Join-Path $LlvmDirectory 'clang++.exe'
foreach ($headunitTool in @($headunitClang, $headunitClangCpp)) {
    if (-not (Test-Path -LiteralPath $headunitTool -PathType Leaf)) { throw "Missing LLVM tool: $headunitTool" }
}
$headunitOutput = Join-Path $headunitRoot 'build/carplay-sanitized'
New-Item -ItemType Directory -Path $headunitOutput -Force | Out-Null
$headunitFlags = @('-g', '-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror')
$headunitObjects = @()
foreach ($headunitName in @('iap2_wire', 'iap2_auth', 'iap2_link', 'iap2_control', 'iap2_identification', 'iap2_transport', 'iap2_carplay', 'iap2_power', 'usbmux_wire')) {
    $headunitObject = Join-Path $headunitOutput "$headunitName.obj"
    & $headunitClang -std=c99 @headunitFlags -c (Join-Path $headunitRoot "src/carplay/$headunitName.c") -o $headunitObject
    if ($LASTEXITCODE -ne 0) { throw "Sanitized compilation failed: $headunitName" }
    $headunitObjects += $headunitObject
}
$headunitResource = & $headunitClang --print-resource-dir
if ($LASTEXITCODE -ne 0) { throw 'LLVM resource lookup failed' }
$headunitSavedPath = $env:Path
try {
    # Normalize inherited Path/PATH duplicates and locate the ASan runtime DLL.
    Remove-Item Env:PATH
    $env:Path = (Join-Path $headunitResource 'lib/windows') + ';' + $headunitSavedPath
    foreach ($headunitTest in @('iap2_tests', 'iap2_link_tests', 'iap2_control_tests', 'iap2_identification_tests', 'iap2_transport_tests', 'iap2_carplay_tests', 'usbmux_tests')) {
        $headunitExe = Join-Path $headunitOutput "$headunitTest.exe"
        & $headunitClangCpp -std=c++20 @headunitFlags '-I' (Join-Path $headunitRoot 'src/carplay') `
            (Join-Path $headunitRoot "tests/$headunitTest.cpp") @headunitObjects -o $headunitExe
        if ($LASTEXITCODE -ne 0) { throw "Sanitized test link failed: $headunitTest" }
        if ($headunitTest -in @('iap2_tests', 'iap2_identification_tests', 'iap2_carplay_tests')) {
            & $headunitExe (Join-Path $headunitRoot 'tests/fixtures/iap2-csm-vectors.txt')
        } elseif ($headunitTest -eq 'usbmux_tests') {
            & $headunitExe (Join-Path $headunitRoot 'tests/fixtures/usbmux-wire-vectors.txt')
        } else { & $headunitExe }
        if ($LASTEXITCODE -ne 0) { throw "Sanitized test failed: $headunitTest" }
    }
} finally { $env:Path = $headunitSavedPath }
Write-Output 'PASS: Host protocol tests completed under AddressSanitizer and UndefinedBehaviorSanitizer.'
