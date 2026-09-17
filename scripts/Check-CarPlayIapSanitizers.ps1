param([string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin')
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayCrypto.ps1')
$iapRoot = Split-Path -Parent $PSScriptRoot
$iapCrypto = Join-Path $iapRoot 'build/monocypher-4.0.3'
$iapOutput = Join-Path $iapRoot 'build/iap-sanitized'
New-Item -ItemType Directory -Force $iapOutput | Out-Null
$iapClang = Join-Path $LlvmDirectory 'clang.exe'
$iapCpp = Join-Path $LlvmDirectory 'clang++.exe'
$iapIncludes = @('-I', (Join-Path $iapRoot 'src/carplay'), '-I', (Join-Path $iapCrypto 'src'), '-I', (Join-Path $iapCrypto 'src/optional'))
$iapFlags = @('-g', '-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror')
$iapSources = @((Join-Path $iapCrypto 'src/monocypher.c'), (Join-Path $iapCrypto 'src/optional/monocypher-ed25519.c'))
foreach ($iapName in @('pair_crypto','control_cipher','projection_iap')) { $iapSources += Join-Path $iapRoot "src/carplay/$iapName.c" }
$iapObjects = @()
foreach ($iapSource in $iapSources) {
    $iapObject = Join-Path $iapOutput ($iapObjects.Count.ToString() + '.obj')
    & $iapClang -std=c99 @iapFlags @iapIncludes -c $iapSource -o $iapObject
    if ($LASTEXITCODE -ne 0) { throw "Sanitized iAP compilation failed: $iapSource" }
    $iapObjects += $iapObject
}
$iapExe = Join-Path $iapOutput 'projection_iap_tests.exe'
& $iapCpp -std=c++20 @iapFlags @iapIncludes (Join-Path $iapRoot 'tests/projection_iap_tests.cpp') @iapObjects -o $iapExe
if ($LASTEXITCODE -ne 0) { throw 'Sanitized iAP test link failed' }
$iapSavedPath = $env:Path
try {
    $iapResource = & $iapClang --print-resource-dir
    if ($LASTEXITCODE -ne 0) { throw 'LLVM resource lookup failed' }
    Remove-Item Env:PATH
    $env:Path = (Join-Path $iapResource 'lib/windows') + ';' + $iapSavedPath
    & $iapExe
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized iAP tests failed' }
    # Verify the assertion-reporting failure path too, with captured stderr.
    $iapFailureInfo = New-Object System.Diagnostics.ProcessStartInfo
    $iapFailureInfo.FileName = $iapExe
    $iapFailureInfo.Arguments = '--failure-test'
    $iapFailureInfo.UseShellExecute = $false
    $iapFailureInfo.CreateNoWindow = $true
    $iapFailureInfo.RedirectStandardError = $true
    $iapFailureProcess = [System.Diagnostics.Process]::Start($iapFailureInfo)
    try {
        if (-not $iapFailureProcess.WaitForExit(10000)) { $iapFailureProcess.Kill(); throw 'Assertion-reporting check timed out' }
        $iapFailureText = $iapFailureProcess.StandardError.ReadToEnd()
        if ($iapFailureProcess.ExitCode -ne 1 -or $iapFailureText -notmatch '^CHECK failed: false at [0-9]+\s*$') {
            throw "Unexpected assertion-reporting result: $iapFailureText"
        }
        Write-Output 'PASS: intentional assertion failure reports its expression and exits with status 1.'
    } finally { $iapFailureProcess.Dispose() }
} finally { $env:Path = $iapSavedPath }
# Separate freestanding compile/relocatable link, NOT a QNX build or an
# expansion of the existing core's import-free portability claim.
$iapArm = Join-Path $iapOutput 'arm'
New-Item -ItemType Directory -Force $iapArm | Out-Null
$iapArmObjects = @()
foreach ($iapSource in $iapSources) {
    $iapObject = Join-Path $iapArm ($iapArmObjects.Count.ToString() + '.o')
    & $iapClang --target=armv7-none-eabi -mcpu=cortex-a8 -mfloat-abi=soft -std=c99 -ffreestanding -fno-builtin -O2 -Wall -Wextra -Werror @iapIncludes -c $iapSource -o $iapObject
    if ($LASTEXITCODE -ne 0) { throw "ARM iAP compilation failed: $iapSource" }
    $iapArmObjects += $iapObject
}
$iapCombined = Join-Path $iapArm 'iap.o'
& (Join-Path $LlvmDirectory 'ld.lld.exe') --relocatable -m armelf -o $iapCombined @iapArmObjects
if ($LASTEXITCODE -ne 0) { throw 'ARM iAP relocatable link failed' }
$iapImports = & (Join-Path $LlvmDirectory 'llvm-nm.exe') --undefined-only $iapCombined
if ($LASTEXITCODE -ne 0) { throw 'ARM iAP symbol inspection failed' }
foreach ($iapImport in $iapImports) {
    $iapSymbol = ($iapImport.Trim() -split '\s+')[-1]
    if ($iapSymbol -notin @('__aeabi_memclr8','__aeabi_uidiv','__aeabi_uidivmod','__aeabi_uldivmod')) { throw "Unexpected ARM iAP import: $iapSymbol" }
    Write-Output "Required ARM runtime symbol: $iapSymbol"
}
Write-Output 'PASS: iAP owner/record codec/crypto/dependencies and tests passed ASan/UBSan; five units compile/link as ARM relocatable objects.'
Write-Output 'Required runtime helpers are not supplied here. No QNX executable, phone or vehicle execution is established.'
