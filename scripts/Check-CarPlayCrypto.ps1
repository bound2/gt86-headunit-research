param([string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin')
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayCrypto.ps1')
$headunitRoot = Split-Path -Parent $PSScriptRoot
$headunitSource = Join-Path $headunitRoot 'build/monocypher-4.0.3'
$headunitOutput = Join-Path $headunitRoot 'build/pairing-sanitized'
New-Item -ItemType Directory -Force $headunitOutput | Out-Null
$headunitClang = Join-Path $LlvmDirectory 'clang.exe'
$headunitCpp = Join-Path $LlvmDirectory 'clang++.exe'
$headunitIncludes = @('-I', (Join-Path $headunitRoot 'src/carplay'), '-I', (Join-Path $headunitSource 'src'), '-I', (Join-Path $headunitSource 'src/optional'))
$headunitFlags = @('-g', '-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror')
$headunitSources = @('src/monocypher.c','src/optional/monocypher-ed25519.c') | ForEach-Object { Join-Path $headunitSource $_ }
foreach ($headunitName in @('pair_tlv','pair_crypto','pair_verify','rtsp_wire','rtsp_channel','control_cipher','projection_control')) {
    $headunitSources += Join-Path $headunitRoot "src/carplay/$headunitName.c"
}
$headunitObjects = @()
foreach ($headunitFile in $headunitSources) {
    $headunitObject = Join-Path $headunitOutput ($headunitObjects.Count.ToString() + '.obj')
    & $headunitClang -std=c99 @headunitFlags @headunitIncludes -c $headunitFile -o $headunitObject
    if ($LASTEXITCODE -ne 0) { throw "Sanitized pairing compilation failed: $headunitFile" }
    $headunitObjects += $headunitObject
}
$headunitSavedPairPath = $env:Path
try {
    $headunitResource = & $headunitClang --print-resource-dir
    if ($LASTEXITCODE -ne 0) { throw 'LLVM resource lookup failed' }
    Remove-Item Env:PATH
    $env:Path = (Join-Path $headunitResource 'lib/windows') + ';' + $headunitSavedPairPath
    foreach ($headunitTest in @('pair_tlv_tests','pair_crypto_tests','control_cipher_tests','projection_control_tests')) {
        $headunitExe = Join-Path $headunitOutput "$headunitTest.exe"
        & $headunitCpp -std=c++20 @headunitFlags @headunitIncludes (Join-Path $headunitRoot "tests/$headunitTest.cpp") @headunitObjects -o $headunitExe
        if ($LASTEXITCODE -ne 0) { throw "Sanitized pairing test link failed: $headunitTest" }
        $headunitFixture = 'tests/fixtures/pair-verify-vectors.txt'
        if ($headunitTest -eq 'control_cipher_tests') { $headunitFixture = 'tests/fixtures/control-cipher-vectors.txt' }
        & $headunitExe (Join-Path $headunitRoot $headunitFixture)
        if ($LASTEXITCODE -ne 0) { throw "Sanitized pairing test failed: $headunitTest" }
    }
} finally { $env:Path = $headunitSavedPairPath }
# Compile the adapter and actual dependency for ARM too, without presenting a
# crypto portability object as a linked QNX process or constant-time proof.
$headunitArm = Join-Path $headunitOutput 'arm'
New-Item -ItemType Directory -Force $headunitArm | Out-Null
$headunitArmObjects = @()
foreach ($headunitFile in $headunitSources) {
    $headunitObject = Join-Path $headunitArm ($headunitArmObjects.Count.ToString() + '.o')
    & $headunitClang --target=armv7-none-eabi -mcpu=cortex-a8 -mfloat-abi=soft -std=c99 -ffreestanding -fno-builtin -O2 -Wall -Wextra -Werror @headunitIncludes -c $headunitFile -o $headunitObject
    if ($LASTEXITCODE -ne 0) { throw "ARM pairing compilation failed: $headunitFile" }
    $headunitArmObjects += $headunitObject
}
$headunitCombined = Join-Path $headunitArm 'pairing.o'
& (Join-Path $LlvmDirectory 'ld.lld.exe') --relocatable -m armelf -o $headunitCombined @headunitArmObjects
if ($LASTEXITCODE -ne 0) { throw 'ARM pairing relocatable link failed' }
$headunitImports = & (Join-Path $LlvmDirectory 'llvm-nm.exe') --undefined-only $headunitCombined
if ($LASTEXITCODE -ne 0) { throw 'ARM pairing symbol inspection failed' }
$headunitAllowed = @('__aeabi_memclr8','__aeabi_uidiv','__aeabi_uidivmod','__aeabi_uldivmod')
foreach ($headunitImport in $headunitImports) {
    $headunitSymbol = ($headunitImport.Trim() -split '\s+')[-1]
    if ($headunitSymbol -notin $headunitAllowed) { throw "Unexpected ARM pairing import: $headunitSymbol" }
    Write-Output "Required ARM runtime symbol: $headunitSymbol"
}
Write-Output 'PASS: four pairing/control suites and dependency passed ASan/UBSan; all nine units compile/link as ARM relocatable objects.'
Write-Output 'Any printed imports need a target runtime; this does not prove a QNX executable or target side-channel safety.'
