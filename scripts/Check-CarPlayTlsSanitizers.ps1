param([string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin')
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayTls.ps1')
$headunitRoot = Split-Path -Parent $PSScriptRoot
$headunitSource = Join-Path $headunitRoot 'build/mbedtls-3.6.7'
$headunitOutput = Join-Path $headunitRoot 'build/tls-sanitized-direct'
New-Item -ItemType Directory -Force $headunitOutput | Out-Null
$headunitClang = Join-Path $LlvmDirectory 'clang.exe'
$headunitCpp = Join-Path $LlvmDirectory 'clang++.exe'
$headunitFlags = @('-g', '-O1', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-DMBEDTLS_USER_CONFIG_FILE=\"tls_config.h\"')
$headunitIncludes = @('-I', (Join-Path $headunitRoot 'src/carplay'))
foreach ($headunitInclude in @('include', 'library', '3rdparty/everest/include', '3rdparty/everest/include/everest',
    '3rdparty/everest/include/everest/kremlib', '3rdparty/p256-m', '3rdparty/p256-m/p256-m')) {
    $headunitIncludes += @('-I', (Join-Path $headunitSource $headunitInclude))
}
# Read the three exact source lists from the pinned release's CMake file.
$headunitLists = [regex]::Matches((Get-Content -Raw (Join-Path $headunitSource 'library/CMakeLists.txt')), '(?ms)^set\(src_(?:crypto|x509|tls)\s+(.*?)\)')
if ($headunitLists.Count -ne 3) { throw 'Unexpected pinned crypto source lists' }
$headunitSources = @()
foreach ($headunitList in $headunitLists) {
    foreach ($headunitName in ($headunitList.Groups[1].Value.Trim() -split '\s+')) {
        if ($headunitName -notmatch '^[a-z0-9_]+\.c$') { throw 'Unexpected crypto source name' }
        $headunitSources += Join-Path $headunitSource "library/$headunitName"
    }
}
foreach ($headunitName in @('3rdparty/everest/library/everest.c', '3rdparty/everest/library/x25519.c',
    '3rdparty/everest/library/Hacl_Curve25519_joined.c', '3rdparty/p256-m/p256-m_driver_entrypoints.c', '3rdparty/p256-m/p256-m/p256-m.c')) {
    $headunitSources += Join-Path $headunitSource $headunitName
}
foreach ($headunitName in @('iap2_wire', 'iap2_auth', 'iap2_link', 'iap2_control', 'iap2_identification', 'iap2_transport',
    'iap2_carplay', 'iap2_power', 'usbmux_wire', 'usbmux_host', 'usbmux_connection', 'usbmux_dispatcher',
    'lockdown_wire', 'lockdown_channel', 'service_plist', 'lockdown_reply', 'lockdown_bootstrap', 'lockdown_tls')) {
    $headunitSources += Join-Path $headunitRoot "src/carplay/$headunitName.c"
}
$headunitObjects = @()
foreach ($headunitFile in $headunitSources) {
    $headunitObject = Join-Path $headunitOutput ($headunitObjects.Count.ToString() + '.obj')
    & $headunitClang -std=c99 @headunitFlags @headunitIncludes -c $headunitFile -o $headunitObject
    if ($LASTEXITCODE -ne 0) { throw "Sanitized compilation failed: $headunitFile" }
    $headunitObjects += $headunitObject
}
$headunitSavedTlsPath = $env:Path
try {
    $headunitResource = & $headunitClang --print-resource-dir
    if ($LASTEXITCODE -ne 0) { throw 'LLVM resource lookup failed' }
    Remove-Item Env:PATH
    $env:Path = (Join-Path $headunitResource 'lib/windows') + ';' + $headunitSavedTlsPath
    $headunitExe = Join-Path $headunitOutput 'lockdown_tls_tests.exe'
    & $headunitCpp -std=c++20 @headunitFlags @headunitIncludes (Join-Path $headunitRoot 'tests/lockdown_tls_tests.cpp') @headunitObjects -Xlinker bcrypt.lib -o $headunitExe
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized TLS build failed' }
    & $headunitExe (Join-Path $headunitRoot 'tests/fixtures/lockdown')
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized TLS tests failed' }
} finally { $env:Path = $headunitSavedTlsPath }
Write-Output 'PASS: TLS adapter, protocol dependencies and Mbed TLS built with AddressSanitizer/UndefinedBehaviorSanitizer.'
