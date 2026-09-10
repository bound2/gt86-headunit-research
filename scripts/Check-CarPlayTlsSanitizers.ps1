param([string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin', [switch]$IncludeEnrollment)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayTls.ps1')
$headunitRoot = Split-Path -Parent $PSScriptRoot
$headunitSource = Join-Path $headunitRoot 'build/mbedtls-3.6.7'
$headunitOutput = Join-Path $headunitRoot 'build/tls-sanitized-direct'
if ($IncludeEnrollment) {
    & (Join-Path $PSScriptRoot 'Prepare-CarPlayCrypto.ps1')
    $headunitOutput = Join-Path $headunitRoot 'build/enrollment-sanitized'
}
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
    'lockdown_wire', 'lockdown_channel', 'service_plist', 'lockdown_reply', 'lockdown_bootstrap', 'rtsp_wire', 'rtsp_channel', 'pair_tlv', 'projection_info', 'projection_timing', 'projection_events', 'projection_command', 'lockdown_tls', 'lockdown_client', 'carkit', 'carkit_iap2')) {
    $headunitSources += Join-Path $headunitRoot "src/carplay/$headunitName.c"
}
if ($IncludeEnrollment) {
    $headunitMono = Join-Path $headunitRoot 'build/monocypher-4.0.3'
    $headunitFlags += '-DPAIR_STORE_TESTING=1'
    $headunitIncludes += @('-I', (Join-Path $headunitMono 'src'), '-I', (Join-Path $headunitMono 'src/optional'))
    $headunitSources += @((Join-Path $headunitMono 'src/monocypher.c'), (Join-Path $headunitMono 'src/optional/monocypher-ed25519.c'))
    foreach ($headunitName in @('pair_crypto','pair_verify','control_cipher','projection_control','pair_srp','pair_setup','pair_setup_channel','pair_store','pair_store_file','mfi_sap','projection_auth','projection_session','projection_receiver','projection_services_win')) {
        $headunitSources += Join-Path $headunitRoot "src/carplay/$headunitName.c"
    }
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
    $headunitTests = @('lockdown_tls_tests', 'carkit_tests', 'carkit_iap2_tests')
    if ($IncludeEnrollment) { $headunitTests += @('pair_setup_tests','pair_store_file_tests','mfi_sap_tests','projection_session_tests','projection_receiver_tests','projection_services_tests') }
    foreach ($headunitTest in $headunitTests) {
        $headunitExe = Join-Path $headunitOutput "$headunitTest.exe"
        & $headunitCpp -std=c++20 @headunitFlags @headunitIncludes (Join-Path $headunitRoot "tests/$headunitTest.cpp") @headunitObjects -Xlinker bcrypt.lib -Xlinker advapi32.lib -Xlinker ws2_32.lib -o $headunitExe
        if ($LASTEXITCODE -ne 0) { throw "Sanitized build failed: $headunitTest" }
        $headunitFixture = 'tests/fixtures/lockdown'
        if ($headunitTest -in @('pair_setup_tests','pair_store_file_tests')) { $headunitFixture = 'tests/fixtures/pair-setup-vectors.txt' }
        if ($headunitTest -in @('mfi_sap_tests','projection_receiver_tests','projection_services_tests')) { $headunitFixture = 'tests/fixtures/mfi-sap-vectors.txt' }
        if ($headunitTest -eq 'projection_session_tests') { $headunitFixture = 'tests/fixtures/projection-session-vectors.txt' }
        $headunitTestArguments = @((Join-Path $headunitRoot $headunitFixture))
        if ($headunitTest -eq 'pair_store_file_tests') { $headunitTestArguments += $headunitOutput }
        if ($headunitTest -in @('mfi_sap_tests','projection_receiver_tests','projection_services_tests')) { $headunitTestArguments += (Join-Path $headunitRoot 'tests/fixtures/pair-setup-vectors.txt') }
        if ($headunitTest -in @('projection_receiver_tests','projection_services_tests')) { $headunitTestArguments += (Join-Path $headunitRoot 'tests/fixtures/projection-session-vectors.txt') }
        & $headunitExe @headunitTestArguments
        if ($LASTEXITCODE -ne 0) { throw "Sanitized tests failed: $headunitTest" }
    }
} finally { $env:Path = $headunitSavedTlsPath }
Write-Output 'PASS: TLS adapter, protocol dependencies and Mbed TLS built with AddressSanitizer/UndefinedBehaviorSanitizer.'
if ($IncludeEnrollment) { Write-Output 'PASS: SRP/pair-setup, Monocypher, Windows store, MFiSAP/control and initial receiver router also instrumented; synthetic credentials/provider only, no target execution or MFi acceptance claim.' }
