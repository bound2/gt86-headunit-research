param(
    [string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin',
    [string]$NMake = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/nmake.exe',
    [string]$SdkBin = 'C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64'
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayCrypto.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayTls.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayAudioCodecs.ps1')
$mediaSanRoot = Split-Path -Parent $PSScriptRoot
$mediaSanSavedPath = $env:Path
Push-Location $mediaSanRoot
try {
    $mediaSanClang = Join-Path $LlvmDirectory 'clang.exe'
    $mediaSanCpp = Join-Path $LlvmDirectory 'clang++.exe'
    $mediaSanResource = & $mediaSanClang --print-resource-dir
    if ($LASTEXITCODE -ne 0) { throw 'LLVM resource lookup failed' }
    Remove-Item Env:PATH
    $env:Path = (Join-Path $mediaSanResource 'lib/windows') + ';' + $mediaSanSavedPath
    $mediaSanFlags = '-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all'
    cmake -S . -B build/media-sanitized -G 'NMake Makefiles' "-DCMAKE_MAKE_PROGRAM=$NMake" `
        "-DCMAKE_RC_COMPILER=$SdkBin/rc.exe" "-DCMAKE_MT=$SdkBin/mt.exe" `
        "-DCMAKE_C_COMPILER=$mediaSanClang" "-DCMAKE_CXX_COMPILER=$mediaSanCpp" `
        "-DCMAKE_C_FLAGS=$mediaSanFlags" "-DCMAKE_CXX_FLAGS=$mediaSanFlags" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
        '-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O1 -g' '-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-O1 -g' -DCMAKE_EXPORT_COMPILE_COMMANDS=ON `
        "-DCARPLAY_MONOCYPHER_SOURCE=$PWD/build/monocypher-4.0.3" "-DCARPLAY_MBEDTLS_SOURCE=$PWD/build/mbedtls-3.6.7" `
        "-DCARPLAY_OPUS_SOURCE=$PWD/build/opus-1.6.1" "-DCARPLAY_FAAD_SOURCE=$PWD/build/faad2-2.11.3"
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized media configure failed' }
    cmake --build build/media-sanitized --target projection_decode_tests projection_decode_services_tests
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized media build failed' }
    ctest --test-dir build/media-sanitized -R '^projection_decode(_services)?_tests$' --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized media tests failed' }
} finally { $env:Path = $mediaSanSavedPath; Pop-Location }
Write-Output 'PASS: both media tests and their full linked dependencies (including Opus and FAAD2) built with ASan/UBSan; no physical playback.'
