param(
    [string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin',
    [string]$NMake = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/nmake.exe',
    [string]$SdkBin = 'C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64',
    [string]$MsvcLib = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/lib/x64',
    [string]$SdkLib = 'C:/Program Files (x86)/Windows Kits/10/Lib/10.0.22621.0'
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayCrypto.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayTls.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayVideoCodec.ps1')
$videoSanSavedPath = $env:Path
$videoSanSavedLib = $env:LIB
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    # Mbed TLS selects MSVC-style flags for this ABI. Use the actual matching
    # clang-cl driver, not a spoofed compiler identity or patched dependency.
    $videoSanClang = Join-Path $LlvmDirectory 'clang-cl.exe'
    $videoSanCpp = $videoSanClang
    $videoSanResource = & (Join-Path $LlvmDirectory 'clang.exe') --print-resource-dir
    if ($LASTEXITCODE -ne 0) { throw 'LLVM resource lookup failed' }
    Remove-Item Env:PATH
    $env:Path = (Join-Path $videoSanResource 'lib/windows') + ';' + $videoSanSavedPath
    $videoSanLibs = @((Join-Path $videoSanResource 'lib/windows'), $MsvcLib, (Join-Path $SdkLib 'um/x64'), (Join-Path $SdkLib 'ucrt/x64'))
    foreach ($videoSanLib in $videoSanLibs) { if (-not (Test-Path -LiteralPath $videoSanLib)) { throw "Missing library directory: $videoSanLib" } }
    $env:LIB = ($videoSanLibs -join ';') + ';' + $videoSanSavedLib
    $videoSanFlags = '/Z7 /O1 -fsanitize=address,undefined -fno-sanitize-recover=all'
    # CMake invokes lld-link directly, so supply the two static runtime archives
    # emitted by this clang-cl driver's -### link command for /MT + ASan/UBSan.
    $videoSanLinkFlags = '/INCREMENTAL:NO /WHOLEARCHIVE:clang_rt.asan-x86_64.lib /WHOLEARCHIVE:clang_rt.asan_cxx-x86_64.lib'
    cmake -S . -B build/video-service-sanitized -G 'NMake Makefiles' "-DCMAKE_MAKE_PROGRAM=$NMake" `
        "-DCMAKE_RC_COMPILER=$SdkBin/rc.exe" "-DCMAKE_MT=$SdkBin/mt.exe" `
        "-DCMAKE_C_COMPILER=$videoSanClang" "-DCMAKE_CXX_COMPILER=$videoSanCpp" `
        "-DCMAKE_C_FLAGS=$videoSanFlags" "-DCMAKE_CXX_FLAGS=$videoSanFlags /EHsc" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
        "-DCMAKE_EXE_LINKER_FLAGS=$videoSanLinkFlags" `
        '-DCMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO=/DEBUG /INCREMENTAL:NO' '-DCMAKE_EXE_LINKER_FLAGS_DEBUG=/DEBUG /INCREMENTAL:NO' `
        '-DCMAKE_C_FLAGS_RELWITHDEBINFO=/O1 /Z7' '-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=/O1 /Z7' -DCMAKE_EXPORT_COMPILE_COMMANDS=ON `
        "-DCARPLAY_OPENH264_SOURCE=$PWD/build/openh264-2.6.0" "-DCARPLAY_MONOCYPHER_SOURCE=$PWD/build/monocypher-4.0.3" "-DCARPLAY_MBEDTLS_SOURCE=$PWD/build/mbedtls-3.6.7"
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized video configure failed' }
    cmake --build build/video-service-sanitized --target projection_h264_tests projection_h264_source_tests projection_h264_source_limit_tests projection_video_tests projection_video_limit_tests projection_video_services_tests projection_video_pixels_tests projection_video_gdi_tests
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized video build failed' }
    ctest --test-dir build/video-service-sanitized -R '^projection_(h264|h264_source|h264_source_limit|video|video_limit|video_services|video_pixels|video_gdi)_tests$' --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized video tests failed' }
} finally { $env:Path = $videoSanSavedPath; $env:LIB = $videoSanSavedLib; Pop-Location }
Write-Output 'PASS: video TCP/session/input/decoder/pixel/GDI adapters, tests, Mbed TLS, Monocypher and generic OpenH264 instrumented with ASan/UBSan; Windows DLLs excluded; no vehicle execution.'
