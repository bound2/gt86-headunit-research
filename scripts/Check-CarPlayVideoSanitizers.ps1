param(
    [string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin',
    [string]$NMake = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/nmake.exe',
    [string]$SdkBin = 'C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64'
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayVideoCodec.ps1')
$videoSanSavedPath = $env:Path
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $videoSanClang = Join-Path $LlvmDirectory 'clang.exe'
    $videoSanCpp = Join-Path $LlvmDirectory 'clang++.exe'
    $videoSanResource = & $videoSanClang --print-resource-dir
    if ($LASTEXITCODE -ne 0) { throw 'LLVM resource lookup failed' }
    Remove-Item Env:PATH
    $env:Path = (Join-Path $videoSanResource 'lib/windows') + ';' + $videoSanSavedPath
    $videoSanFlags = '-g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all'
    cmake -S . -B build/video-sanitized -G 'NMake Makefiles' "-DCMAKE_MAKE_PROGRAM=$NMake" `
        "-DCMAKE_RC_COMPILER=$SdkBin/rc.exe" "-DCMAKE_MT=$SdkBin/mt.exe" `
        "-DCMAKE_C_COMPILER=$videoSanClang" "-DCMAKE_CXX_COMPILER=$videoSanCpp" `
        "-DCMAKE_C_FLAGS=$videoSanFlags" "-DCMAKE_CXX_FLAGS=$videoSanFlags" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
        '-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O1 -g' '-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-O1 -g' -DCMAKE_EXPORT_COMPILE_COMMANDS=ON `
        "-DCARPLAY_OPENH264_SOURCE=$PWD/build/openh264-2.6.0"
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized video configure failed' }
    cmake --build build/video-sanitized --target projection_h264_tests
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized video build failed' }
    ctest --test-dir build/video-sanitized -R '^projection_h264_tests$' --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Sanitized video tests failed' }
} finally { $env:Path = $videoSanSavedPath; Pop-Location }
Write-Output 'PASS: video adapter, tests and generic OpenH264 dependency instrumented with ASan/UBSan; no target execution.'
