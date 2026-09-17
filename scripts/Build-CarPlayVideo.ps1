$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayCrypto.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayTls.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayVideoCodec.ps1')
$videoBuildPath = $env:Path
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    Remove-Item Env:PATH
    $env:Path = $videoBuildPath
    cmake -S . -B build/video -G 'Visual Studio 17 2022' -A x64 "-DCARPLAY_OPENH264_SOURCE=$PWD/build/openh264-2.6.0" "-DCARPLAY_MONOCYPHER_SOURCE=$PWD/build/monocypher-4.0.3" "-DCARPLAY_MBEDTLS_SOURCE=$PWD/build/mbedtls-3.6.7"
    if ($LASTEXITCODE -ne 0) { throw 'Video configure failed' }
    cmake --build build/video --config Release -- /verbosity:quiet
    if ($LASTEXITCODE -ne 0) { throw 'Video build failed' }
    ctest --test-dir build/video -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Video tests failed' }
} finally { $env:Path = $videoBuildPath; Pop-Location }
