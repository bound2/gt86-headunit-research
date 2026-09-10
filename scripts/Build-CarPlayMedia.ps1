$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayCrypto.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayTls.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayAudioCodecs.ps1')
$codecBuildPath = $env:Path
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    Remove-Item Env:PATH
    $env:Path = $codecBuildPath
    cmake -S . -B build/media -G 'Visual Studio 17 2022' -A x64 "-DCARPLAY_MONOCYPHER_SOURCE=$PWD/build/monocypher-4.0.3" "-DCARPLAY_MBEDTLS_SOURCE=$PWD/build/mbedtls-3.6.7" "-DCARPLAY_OPUS_SOURCE=$PWD/build/opus-1.6.1" "-DCARPLAY_FAAD_SOURCE=$PWD/build/faad2-2.11.3"
    if ($LASTEXITCODE -ne 0) { throw 'Media configure failed' }
    cmake --build build/media --config Release -- /verbosity:quiet
    if ($LASTEXITCODE -ne 0) { throw 'Media build failed' }
    ctest --test-dir build/media -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Media tests failed' }
} finally { $env:Path = $codecBuildPath; Pop-Location }
