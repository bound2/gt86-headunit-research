$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayCrypto.ps1')
& (Join-Path $PSScriptRoot 'Prepare-CarPlayTls.ps1')
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $headunitCryptoPath = $env:Path
    Remove-Item Env:PATH
    $env:Path = $headunitCryptoPath
    cmake -S . -B build/crypto -G 'Visual Studio 17 2022' -A x64 "-DCARPLAY_MONOCYPHER_SOURCE=$PWD/build/monocypher-4.0.3" "-DCARPLAY_MBEDTLS_SOURCE=$PWD/build/mbedtls-3.6.7"
    if ($LASTEXITCODE -ne 0) { throw 'Pairing configure failed' }
    cmake --build build/crypto --config Release -- /verbosity:quiet
    if ($LASTEXITCODE -ne 0) { throw 'Pairing build failed' }
    ctest --test-dir build/crypto -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Pairing tests failed' }
} finally { Pop-Location }
