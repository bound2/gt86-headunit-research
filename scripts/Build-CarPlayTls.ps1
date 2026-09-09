$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Prepare-CarPlayTls.ps1')
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $headunitTlsPath = $env:Path
    Remove-Item Env:PATH
    $env:Path = $headunitTlsPath
    cmake -S . -B build/tls -G 'Visual Studio 17 2022' -A x64 "-DCARPLAY_MBEDTLS_SOURCE=$PWD/build/mbedtls-3.6.7"
    if ($LASTEXITCODE -ne 0) { throw 'TLS configure failed' }
    cmake --build build/tls --config Release -- /verbosity:quiet
    if ($LASTEXITCODE -ne 0) { throw 'TLS build failed' }
    ctest --test-dir build/tls -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'TLS tests failed' }
} finally { Pop-Location }
