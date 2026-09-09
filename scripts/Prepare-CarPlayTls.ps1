# Host-only dependency preparation. Never reads phone records or touches USB.
$ErrorActionPreference = 'Stop'
$headunitRoot = Split-Path -Parent $PSScriptRoot
$headunitArchive = Join-Path $headunitRoot 'downloads/mbedtls-3.6.7.tar.bz2'
$headunitSource = Join-Path $headunitRoot 'build/mbedtls-3.6.7'
$headunitSha = 'a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6'
New-Item -ItemType Directory -Force (Join-Path $headunitRoot 'downloads'), (Join-Path $headunitRoot 'build') | Out-Null
if (-not (Test-Path -LiteralPath $headunitArchive)) {
    Invoke-WebRequest -UseBasicParsing 'https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2' -OutFile $headunitArchive
}
if ((Get-FileHash -LiteralPath $headunitArchive -Algorithm SHA256).Hash -ne $headunitSha) { throw 'Mbed TLS archive hash mismatch' }
if (-not (Test-Path -LiteralPath $headunitSource)) {
    tar -xf $headunitArchive -C (Join-Path $headunitRoot 'build')
    if ($LASTEXITCODE -ne 0) { throw 'Mbed TLS extraction failed' }
}
Write-Output "Verified archive; source directory: $headunitSource"
Write-Output 'Existing extracted sources are not overwritten or independently reverified.'
