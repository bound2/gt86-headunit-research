# Host-only, pinned source preparation. No install, device access or key generation.
$ErrorActionPreference = 'Stop'
$headunitRoot = Split-Path -Parent $PSScriptRoot
$headunitArchive = Join-Path $headunitRoot 'downloads/monocypher-4.0.3.tar.gz'
$headunitSource = Join-Path $headunitRoot 'build/monocypher-4.0.3'
$headunitPins = [ordered]@{
    'src/monocypher.c' = '57eb914fc88136119bd41655cccb8c250048bf54d470540625186f8ab16f64be'
    'src/monocypher.h' = 'c494da712122da7ff679fdcf318a5317e84972b6c950fe9d896212947797facd'
    'src/optional/monocypher-ed25519.c' = '60fce3578fb00b00da96490653d993c4cb427b1e1be38183285c66e04d22cc18'
    'src/optional/monocypher-ed25519.h' = 'abc4fad381879f5c29176ebe014b9189956b3dfe0a3e36459b6990bc57212380'
    'LICENCE.md' = '5f8360e4c06ddcc584bdb4b210c6af824c4bb301e6a9a521869b6d90795ca4b3'
    'AUTHORS.md' = '75a4d04559754a1016006f2c0e194cc7b459583cf9b1e2ce4ec10c74cb3de578'
}
New-Item -ItemType Directory -Force (Join-Path $headunitRoot 'downloads'), (Join-Path $headunitRoot 'build') | Out-Null
if (-not (Test-Path -LiteralPath $headunitArchive)) {
    Invoke-WebRequest -UseBasicParsing 'https://monocypher.org/download/monocypher-4.0.3.tar.gz' -OutFile $headunitArchive
}
if ((Get-FileHash -LiteralPath $headunitArchive -Algorithm SHA256).Hash -ne '8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66') { throw 'Monocypher archive hash mismatch' }
# Extract only known regular source/license members; avoid documentation symlinks.
# Existing files are checked, never overwritten (even if a prior extraction failed).
foreach ($headunitEntry in $headunitPins.GetEnumerator()) {
    $headunitFile = Join-Path $headunitSource $headunitEntry.Key
    if (-not (Test-Path -LiteralPath $headunitFile)) {
        tar -xf $headunitArchive -C (Join-Path $headunitRoot 'build') ('monocypher-4.0.3/' + $headunitEntry.Key)
        if ($LASTEXITCODE -ne 0) { throw "Monocypher member extraction failed: $($headunitEntry.Key)" }
    }
    if ((Get-FileHash -LiteralPath $headunitFile -Algorithm SHA256).Hash -ne $headunitEntry.Value) { throw "Monocypher source hash mismatch: $($headunitEntry.Key)" }
}
Write-Output "Verified Monocypher 4.0.3 archive and all six used source/license files: $headunitSource"
