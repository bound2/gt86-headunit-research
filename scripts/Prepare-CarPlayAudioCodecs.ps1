# Pinned source-only checkouts; no install, phone, output device or credentials.
$ErrorActionPreference = 'Stop'
$codecRoot = Split-Path -Parent $PSScriptRoot
$codecPins = @(
    @{ Directory='opus-1.6.1'; Url='https://github.com/xiph/opus.git'; Tag='v1.6.1'; Commit='22244de5a79bd1d6d623c32e72bf1954b56235be' },
    @{ Directory='faad2-2.11.3'; Url='https://github.com/knik0/faad2.git'; Tag='2.11.3'; Commit='6918ebb51b8f7e86278da15884bd7114e4b9661e' }
)
New-Item -ItemType Directory -Force (Join-Path $codecRoot 'build') | Out-Null
foreach ($codecPin in $codecPins) {
    $codecDirectory = Join-Path $codecRoot ('build/' + $codecPin.Directory)
    if (-not (Test-Path -LiteralPath $codecDirectory)) {
        git -c core.autocrlf=false -c advice.detachedHead=false clone --depth 1 --branch $codecPin.Tag $codecPin.Url $codecDirectory
        if ($LASTEXITCODE -ne 0) { throw "Codec clone failed: $($codecPin.Directory)" }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $codecDirectory '.git') -PathType Container)) { throw "Not an owned source checkout: $codecDirectory" }
    $codecHead = git -C $codecDirectory rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $codecHead -ne $codecPin.Commit) { throw "Codec commit mismatch: $codecDirectory" }
    $codecStatus = git -C $codecDirectory status --porcelain --untracked-files=all --ignored=matching
    if ($LASTEXITCODE -ne 0 -or $codecStatus) { throw "Codec checkout changed (including extra/ignored files); preserved, not overwritten: $codecDirectory" }
    git -C $codecDirectory diff --quiet HEAD --
    if ($LASTEXITCODE -ne 0) { throw "Codec tracked source mismatch: $codecDirectory" }
    Write-Output "Verified clean codec source $($codecPin.Directory) at $codecHead"
}
