# Public source only; no firmware, install, device access or prebuilt DLL.
$ErrorActionPreference = 'Stop'
$videoRoot = Split-Path -Parent $PSScriptRoot
$videoSource = Join-Path $videoRoot 'build/openh264-2.6.0'
New-Item -ItemType Directory -Force (Join-Path $videoRoot 'build') | Out-Null
if (-not (Test-Path -LiteralPath $videoSource)) {
    git -c core.autocrlf=false -c advice.detachedHead=false clone --depth 1 --branch v2.6.0 https://github.com/cisco/openh264.git $videoSource
    if ($LASTEXITCODE -ne 0) { throw 'OpenH264 clone failed' }
}
if (-not (Test-Path -LiteralPath (Join-Path $videoSource '.git') -PathType Container)) { throw 'OpenH264 must be a source checkout' }
$videoHead = git -C $videoSource rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $videoHead -ne '652bdb7719f30b52b08e506645a7322ff1b2cc6f') { throw 'OpenH264 commit mismatch' }
$videoChanges = git -C $videoSource status --porcelain --untracked-files=all --ignored=matching
if ($LASTEXITCODE -ne 0 -or $videoChanges) { throw 'OpenH264 checkout changed; preserved, not overwritten' }
git -C $videoSource diff --quiet HEAD --
if ($LASTEXITCODE -ne 0) { throw 'OpenH264 tracked source mismatch' }
Write-Output "Verified clean OpenH264 2.6.0 source at $videoHead"
