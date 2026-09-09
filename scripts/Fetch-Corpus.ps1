# Public Toyota download; only fetches firmware entries, not the map payload.
# Requires a built fwinspect.exe. Never accesses the vehicle.
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $url = 'https://mapupdatecontent.toyota-europe.com/Updates/Toyota/6.17.0L_EU/6.17.0L_EU.zip'
    if (-not (Test-Path build/Release/fwinspect.exe)) { throw 'Run scripts/Build.ps1 first' }
    $names = @('KaliSWDL.log', 'swdl.iso', 'swdl.iso.md5', 'swdlInstall.iso', 'swdlInstall.iso.md5')
    $present = @($names | Where-Object { Test-Path -LiteralPath (Join-Path 'downloads/6.17.0L' $_) })
    if ($present.Count -eq $names.Count) { & "$PSScriptRoot/Verify-Firmware.ps1"; return }
    if ($present.Count -gt 0) { throw 'Partial corpus exists. Preserve it and use a fresh project copy for a clean fetch.' }
    New-Item -ItemType Directory -Path downloads -Force | Out-Null
    $requests = @(
        @{ Name='tail'; Start=5224498196L; End=5224629267L },
        @{ Name='firmware-range'; Start=5035207263L; End=5224501483L },
        @{ Name='log-range'; Start=0L; End=18175L }
    )
    foreach ($request in $requests) {
        $file = "downloads/6.17.0L-$($request.Name).bin"
        $headers = "downloads/6.17.0L-$($request.Name).headers.txt"
        $range = "$($request.Start)-$($request.End)"
        & curl.exe --fail --silent --show-error --location --max-time 180 --range $range --dump-header $headers --output $file $url
        if ($LASTEXITCODE -ne 0) { throw "Download failed: $file" }
        if ((Get-Item -LiteralPath $file).Length -ne $request.End - $request.Start + 1) { throw 'HTTP range size mismatch' }
        $headerText = Get-Content -LiteralPath $headers -Raw
        if ($headerText -notmatch [regex]::Escape("Content-Range: bytes $range/5224629268")) { throw 'HTTP Content-Range mismatch' }
    }
    & "$PSScriptRoot/Read-ZipDirectory.ps1" -Tail downloads/6.17.0L-tail.bin -OutputJson reports/6.17.0L-zip-directory.json
    & "$PSScriptRoot/Expand-ZipRange.ps1" -InputFile downloads/6.17.0L-firmware-range.bin -BaseOffset 5035207263 -DirectoryJson reports/6.17.0L-zip-directory.json -OutputDirectory downloads/6.17.0L
    & "$PSScriptRoot/Expand-ZipRange.ps1" -InputFile downloads/6.17.0L-log-range.bin -BaseOffset 0 -DirectoryJson reports/6.17.0L-zip-directory.json -OutputDirectory downloads/6.17.0L
    & "$PSScriptRoot/Verify-Firmware.ps1"
} finally { Pop-Location }
