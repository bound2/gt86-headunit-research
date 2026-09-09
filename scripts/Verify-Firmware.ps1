$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $entries = Get-Content reports/6.17.0L-zip-directory.json -Raw | ConvertFrom-Json
    $expectedHashes = Get-Content reports/6.17.0L-sha256.json -Raw | ConvertFrom-Json
    $results = foreach ($item in $expectedHashes) {
        $file = Join-Path 'downloads/6.17.0L' $item.File
        $entry = $entries | Where-Object { $_.Name -ceq $item.File }
        if (-not $entry) { throw "Missing ZIP directory record: $($item.File)" }
        if ((Get-Item -LiteralPath $file).Length -ne $entry.Size) { throw "Size mismatch: $file" }
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        if ($hash -cne $item.Hash) { throw "SHA256 mismatch: $file" }
        $crcResult = & ./build/Release/fwinspect.exe crc $file $entry.CRC32
        if ($LASTEXITCODE -ne 0) { throw "CRC32 mismatch: $file" }
        $md5Matches = $null
        if ($item.File.EndsWith('.iso')) {
            $sidecar = Get-Content -LiteralPath ($file + '.md5') -Raw
            if ($sidecar -notmatch 'MD5\([^\r\n]+\)= ([0-9a-f:]+)') { throw 'Unrecognized MD5 sidecar' }
            $expectedMd5 = $Matches[1].Replace(':', '')
            $md5Matches = (Get-FileHash -LiteralPath $file -Algorithm MD5).Hash -ieq $expectedMd5
            if (-not $md5Matches) { throw "MD5 sidecar mismatch: $file" }
        }
        [pscustomobject]@{File=$item.File;Bytes=$entry.Size;SHA256=$hash;CRC32=$entry.CRC32;CRC32Verified=$true;PublishedMD5Verified=$md5Matches}
    }
    $results | ConvertTo-Json | Set-Content reports/firmware-integrity.json -Encoding UTF8
    $results | Select-Object File,Bytes,CRC32Verified,PublishedMD5Verified | Format-Table
} finally { Pop-Location }
