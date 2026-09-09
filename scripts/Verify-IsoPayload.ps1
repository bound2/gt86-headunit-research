param([string[]]$Path=@('downloads/6.17.0L/swdl.iso','downloads/6.17.0L/swdlInstall.iso'))
$ErrorActionPreference='Stop'
# Reproduce the observed digest comparison, not either vendor signature check.
foreach ($item in $Path) {
    $stream=[IO.File]::OpenRead((Resolve-Path -LiteralPath $item).Path)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        if ($stream.Length -le 32768) { throw "Truncated ISO: $item" }
        [void]$stream.Seek(64,[IO.SeekOrigin]::Begin)
        $stored=New-Object byte[] 32
        if ($stream.Read($stored,0,32) -ne 32) { throw 'Truncated embedded digest' }
        [void]$stream.Seek(32768,[IO.SeekOrigin]::Begin)
        $actual=$sha.ComputeHash($stream)
        $storedHex=[BitConverter]::ToString($stored).Replace('-','').ToLowerInvariant()
        $actualHex=[BitConverter]::ToString($actual).Replace('-','').ToLowerInvariant()
        if ($storedHex -ne $actualHex) { throw "Embedded payload SHA256 mismatch: $item" }
        [pscustomobject]@{File=$item;PayloadOffset=32768;DigestOffset=64;SHA256=$actualHex;PayloadHash='PASS';VendorSignatures='NOT_VERIFIED'}
    } finally { $sha.Dispose(); $stream.Dispose() }
}
