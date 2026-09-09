param(
    [Parameter(Mandatory=$true)][string]$InputFile,
    [Parameter(Mandatory=$true)][uint64]$BaseOffset,
    [Parameter(Mandatory=$true)][string]$DirectoryJson,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$entries = Get-Content -LiteralPath $DirectoryJson -Raw | ConvertFrom-Json
$root = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($root) | Out-Null
$inputStream = [IO.File]::OpenRead((Resolve-Path -LiteralPath $InputFile))
try {
    foreach ($entry in $entries) {
        if ($entry.Name -notmatch '^(swdl\.iso(\.md5)?|swdlInstall\.iso(\.md5)?|KaliSWDL\.log)$') { continue }
        [int64]$relative = [int64]$entry.LocalHeaderOffset - [int64]$BaseOffset
        if ($relative -lt 0 -or $relative -ge $inputStream.Length) { continue }
        $inputStream.Position = $relative
        $header = New-Object byte[] 30
        if ($inputStream.Read($header, 0, 30) -ne 30) { throw 'Truncated local header' }
        if ([BitConverter]::ToUInt32($header, 0) -ne 0x04034b50) { throw 'Bad ZIP local header signature' }
        if (($entry.Flags -band 1) -ne 0) { throw 'Encrypted ZIP entries are not supported' }
        if ([BitConverter]::ToUInt16($header, 8) -ne $entry.Method) { throw 'Method mismatch' }
        $nameLen = [BitConverter]::ToUInt16($header, 26)
        $extraLen = [BitConverter]::ToUInt16($header, 28)
        $nameBytes = New-Object byte[] $nameLen
        if ($inputStream.Read($nameBytes, 0, $nameLen) -ne $nameLen) { throw 'Truncated ZIP name' }
        if ([Text.Encoding]::UTF8.GetString($nameBytes) -cne $entry.Name) { throw 'ZIP filename mismatch' }
        $inputStream.Position += $extraLen
        if ($entry.CompressedSize -gt 536870912 -or $entry.Size -gt 1073741824) { throw 'Entry exceeds research size limit' }
        if ($inputStream.Position + $entry.CompressedSize -gt $inputStream.Length) { throw 'Entry extends beyond downloaded range' }
        $payload = New-Object byte[] ([int]$entry.CompressedSize)
        $done = 0
        while ($done -lt $payload.Length) {
            $read = $inputStream.Read($payload, $done, $payload.Length - $done)
            if ($read -eq 0) { throw 'Truncated compressed payload' }
            $done += $read
        }
        $memory = [IO.MemoryStream]::new($payload, $false)
        $outputPath = Join-Path $root $entry.Name
        $outputStream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew)
        $decoder = $null
        try {
            if ($entry.Method -eq 8) {
                $decoder = [IO.Compression.DeflateStream]::new($memory, [IO.Compression.CompressionMode]::Decompress)
                $source = $decoder
            } elseif ($entry.Method -eq 0) { $source = $memory }
            else { throw 'Unsupported ZIP compression method' }
            $buffer = New-Object byte[] 65536
            [int64]$total = 0
            while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $read
                if ($total -gt $entry.Size) { throw 'Decompressed payload exceeds declared size' }
                $outputStream.Write($buffer, 0, $read)
            }
            if ($total -ne $entry.Size) { throw 'Decompressed size mismatch' }
        } finally {
            if ($decoder) { $decoder.Dispose() }
            $memory.Dispose()
            $outputStream.Dispose()
        }
        Get-FileHash -LiteralPath $outputPath -Algorithm SHA256 | Select-Object Path,Hash
    }
} finally { $inputStream.Dispose() }
