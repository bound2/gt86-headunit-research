param([Parameter(Mandatory=$true)][string]$BuildDirectory)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$scratch = Join-Path $BuildDirectory ('zip-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
Add-Type -AssemblyName System.IO.Compression

# Independent ZIP encoder provides a real deflated entry to test the whole path.
$zipPath = Join-Path $scratch 'sample.zip'
$file = [IO.File]::Create($zipPath)
$zip = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Create)
try {
    $entry = $zip.CreateEntry('swdl.iso')
    $stream = $entry.Open()
    try {
        $payload = [Text.Encoding]::ASCII.GetBytes('123456789')
        $stream.Write($payload, 0, $payload.Length)
    } finally { $stream.Dispose() }
} finally { $zip.Dispose(); $file.Dispose() }
$json = Join-Path $scratch 'directory.json'
& "$project/scripts/Read-ZipDirectory.ps1" -Tail $zipPath -OutputJson $json | Out-Null
$record = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
if ($record.CRC32 -cne 'cbf43926' -or $record.Size -ne 9) { throw 'ZIP directory roundtrip failed' }
$expanded = Join-Path $scratch 'expanded'
& "$project/scripts/Expand-ZipRange.ps1" -InputFile $zipPath -BaseOffset 0 -DirectoryJson $json -OutputDirectory $expanded | Out-Null
if ([IO.File]::ReadAllText((Join-Path $expanded 'swdl.iso')) -cne '123456789') { throw 'Deflate extraction failed' }

# Synthetic central directory: ZIP64 offset >4 GiB catches signed sentinel bugs.
$name = [Text.Encoding]::ASCII.GetBytes('swdl.iso')
$central = New-Object byte[] (46 + $name.Length + 12)
[BitConverter]::GetBytes([uint32]0x02014b50).CopyTo($central, 0)
[BitConverter]::GetBytes([uint16]$name.Length).CopyTo($central, 28)
[BitConverter]::GetBytes([uint16]12).CopyTo($central, 30)
[BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($central, 42)
$name.CopyTo($central, 46)
$p = 46 + $name.Length
[BitConverter]::GetBytes([uint16]1).CopyTo($central, $p)
[BitConverter]::GetBytes([uint16]8).CopyTo($central, $p + 2)
[BitConverter]::GetBytes([uint64]5035207263).CopyTo($central, $p + 4)
$end = New-Object byte[] 22
[BitConverter]::GetBytes([uint32]0x06054b50).CopyTo($end, 0)
[BitConverter]::GetBytes([uint16]1).CopyTo($end, 8)
[BitConverter]::GetBytes([uint16]1).CopyTo($end, 10)
[BitConverter]::GetBytes([uint32]$central.Length).CopyTo($end, 12)
$fixture = Join-Path $scratch 'zip64-directory.bin'
[IO.File]::WriteAllBytes($fixture, [byte[]]($central + $end))
& "$project/scripts/Read-ZipDirectory.ps1" -Tail $fixture -OutputJson $json | Out-Null
$record = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
if ($record.LocalHeaderOffset -ne 5035207263) { throw 'ZIP64 offset was truncated or misread' }

# A truncated tail must be rejected, not produce a plausible partial inventory.
$truncated = Join-Path $scratch 'truncated.bin'
[IO.File]::WriteAllBytes($truncated, $central)
$rejected = $false
try { & "$project/scripts/Read-ZipDirectory.ps1" -Tail $truncated -OutputJson $json | Out-Null }
catch { $rejected = $true }
if (-not $rejected) { throw 'Truncated ZIP was accepted' }
Write-Output 'ZIP roundtrip, ZIP64 offset and truncated-tail tests passed'
