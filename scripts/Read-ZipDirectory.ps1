param(
    [Parameter(Mandatory=$true)][string]$Tail,
    [Parameter(Mandatory=$true)][string]$OutputJson
)
$ErrorActionPreference = 'Stop'
$bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Tail))
function U16([int]$p) { [BitConverter]::ToUInt16($bytes, $p) }
function U32([int]$p) { [BitConverter]::ToUInt32($bytes, $p) }
function U64([int]$p) { [BitConverter]::ToUInt64($bytes, $p) }
$eocd = -1
for ($p = $bytes.Length - 22; $p -ge [Math]::Max(0, $bytes.Length - 65557); $p--) {
    if ((U32 $p) -eq 0x06054b50 -and $p + 22 + (U16 ($p + 20)) -eq $bytes.Length) { $eocd = $p; break }
}
if ($eocd -lt 0) { throw 'ZIP end-of-central-directory record not found' }
if ((U16 ($eocd + 4)) -ne 0 -or (U16 ($eocd + 6)) -ne 0) { throw 'Multi-disk ZIP is unsupported' }
[uint64]$expectedCount = U16 ($eocd + 10)
[uint64]$directorySize = U32 ($eocd + 12)
$directoryEnd = $eocd
if ($eocd -ge 20 -and (U32 ($eocd - 20)) -eq 0x07064b50) {
    $zip64 = -1
    for ($p = $eocd - 76; $p -ge 0; $p--) {
        if ((U32 $p) -eq 0x06064b50 -and $p + 12 + (U64 ($p + 4)) -eq $eocd - 20) { $zip64 = $p; break }
    }
    if ($zip64 -lt 0) { throw 'ZIP64 directory metadata missing from downloaded tail' }
    if ((U32 ($zip64 + 16)) -ne 0 -or (U32 ($zip64 + 20)) -ne 0) { throw 'Multi-disk ZIP64 is unsupported' }
    $expectedCount = U64 ($zip64 + 32)
    $directorySize = U64 ($zip64 + 40)
    $directoryEnd = $zip64
}
if ($directorySize -gt $directoryEnd) { throw 'Downloaded tail does not contain the complete ZIP directory' }
$directoryStart = $directoryEnd - [int]$directorySize
$entries = @()
for ($i = $directoryStart; $i -lt $directoryEnd; $i++) {
    if ($i + 46 -gt $directoryEnd -or (U32 $i) -ne 0x02014b50) { throw 'Invalid central directory record' }
    $nameLen = U16 ($i + 28)
    $extraLen = U16 ($i + 30)
    $commentLen = U16 ($i + 32)
    if ($i + 46 + $nameLen + $extraLen + $commentLen -gt $directoryEnd) { throw 'Truncated ZIP directory record' }
    $name = [Text.Encoding]::UTF8.GetString($bytes, $i + 46, $nameLen)
    [uint64]$compressed = U32 ($i + 20)
    [uint64]$size = U32 ($i + 24)
    [uint64]$offset = U32 ($i + 42)
    $extraPos = $i + 46 + $nameLen
    $extraEnd = $extraPos + $extraLen
    while ($extraPos + 4 -le $extraEnd) {
        $tag = U16 $extraPos
        $len = U16 ($extraPos + 2)
        $p = $extraPos + 4
        if ($p + $len -gt $extraEnd) { throw 'Invalid ZIP extra field' }
        if ($tag -eq 1) {
            $needed = 0
            if ($size -eq 4294967295) { $needed += 8 }
            if ($compressed -eq 4294967295) { $needed += 8 }
            if ($offset -eq 4294967295) { $needed += 8 }
            if ($len -lt $needed) { throw 'Truncated ZIP64 extra field' }
            if ($size -eq 4294967295) { $size = U64 $p; $p += 8 }
            if ($compressed -eq 4294967295) { $compressed = U64 $p; $p += 8 }
            if ($offset -eq 4294967295) { $offset = U64 $p }
        }
        $extraPos += 4 + $len
    }
    $entries += [pscustomobject]@{
        Name=$name; Method=(U16 ($i + 10)); Flags=(U16 ($i + 8));
        CRC32=('{0:x8}' -f (U32 ($i + 16))); Size=$size;
        CompressedSize=$compressed; LocalHeaderOffset=$offset
    }
    $i += 45 + $nameLen + $extraLen + $commentLen
}
if ($entries.Count -ne $expectedCount) { throw 'ZIP directory count does not match end record' }
$entries | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputJson -Encoding UTF8
Write-Output "Saved $($entries.Count) directory records to $OutputJson"
$entries | Where-Object { $_.Name -notlike 'nav/*' } | Format-List
