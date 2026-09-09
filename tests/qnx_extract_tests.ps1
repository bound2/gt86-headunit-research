param([Parameter(Mandatory=$true)][string]$Inspector, [Parameter(Mandatory=$true)][string]$FixtureGenerator)
$ErrorActionPreference='Stop'
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('gt86-qnx-test-'+[guid]::NewGuid())
[void][IO.Directory]::CreateDirectory($testRoot)
try {
    $fixture=Join-Path $testRoot 'fixture.bin'
    $output=Join-Path $testRoot 'output'
    & $FixtureGenerator --write-fixture $fixture
    if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed' }
    & $Inspector unpack $fixture $output
    if ($LASTEXITCODE -ne 0) { throw 'Extraction failed' }
    $rows=Import-Csv -Delimiter "`t" (Join-Path $output 'inventory.tsv')
    $files=@($rows | Where-Object type -eq 'file')
    if ($files.Count -ne 2) { throw 'Missing duplicate entry' }
    $first=[IO.File]::ReadAllBytes((Join-Path $output $files[0].extracted_path))
    $second=[IO.File]::ReadAllBytes((Join-Path $output $files[1].extracted_path))
    if ([BitConverter]::ToString($first) -ne '61-62-63-00' -or [BitConverter]::ToString($second) -ne '78-79-7A-00') { throw 'Duplicate payload was lost' }
    if (Test-Path -LiteralPath (Join-Path $output 'image-0/link')) { throw 'Archive symlink was materialized' }
    & $Inspector unpack $fixture $output
    if ($LASTEXITCODE -eq 0) { throw 'Existing extraction root was accepted' }
    Write-Output 'QNX extraction integration tests passed'
} finally {
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if (!$resolved.StartsWith($tempBase,[StringComparison]::OrdinalIgnoreCase) -or !(Split-Path -Leaf $resolved).StartsWith('gt86-qnx-test-')) { throw 'Invalid cleanup target' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
