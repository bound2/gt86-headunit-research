$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    # Normalize inherited Path/PATH duplicates that can break MSBuild.
    $headunitBuildPath = $env:Path
    Remove-Item Env:PATH
    $env:Path = $headunitBuildPath
    cmake -S . -B build -G 'Visual Studio 17 2022' -A x64
    if ($LASTEXITCODE -ne 0) { throw 'CMake configure failed' }
    cmake --build build --config Release -- /verbosity:quiet
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    ctest --test-dir build -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
} finally { Pop-Location }
