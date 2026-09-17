param([string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin')
$ErrorActionPreference = 'Stop'
$pixelsRoot = Split-Path -Parent $PSScriptRoot
$pixelsClang = Join-Path $LlvmDirectory 'clang.exe'
$pixelsNm = Join-Path $LlvmDirectory 'llvm-nm.exe'
$pixelsOutput = Join-Path $pixelsRoot 'build/carplay-video-arm'
New-Item -ItemType Directory -Force -Path $pixelsOutput | Out-Null
$pixelsObject = Join-Path $pixelsOutput 'projection_video_pixels.o'
& $pixelsClang --target=armv7-none-eabi -mcpu=cortex-a8 -mfloat-abi=soft `
    -std=c99 -ffreestanding -fno-builtin -O2 -Wall -Wextra -Werror `
    -c (Join-Path $pixelsRoot 'src/carplay/projection_video_pixels.c') -o $pixelsObject
if ($LASTEXITCODE -ne 0) { throw 'ARM pixel conversion compilation failed' }
$pixelsUndefined = @(& $pixelsNm --undefined-only $pixelsObject)
if ($LASTEXITCODE -ne 0) { throw 'ARM pixel symbol inspection failed' }
$pixelsSymbols = @($pixelsUndefined | ForEach-Object { ($_ -split '\s+')[-1] } | Sort-Object -Unique)
if (($pixelsSymbols -join ',') -ne '__aeabi_uidiv,__aeabi_uldivmod') { throw "Unexpected ARM pixel runtime imports: $pixelsSymbols" }
Write-Output 'PASS: C99 pixels/source-aspect fit compile to 32-bit ARM; required runtime helpers: __aeabi_uidiv, __aeabi_uldivmod.'
Write-Output 'Separate from the import-free core claim. Not a QNX build, rendering backend or target execution.'
