param(
    [string]$LlvmDirectory = 'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin'
)
$ErrorActionPreference = 'Stop'
$headunitRoot = Split-Path -Parent $PSScriptRoot
$headunitClang = Join-Path $LlvmDirectory 'clang.exe'
$headunitLinker = Join-Path $LlvmDirectory 'ld.lld.exe'
$headunitNm = Join-Path $LlvmDirectory 'llvm-nm.exe'
foreach ($headunitTool in @($headunitClang, $headunitLinker, $headunitNm)) {
    if (-not (Test-Path -LiteralPath $headunitTool -PathType Leaf)) {
        throw "Missing LLVM tool: $headunitTool. Set -LlvmDirectory to the installed tools."
    }
}
$headunitOutput = Join-Path $headunitRoot 'build/carplay-arm'
New-Item -ItemType Directory -Path $headunitOutput -Force | Out-Null
$headunitObjects = @()
foreach ($headunitName in @('iap2_wire', 'iap2_auth', 'iap2_link', 'iap2_control', 'iap2_identification', 'iap2_transport', 'iap2_carplay', 'iap2_power', 'usbmux_wire', 'usbmux_host', 'usbmux_connection', 'usbmux_dispatcher', 'lockdown_wire', 'lockdown_channel')) {
    $headunitSource = Join-Path $headunitRoot "src/carplay/$headunitName.c"
    $headunitObject = Join-Path $headunitOutput "$headunitName.o"
    & $headunitClang --target=armv7-none-eabi -mcpu=cortex-a8 -mfloat-abi=soft `
        -std=c99 -ffreestanding -fno-builtin -O2 -Wall -Wextra -Werror `
        -c $headunitSource -o $headunitObject
    if ($LASTEXITCODE -ne 0) { throw "ARM compilation failed: $headunitName" }
    $headunitObjects += $headunitObject
}
$headunitCombined = Join-Path $headunitOutput 'carplay_protocol.o'
& $headunitLinker --relocatable -m armelf -o $headunitCombined @headunitObjects
if ($LASTEXITCODE -ne 0) { throw 'ARM relocatable link failed' }
$headunitUndefined = & $headunitNm --undefined-only $headunitCombined
if ($LASTEXITCODE -ne 0) { throw 'ARM symbol inspection failed' }
if ($headunitUndefined) { throw "Unexpected undefined ARM symbols: $headunitUndefined" }
Write-Output 'PASS: C99 receiver components compile as 32-bit ARM and link without runtime imports.'
Write-Output 'This is a relocatable portability-check object, not a QNX executable or installable update.'
