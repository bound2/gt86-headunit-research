# MirrorLink graphics producer: CPU pixels, GLES and EGL presentation

Date: 2026-09-10. Starting checkpoint: `33d7f1b`.
Continues [CarPlay progress, Step 82](carplay-progress.md#step-82---recover-the-omitted-wicome-libraries-and-trace-native-frame-presentation)
and [the factory window-manager trace](factory-graphics-path.md).
Scope: offline inspection of the later `6.17.0WL` corpus. No vendor library was
loaded or executed, and no device or service command was issued.

## Step 1 - Correct the extraction scope before interpreting absence

The original README extraction selected `MMC_PROG_DATA/bin` and
`MMC_PROG_DATA/usr/lib`, but not `MMC_PROG_DATA/wicome`. Therefore earlier
searches of the extracted files did not cover the actual WiCoME implementation.
The existing verified installation ISO contains those additional libraries.
This is an extraction-coverage correction, not a newly downloaded firmware.

The first inspected candidates were not the renderer: `mirrorLinkSvc` has no
direct Screen imports, and the small `libmmlink.so.1` exports `memq_*` queue
operations. Neither filename alone establishes a frame producer.

`bluetooth.sh:25-33` sets the WiCoME resource/library paths and links
`/usr/lib/wicome` to `/fs/mmc0/ifs/wicome`. Its ordinary startup branch launches
`WicomeSCP` using `wicome.cfg`; `connectivity.sh` subsequently waits for the
WiCoME endpoint and conditionally starts `mirrorLinkSvc`. These scripts were
read only. Their presence is not proof that MirrorLink runs on this GT86.

## Step 2 - Extract and verify only the selected additional inputs

Rechecked the complete `swdlInstall.iso` SHA256 against
[the recorded corpus hashes](6.17.0L-sha256.json):
`06bdc5c05b889ae68bd372dd060502226ea911fc0715a646072c59b1832bf30d`.
Listed the selected archive directory and confirmed regular files before
extracting into the fresh, ignored `extracted/factory-wicome-617-step82/` folder.
No existing extraction or ISO was overwritten. Use Windows' bundled bsdtar by
absolute path: the GNU `tar.exe` first found on PATH could not read this ISO.

Reproduction on the PC, from the repository root; an existing output folder is
deliberately refused:

```powershell
$graphicsIso = (Resolve-Path -LiteralPath downloads/6.17.0L/swdlInstall.iso).Path
if ((Get-FileHash -LiteralPath $graphicsIso -Algorithm SHA256).Hash -ne '06BDC5C05B889AE68BD372DD060502226EA911FC0715A646072C59B1832BF30D') { throw 'Unpinned ISO' }
$graphicsOutput = Join-Path (Get-Location).Path 'extracted/factory-wicome-617-step82'
if (Test-Path -LiteralPath $graphicsOutput) { throw 'Refusing existing destination' }
New-Item -ItemType Directory -Path $graphicsOutput | Out-Null
& C:/Windows/System32/tar.exe -xkf $graphicsIso -C $graphicsOutput usr/share/MMC_PROG_DATA/wicome/libpal_graphic.so usr/share/MMC_PROG_DATA/wicome/libremoteuiservice.so usr/share/MMC_PROG_DATA/wicome/libwicome_config.so usr/share/MMC_PROG_DATA/wicome/RUI.rnf
if ($LASTEXITCODE -ne 0) { throw 'Inspect partial extraction; do not overwrite it' }
```

All four files were then compared byte-for-byte with a second, stdout-only
extraction from that pinned ISO. No second set of files was written.

| Member under `usr/share/MMC_PROG_DATA/wicome/` | Bytes | SHA256 |
| --- | ---: | --- |
| `libpal_graphic.so` | 153,470 | `e86a25975368a5bddf9ea55c365dacb54e2ce2bfab0a25d7cf015ed6118f1c98` |
| `libremoteuiservice.so` | 3,466,904 | `b4cd37a07ddefeea4949f0044cfa88309f515beeaf443f11927062ea450c579e` |
| `libwicome_config.so` | 20,100 | `b4997dd6bac75245215497da36c3bc353611b3e5c50d1d6ca5094442b9b3c35d` |
| `RUI.rnf` | 26,624 | `ff5231e0e6fcda82c0bc97c6e44e09dbd424b8256f0f68fd02ecb8745d6cf96b` |

The selected trace uses the first two libraries; the configuration/registry
files are retained as unexecuted follow-up inputs, not decoded here. Their
private binary bodies are not committed. The new inspector also pins the
existing `mirrorLinkSvc` and `bluetooth.sh` inputs.

## Step 3 - Follow the service boundary into the graphics factory

In `mirrorLinkSvc`, the start/stop frame-update methods construct named GCF
commands. Calls at `0x11379c` and `0x1136a4` both target the writer at
`0x11b5a0`. That writer invokes `GCFCreator_Create` at `0x11b604` and
`sss_write` at `0x11b690`. It is a command-transport boundary, not pixel upload;
its local result does not demonstrate a displayed frame.

The newly extracted `libremoteuiservice.so` depends on `libpal_graphic.so` and
imports its `PAL::Graphic::IGraphicWindow` creation/destruction functions.
Its intact static symbol table identifies the actual callers:

| Remote-UI call VA | Enclosing function | Resolved graphics factory operation |
| --- | --- | --- |
| `0x58c0c` | `MirrorLinkClient::CResourceManager::initDefaultGraphicWindow` at `0x58628` | `IGraphicWindow::Create` |
| `0x59624` | `MirrorLinkClient::CResourceManager::GetGraphicWindow` at `0x592e4` | `IGraphicWindow::Create` |
| `0x582e0` | `MirrorLinkClient::CResourceManager::ReleaseGraphicWindow` at `0x58258` | `IGraphicWindow::Destroy` |

Addresses are library-relative ELF virtual addresses. Imports with a zero
dynamic-symbol value are resolved through the observed three-instruction ARM
PLT and jump-slot relocation, not guessed from function proximity. The service
command-to-all-receiving-handler dispatch is not exhaustively traced here.

## Step 4 - Trace native window creation and the CPU pixel buffer

`libpal_graphic.so` exports `CWindowManagerEGLScreenAPI::CreateWindow`
(`0xaa5c`, 1,484 bytes). The selected successful path creates a Screen context
and window, assigns the supplied caption as both class and ID, sets properties,
creates **two window buffers**, and explicitly sets visibility to zero.

| Call VA | Native operation / selected argument |
| --- | --- |
| `0xaba0`, `0xac08` | `screen_create_context`, `screen_create_window_type`; selected flags/type are zero |
| `0xac80`, `0xacf8` | Character properties 7 (class) and 20 (ID string) use the supplied caption |
| `0xad64`, `0xadd0`, `0xae3c` | Integer properties 14 (format), 48 (usage, value 32), 40 (size) |
| `0xaea4` | `screen_create_window_buffers` with count 2 |
| `0xaf10` | Integer property 51 (visibility), value 0 |
| `0xd984`, `0xda08` | EGL window-surface and context creation in `CWindowControlEGL::Init` |

Property names agree with the reference used in Step 81. These values are
observed factory arguments, not a replacement SDK/header or a claim that arbitrary
new clients have the same permissions.
[QNX Screen property types](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.screen/topic/screen_8h_1Screen_Property_Types.html).

The renderer also owns a separate **CPU pixel buffer**, not merely a pointer to
one of those Screen window buffers. `ConfigureBuffer` (`0x138d4`) allocates an
array at `0x14360` and stores its pointer at object offset `+0xc` (`0x1436c`).
`LockBuffer` (`0x120f8`) returns that stored pointer and a calculated byte stride,
while saving the selected rectangle. `UnlockBuffer` (`0x134f4`) passes the same
stored pointer and saved rectangle to `glTexSubImage2D` at `0x136a0`.
This path consumes pixel data; it does not decode an H.264 bitstream.

## Step 5 - Distinguish drawing, presentation and destruction

`CGraphicWindow::Redraw` (`0x16854`) takes its mutex and calls a renderer virtual
method, then a control virtual method if rendering succeeded. Selected
relocations link those slots to `RenderBuffer` (`0xffc0`) and `UpdateWindow`
(`0xc05c`). Rendering draws textured geometry through `glDrawElements`
(`0x10724`). The control method calls `eglSwapBuffers` (`0xc13c`), with
Bind/UnBind virtual calls around the operation.

This explains why searching only for `screen_post_window` missed this producer:
the selected application-level presentation path uses **EGL swapping**. Khronos
documents that operation as presenting a surface's color buffer to its native
window. It does not grant Toyota display ownership or prove a frame reached the
physical audio-unit screen.
[Khronos EGL 1.4 reference, page 2](https://www.khronos.org/files/egl-1-4-quick-reference-card.pdf).

Cleanup is split across resource types. Selected calls delete the GL texture
and framebuffer objects and the CPU array (`0x14414..0x1443c`); the EGL control
destructor destroys its context and surface (`0xc33c`, `0xc3ac`). It calls
`eglTerminate` only under its shared-object-count condition, then has an
`eglReleaseThread` path. The Screen manager destroys its window and context
(`0x9ff8`, `0xa060`). These are observed cleanup paths, not a proof that every
failure/partial-initialization path is leak-free or restores the factory UI.

## Step 6 - Apply the finding to the CarPlay implementation plan

The native rendering candidate is now concrete: decoded pixels in owned CPU
memory, GLES texture upload/draw, an EGL window surface, and Screen window
coordination with the existing factory manager. A future backend must preserve
thread/context ownership, explicit hidden initialization, error propagation and
resource-specific cleanup. Do not mix this CPU staging pointer with Screen's
window buffers or assume direct `screen_post_window` is required by this path.

The inspected factory creates a class/ID from a caption supplied by its caller;
that is not authorization to reuse `mlc` or another factory name. Step 81's
visibility-cache warning and Step 80's physical-ownership provenance requirement
still apply. The full caption/property/event path remains to be correlated.

Next, trace the remote-UI pixel producer and decoder boundary. The new library
contains RFB/HSML graphics code and WFD/H.264 negotiation names; those names do
not establish a reusable H.264 decoder. Determine what supplies pixels before
attempting to connect CarPlay video to the identified presentation interface.
Matching QNX SDK/ABI, native execution/recovery, real chip/transport access and
phone validation still prevent calling this a deployable CarPlay implementation.

## Step 7 - Verify reproducibility and limits

```powershell
python -B scripts/inspect_mirrorlink_graphics.py
python -B scripts/inspect_mirrorlink_graphics.py --disassemble create_window
python -B scripts/inspect_mirrorlink_graphics.py --disassemble swap
python -B -m unittest discover -s tests -p 'test_*.py'
```

[The new inspector](../scripts/inspect_mirrorlink_graphics.py) validates four
complete hashes before analysis, checks selected instruction words, resolves
26 graphics calls and three remote-UI factory calls, and links four selected
virtual-method relocations. It reads the remote library's bounded static symbol
table to name callers. Default inspection launches no subprocess and writes no
files. Optional disassembly remains bounded and uses the existing in-memory
LLVM header adaptation, never the target dynamic loader.

All **58 Python tests pass**, including **nine new checks** covering the traced
boundaries, static-table bounds, ARM PLT form/relocations, changed-input refusal,
repeatability and no default process launches. Three selected LLVM listings
also passed their start-address and unchanged-input checks. Tests do not emulate
WiCoME, render video, test latency, prove CarPlay acceptance or exercise the car.

No original firmware, update media, service flags or vehicle state changed.
The four additional vendor files exist only in the ignored research directory;
the commit contains the inspector, tests and documentation.
