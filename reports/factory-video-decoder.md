# Factory video boundary: RAW pixels and a null WFD factory

Date: 2026-09-10. Starting checkpoint: `f0afaca`.
Continues [CarPlay progress, Step 83](carplay-progress.md#step-83---separate-raw-pixel-copying-from-the-null-wfd-client-factory)
and [the native graphics producer trace](mirrorlink-graphics-producer.md).
Scope: static inspection of the later `6.17.0WL` corpus, not execution on the
owner's `6.9.0WL` unit. No vendor program, phone session or vehicle operation ran.

## Step 1 - Keep pixel presentation separate from video decoding

Step 82 established CPU pixel staging, GLES texture upload/drawing and EGL
presentation. It did not establish what decompresses CarPlay video into those
pixels. This step follows two specific leads in the recovered remote-UI library:
the RAW framebuffer codec and the WFD client factory behind the H.264 names.

The result is narrower than a complete decoder audit: the selected RAW routine
copies pixel bytes, and the selected WFD factory returns null. Neither supplies
a usable H.264 decoder. This does not prove that every other firmware component
lacks one, nor that software-only CarPlay is impossible.

## Step 2 - Reuse verified inputs without another extraction

Both libraries remain under the ignored directory
`extracted/factory-wicome-617-step82/usr/share/MMC_PROG_DATA/wicome/`.
Their extraction provenance and ISO pin are recorded in
[Step 82's extraction instructions](mirrorlink-graphics-producer.md#step-2---extract-and-verify-only-the-selected-additional-inputs).

| File | Bytes | Complete SHA256 |
| --- | ---: | --- |
| `libremoteuiservice.so` | 3,466,904 | `b4cd37a07ddefeea4949f0044cfa88309f515beeaf443f11927062ea450c579e` |
| `libpal_graphic.so` | 153,470 | `e86a25975368a5bddf9ea55c365dacb54e2ce2bfab0a25d7cf015ed6118f1c98` |

The new inspector checks both complete hashes before parsing either ELF. The
remote library's intact static symbol table names local functions that are not
available as ordinary dynamic imports. All addresses below are library-relative
ELF virtual addresses, not callable host pointers or raw file offsets.

## Step 3 - Follow the RAW codec's graphics-buffer boundary

`Rfb::CRfbGraphicCodecBase::FromBuffer` is at `0x172744`, size 1,556 bytes.
Selected virtual calls match the factory graphic-window table:

| Remote call | Virtual slot | Corresponding factory method |
| --- | --- | --- |
| `0x1728bc` | Window `+0x14` | `GetBufferPixelFormat`, relocation `0x1d42c` -> `0x17880` |
| `0x1729e4` | Window `+0x24` | `LockBuffer`, relocation `0x1d43c` -> `0x16ca0` |
| `0x172ab0` | Codec `+0x1c` | RAW `decodeFromBuffer`, relative relocation `0x1e065c` -> `0x173028` |
| `0x172be0` | Window `+0x28` | `UnlockBuffer`, relocation `0x1d440` -> `0x16ac4` |

The lock call supplies references to the codec's destination pointer at `+0x14`
and stride at `+0x18`, alongside rectangle fields. The base routine obtains the
pixel format and computes row bytes from bytes per pixel and rectangle width.
Its successful path advances through lock, codec processing and unlock states;
it also has error/reset paths. This is a selected successful-path trace, not a
proof of every failure path or every possible graphic-window implementation.

The RAW constructor at `0x1733c4` loads its vtable through the GOT entry at
`0x1e17d8`, whose relative relocation points to `0x1e0628`. It sets the address
point to that table plus `0x18`. The decoding slot at address-point plus `0x1c`
therefore reaches `0x1e065c`. The graphics method slots instead use named
absolute-symbol relocations. The inspector deliberately distinguishes those
two relocation forms.

## Step 4 - Identify what the RAW routine actually does

`Rfb::CRfbCodecRaw::decodeFromBuffer` occupies `0x173028..0x1732ab`
(644 bytes including its literal pool). Its selected data path:

1. Resets consumed-byte count and completion output; rejects a null input pointer.
2. Determines how much input fits the remaining row or rectangle. When source
   row bytes equal destination stride, it can copy across multiple rows; this
   is not exclusively a one-row-at-a-time loop.
3. Unless its existing skip-copy field is set, calculates the destination from
   buffer base, row progress, stride and byte offset.
4. Calls `memcpy` at `0x1731a0`, resolved through PLT `0x1b604` and GOT `0x1e1078`.
5. Advances consumed bytes and row/byte progress, and marks completion when the
   rectangle's rows have been consumed.

This is pixel-byte copying with layout/progress accounting, not H.264
decompression. The meaning and external control of the skip-copy field were not
established here. The routine was read, not run on crafted frame data; no memory
safety, performance or protocol-interoperability claim follows from this trace.

Step 82's upload/presentation path can consume decoded pixels, but this RAW
codec does not create those pixels from CarPlay's compressed video. Do not route
compressed data into the pixel buffer or treat the shared word "codec" as an API
compatibility result. The full RFB/HSML dispatch-to-redraw chain remains outside
this selected boundary audit.

## Step 5 - Follow the WFD factory, not just H.264 format names

The library contains H.264 profile/level mapping, video-format structures and
WFD attach/session setup methods. The decisive selected implementation is
`MirrorLink::Wfd::Client::IMirrorLinkWfdClient::Create` at `0x1050fc`, size 180.
The complete function has 39 ARM instruction words followed by six literal
words. It initializes `r5` to zero at `0x105118`, makes only two calls, then
moves `r5` into result register `r0` at `0x10518c` and returns at `0x105194`.
There is no intervening assignment to `r5` and no conditional creation path.

Both calls (`0x105158`, `0x105188`) resolve to `StarRec_TraceOut_trace`, via
PLT `0x1b3c4` and jump slot `0x1e0fb8`. They are logging calls, not allocation,
dynamic loading or decoder construction. This means the factory returns null
on ordinary return, assuming the native calls obey the usual preserved-register
contract. Arm's procedure-call standard specifies preservation of `r5`; this
supports the interpretation, not a claim to have run the function or audited the
entire QNX runtime. [Arm AAPCS32, core registers](https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst#611-core-registers).

The inspector pins the complete 180-byte factory body, including its literal
pool, to SHA256
`533750574eae1612fcbd99cfd1d85386d540708173dd9ebee22e7c6a66fc3b1f`.
It checks the selected return instructions and both resolved calls. This is a
guard for a manually audited body, not a general static interpreter.

The caller corroborates the null-pointer meaning. In `CServerDevice::InitWfd`
(`0x723f4`, 4,468 bytes), the direct call at `0x73010` reaches that factory.
It compares the result against zero, stores it at object offset `+0x12c`, and
branches past the failure path only for a nonnull result. The null path logs,
sets the selected result to 1 and branches toward cleanup at `0x732b0`.
No enum name is assigned to numeric result 1 without additional evidence.

Thus this particular compiled WFD creation path cannot supply an operational
client/decoder merely by selecting one of its advertised format structures.
Do not patch out the check or replace null with a fabricated pointer: the missing
object implementation would still be missing. This conclusion is limited to the
pinned library and this factory, not all WFD products or the installed version.

## Step 6 - Keep the remaining decoder lead explicit

The existing AIR library remains a separate candidate, not a proven backend.
Earlier analysis found H.264 decompressor names, acquisition-failure messages
and media-graph imports, but no established externally callable decoder API.
See [the prior interface findings](carplay-progress.md#step-8---trace-the-existing-apple-hardware-connection).

Its complete pin remains
`9f8a7dea6c168cd3c71d4db93885ced8b2a696ab26c403bf27c8bf3b2254f12d`
for `image-380000/lib/air/runtimeSDK/Adobe AIR/Versions/1.0/libCore.so`.
This turn also checked its section directory: unlike the recovered remote-UI
library, it has no intact static symbol table available to the same parser.
That limits easy function naming; it does not show that the decoder is absent.

Follow-up: [Step 84 traces AIR's concrete media-graph and buffer-push boundary](air-video-graph.md).
Its separate MainConcept-associated decompressor remains to be traced.

The next step identified at this checkpoint was to trace AIR's media-graph acquisition and
compressed-input/output boundaries, including how it selects a decoder and
handles failure. Only then decide whether external use is technically supported
or a separate decoder port is necessary. Do not infer decoder availability from
the `AirDDK17` name in the WiCoME GLES renderer.

Matching native execution/recovery, QNX ABI/toolchain, actual phone/chip access,
display ownership and input/audio integration are still unresolved. No CarPlay
installation package or working on-car receiver is produced by this step.

## Step 7 - Reproduce and verify without target execution

```powershell
python -B scripts/inspect_factory_video.py
python -B scripts/inspect_factory_video.py --disassemble wfd_factory
python -B scripts/inspect_factory_video.py --disassemble wfd_caller
python -B scripts/inspect_factory_video.py --disassemble raw
python -B -m unittest discover -s tests -p 'test_*.py'
```

[The inspector](../scripts/inspect_factory_video.py) and
[six new regression tests](../tests/test_factory_video_trace.py) preserve the
input pins, named boundaries, different relocation types, copy/logging calls
and selected null-factory interpretation. Tests reject changed firmware before
ELF analysis and reject modified copies of the audited factory body. Default
inspection launches no process and writes no file. Optional host disassembly
retains the existing in-memory header adaptation and bounded execution limits.

All **64 Python tests pass**. These are static-evidence/host-tool checks, not
decoding, rendering, iPhone acceptance, latency or recovery tests. No vendor
binary was changed or committed, and no vehicle state was touched.
