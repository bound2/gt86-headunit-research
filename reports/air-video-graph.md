# AIR video: graph dependencies, buffer submission and Screen output

Date: 2026-09-10. Starting checkpoint: `621da0a`.
Continues [CarPlay progress, Step 84](carplay-progress.md#step-84---trace-the-air-media-graph-and-its-buffer-push-boundary)
and [the RAW/WFD decoder audit](factory-video-decoder.md).
Scope: offline inspection of the later `6.17.0WL` corpus. No vendor code or
media filter was loaded, no environment/service setting changed, and no car or
iPhone operation ran.

## Step 1 - Identify the actual interface behind the AIR decoder names

AIR's selected MMF path is a media-graph client, not an exported function that
takes H.264 and returns RGBA pixels. It requests a `flash_reader`, obtains a
buffer-push callback from a named resource, asks the framework for a matching
processing filter, and connects raw video output to a writer. A plane-codec
path explicitly selects `screen_writer`.

This replaces the previous vague "AIR imports media APIs" lead with specific
input, filter-selection and output boundaries. Availability of the requested
filters, a complete callback ABI, actual video decoding and outside-AIR use
remain unverified. A different AIR `H264VideoDecompressor`/MainConcept lead is
still separate; this report does not rule it out.

## Step 2 - Pin the input and recover bounded analysis intervals

Input under `extracted/qnx-system-v3/image-380000/`:

```text
lib/air/runtimeSDK/Adobe AIR/Versions/1.0/libCore.so
bytes: 10992051
SHA256: 9f8a7dea6c168cd3c71d4db93885ced8b2a696ab26c403bf27c8bf3b2254f12d
```

There is no intact static symbol table in this stripped input. Its ARM exception
index is nevertheless available through program-header type `0x70000001`:
VA/file offset `0xa05904`, 217,920 bytes, 27,240 entries. The new inspector reads
each first word as a signed place-relative 31-bit offset and validates ordering,
file bounds and executable-segment coverage.

These are **unwind intervals**, not guaranteed one-function-per-entry sizes or
recovered source names. Arm describes the two-word index format and permits
linkers to combine certain non-unwindable entries, so the distinction matters.
[Arm exception-handling ABI, index entries](https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst#6-index-table-entries).

Selected interval starts are `0x35940c` (initialization), `0x3595b4` (graph setup),
`0x35ad74` (plane-codec setup path), `0x3556f8` (buffer handling) and `0x354204`
(push helper). Labels describe the inspected behavior, not exported API names.
Addresses are library-relative ELF virtual addresses; the writable segment's
virtual addresses differ from file offsets by `0x1000`.

Relative relocations connect RTTI name `17H264MMFPlaneCodec` at `0x92e5b8` to
type information at `0xa5a2a0` and the table with type-information pointer at
`0xa59b1c`. Its selected method slot at `0xa59b38` points to `0x35ad74`.
That method directly calls graph setup at `0x35b120` -> `0x3595b4`. This is
class/call evidence, not merely a neighboring H.264 string.

## Step 3 - Trace initialization and its required controls

The initialization routine obtains `getenv("MM_INIT")` at `0x359434` and passes
the result to `MmInitialize` at `0x359438`. It then looks up four AOI controls
with `AoFindName`, passing their names with null interface/zero version:

| Call VA | Required name |
| --- | --- |
| `0x35948c` | `queue_filter` |
| `0x3594c8` | `flash_reader` |
| `0x359508` | `screen_writer` |
| `0x359544` | `frame_writer` |

Each selected lookup tests for null; failure reports an error and does not set
the routine's success flag. However, the graph-setup caller does not check that
initialization return at `0x359608`; it continues to its own graph/filter checks.
Do not treat every failed initialization lookup as an unconditional graph veto.
QNX documents `AoFindName` as finding a control's
declared Name interface, not requiring an identically named file. Therefore
filename searches alone cannot prove these controls are unavailable.
[QNX 6.4 AOI name lookup](https://www.qnx.com/developers/docs/6.4.0/neutrino/addon/ao/aofindname.html).

The older QNX multimedia guide describes `MmInitialize`'s optional filter path
and the default `/lib/dll/mmedia` directory. This explains why the environment
value and plugin registry are relevant. It is contextual documentation, not
proof of this unit's running environment or permission to alter it.
[QNX multimedia initialization and graphs](https://www.qnx.com/developers/docs/6.3.2/photon/multimedia2/using_graphs.html).

## Step 4 - Follow graph creation and the compressed-input callback

The selected graph path calls `MmCreateGraph("AIRMediaOut")` at `0x3596c0`,
then `MmFindFilter(graph, "flash_reader")` at `0x3596d4`. It configures named
reader resources, including standalone operation and queue size.

At `0x359730`, `MmGetResourceValue` requests
`MM_FLASH_READER_PUSH_ENTRY_PT`. The returned resource pointer is checked and
dereferenced at `0x359738`; the resulting callback pointer is saved at helper
object offset `+0x20` at `0x359740`. A missing resource or null entry point
takes an error path. This is a runtime-supplied callback, not a statically
exported H.264 decoding function in `libCore.so`.

The push helper at `0x354204` selects buffered data, length and timestamp
metadata, reloads that same `+0x20` callback at `0x3542a8`, and invokes it at
`0x3542c0`. Its selected arguments include the supplied channel, buffer pointer
and length, with further metadata on the stack. Calls from `0x355808` and
`0x355858` connect the buffer-handling routine to this helper. The graph startup
path also drains previously buffered data through `0x35a1d4` -> `0x3556f8`.

The complete callback declaration, all flags, ownership after return, framing
of configuration data versus pictures, and timestamp requirements have **not**
been established. Do not invent a C prototype or directly submit CarPlay packets
based only on these register observations. No vendor callback was invoked.

## Step 5 - Separate decoder selection from the output writer

The plane-codec setup method selects numeric marker `0x48323634` on its observed
type-7 branch and saves it as the reader video-format value. That marker spells
H264 as a numeric FourCC; this says nothing about CarPlay's wire byte order.
The same path saves `screen_writer` as the writer name. Width and height are
passed via `MM_FLASH_READER_VIDEO_WIDTH` and `MM_FLASH_READER_VIDEO_HEIGHT`.

The selected video path then proceeds through these boundaries:

```text
owned buffered bytes -> flash_reader push callback / compressed output channel
                     -> framework-selected processing filter / raw video output
                     -> optional decoded queue -> screen_writer input
```

| Call VA | Observed operation |
| --- | --- |
| `0x35980c` | Acquire reader output with selected type value `0x80000002`; save channel at `+0x74` |
| `0x359820` | `MmFindChannelsFilter` for that output; no hardcoded H.264 decoder filename here |
| `0x359830` | Request type-2 output from the selected filter; associated error identifies raw video |
| `0x359878`, `0x35990c`, `0x35991c` | Optional `queue_filter`, its input, and channel attachment |
| `0x3599f0` | Look up the writer name saved at helper offset `+0x6c` |
| `0x359d3c`, `0x359d4c` | Acquire writer input and attach the current raw video output |

QNX's graph guide describes `MmFindChannelsFilter` as selecting a matching
filter and connecting its input to the supplied output channel. The exact
decoder implementation and successful raw-output production are still unknown
here; selecting a filter is not proof that this corpus has a working H.264
decoder. [QNX filter selection](https://www.qnx.com/developers/docs/6.3.2/photon/multimedia2/using_graphs.html).

The writer configuration includes external Screen context/back-window resources,
aspect control, overlay/posting and media-clock options. Some are conditional.
These establish an intended Screen-output integration, **not CPU RGBA frames
returned to our receiver**. This is a different interface shape from Step 82's
WiCoME CPU staging buffer. Copying addresses or reusing factory window names
would not establish ownership or a compatible backend.

## Step 6 - Keep startup, failure and performance claims separate

`MmFinalizeGraph` is called at `0x35a0e8`; its nonzero-result path reaches
`MmDestroyGraph` at `0x35a118`. The successful path has a conditional
`VideoDecoderLowLatencyMode` resource setting and calls `MmStart` at `0x35a164`.
The backlog-submission failure path destroys the graph at `0x35a1f8` and clears
the stored graph pointer. Other start/stop/resume calls exist elsewhere in AIR.

Neither a successful setup return nor the low-latency resource name proves
playing video or adequate latency. Not all optional resource failures abort
setup. This step does not claim exhaustive cleanup correctness or that every
allocated channel, buffer and window is safely released on every path.

## Step 7 - Check availability without overstating negative searches

A bounded content search of `extracted/qnx-system-v3` and the existing selective
`extracted/install` directory found the requested filter names in AIR and
`io-media-generic` (also in the containing imagefs blob). It did not establish
actual registered `flash_reader`/Screen-writer implementations. The extracted
multimedia directory does contain `queue_filter.so`; names alone do not settle
the remaining controls or the selected decoder.

Also revalidated the complete installation ISO SHA256 against
`06bdc5c05b889ae68bd372dd060502226ea911fc0715a646072c59b1832bf30d`
and listed all 842 direct archive entries with host bsdtar. No direct member name
matched `flash_reader`, `screen_writer`, `h264`, `mmedia` or `ce_video`.
That listing does not search inside embedded IFS/package contents and does not
eliminate static registrations, alternate paths or differently named plugins.
No additional firmware was downloaded or extracted.

The separate RTTI for `H264VideoDecompressor` at `0x931d20` is now located via
its relocation at `0xa5d164`; its type/table neighborhood is distinct from the
MMF plane codec. Its MainConcept-associated construction, frame interface and
fallback selection are the next decoder lead to trace. Do not label it a usable
software decoder before following that code. AOI registry/filter provenance
remains necessary if pursuing the MMF route.

## Step 8 - Preserve reproducibility and the actual CarPlay completion gates

```powershell
python -B scripts/inspect_air_video.py
python -B scripts/inspect_air_video.py --disassemble initialize
python -B scripts/inspect_air_video.py --disassemble graph
python -B scripts/inspect_air_video.py --disassemble push
python -B -m unittest discover -s tests -p 'test_*.py'
```

[The inspector](../scripts/inspect_air_video.py) validates the complete input,
five unwind intervals, selected RTTI/virtual relocations, 25 imported calls,
five direct calls, resource literals and instruction anchors. Default operation
reads only. Optional LLVM listings are bounded and use an in-memory header
adaptation; the original file stays unchanged.
[Seven new tests](../tests/test_air_video_trace.py) cover these relationships,
signed PREL31 decoding, malformed index bounds/order/targets, changed-input
refusal and repeatable inspection without subprocesses or file writes.

All **71 Python tests pass**. These are host/static-evidence tests, not native decoding or CarPlay validation.
The receiver still needs native execution/recovery, a matching QNX ABI/toolchain,
actual Apple-chip/phone transport, video performance and display/input/audio
integration. No installation image, target decoder backend or on-car receiver
was produced by this step; no vehicle state changed.
