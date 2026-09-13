# AIR MainConcept path: construction, compressed input and frame planes

Date: 2026-09-13. Starting checkpoint: `41de6b2`.
Continues [CarPlay progress, Step 85](carplay-progress.md#step-85---trace-the-air-mainconcept-decoder-input-and-frame-boundaries)
and [the separate AIR MMF graph investigation](air-video-graph.md).

Follow-up: [Step 86 frame storage and initialization](air-frame-storage.md)
distinguishes descriptor borrowing from pixel copying and updates the next
implementation decision. The Step 85 observations below are historical.

## Step 1 - State what this changes

The `H264 - MainConcept` lead is now connected to a constructed
`H264VideoDecompressor` object, an internal compressed-byte submission interface,
and frame-plane handling. It is more than a nearby string or another MMF graph
name. The selected path converts length-prefixed picture units into start-code
submissions and has a fallback output request with numeric marker `0x59563132`
(YV12). These are concrete reasons to keep investigating a software decoder.

This is **not yet a usable CarPlay decoder**. The outside-AIR initialization,
command structures, frame ownership, speed, installed-version behavior and
target execution remain unverified. No receiver production code, vendor file,
firmware, USB installation media or vehicle state changed in this step.

## Step 2 - Pin the input and keep addresses in scope

Same later `6.17.0WL` research input used by Step 84, under
`extracted/qnx-system-v3/image-380000/`:

```text
lib/air/runtimeSDK/Adobe AIR/Versions/1.0/libCore.so
bytes: 10992051
SHA256: 9f8a7dea6c168cd3c71d4db93885ced8b2a696ab26c403bf27c8bf3b2254f12d
```

All addresses below are library-relative ELF virtual addresses, not instructions
for calling functions on the head unit. The writable segment has a different
file offset. This input is not the owner's installed `6.9.0WL` image.

The existing ARM exception-index reader supplies bounded unwind intervals.
Those intervals are not guaranteed function sizes. In particular, constructor
target `0x5ffefc` falls inside the much larger interval
`0x5f9a94..0x613870`; do not label that whole interval as its body. Host LLVM
only interpreted bytes using the existing in-memory header adaptation. No QNX
loader, AIR runtime or vendor decoder executed.

## Step 3 - Connect construction, RTTI and the MainConcept label

The generic factory at `0x260710` selects its original kind-7 argument through
branch-table entry `0x260744`. That branch requests `0x13f0` bytes from the
shared allocation helper at `0x4400c0`, then calls constructor `0x39feb4` at
`0x2607d8`. The constructor calls the base constructor at `0x260cd8` and installs
vtable address point `0xa5d0e8` at `0x39fee8`.

Relative relocations establish the class relationships:

| Slot | Target / observed role |
| --- | --- |
| `0xa5d0e4` | RTTI object `0xa5d160` |
| `0xa5d164` | RTTI name `21H264VideoDecompressor` at `0x931d20` |
| `0xa5d0f4` | Record-dispatch method `0x39fc08` |
| `0xa5d104` | Method `0x39be08`, returning object field `+0x17c` |
| `0xa5d12c` | Plane-rendering method `0x39c258` |
| `0xa5d140` | Label method `0x39be10` |

When object field `+0x170` is null, the label method returns the actual
`H264 - MainConcept` string at `0x931d54`, through literal `0x39be48` and GOT
base `0xa66654`. When that field is nonnull it delegates to the other object's
virtual method. This connects the label to the selected fallback path; it does
not prove which path the running unit selects or identify a licensed SDK version.

## Step 4 - Separate the alternative object from the internal backend

Setup at `0x39de6c` conditionally attempts an alternative object via `0x25f3cc`
and field `+0x170`. That alternative depends on AIR state and flags. If it is
present, setup returns before constructing the internal instance. The surrounding
configuration routine has conditional hardware-AV/SPS/PPS handling, but this
step does not claim its entire selection policy is recovered.

With no alternative and no existing `+0x178` instance, setup requests 80 bytes,
calls `0x39cb88`, and stores the instance at outer-object `+0x178`. Its RTTI name
is `24H264DecompressorInstance` at `0x931d38`, connected by `0xa5d170` and
`0xa5d0bc`. The selected creation path then constructs **both** of these objects:

| Call | Stored result |
| --- | --- |
| `0x39df80` -> `0x5ffefc` | Instance `+0x08` |
| `0x39df88` -> `0x574280` | Instance `+0x04` |

These are not evidence of two mutually exclusive hardware/software choices.
Their full relationship remains to be traced. Reference-counted release at
`0x39da74` releases `+0x04` via `0x574250` and `+0x08` via `0x5ffef8` before
virtual instance deletion when the selected count reaches its release condition.

Factory `0x574280` allocates and clears a 44-byte object and `0x15c8` bytes of
state. Both selected allocations import `_Znaj`, not `malloc`. It constructs a
deeper object via `0x576644` and saves state at backend `+0x28` on the selected
success path. The first two installed function pointers are:

- Backend `+0x00` -> `0x573e74`: byte submission/consumption.
- Backend `+0x04` -> `0x574440`: numeric-command dispatch.

These targets are resolved from constructor literals `0x5743b0/0x5743b4`, not
guessed from function names. Allocation/error cleanup is not exhaustively audited.

## Step 5 - Establish the outer input format and inner byte boundary

Record dispatch at `0x39fc08` reads a type byte at record `+0x18`. Type 9 goes
to `0x39fb38`; type 23 goes to an internal frame-handling path at `0x39dc64`.
The type-9 handler obtains payload pointer `record+0x24` and dispatches payload
byte 1: value 0 to configuration at `0x39ee54`, value 1 to picture handling at
`0x39f1c8`, and value 2 to draining at `0x39d11c`. A separate value-3 branch
exists; this report does not assign it a public FLV meaning.

The configuration path derives length from the record's three bytes at
`+0x19..+0x1b`, subtracts five, copies payload bytes after a five-byte header to
owned storage at outer `+0x180`, and calls configuration routine `0x39df98`.
That routine checks the first configuration byte and derives the NAL length
field width as `(byte & 3) + 1`, storing it at `+0x194`.

This combination is consistent with Flash/FLV AVC framing, not a raw CarPlay
input API. Adobe's specification defines AVC packet values 0/1/2 for
configuration/picture/end-of-sequence and a signed three-byte composition-time
offset. Its configuration payload is an AVC decoder configuration record.
The format identification is an inference from those definitions plus the
observed code; AIR's surrounding in-memory record is not the on-disk file header.
[Adobe FLV specification 10.1, sections E.4.3.1-2, preserved by Veovera](https://veovera.org/docs/legacy/video-file-format-v10-1-spec.pdf#page=78).

Picture helper `0x39d2d8` removes the same five-byte payload header, adds the
signed 24-bit composition offset to the record timestamp, and parses the
configured length prefix. On its instance/backend path:

1. `0x39d504` calls backend `+0x00` with the four-byte constant `00 00 00 01`
   at `0x931d08`, handling partial consumption.
2. `0x39d62c` calls the same function with picture-unit bytes and a bounded
   current chunk length; the returned count updates remaining input.
3. Calls such as `0x39d52c` and `0x39d6dc` collect available frame information
   through `0x39ccd0` between submissions.

Inside backend submission `0x573e74`, a deeper object's `+0x0c` callback receives
the byte pointer, remaining count and a consumed-count output pointer. The loop
advances the pointer and subtracts that count. This confirms byte-stream
consumption behavior, not successful H.264 reconstruction or bounded latency.
All error codes, progress guarantees and reentrancy remain unverified.

## Step 6 - Trace frame retrieval separately from rendering

Frame collection at `0x39ccd0` uses backend command function `+0x04`. Selected
calls query state, metadata and output. At `0x39cef0`, numeric command `0x10027`
receives a 72-byte local descriptor; on the selected zero-result branch that
descriptor is copied into the outer object's frame ring. Do not assume this
copies or transfers ownership of the pointed-to pixels.

The fallback branch at `0x39d070` instead prepares output with three pointers,
stride/dimension values and marker `0x59563132` at literal `0x39d114`, then calls
command `0x10007` at `0x39d0e4`. The marker spells YV12 numerically. Its presence
does not establish the actual chroma plane order, color range, cropping, memory
alignment or format of every other branch. No RGBA conversion is established.

On the internal-record path, `0x39dc64` transfers selected ring plane pointers
into the instance's `+0x28` pointer array and records strides at `+0x2c/+0x30`.
The separate virtual method `0x39c258` passes that plane array and strides to
AIR rendering callbacks, including the selected call at `0x39c350`. Method
`0x39be08` merely returns the current `+0x17c` instance pointer; it is not an
owning frame-copy API. The renderer, instance references and ring lifetimes are
part of the integration problem.

## Step 7 - Record the remaining feasibility decision

None of the nine selected factory/setup/submission/rendering addresses checked
by the inspector has a defined dynamic symbol among this input's 1,272 dynamic
symbols. This is a bounded negative check, not proof that no indirect external
interface exists anywhere in AIR. Hardcoding these addresses would not supply
the missing initialization or a stable ABI.

Next inspect the deeper object constructed at `0x576644`, the command cases for
`0x10027/0x10007` in `0x574440`, and the `+0x08` companion object's role. Establish
pixel ownership/release, configuration requirements, runtime dependencies and
whether a supported outside-AIR route exists before implementing a target
backend. If that route is unavailable, a separately buildable decoder remains
an alternative; do not assume extracting embedded proprietary code is a solution.

The independent execution/recovery, matching QNX toolchain, existing Apple-chip
transport, physical display/input and audio-focus gates still apply. This
research neither closes the software-only possibility nor demonstrates it on
the owner's factory unit.

## Step 8 - Reproduce and validate this checkpoint

```powershell
python -B scripts/inspect_air_mainconcept.py
python -B scripts/inspect_air_mainconcept.py --disassemble label
python -B scripts/inspect_air_mainconcept.py --disassemble submit_record
python -B scripts/inspect_air_mainconcept.py --disassemble collect_frames
python -B -m unittest discover -s tests -p 'test_*.py'
```

[The new inspector](../scripts/inspect_air_mainconcept.py) checks the whole-file
pin, 12 selected unwind intervals, eight relative relocations, 20 direct calls,
eight imported calls, constructor/label/function-pointer relationships, numeric
commands, the start-code constant and selected instructions. Its default mode
reads only and starts no processes; optional LLVM mode does not run the vendor
code. The original file was unchanged after inspection.

[Seven new tests](../tests/test_air_mainconcept_trace.py) cover these
relationships, changed-input refusal, altered anchors/relocations/pointers and
repeatable read-only inspection. All **78 Python tests pass**. The optional
label listing also passed. An initial import expectation was corrected after
the validator resolved `_Znaj` rather than `malloc`; the test now pins that
actual symbol. No new C++ receiver, phone or on-car tests ran.
