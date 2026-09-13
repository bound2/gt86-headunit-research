# AIR frame storage: borrowed descriptors, pixel copies and initialization

Date: 2026-09-13. Starting checkpoint: `20dc301`.
Continues [CarPlay progress, Step 86](carplay-progress.md#step-86---separate-air-frame-borrowing-copying-and-core-initialization)
and [the MainConcept input/frame trace](air-mainconcept-decoder.md).

## Step 1 - Record the implementation consequence

The internal decoder offers two materially different output paths: a descriptor
containing frame pointers, and a copy into caller-supplied pixel storage. The
current frame is released by a later input submission. Therefore our receiver
must not retain descriptor pointers across decoder activity without a verified
retention contract. An owned frame copy is a separate operation.

The deeper constructor and initial command are now located too, but there is
still no verified outside-AIR API or matching installed-version entry point.
Keep this code as interface evidence. The next implementation step is a
separately buildable H.264 backend with explicit frame ownership, not calls to
hardcoded AIR addresses. This decision does not require extra head-unit hardware
and does not change the requested software-only outcome.

## Step 2 - Preserve input provenance and scope

All observations are from the same whole-file-pinned `6.17.0WL` research input:

```text
extracted/qnx-system-v3/image-380000/
  lib/air/runtimeSDK/Adobe AIR/Versions/1.0/libCore.so
bytes: 10992051
SHA256: 9f8a7dea6c168cd3c71d4db93885ced8b2a696ab26c403bf27c8bf3b2254f12d
```

Addresses are library-relative ELF virtual addresses. The newly selected
disassembly windows include portions of larger functions and a companion
constructor inside a merged unwind interval. They are not newly recovered
function sizes. No vendor code, QNX process, phone operation, firmware change
or vehicle operation ran. This is not the installed `6.9.0WL` image.

## Step 3 - Separate allocation from decoder initialization

The deeper factory at `0x576644` allocates `0xfdad0` bytes (1,039,056), clears
them, installs callbacks and initializes table entries. Its allocation helper
at `0x576640` tail-branches to the `_Znaj` import already resolved in Step 85.
This is an initial core allocation, not total decoder memory or an estimate of
memory available on the unit.

Selected callback mappings derived from its literal pool:

| Core slot | Wrapper | Further target / behavior |
| --- | --- | --- |
| `+0x00` | `0x57662c` | Adds `0x40` to the object pointer, then branches to `0x577e30` |
| `+0x04` | `0x57654c` | Adds `0x40`, then branches to `0x58097c` |
| `+0x0c` | `0x576624` | Adds `0x40`, then branches to byte-processing target `0x57ad34` |
| `+0x20` | `0x5765fc` | Adds `0x40`, then branches to command dispatcher `0x578068` |

Backend command `0x10000`, issued by the outer configuration path in Step 85,
reaches `0x574694`. The selected case invokes core `+0x04` at `0x5746a4` and
core `+0x00` at `0x5746b0`, testing the latter result at `0x5746b4`. Thus a
successful allocation is not completed initialization. The subsequent options,
all internal allocation failures, runtime globals, threading and complete
transitive dependencies have not been established. These routines still reside
inside the stripped AIR monolith; finding their offsets does not make them a
standalone library API.

## Step 4 - Follow the descriptor-return command

In backend dispatcher `0x574440`, the comparisons derived from literal
`0x5753e0 = 0x10029` select command `0x10027` through branch `0x574564` to
`0x5750e0`. Command `0x10028` shares that region but takes a different initial
query path. Do not conflate the two commands.

The selected `0x10027` path requires a current frame and queries it through its
`+0x04` callback. The mapping into the caller's descriptor is:

| Query number | Destination offset | Use established by the outer consumer |
| --- | --- | --- |
| 0, 1, 2 | `+0x10`, `+0x14`, `+0x18` | Three plane pointers |
| 3, 4, 5 | `+0x20`, `+0x24`, `+0x28` | Plane strides |

The case also computes dimensions and fills metadata fields. It assigns values
obtained from the current frame; it does not perform the pixel `memcpy` seen in
the other output case. Copying its 72-byte descriptor into AIR's frame ring, as
Step 85 observed, is not copying the images or demonstrating a transferred frame
reference. The complete getters/retention ABI is still unverified.

## Step 5 - Follow pixel copying and the current-frame lifetime

Command `0x10007` is selected by the low-command comparison tree using literal
`0x5753d4 = 0x10005` plus two, then branch `0x5744f8` to `0x575490`.
It obtains source plane pointers/strides, applies conditional cropping and
conversion paths, and writes through destination plane pointers in the supplied
descriptor. Selected ordinary row-copy calls resolve to `memcpy` at
`0x575a3c`, `0x575adc` and `0x575d58`. Other branches call conversion helpers;
a selected absent-chroma path fills destination bytes with 128 through `memset`
at `0x575b48`. This is not a general RGBA output implementation.

The caller's fallback allocator at `0x39be58` requests a single block through
the shared helper, records its size at record `+0x38`, stores the allocation at
`+0x28`, and derives additional plane addresses at `+0x2c/+0x30`. Its request
uses the existing instance's height and stride fields. This is different from
the descriptor-return command's pointer assignment.

Crucially, the zero-result exit at `0x576528` is also reachable from branches
that skip copying, including a zero queried property or zero format marker at
`0x5755a0..0x5755b4`. A zero return alone is not evidence that pixels changed.
The complete format/capacity validation policy is not established.

Current-frame handling supplies a concrete lifetime boundary:

1. Core command 4 at `0x5780f0` locates its current frame and calls frame
   `+0x08` at `0x578108` before returning the pointer. This is consistent with
   acquiring a frame reference, but the counter implementation is not claimed.
2. Backend frame collection uses that command to populate state `+0x04`.
3. Before processing more input, backend submission loads that state pointer,
   calls frame `+0x0c` at `0x573eb8`, and clears it at `0x573ec0`.
4. It then resumes frame collection via `0x573ec8` -> `0x573900`.

This release/clear sequence is why externally queued descriptor pointers cannot
be assumed stable. It does not prove immediate deallocation: other references
and the decoder's picture pool may keep storage alive or later reuse it. A real
adapter must copy while valid or use a verified retain/release mechanism.

## Step 6 - Narrow the companion-object hypothesis

The instance `+0x08` companion is created at `0x5ffefc`, separately from the
compressed-byte backend at instance `+0x04`. Its constructor allocates `0xc34`
bytes, calls `0x5fef60`, and constructs 256-entry numeric tables. The latter
helper caches a mode at `+0xc2c` and a flag at `+0xc30`, performs matrix-like
floating-point calculations and stores coefficients/tables. The outer codec
calls the same helper with several mode values at `0x39e710/0x39e730` and nearby
branches. Constructor constants include 65.738, 129.057 and 25.064.

These observations favor a color-matrix/table helper, not a second H.264 decoder
or a hardware/software selector. That role remains an inference: complete
pixel-conversion consumers, exact colorimetry, threading and output format are
not established. No claim of working RGB conversion is made.

## Step 7 - Move the next implementation onto a buildable interface

Further private-offset tracing is not the immediate implementation dependency.
The receiver needs a decoder we can build, call and test with known compressed
frames, with a porting path to ARM/QNX. It must provide configuration handling,
bounded input, explicit dimensions/strides/format, owned output, decoder error
handling, draining and reset behavior. Test actual decoded pixels, not only
mock callbacks or a descriptor's shape.

OpenH264 is one candidate to evaluate, not a dependency added by this step.
Its upstream documentation describes Annex-B input, planar 4:2:0 output and
ARMv7 support, but its documented decoder profile coverage and platform list
must not be treated as proof of the required CarPlay stream or QNX support.
[Cisco OpenH264 documentation](https://github.com/cisco/openh264#decoder-features).
The latest-release endpoint resolved to `v2.6.0` during this check; any selection
must pin the actual source and validate the needed profile/level and public API
before implementation. [Upstream release](https://github.com/cisco/openh264/releases/tag/v2.6.0).

Next implement and test a separately buildable decoder/backend after that
compatibility check, keeping output ownership independent of AIR's ring. A host
decoder does not replace the missing native execution/recovery, QNX toolchain,
phone/chip transport, display/input/audio-focus and actual car testing. The full
goal remains CarPlay on the owner's factory unit, not host-only playback.

## Step 8 - Reproduce this checkpoint

```powershell
python -B scripts/inspect_air_mainconcept.py
python -B scripts/inspect_air_mainconcept.py --disassemble core_factory
python -B scripts/inspect_air_mainconcept.py --disassemble core_initialize
python -B scripts/inspect_air_mainconcept.py --disassemble descriptor_case
python -B scripts/inspect_air_mainconcept.py --disassemble copy_case
python -B scripts/inspect_air_mainconcept.py --disassemble release_current
python -B -m unittest discover -s tests -p 'test_*.py'
```

Extended the existing read-only inspector with frame-storage evidence and eight
optional bounded windows, without weakening its whole-file pin. Added
[five focused regression tests](../tests/test_air_frame_storage.py) for command
separation, core callbacks, lifetime/zero-result limits and changed-anchor
refusal. All **83 Python tests pass**. The optional acquisition listing passed;
the original input stayed unchanged. Existing default-mode tests still verify
repeatability without subprocesses or writes. No new C++ build, actual decoder
test, iPhone test or on-car test ran; this step adds evidence, not a video backend.
