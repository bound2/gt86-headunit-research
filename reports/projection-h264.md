# Step 87 - Source-built H.264 decoding with owned frames

Date: 2026-09-13. Continues [AIR frame storage](air-frame-storage.md).

## Result and boundary

An optional, real H.264 decoder now builds from pinned public source and returns
independently owned I420 pictures. Five compressed test streams, **395 frames**,
match FFmpeg's native H.264 decoder byte-for-byte and in output order. Both
explicit-final-AU and terminal-drain variants pass. This is actual host decoding,
not synthetic callbacks or a reference to a firmware symbol.

The admitted subset is progressive 8-bit 4:2:0 **I/P slices**, with Baseline,
Main and High SPS profiles (66/77/100). B/SP/SI slices are rejected. This is not
full profile conformance, a verified phone format, an on-car decoder or a working
CarPlay update. Nothing is advertised to a phone and no firmware/vehicle state
changes. The goal remains software-only CarPlay on the existing factory hardware.

## 1. Acquire and identify the dependency

Selected [Cisco OpenH264 v2.6.0](https://github.com/cisco/openh264/releases/tag/v2.6.0),
commit `652bdb7719f30b52b08e506645a7322ff1b2cc6f`. Source is cloned into ignored
`build/openh264-2.6.0`. Preparation and direct CMake configuration require the
exact commit and clean checkout, including ignored/untracked files; an existing
changed checkout is preserved and rejected, never reset.

The [pinned decoder API](https://github.com/cisco/openh264/blob/652bdb7719f30b52b08e506645a7322ff1b2cc6f/codec/api/wels/codec_api.h)
provides initialization, decoded plane views and delayed-output draining. Its
SPS parser admits Main/High as well as Baseline; only real output checks establish
the tested subset below. AIR private offsets are not used.

The build explicitly lists 16 common and 21 decoder C++ files from the pinned
source lists. No encoder, assembly, downloaded DLL, display driver or automatic
codec discovery is used. Codec threads are configured to zero for synchronous
decoding. This uses the project's hosted C++20 build, not the existing import-free
ARM C99 target. See [dependency notices](../third_party/README.md).

## 2. Implement input, state and frame ownership

Public C interface: [projection_h264.h](../src/carplay/projection_h264.h).
Implementation: [projection_h264.cpp](../src/carplay/projection_h264.cpp).

1. Create a serial decoder with a fresh nonzero stream generation and explicit
   **coded** size limits: multiples of 16, at most 1920 x 1088. These are allocation
   limits, not display capability declarations.
2. Feed exactly one complete Annex-B NAL per push, with a 3/4-byte start code.
   Authentication, ordering, transport framing and conversion from length-
   prefixed AVC belong to the future video owner. Input can be overwritten
   immediately after push returns.
3. Preflight every SPS before decoding: bounded Exp-Golomb/scaling-list parsing,
   coded dimensions, references, bit depth, chroma and progressive format.
   Cropping cannot hide oversized coded pictures. Reject extension NALs, embedded
   extra NALs, malformed emulation-prevention bytes and B/SP/SI slices. This is
   not a complete H.264 syntax/conformance validator.
4. End each complete access unit explicitly after all its slices. A new first
   macroblock of zero while an AU remains active, or a changed slice timestamp,
   fails closed. The caller must identify complete AUs; arbitrary network reads
   are not AU boundaries. Each AU is limited to 1 MiB / 256 NALs.
5. Disable concealment. Only an actual output flag plus valid dimensions/format/
   strides produces a frame. Copy every visible Y/U/V row into an independent,
   tight allocation; never return borrowed codec planes or padding. `FRAME`,
   `MORE` and terminal `END` are distinct results.
6. Transfer frame ownership to the caller. Frames retain generation and opaque
   timestamp and survive further decoding, failure, draining and destruction.
   Caller must bound its retained-frame queue and destroy each frame once. Views
   remain valid only for the lifetime of their owning frame.
7. Terminal drain finishes any pending AU, then requests delayed output until
   `END`. It refuses subsequent input. Restart/discontinuity requires destroy/
   create with a fresh generation and resent SPS/PPS. Old frames remain owned
   but must not be rendered for a new session.

Stale-generation/local-argument errors do not mutate the owner. Detected peer
errors, exhausted budgets and reported codec failures release its backend.
Output slots are cleared on entry; release an existing frame before reusing a
slot. No secure-erasure promise is made for codec allocations. This adapter does
not provide a hard aggregate heap/CPU cap, frame queue, color range/matrix
interpretation, RGB conversion, clock mapping, rendering or presentation feedback.

## 3. Resolve issues found by real tests

### Explicit AU completion

For `test_scalinglist_jm.264`, NAL feeding with only an EOF drain reproduced the
[upstream test hash](https://github.com/cisco/openh264/blob/652bdb7719f30b52b08e506645a7322ff1b2cc6f/test/api/decoder_test.cpp)
`992a25b4ec98db4a16d61c097e614eb16afe3478`, but the last two I/P pictures came
out in the opposite order from FFmpeg. Explicit AU completion produced
`f690a3af2896a53360215fb5d35016bfd41499b3`, matching FFmpeg and each picture's
pixels. The final API requires AU boundaries; the old mode is not accepted.

The two `Cisco_Men_whisper_640x320_*_Bframe_9.264` streams produced nine pictures,
but **four pictures per stream differed in pixels** from FFmpeg, even with
explicit boundaries. Experimental outputs matched upstream hashes
`931ba1caf075e7b47445c1f4410ade77a46048f6` (CABAC) and
`9819c0345abdd4faedbaf8f8c4dadb7749515e4d` (CAVLC). Native-FFmpeg outputs were
`2b349c1bc806b6e0412008747b2463d77b576476` and
`e5b76ff7e2f44e9b33906f8a4039d0d2bdb1580b`. Cause remains unresolved. The final
adapter rejects B slices before the codec sees them; tests verify fail-closed
rejection while an already owned I-frame stays valid.

### Unaligned native loads

The first full sanitizer run failed at `decoder.cpp:785`: an arbitrary byte
position reached `LD16` in the non-GNU branch of
[`ls_defines.h`](https://github.com/cisco/openh264/blob/652bdb7719f30b52b08e506645a7322ff1b2cc6f/codec/common/inc/ls_defines.h),
which dereferences an aligned integer pointer. Windows-target Clang does not
select the GNU packed-structure branch.

Added a local [load/store header override](../third_party/openh264/ls_defines.h)
using native-endian `memcpy` for all widths/alignment-hinted variants. CMake places
it first for the six decoder/common include sites. The upstream checkout stays
unchanged; no compiler identity is forged and no sanitizer check is disabled.
Tests cover byte offsets 0..7 and every helper width. The full codec, adapter
and tests now pass ASan/UBSan. This addresses the observed issue, not all possible
malformed-stream bugs or target portability.

## 4. Verify reproducibly

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayVideo.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayVideoSanitizers.ps1
./build/media-reference/Scripts/python.exe -B scripts/check_projection_h264.py build/video/Release/projection_h264_tests.exe build/openh264-2.6.0/res
python -B -m unittest discover -s tests -p 'test_*.py'
git diff --check
```

The independent check reuses the existing hash-pinned PyAV environment documented
in [audio decoding](projection-decode.md). On a fresh checkout:

```powershell
python -B -m venv build/media-reference
./build/media-reference/Scripts/python.exe -B -m pip install --require-hashes --only-binary=:all: --no-deps -r scripts/media-reference-requirements.txt
```

The checker requires PyAV 18.1.0 / libavcodec 62.28.102, selects native `h264`
(not libopenh264), verifies fixture SHA256, and compares row-packed visible planes
and output order against both adapter variants. SHA1 is a pixel-test convention,
not media authentication.

| Public compressed fixture | Profile | Visible size | Frames |
| --- | --- | --- | --- |
| `Static.264` | Baseline | 152 x 100 | 10 |
| `test_qcif_cabac.264` | Main | 176 x 144 | 30 |
| `test_scalinglist_jm.264` | High | 320 x 192 | 5 |
| `Adobe_PDF_sample_a_1024x768_50Frms.264` | Baseline | 1024 x 768 | 50 |
| `test_cif_P_CABAC_slice.264` | Main, 14 slices/picture | 352 x 288 | 300 |

Recorded results:

- All **23 optional-video CTest tests** pass.
- Video tests and the entire linked generic codec pass **ASan/UBSan** with no
  suppressed checks; no leak-sanitizer claim is made for this Windows run.
- **395 independent FFmpeg frames** match both AU/drain variants (790 adapter
  frames), including the 300-picture/4,200-slice stream.
- C-compiled API use, delayed output, frame lifetime across input overwrite/
  subsequent decode/destroy, stale tokens, missing boundaries, NAL/AU budgets,
  unsupported formats, crop bounds and **256 SPS mutations** pass. This is a
  limited regression corpus, not comprehensive fuzzing.
- All **83 existing Python tests** pass. The dependency checkout stays clean.

Public upstream streams stay in the ignored dependency clone. No proprietary
firmware, owner photographs or phone media are inputs or committed files.

## 5. Next work and target assessment

Later follow-up: [Step 91](projection-video-source.md) extends the frame view with
owned SPS/VUI source metadata and internal per-picture token association. The
dimension-only preflight and absent-metadata limitations above describe Step 87;
the I/P-only codec and unverified ARM/QNX integration boundaries still apply.

Follow-up: [Step 88](projection-video-stream.md) implements owning memory-input
screen framing, authenticated frame records, explicit clear AVC configuration,
complete-AU conversion and bounded frame queues using a pinned public reference.
It preserves configuration epochs and raw authenticated headers, with record
counters rather than guessed presentation timestamps. Its 740-frame independent
encryption/decoding check uses synthetic wire records, not actual phone captures.
The next layer is a peer-bound session/socket service; actual phone framing and
timing still need verification. The build/test counts above record Step 87;
Step 88's report records the expanded optional build and checks.

ARM/QNX porting remains separate: establish a matching compiler/C++ runtime and
OS/thread/time/allocation APIs, then measure memory and latency at the actual
display resolution. Generic C++ without assembly does not prove adequate ARM
speed, QNX ABI compatibility or a deployable executable. No ARM/QNX decoder build
or target benchmark was produced here.

Before anything runs on the car, installed-version execution/recovery, USB/chip
ownership, display/input routing, audio focus and microphone access still need
verification. The exact navigation-module revision remains unknown. This backend
does not authorize flashing the later 6.17.0WL research corpus onto 6.9.0WL.
