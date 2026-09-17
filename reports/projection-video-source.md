# Step 91 - Preserve and render per-picture source metadata

Date: 2026-09-17. Continues [owned native video rendering](projection-video-render.md).

Follow-up: [Step 92](projection-video-clock.md) checks sender-time references and
fixes empty/repeated configuration handling. Only changed codec configuration
now resets the epoch; source metadata and presentation-time limits remain separate.

## Result and boundary

Decoded pictures now carry their own SPS/VUI colour, range, sample-aspect-ratio
and nominal timing metadata. A new explicit GDI policy selects supported source
colour and non-square-pixel fitting from that metadata. Forty additional real
TCP/AEAD/decoder/GDI readbacks match an independent FFmpeg-based interpretation
and pixel calculation, with zero observed RGB error on the chosen fixture.

This is host implementation progress, **not CarPlay installed or working on the
factory unit**. Configuration remains explicitly unauthenticated; authenticated
picture payloads do not authenticate the SPS from which these values came.
The tests use synthetic SPS/wire records and a public compressed fixture, not a
phone capture. No hardware, visible window, service menu or firmware was changed.

## 1. Carry explicit source values rather than resolution guesses

The [public frame view](../src/carplay/projection_h264.h) gains a by-value
`projection_h264_source`. The [decoder preflight](../src/carplay/projection_h264.cpp)
now consumes the supported SPS through VUI and RBSP trailing bits, rather than
stopping at the VUI presence flag. It retains:

- Presence flags, aspect code and sample aspect ratio (SAR).
- Video format, range, colour primaries, transfer and matrix code points.
- Chroma-location flags and values.
- Nominal `num_units_in_tick`, `time_scale` and fixed-frame-rate flag.

Unspecified SAR stays `0:0`; absent colour description keeps code point 2 rather
than guessing BT.601/BT.709 from image dimensions. Absent video-signal information
keeps the syntax's limited-range default, distinct from an explicitly signalled
colour description. Extended SAR with either zero component becomes unspecified.
All 17 table entries and 16-bit extended ratios are handled. Reserved aspect
codes, malformed/truncated fields and invalid trailing bits reject the owner.

Field order was cross-checked against the pinned OpenH264 2.6.0
[ParseVui implementation](https://github.com/cisco/openh264/blob/652bdb7719f30b52b08e506645a7322ff1b2cc6f/codec/decoder/core/src/au_parser.cpp),
and SAR interpretation against H.264 Annex E/Table E-1 in the ITU's indexed 2024
text. The [ITU recommendation catalogue](https://www.itu.int/rec/T-REC-H.264)
now lists a newer 2026 edition; this is not a claim of expanded codec conformance.
The local parser is not copied upstream implementation code.

The 4 KiB SPS limit, bounded Exp-Golomb reader, progressive 8-bit 4:2:0 profile
66/77/100 gate, coded-dimension limits and I/P-only policy remain. HRD/restriction
syntax is traversed with bounded loops, but HRD scheduling is not implemented.
OpenH264 still validates picture/parameter-set syntax; this is not a replacement
full H.264 validator. Unsupported colour code points are retained for inspection,
not silently converted using another matrix.

## 2. Associate metadata with the picture that actually used it

Simply reading the latest SPS at output time would mislabel delayed pictures.
The decoder now tracks 32 SPS IDs and 256 PPS-to-SPS mappings. The first slice
selects its PPS/SPS, snapshots the metadata and cropped dimensions, and allocates
a unique nonzero internal codec token. Further slices must name the same PPS and
caller timestamp until the explicit end-of-access-unit boundary.

There are at most 32 pending snapshots. The codec receives the internal token;
output resolves that token back to the original caller timestamp and metadata.
This handles repeated caller timestamps without using them as unique keys.
The returned frame owns its snapshot even after parameter replacement, another
decode or decoder destruction. Output dimensions must match the selected SPS.
Missing/repeated output associations, unmatched snapshots at terminal drain,
pending-slot exhaustion and token wrap terminate the decoder instead of guessing.

This adds fixed owner storage, not another pixel queue. The downstream owning
video service still controls its separate frame queue and deadlines. New stream
configuration still constructs a new decoder/epoch; the existing video-input
layer still rejects changed in-band parameter sets without a new configuration.
No changes weaken authentication, reply-drain or generation/epoch gates.

The C structs grew; rebuild all consumers together. This research API does not
claim binary ABI compatibility with previously compiled callers.

## 3. Make the rendering policy explicit

The [pixel API](../src/carplay/projection_video_pixels.h) adds a source-colour
resolver and `projection_video_fit_sar`. Fit calculations use bounded 64-bit
integer products/division, preserve the source display aspect, floor the second
extent to at least one pixel and centre with black borders. The old square-pixel
fit is an explicit 1:1 wrapper, not an inferred source property.

| GDI target policy | Colour | Sample aspect ratio |
| --- | --- | --- |
| Existing modes 1..4 | Explicit caller override | Explicit legacy square-pixel override |
| `PROJECTION_VIDEO_SOURCE` | Required signalled supported SDR values | Required signalled nonzero SAR |

The strict source resolver accepts matrix 1 (BT.709) or 5/6 (BT.601), explicit
range, primaries 1/5/6 and transfer 1/6. Missing/unspecified values, unsupported
matrices, HDR transfer functions and wider-gamut primaries are rejected. There
is no implicit fallback and no automatic advertisement of display readiness.
These are deliberately limited source R'G'B' conversions, **not display gamut,
transfer, ICC or HDR management**. Other valid SDR transfers need separate support.
Chroma remains nearest 2x2 replication, not phase-aware reconstruction.

The [GDI sink](../src/carplay/projection_video_gdi_win.cpp) retains the resolved
colour and SAR alongside the owned converted picture. Repaint/resize uses that
retained SAR, never the caller's expired descriptor or a later SPS. Status exposes
the resolved values. Reconfiguration clears pixels and metadata; partial close
and terminal failure retain the existing black-only repaint contract.

Only the explicit policy value 5 invokes source interpretation. The raw BGRA
converter still requires one of modes 1..4; accidental use of 5 there rejects.
The existing memory ownership, two-buffer maximum, DPI/thread requirements,
backpressure and no-presentation-clock restrictions remain unchanged.

## 4. Verify decoding, selection and actual output independently

Reproduction, using the existing pinned dependency environments:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayVideo.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayVideoSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayPixelsArm.ps1
./build/media-reference/Scripts/python.exe -B scripts/check_projection_video_source.py build/video/Release/projection_video_gdi_tests.exe build/openh264-2.6.0/res
./build/media-reference/Scripts/python.exe -B scripts/check_projection_video_render.py build/video/Release/projection_video_gdi_tests.exe build/openh264-2.6.0/res
./build/media-reference/Scripts/python.exe -B scripts/check_projection_h264.py build/video/Release/projection_h264_tests.exe build/openh264-2.6.0/res
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_video.py build/video/Release/projection_video_tests.exe build/openh264-2.6.0/res
python -B -m unittest discover -s tests -p 'test_*.py'
git diff --check
```

Results:

- **48/48 optional-video CTest suites pass.** Both new source suites are included.
- **8/8 media ASan/UBSan suites pass**, including generic OpenH264 and the new
  production/parser paths. No suppressed sanitizer checks, Windows-DLL
  instrumentation or Windows leak-sanitizer claim.
- The new public-API source suite decodes 30 generated VUI variants over the
  unchanged public IDR: all table SARs, extended/zero/absent SAR, absent fields,
  full range, unsupported HDR metadata retention, chroma/timing extrema and HRD.
  It tests selected-SPS versus last-SPS, PPS remapping including ID 255, repeated
  external timestamps, retained frame/pixel lifetime, truncation and bad syntax.
- A separate **white-box-only** executable injects delayed/reordered outputs,
  32-slot exhaustion, token wrap, duplicate/unknown output tokens, dimension
  disagreement and orphaned terminal snapshots. This proves the adapter's
  association gates, not natural 32-frame delay or new codec/B-frame support.
  It compiles the production implementation locally without adding test hooks.
- Real IPv4/IPv6 video streams exercise four strict source modes, startup holds,
  changed colour/SAR at a new configuration epoch without counter reset, and
  tag-failure blanking. Direct GDI tests additionally verify retained SAR across
  descriptor mutation/resize and rejection/blanking of missing/HDR metadata.
- The [independent source checker](../scripts/check_projection_video_source.py)
  verifies the original SHA256 pin, reads the exact generated SPS used by the
  C++ test, then uses native FFmpeg to decode it and independently report colour,
  range, primaries, transfer and SAR. It calculates source RGB and exact integer
  scaling/letterboxing separately, comparing **40 actual GDI readbacks**. All
  B/G/R differences are **0**. Both planar `yuv420p` and FFmpeg's full-range
  `yuvj420p` representation are accepted without rescaling the source planes.
  Destination alpha is deliberately excluded. Non-integer GDI scaling is not
  independently validated by this check.
- The previous **40 explicit-mode renders**, **395 independent decoded frames**
  (both drain variants), **740 independently encrypted/decoded frames** and
  **83 Python regression tests** still pass.
- The standalone host pixel target still builds/tests with optional codec and
  crypto source paths empty. The separate ARM object check now declares both
  **`__aeabi_uidiv` and `__aeabi_uldivmod`**, the latter needed by SAR fitting.
  This is not an import-free core, QNX executable or factory-device benchmark.

No new library or fixture binary was committed. Generated metadata lives in
test source, and downloaded codec/test media remain outside Git. The existing
dependency pins and Mbed TLS extracted-tree verification limitation still apply.

## 5. Next work toward software-only factory CarPlay

Investigate sender presentation-time fields against the pinned receiver evidence
and connect only verified units/epochs to the existing timing clock. VUI frame
rate, a decoded frame counter and GDI completion are **not** presentation
timestamps or proof of A/V synchronization. SEI timing, display orientation and
alternative colour/transfer signalling are not interpreted; SPS/VUI support is
not comprehensive stream-display metadata support. Source-to-display colour
management, phase-aware chroma, visible-device behavior and actual-phone
interoperability remain unverified.

The factory path still needs installed-version execution/recovery, a matching
ARM/QNX compiler/runtime, USB/authentication-chip ownership, display/input
routing, audio focus/microphone access and measured memory/CPU/latency budgets.
The Windows sink cannot be installed as a QNX driver. The navigation-module
revision remains unknown; the later 6.17.0WL corpus is still offline reference,
not a firmware package to flash onto the installed 6.9.0WL unit.
