# Step 88 - Encrypted video input with owned decoded frames

Date: 2026-09-13. Continues [the H.264 decoder](projection-h264.md).

Follow-up: [Step 92](projection-video-clock.md) admits exact reserved-zero AVC
wrappers and treats empty/identical codec configuration as no-ops. New changed
configuration still invalidates history/epochs; this report's reset-on-every-
configuration behavior and 740-frame count describe the historical Step 88.

## Result and boundary

An optional owning video-input layer now joins fragmented screen records to the
real source-built H.264 decoder. It authenticates encrypted frame records,
parses explicit cleartext AVC configuration, converts bounded length-prefixed
NALs, and queues independently owned I420 pictures. **740 decrypted/decoded
frames** match independently checked pixel/order goldens across nine variants.

This is memory-input host implementation, not a network listener, real phone
session, renderer, ARM/QNX port or installable CarPlay update. The wire records
in tests are synthetic; compressed pictures are public upstream fixtures.
Receiver capabilities remain unchanged. No firmware, USB media, service-menu
setting or vehicle state changed. Software-only CarPlay on the existing factory
unit remains the goal, not a host-only substitute.

## 1. Establish the selected wire profile from primary source

The inspected LIVI checkout is clean at commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Relevant Git blob identifiers:

| Pinned file | Blob SHA1 |
| --- | --- |
| [TypeScript screen input](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/screenStream.ts) | `c02d2385a0fb2fb1be2dfe214ec4456420cfa3a2` |
| [TypeScript configuration helper](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/nalu.ts) | `4f9ace3ee0849d238d5f132d6e37fdbea151c4e6` |
| [Rust screen input](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/screen/src/lib.rs) | `249c8af60ff20f5ffa411ac95046a686bfa2336e` |
| [Rust NAL helper](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/nal/src/lib.rs) | `b8e8744e5a5256bced4aa3a73628121b7d84f623` |

Both screen implementations consume a 128-byte header followed by a body. The
header begins with a little-endian 32-bit body length and opcode at byte 4.
Opcode 1 configuration is cleartext and does not advance the frame counter.
Opcode 0 frames use ChaCha20-Poly1305, a trailing 16-byte tag, all 128 header
bytes as associated data, and nonce `zero32 || LE64(counter)`, starting at zero.
These are reference implementation observations, not an Apple specification or
evidence captured from the owner's phone. See the pinned screen files above.

The [pinned session stack](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts)
connects screen resources to SETUP and derives their directional key using
HKDF-SHA512: pair-verify shared secret, salt `DataStream-Salt` plus decimal
stream-connection ID, info `DataStream-Output-Encryption-Key`, 32-byte output.
The existing [session layer](projection-session.md) implements that derivation.
This step accepts a key through a trusted-owner contract; it does not yet connect
the video child to that session provider.

Neither inspected screen reader establishes a wire presentation timestamp.
Consequently, the decoder's opaque timestamp is the authenticated record counter,
**not** an invented NTP field. Original authenticated frame headers are retained
for future timing investigation. Treating one frame message as one complete
access unit is this initial adapter's selected model, informed by the reference
frame boundary; actual phone segmentation still needs verification.

## 2. Make security and compatibility policies explicit

Public interface: [projection_video.h](../src/carplay/projection_video.h).
Implementation: [projection_video.cpp](../src/carplay/projection_video.cpp).

1. Require a fresh nonzero generation, a fresh directional resource key and
   explicit `allow_clear_config=1`. The future transport owner must pin the peer
   and permit exactly one connection for this key's lifetime. This layer cannot
   verify those external conditions itself.
2. Expose `frame_authenticated=1` and `configuration_authenticated=0` on every
   output. Configuration snapshots also report unauthenticated provenance.
   Valid frame authentication does not authenticate the earlier SPS/PPS or
   prevent cleartext configuration injection/denial of service on an exposed
   transport. Do not interpret the output flag as end-to-end pixel provenance.
3. Reject frame bodies shorter than a tag, rather than adopting the reference's
   plaintext short-frame fallback. A valid tagged empty frame advances the
   counter but produces no fabricated picture.
4. Fail closed on bad authentication; do not adopt the reference's catch/drop/
   continue behavior. Advance the counter once after a valid tag, including
   parameter-only/empty frames. Later format/decoder errors are terminal.
5. Configuration and bounded unknown opcodes do not advance the counter. Unknown
   records are ignored, never executed as keyframe/control commands. Never reset
   the counter for reconfiguration, RECORD or reconnect. No reconnect/reset API
   exists. Counter `UINT64_MAX` may authenticate once; the next frame is refused.

The Rust reference additionally resets its counter when a connection is replaced.
The local owner deliberately has no such operation under an existing key. These
fail-closed/lifetime policies are local choices and may reject unverified phone
variants; they are not claimed to be complete reference equivalence.

## 3. Parse configuration and preserve complete access units

The reference configuration helpers locate fourcc markers and fall back to HEVC.
This implementation instead accepts only a bare AVC configuration record, one
exact `avcC` box, or one bounded `avc1` sample entry containing exactly one `avcC`.
It walks child lengths, including extended-size boxes, rather than searching
arbitrary payload bytes. HEVC, duplicate AVC children and inconsistent sizes
are rejected. Bounded unknown children and an optional final four-zero-byte
terminator are allowed. The fixed sample-entry region is 78 bytes after the box
header; its individual fields are not all semantically validated.

Cross-checks used [FFmpeg n8.1's AVC extradata parser](https://github.com/FFmpeg/FFmpeg/blob/n8.1/libavcodec/h264_parse.c#L433)
for SPS/PPS group lengths and the NAL-length-size field, and Apple's
[video sample description](https://developer.apple.com/documentation/quicktime-file-format/video_sample_description),
[sample description](https://developer.apple.com/documentation/quicktime-file-format/sample_description_atom)
and [atom structure](https://developer.apple.com/documentation/quicktime-file-format/atoms)
references for containment/size conventions. No upstream implementation bodies
were copied. The parser is intentionally narrower than a general MP4 demuxer.

1. Require version 1, reserved-bit patterns, nonempty SPS/PPS groups, supported
   profiles 66/77/100 and 1/2/4-byte NAL lengths; reserved 3-byte lengths fail.
   The first SPS profile/compatibility/level must match the record fields.
   Each set has bounded length and the expected NAL type/reference bits.
2. For High profile, an omitted extension is admitted. A present extension must
   be exactly 8-bit 4:2:0 with no SPS extensions. Other suffixes are rejected.
3. Initialize a candidate H.264 decoder with all configuration sets and an
   explicit AU boundary before replacing live history. The decoder's existing
   progressive-format, coded-size, I/P-only and syntax gates still apply.
4. On success, retain owned configuration bytes, increment its epoch, release
   queued old pictures/pending associations and replace decoder history. The
   first new VCL picture must be IDR. Already transferred frames remain allocated
   but the caller must invalidate old epochs before presenting them.
5. Authenticate an entire frame record, then validate its entire NAL length
   table before submitting any NAL. In-band SPS/PPS must exactly match the
   retained configuration; changes require a configuration record/new epoch.
6. Convert each NAL to Annex B and explicitly finish the complete access unit.
   Associate delayed output with pending authenticated counter/epoch metadata.
   A second complete picture inside one record is rejected by the H.264 boundary
   gate. This is not a full H.264 conformance validator.

## 4. Bound buffers, queues and lifetime

| Local bound | Policy |
| --- | --- |
| Frame record | 1 MiB plaintext, plus 16-byte tag and 128-byte header |
| Configuration/unknown body | 64 KiB |
| Converted access unit | At most 1 MiB / 256 NALs |
| Parameter sets | At most 64 total, each 2..4096 bytes |
| Sample-entry children | At most 32 |
| Configuration lifetime | At most 64 successful epochs |
| Decoder associations | At most 32 pending frame metadata entries |
| Owned output queue | Explicit capacity 2..8; require two free slots before input/drain |
| Receive/hold deadlines | Explicit 1..60000 ms, absolute and independently enforced |
| Coded dimensions | Explicit multiples of 16, at most 1920 x 1088 |

The frame bound is narrower than LIVI's 8 MiB body allowance. Video calls the
existing pinned Monocypher implementation directly behind its private adapter
boundary; the pairing/control AEAD API's existing 64 KiB limit is unchanged.
About 3 MiB of input/plain/conversion buffers plus parameter storage is allocated
per owner, separate from codec storage and decoded pictures. The table does not
establish an aggregate heap/CPU limit or adequate factory-unit performance.

`feed` owns fragments and consumes at most one record per call. The caller retains
any coalesced tail. `BUSY` consumes zero bytes; partial input/backpressure never
refreshes a deadline. Receive expiry starts at the first record byte; queue
expiry starts when the oldest retained picture is queued. The caller must poll
with a monotonic clock; stale generations and clock rollback are rejected.

Decode/queue may precede RECORD, but `take` is gated by an explicit `start` after
the control reply drains. `take` transfers a frame, not a presentation event.
The caller must bound external holdings and destroy each frame once. Generation,
configuration epoch and failure state must be checked before display.

Explicit clean EOF rejects partial records, closes input, wipes the key and
drains delayed output through the same bounded queue. `END` means decoder drain
completed, not that the queue is empty. Errors/TEARDOWN should destroy the child,
not present a drained tail. Terminal failures free queued frames and the decoder
and wipe owned key/wire/plain/conversion/configuration bytes. Pixel/codec
allocations have no secure-erasure guarantee. No C++ exception crosses the C API.

## 5. Verify with real compressed data and independent encryption

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayVideo.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayVideoSanitizers.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_video.py build/video/Release/projection_video_tests.exe build/openh264-2.6.0/res
./build/media-reference/Scripts/python.exe -B scripts/check_projection_h264.py build/video/Release/projection_h264_tests.exe build/openh264-2.6.0/res
python -B -m unittest discover -s tests -p 'test_*.py'
git diff --check
```

The optional build now prepares both existing pinned dependencies: OpenH264 2.6.0
and Monocypher 4.0.3. No new receiver dependency is introduced. The video owner
target exists only when both optional targets are configured.

For a fresh independent encryption environment:

```powershell
python -B -m venv build/pair-reference
./build/pair-reference/Scripts/python.exe -B -m pip install --only-binary=:all: -r scripts/pair-reference-requirements.txt
```

This test-only environment is version-pinned, **not hash-pinned**. The checker
requires cryptography 50.0.1; PyCA's ChaCha20Poly1305 independently seals records
read by the Monocypher-backed production library. The media-reference PyAV
environment is separately hash-pinned; see [Step 87](projection-h264.md#4-verify-reproducibly).

The [wire checker](../scripts/check_projection_video.py) verifies five compressed
fixture SHA256 pins, extracts SPS/PPS, forms synthetic complete-AU records,
encrypts with deterministic public test keys/counters/header bytes, and streams
them through stdin in fragmented reads. It compares owned pixel output/order
with the FFmpeg-checked goldens from Step 87:

| Fixture | Prefix widths tested | Decoded frames across variants |
| --- | --- | --- |
| `Static.264` | 2, 4 | 20 |
| `test_qcif_cabac.264` | 2, 4 | 60 |
| `test_scalinglist_jm.264` | 2, 4 | 10 |
| `Adobe_PDF_sample_a_1024x768_50Frms.264` | 4 | 50 |
| `test_cif_P_CABAC_slice.264` | 2, 4 | 600 |

Largest tested plaintext AU: **198,956 bytes**, exercising input beyond the
pairing API's 64 KiB boundary. One-byte prefixes have a separate parameter-only
NAL test, not a full encrypted picture fixture. SHA1 is solely the upstream
pixel-comparison convention, never the authentication mechanism.

Recorded verification:

- **30/30 optional-video CTest suites pass.**
- **3/3 video/decoder/limit suites pass ASan/UBSan**, with Monocypher and all linked
  generic OpenH264 source instrumented; no suppressed checks or Windows leak-
  sanitizer claim.
- **740 independently encrypted/decrypted/decoded frames pass** across nine
  variants; **395 independent FFmpeg frames** again match both decoder drain
  variants (790 adapter frames).
- C-compiled API calls, fragmented/coalesced input, pre-RECORD gating,
  backpressure, reconfiguration/old-frame lifetime, nonce retention/replay,
  header/ciphertext/tag tampering, no plaintext fallback, IDR/in-band-set gates,
  malformed AU tails/multiple AUs, exact/truncated/extended configuration boxes,
  High extension fields, deadlines, stale generations and partial EOF pass.
- A separate white-box executable injects counter/epoch lifetime boundaries and
  checks close/wipe behavior. Production-library tests have no such hooks; this
  is not a claim of sending 2^64 frames or testing every malformed stream.
- All **83 Python regression tests pass**. Public dependency checkouts remain
  clean. No owner media, credentials or firmware are committed.

## 6. Next implementation and factory requirements

Follow-up: [Step 89](projection-video-services.md) implements and verifies the
session-bound Windows TCP service described below, including explicit sink
ownership and concurrent audio delegation. The memory-input layer and historical
Step 88 counts above remain separate; actual rendering/timing and target
integration are still unfinished.

Next add a session-bound video service: allocate the screen TCP endpoint from
the existing resource lease, pin the expected peer, admit one transport, own
coalesced tails/backpressure/deadlines, and propagate CONFIG epochs, RECORD
reply-drain startup, failures and TEARDOWN to the child. Verify real IPv4/IPv6
loopback bytes through the actual decoder before adding a display sink. Do not
enable a capability merely because the input library compiled.

Presentation timestamps, continuous A/V synchronization, rendering/color
conversion, actual phone configuration/AU variants, broader codec support and
physical input are still unresolved. B/SP/SI slices remain disabled. No actual
phone pairing, MFi-chip access or media reception occurred here.

For the owner's Panasonic TAS400/Harman navigation hardware, a matching ARM/QNX
compiler/runtime, safe installed-version execution/recovery, USB/authentication
ownership, display/input routing, audio focus/microphone access and measured
resource/performance behavior remain required. Exact navigation-module revision
is still unknown; no further owner information is assumed. This work does not
authorize installing the later 6.17.0WL research corpus over installed 6.9.0WL.
