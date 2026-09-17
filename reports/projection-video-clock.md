# Step 92 - Check sender-time evidence and fix configuration interoperability

Date: 2026-09-17. Continues [per-picture source metadata](projection-video-source.md).

## Result and boundary

The selected CarPlay reference does **not** supply a verified wire-to-local
presentation-time mapping. This step does not invent one from a video counter,
VUI frame rate or a superficially similar AirPlay header.

The source review instead exposed three concrete configuration compatibility
gaps, now fixed: empty configurations, repeated codec data and a reserved-zero
AVC wrapper. They no longer abort startup or unnecessarily reset decoder history.
The complete encrypted-video path still rejects malformed nonempty input and
preserves its authentication, queue, epoch and deadline gates.

All execution remains on the PC with synthetic wire records and public codec
fixtures. This is not a phone capture, a factory/QNX renderer, demonstrated A/V
synchronization or installable software-only CarPlay. No car/USB/service-menu
state was changed. UxPlay source objects were downloaded for static comparison;
no upstream receiver, installer or build was run.

## 1. Trace the timestamp path, including what consumers actually receive

The existing LIVI reference remains pinned to
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. The additional UxPlay comparison is
pinned to `2c7b63ee9c36edfb121186db928397c582852133`.

| Selected source path | Observed behavior | What it establishes |
| --- | --- | --- |
| LIVI TypeScript/Rust screen readers | Authenticate the 128-byte header, then deliver only compressed payload to the frame callback | No sender timestamp is propagated by these readers |
| LIVI native addon/player | Route payload bytes to GStreamer; the selected player disables sink clock synchronization | This path is immediate/arrival-driven, not evidence of sender-PTS scheduling |
| UxPlay mirror/NTP path | Read a raw 64-bit value at header offset 8, adjust its epoch, map remote to local time and deliver that time with video | A timestamp implementation in a different media profile, not proof of equivalent CarPlay semantics |

Primary LIVI references:
[TypeScript screen](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/screenStream.ts),
[Rust screen](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/screen/src/lib.rs),
[addon](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/addon/src/screen_recv.rs),
[player](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/player/src/lib.rs).

In UxPlay, `byteutils_get_long` is a native `uint64_t` load, not an explicit
portable little-endian parser. The video path calls the epoch adjustment with
the 1900-to-1970 addition enabled; timing responses use a different setting.
Its media cipher is AES-CTR with different key derivation, not this project's
LIVI-derived ChaCha20-Poly1305 screen profile. Neither the raw offset nor its
epoch relationship can be copied into this receiver and called verified.
See the pinned [mirror reader](https://github.com/FDH2/UxPlay/blob/2c7b63ee9c36edfb121186db928397c582852133/lib/raop_rtp_mirror.c),
[byte helpers](https://github.com/FDH2/UxPlay/blob/2c7b63ee9c36edfb121186db928397c582852133/lib/byteutils.c),
[NTP conversion](https://github.com/FDH2/UxPlay/blob/2c7b63ee9c36edfb121186db928397c582852133/lib/raop_ntp.c)
and [cipher](https://github.com/FDH2/UxPlay/blob/2c7b63ee9c36edfb121186db928397c582852133/lib/mirror_buffer.c).

The existing synchronized timing clock and inverse mapping remain available,
but there is no newly verified source video time to feed them. Raw authenticated
frame headers remain preserved, and decoder timestamps remain record counters.
No production timestamp parser, epoch offset, scheduling mode or false played
position was added.

## 2. Correct three observable configuration mismatches

The pinned native addon explicitly returns without reporting empty codec data,
and suppresses repeats of the same codec/data. Its
[NAL-helper tests](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/nal/src/lib.rs)
also construct an AVC wrapper with four reserved zero bytes before `avcC`.
These are retrievable source/test observations, not claimed owner-phone evidence.

A web-search lead, an indexed `redline-labs/digital_dashboard` bring-up document,
also reported empty startup configuration. Its direct GitHub/raw URLs returned
404 or could not be fetched during this investigation. It was **not** used as
independent hardware validation or as the implementation's authority; the pinned
LIVI code above supplies the reproducible basis.

Previously our parser rejected empty configuration and the zero-prefix wrapper.
Every repeated configuration also created a new decoder/epoch, discarded queued
frames and required another IDR. That can disrupt a continuing P-picture stream.
The [video input owner](../src/carplay/projection_video.cpp) now applies:

1. An empty opcode-1 body is `IGNORED`, never codec readiness or authenticated data.
2. Exactly `00 00 00 00` followed immediately by `avcC` at the top level selects
   the rest of this bounded screen record as codec data. This is a narrow
   reference-wrapper rule, **not** arbitrary marker search or general MP4
   size-to-EOF support. Nonempty extracted data still receives full AVC validation.
3. A correctly bounded supported AVC wrapper whose selected codec data is empty
   is also ignored. Empty HEVC/unknown wrappers are not adopted as a codec switch.
4. Byte-identical normalized codec data already validated by the live decoder is
   ignored, including when repeated in another supported wrapper. No decoder is
   constructed, configuration callback sent or new epoch allocated.
5. A changed nonempty configuration still builds/validates a candidate before
   replacing history. It still retires the old queued epoch, requires an IDR,
   increments the change count and preserves the frame nonce counter.

Ignored configurations do not change the nonce, epoch, queued frame ownership,
reference-picture history, required-IDR flag or existing deadlines. They cannot
bypass pre-RECORD delivery or the two-free-slots input rule. They cannot clear a
renderer-held picture to escape its hold deadline. The 64-change lifetime limit
still rejects a 65th changed configuration, while harmless repeats/empty records
do not consume that budget.

Malformed nonempty AVC and container lengths still terminate the stream. General
nested zero-size boxes, HEVC wrappers, duplicate AVC children, trailing garbage
and a misplaced marker remain rejected. Only extracted AVC bytes define duplicate
identity; interpretation of other sample-entry metadata remains outside this
adapter's existing supported subset. Whole-session idle/readiness budgeting is
unchanged; a keepalive does not prove that usable video will ever arrive.

## 3. Pin and reproduce the source evidence without executing it

The new [offline source checker](../scripts/inspect_video_clock_reference.py)
verifies these Git blob identities before checking the reviewed call-site markers:

| Reference / selected file | Git blob SHA1 |
| --- | --- |
| LIVI `screenStream.ts` | `c02d2385a0fb2fb1be2dfe214ec4456420cfa3a2` |
| LIVI Rust `screen/src/lib.rs` | `249c8af60ff20f5ffa411ac95046a686bfa2336e` |
| LIVI `addon/src/screen_recv.rs` | `e73033cc7722acc45ff90e3a808806f9884ef61f` |
| LIVI `nal/src/lib.rs` | `b8e8744e5a5256bced4aa3a73628121b7d84f623` |
| LIVI `player/src/lib.rs` | `f9c763418cb1af4bd9e7340b08aa4cb243ffac31` |
| LIVI `timingServer.ts` | `2eb385de51fd3ceda2e720bfa4687d277b467d70` |
| UxPlay `lib/raop_rtp_mirror.c` | `3c1dcabe5175551a9a2b7dc3b5b13ff80cb11060` |
| UxPlay `lib/byteutils.c` | `095020881258a95eb2a33995653868c73a24ac2d` |
| UxPlay `lib/raop_ntp.c` | `892de9c407746ac13e3b10539b8cca0f40ff96db` |
| UxPlay `lib/mirror_buffer.c` | `95492e81ecd67277d11e850f2ac5a65cc7b0a5e2` |

The checker reads commit objects, not the worktree, and runs only Git object
reads. It bounds each object to 512 KiB, verifies its Git blob hash, uses no
shell command construction, disables lazy fetch/network protocols and has
30-second subprocess timeouts. The checks preserve a reviewed evidence snapshot;
they are not a general semantic analyzer or proof that a real sender matches it.

If UxPlay objects are absent, fetch the comparison separately. For a fresh
destination only (do not overwrite an existing checkout):

```powershell
git clone --filter=blob:none --no-checkout https://github.com/FDH2/UxPlay.git build/uxplay-reference
git -C build/uxplay-reference fetch --filter=blob:none origin 2c7b63ee9c36edfb121186db928397c582852133
$videoClockPin = '2c7b63ee9c36edfb121186db928397c582852133'
foreach ($videoClockFile in @('lib/raop_rtp_mirror.c','lib/byteutils.c','lib/raop_ntp.c','lib/mirror_buffer.c')) {
    git -C build/uxplay-reference show "${videoClockPin}:$videoClockFile" | Out-Null
}
python -B scripts/inspect_video_clock_reference.py
```

The existing LIVI Git-object cache supplies the other six files; a sparse
worktree need not contain them. Fetch missing pinned objects explicitly before
the offline checker, not by enabling network access inside it. No source is
compiled and neither comparison becomes a receiver dependency.

## 4. Verify the changed path and its unchanged limits

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayVideo.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayVideoSanitizers.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_video.py build/video/Release/projection_video_tests.exe build/openh264-2.6.0/res
./build/media-reference/Scripts/python.exe -B scripts/check_projection_video_render.py build/video/Release/projection_video_gdi_tests.exe build/openh264-2.6.0/res
./build/media-reference/Scripts/python.exe -B scripts/check_projection_video_source.py build/video/Release/projection_video_gdi_tests.exe build/openh264-2.6.0/res
python -B scripts/inspect_video_clock_reference.py
python -B -m unittest discover -s tests -p 'test_*.py'
git diff --check
```

Verification covers:

- Empty startup, fragmented headers, coalesced records and the reserved wrapper.
- Repeated bare/boxed/extended/sample-entry AVC normalizing to the same validated
  codec bytes, without retiring queued frames or requiring a new IDR.
- Continuing authenticated P pictures after repeated configuration, unchanged
  counters, failed nonce replay and unchanged pre-RECORD readiness gates.
- Absolute partial-record/queued/renderer-held deadlines and backpressure.
- 64 real validated configuration changes with interleaved repeats, harmless
  empty/repeat records at the limit, and rejection of the 65th change.
- Real IPv4/IPv6 TCP through the decoder and GDI with interleaved no-ops; changed
  configuration tests now actually change codec data instead of relying on a
  repeated byte string to reset the stream.
- Five Python tests for source hash/bounds, missing evidence markers and the
  checker's no-shell/offline subprocess contract.

The first full rerun exposed an old white-box limit fixture using an invalid
one-byte wrapper. It now selects the bare AVC discriminator so that it isolates
the intended epoch-limit branch. A separate public-API test supplies fully valid
records for the complete 64/65 boundary; the production limit was not weakened.

The independent PyCA wire check now runs all nine prior fixture/prefix variants
both normally and with configuration no-ops: **18 variants / 1,480 decoded
frames** match their existing independent pixel/order goldens. Both GDI checks
still match **80 rendered frames** with zero observed RGB difference, now through
the updated startup/repeat path. These records remain synthetic, not phone logs.
The final reruns pass all **48 CTest suites**, **eight full video/codec/crypto
sanitizer suites** and **88 Python tests**. The offline source check verifies all
ten pinned blobs. These results are also recorded in the Step 92 progress entry.

## 5. Continue toward the requested factory installation

Do not enable a guessed timestamp profile based on offset 8 alone. A compatible
sender/receiver trace must establish byte order, epoch, units, flags, discontinuity
handling and the relationship to session timing before scheduling is enabled.
Rendering immediately remains the explicit implemented behavior, not A/V proof.

Continue reviewing real session-start/transport compatibility and completing
receiver integration, while keeping physical display/input/audio and MFi ownership
explicit. The actual unit still needs verified installed-version execution and
recovery, a matching ARM/QNX runtime/toolchain and performance evidence. Bluetooth
and wired Apple USB alone do not establish those interfaces. The navigation
module revision remains unknown; no further owner identification is assumed.
The later 6.17.0WL corpus remains offline reference, not a 6.9.0WL update to flash.
