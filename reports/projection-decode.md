# AAC-LC/Opus decoding and owned PCM delivery

Date: 2026-09-10. Continues [PCM output](projection-pcm-output.md) and
[CarPlay progress, Step 68](carplay-progress.md#step-68---decode-aac-lcopus-and-own-pcm-delivery).

## Step 1 - Keep the implementation and installation claims separate

The optional hosted receiver now decodes real AAC-LC and Opus packets and feeds
the existing PCM renderer through an owning adapter. This closes the previous
compressed-audio implementation gap, not the factory installation gap. Tests
use synthetic media, real codecs/cryptography/loopback sockets and a synthetic
final audio device. No iPhone, head unit, speaker or microphone was exercised.

The software-only factory-hardware goal is unchanged. The photographed display
is `13TFDAEU-DA05`, software `0101B0`; installed navigation is `6.9.0WL`. The later
`6.17.0WL` research corpus is not an installed-version match or a safe update.
Go-module identity, execution/recovery, native USB/network ownership and a usable
existing Apple authentication-chip provider remain unresolved.

## Step 2 - Pin explicit source dependencies

`Prepare-CarPlayAudioCodecs.ps1` creates source-only Git checkouts under ignored
`build/`, with exact release commits:

| Library | Release | Required commit |
| --- | --- | --- |
| Xiph Opus | 1.6.1 | `22244de5a79bd1d6d623c32e72bf1954b56235be` |
| FAAD2 | 2.11.3 | `6918ebb51b8f7e86278da15884bd7114e4b9661e` |

Both preparation and direct CMake configuration reject another commit or a dirty
checkout, including additional ignored/untracked files. Existing changes are
preserved, never reset. Configure/build does not download or install codecs;
the preparation script is the explicit download step. Default ordinary,
TLS-only and combined crypto builds remain unchanged. `Build-CarPlayMedia.ps1`
opts into both sources and builds the separate `carplay_decode` target.

Opus uses its portable floating-point implementation, with hardening enabled,
intrinsics/fast math/custom modes/neural extensions disabled. FAAD builds only
the linked floating-point library; `LC_ONLY_DECODER` and `DISABLE_SBR` restrict
the compiled decoder, and DRC is disabled. Upstream command-line programs are
not built or installed. This is not a QNX/ARM performance or portability claim.
[Opus release](https://opus-codec.org/release/stable/2026/01/14/libopus-1_6_1.html),
[FAAD2 release](https://github.com/knik0/faad2/releases/tag/2.11.3),
[pinned FAAD build](https://github.com/knik0/faad2/blob/6918ebb51b8f7e86278da15884bd7114e4b9661e/CMakeLists.txt).

Opus ships BSD-style copyright and patent-license notices. FAAD identifies its
license as GPL-2.0-or-later and specifies this notice:
"Code from FAAD2 is copyright (c) Nero AG, www.nero.com".
Its README also flags possible patent obligations; this project provides no
legal clearance or distribution assurance. Local adapter/test code selects
GPL-3.0-only. Preserve upstream notices/source obligations in any future
distribution; no installer or redistributable firmware is produced here.
[Opus COPYING](https://github.com/xiph/opus/blob/22244de5a79bd1d6d623c32e72bf1954b56235be/COPYING),
[FAAD README](https://github.com/knik0/faad2/blob/6918ebb51b8f7e86278da15884bd7114e4b9661e/README).

## Step 3 - Decode one authenticated, ordered unit

`projection_decode.h` owns one heap-allocated, generation-bound decoder per
stream. It accepts the existing seventeen exact format descriptors:

| Input | Output and bounds |
| --- | --- |
| Twelve PCM selections | Same rate/channels; S16BE to native PCM16 |
| AAC-LC 44.1/48 kHz stereo | One raw AU, exact ASC `1210`/`1190`, 1,024 frames |
| Three Opus selections | Raw mono packet; 48 kHz output clock, at most 5,760 frames / 120 ms |

The existing Opus descriptor's input-rate field does not change its downlink
48 kHz sample clock. No container parser, ADTS/ADIF/LATM/Ogg demux, HE-AAC,
stereo Opus, channel renegotiation, PLC/FEC or guessed loss concealment is added.
Opus validates packet duration/channels before decoding. FAAD receives a bounded
caller buffer and must report exact consumption, raw LC, negotiated rate/stereo,
no SBR/PS and the expected sample count before samples are exposed.
[Opus decoder API](https://opus-codec.org/docs/opus_api-1.6/group__opus__decoder.html),
[FAAD API](https://github.com/knik0/faad2/blob/6918ebb51b8f7e86278da15884bd7114e4b9661e/include/neaacdec.h).

Disabling SBR is a decoding-capability restriction, not a full AAC extension
validator: FAAD can skip unsupported fill extensions while decoding the LC core.
The returned no-SBR flag does not prove that an input contained no ignored
extension. Do not advertise HE-AAC or infer full bitstream conformance from it.

The owner copies up to 8,192 input bytes into padded scratch and retains at most
11,520 interleaved PCM16 samples (23,040 bytes). Input and output storage are
wiped on discard/failure/destruction; codec allocations are released. Opus's
contiguous state is wiped before free. FAAD's opaque internal heap wiping is
not promised. Library allocations/stack and PCM renderer queues are additional.

Nonempty packets require strictly increasing authenticated counters and exactly
contiguous sample timestamps modulo 2^32. Gaps/overlaps fail closed, rather than
inventing a decoder reset or silence interval. Empty transport packets are
no-ops, never an implicit Opus packet-loss request. These are deliberately narrow
local policies, not sufficient handling of arbitrary handset media traffic.

FAAD suppresses the first decoded raw AAC frame while priming its overlap state.
The adapter reports `duration=1024`, `frames=0`, `priming=1` and wipes discarded
PCM. It does not override FAAD's frame counter. Subsequent output retains that
AU's own timestamp; no Ogg pre-skip or guessed encoder-delay correction is
applied. The comparison below confirms sample alignment on synthetic packets,
not the correct end-to-end latency for a real phone.
[Pinned FAAD decoder](https://github.com/knik0/faad2/blob/6918ebb51b8f7e86278da15884bd7114e4b9661e/libfaad/decoder.c).

## Step 4 - Own decoded output across backpressure

The optional stack is:

```text
session/RECORD gate -> authenticated UDP/reorder owner -> decoder adapter
                    -> PCM queue/output engine -> explicitly selected device
                    <- observed device position only <-
```

`projection_decode_sink.h` supplies the same six callbacks as the existing sink.
Each stream type 100..102 owns a real decoder and downstream PCM lease. SETUP
maps the format to same-rate/channel PCM and clears `frames_per_packet`, because
decoded blocks may split. Nonzero partial-open leases are retired on error.
RECORD authorizes start; prepare alone never decodes or plays.

Submit copies/decodes an entire packet or consumes nothing while output is
pending. Poll calls the renderer once and delivers at most one 8,192-byte
S16BE chunk. A 120 ms mono Opus packet becomes 4,096 + 1,664 frame chunks;
timestamps advance by exact frame offsets. Its original counter is retained
on both chunks, not reused as a new cryptographic identity. No upstream payload
view survives submit. Pending PCM has an absolute 1..60,000 ms configured hold
budget; partial consumption cannot renew it. Clocks are checked around work and
callbacks. Synchronous library work is not a hard execution-time guarantee.

Playback delegates the downstream device observation at the original rate.
Decoded samples, submissions and elapsed time never become a played position.
Backend/clock/decode/deadline failures close every adapter resource; enclosing
audio/root owners propagate failure and retire their sockets/keys/session.

To wire a real explicitly selected Windows endpoint: create WASAPI on its STA
thread, use its sink as `projection_decode_sink_config.pcm`, then use the
decoder's provider as `projection_audio_services_config.sink`. Use the same
absolute QPC-ns clock throughout decoder/audio/root services. Close borrowing
audio services before destroying the decoder adapter, then destroy WASAPI on
its creating thread. No default endpoint or automatic capability advertisement
is supplied. The [previous report](projection-pcm-output.md) documents the opt-in
physical probe; endpoint approval is still outstanding and no stream was started.

## Step 5 - Compare actual decoded samples and retain discrepancies

The test-only `build/media-reference` environment pins PyAV 18.1.0 with one exact
Windows x64 ABI3 wheel hash. It does not modify global Python or the receiver.
`check_projection_decode.py` generates synthetic two-tone signals, verifies all
33 committed encoded packets exactly, and compares 59,648 output samples. Four
AAC priming packets deliberately have no published C PCM. The reference wheel
contains libavcodec 62.28.102 and libswresample 6.3.102.
[PyAV release](https://pypi.org/project/av/18.1.0/).

The initial blanket 8-LSB comparison failed. Investigation retained the original
packets and added controls, rather than replacing the difficult fixtures:

| Fixture | Comparison | Observed maximum PCM16 difference |
| --- | --- | --- |
| AAC 44.1/48 kHz, PNS enabled | Native FFmpeg; bounded noise residual | 134 / 121; minimum SNR 43.47 / 42.80 dB |
| AAC 44.1/48 kHz, PNS disabled | Native FFmpeg; <=8 LSB required | 1 / 0 |
| Opus 20 ms hybrid | PyAV/libopus wrapper; same algorithm | 0 |
| Opus 120 ms CELT | Native FFmpeg; <=8 LSB required | 1 |
| Opus 20 ms CELT-only control | Native FFmpeg; <=8 LSB required | 1 |

AAC perceptual noise substitution generates decoder-local random samples; the
no-PNS controls isolate deterministic reconstruction. Original PNS packets must
still meet <=256 LSB peak residual and >=40 dB SNR, not pointwise equivalence.
These are fixture regression thresholds, not a codec certification criterion.
[FAAD PNS implementation](https://github.com/knik0/faad2/blob/6918ebb51b8f7e86278da15884bd7114e4b9661e/libfaad/pns.c),
[FFmpeg codec options](https://www.ffmpeg.org/ffmpeg-codecs.html).

The original hybrid Opus packets have TOC configuration 15. Native FFmpeg differs
by as much as 1,836 PCM16 units, while the separate PyAV/libopus wrapper matches
exactly. The CELT controls match independent native FFmpeg within one unit.
The hybrid discrepancy's underlying decoder/filter cause is not established;
the script explicitly reports it as a limitation. The hybrid comparison is not
an independent algorithm or proof that either decoder is universally correct.
No threshold was widened to declare those hybrid samples pointwise equivalent.

## Step 6 - Reproduce the checks

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayMedia.ps1
# Once, in a new test-only environment:
python -B -m venv build/media-reference
./build/media-reference/Scripts/python.exe -B -m pip install --require-hashes --only-binary=:all: --no-deps -r scripts/media-reference-requirements.txt
./build/media-reference/Scripts/python.exe -B scripts/check_projection_decode.py build/media/Release/projection_decode_tests.exe tests/fixtures/projection-codec-vectors.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayMediaSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
```

Five decoder/adapter groups cover real PCM, all descriptors, priming, timestamp
wrap, stale generations/leases, malformed formats/media, bounded chunk ownership,
busy output, absolute deadlines, backend failures and 1,000 deterministic packet
mutations, both fresh and after a valid priming packet. Three service groups use
actual IPv4/IPv6 encrypted UDP, reverse packet arrival, RECORD gating, all four
original codec cases, actual PCM byte delivery, independent synthetic device
positions, three-stream cleanup and actual port reuse. Only the final device is
synthetic. Existing paired receiver/root/timing suites are unchanged and rerun.

Verification passes 42 media-enabled, 40 existing combined, 22 ordinary and
25 TLS-only CTest suites, 25 Python regressions and both audio reference checkers.
Both new suites pass ASan/UBSan with their linked source dependencies instrumented,
including Opus, FAAD, Monocypher, audio/session and the PCM engine. Thirteen
existing hosted suites pass their separate sanitizer script, including Mbed TLS.
The comparison also passes against the instrumented decoder executable. Strict
Clang C99 warnings and static analysis pass for both production decoder modules
with external codec headers treated as system headers.

The media sanitizer script explicitly selects installed Clang 19.1.5, NMake,
SDK resource tools and release static CRT to match the installed sanitizer
runtime. Defaults can be overridden for another installation. Initial missing
resource-compiler and CRT mismatch failures were build-configuration errors.
The integration test links only its used media/session dependencies; Mbed TLS's
GNU-style Windows Clang CMake flag mismatch is not bypassed by disabling checks,
and full TLS sanitization remains covered by the existing direct-build script.
Upstream Windows typedef/unused-parameter/deprecation warnings remain. Existing
privileged-symlink skips and Clang named-catch diagnostic limitations remain as
documented in the previous report. No sanitizer suppression was added.

## Step 7 - Continue toward usable CarPlay

Next add timestamp-aware playout: explicit latency, gaps/overlaps, flush/reset
ownership, loss policy and synchronized pacing. Preserve actual-device-only
feedback and prove history/queue retirement before accepting a new media epoch.
Further codec interoperability work should investigate the hybrid reference
discrepancy and actual phone AAC priming/timestamp behavior. None of these local
tests establishes safe sustained playback or A/V synchronization on the car.

Physical audio validation, video/display/input, microphone and control mode/
resource/audio-focus semantics remain. Factory execution/recovery, native USB,
compatible authentication-chip access and real iPhone acceptance remain required.
No modified firmware image, installation USB, real pairing credential or vehicle
change was created by this step.
