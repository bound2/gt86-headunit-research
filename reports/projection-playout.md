# Relative audio pacing and bounded packet-loss recovery

Date: 2026-09-10. Continues [authenticated FLUSH](projection-flush.md) and
[CarPlay progress, Step 70](carplay-progress.md#step-70---pace-decoded-audio-and-recover-bounded-packet-loss).

## Step 1 - Replace the fail-on-every-gap path without overstating readiness

The optional codec/PCM path now supports timestamp-relative local scheduling,
prefilled timed startup and bounded loss recovery. Sustained AAC/Opus streams
continue through intentional packet losses in real encrypted-UDP tests instead
of immediately closing the session. The final device and its progression are
synthetic. No phone, physical speaker, head unit or USB connection was exercised.

This advances the software-only receiver, not the factory installation path.
There is still no verified executable/installable CarPlay update for the owner's
`13TFDAEU-DA05`/`0101B0` display and `6.9.0WL` navigation installation.

The pinned [LIVI player](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/audioplayer/src/lib.rs)
uses an RTP jitter buffer and clock synchronization for compressed bursts, with
a configured latency. Its PCM path does not use that RTP jitter buffer. The
[GStreamer jitter-buffer documentation](https://gstreamer.freedesktop.org/documentation/rtpmanager/rtpjitterbuffer.html)
describes combining arrival time with RTP timestamps, bounded waiting for missing
packets, and downstream loss notification. These are pipeline references, not
proof of an authenticated sender-to-local NTP mapping or CarPlay conformance.
No GStreamer dependency or implementation body is added here.

## Step 2 - Recover only bounded, authenticated gaps

`projection_decode_sink_config.max_gap_ms` is explicit: zero retains the strict
previous behavior; 1..1000 permits recovery when a subsequent authenticated,
nonce-ordered packet demonstrates both a nonce gap and a forward sample-time
gap. The duration comes from timestamps, not an assumed duration multiplied by
unprotected RTP sequence numbers. Overlap, nonce reuse, a contiguous nonce with
a timestamp jump, excessive gaps and invalid frame geometry fail closed.

The adapter copies one future AU, bounded to 8,192 bytes, and owns it while
emitting replacement PCM. Poll performs at most one bounded conceal/decode step
and one <=8,192-byte PCM submission, alongside the existing renderer poll. A
successful submit consumes the whole AU; a busy result consumes nothing. Later
caller mutation cannot change the retained input. No future packet is borrowed.

| Format | Replacement policy | Duration constraint |
| --- | --- | --- |
| Opus | Actual `opus_decode` packet-loss concealment, not a zero-fill substitute | Multiples of 120 frames at 48 kHz; <=5,760 frames per call |
| PCM16 | Explicit marked silence | Whole sample frames; <=5,760 frames per call |
| AAC-LC | Marked silence; recreate decoder overlap/history, then mark the next priming AU as silence too | Multiples of 1,024 frames; <=5,120 frames per call |

The [Opus decoder API](https://opus-codec.org/docs/opus_api-1.6/group__opus__decoder.html)
specifies NULL input for PLC and an exact missing duration in 2.5 ms multiples.
The implementation uses the existing pinned Opus 1.6.1 source. It does not request
in-band FEC or infer absent packets from empty transport payloads.

For AAC, the pinned [FAAD seek-reset function](https://github.com/knik0/faad2/blob/6918ebb51b8f7e86278da15884bd7114e4b9661e/libfaad/decoder.c#L586)
sets seek/frame flags, not a complete fresh LC filter-bank owner. This local
policy recreates the decoder instead. Initial stream priming still produces no
fabricated samples; after explicit loss recovery the known next priming interval
is replaced by marked silence. This can audibly interrupt music and is not a
perceptually validated AAC concealment algorithm. FAAD opaque heap erasure is
not promised, as already documented in Step 68.

`projection_decode_conceal` advances only the sample timeline. It does not advance
or reset the last received counter, invent authenticated packets, or modify the
outer replay window. A subsequent late replay remains rejected by the UDP owner.
Replacement PCM has `concealed=1`; its counter field is a zero placeholder with
no nonce/authentication meaning.

## Step 3 - Schedule from exact frame counts, not a guessed played position

`paced=1` requires an explicitly timed-capable PCM sink. The local base is:

```text
base = max(first nonempty packet's receipt time, start authorization time)
       + SETUP audioLatencyMs
presentation(frame_offset) = base + floor(frame_offset * 1,000,000,000 / rate)
```

The implementation uses checked quotient/remainder arithmetic and accumulated
64-bit frame offsets, avoiding per-packet rounding drift at 44.1 kHz. RTP sample
timestamps still wrap modulo 2^32. AAC's initial priming duration contributes to
the offset even though that AU emits no PCM. All times use the same explicit
monotonic ns domain as the enclosing services and device clock, not UTC.

`ahead_ms` (0..500) limits how early a decoded chunk is handed to PCM. The PCM
engine can prefill an OS buffer before its first presentation time, but its Start
call waits until that bound. Later transfers follow actual device capacity and
clock progression. Timing metadata must remain contiguous within one ns of
integer rounding; it cannot silently relabel a different timeline.

This is local relative pacing, **not peer-NTP synchronization or a guarantee of
acoustic latency**. Poll cadence, OS/device buffering, conversion and initial AAC
priming add timing effects. Scheduling never becomes evidence that a sample has
actually played. No sender clock, volume, audio focus or hardware route is guessed.

## Step 4 - Keep replacement audio out of source playback feedback

The PCM sink advertises explicit internal `PROJECTION_AUDIO_SINK_CONCEALMENT`
and `PROJECTION_AUDIO_SINK_TIMED` feature flags. An adapter cannot enable the
corresponding policy against a sink that does not attest support. These are
local C API features, not new advertised CarPlay protocol capabilities.

Bounded bitmaps follow replacement provenance through the PCM byte ring and
device frame ring. Accurate device position/QPC observations still drive
feedback, but positions in replacement PCM, overwritten provenance history or
drained/unstarted media report no source anchor. A subsequent genuine sample can
again produce an observation. Received RTP always has zero local timing and
replacement flags; those metadata fields are never accepted from the wire.

Timed prefill, pending future AUs, decoder history, scheduling offsets and
provenance are all retired by the existing two-phase FLUSH. Resumption needs the
normal encrypted-reply drain and a new media base. Keys, replay counters, leases
and peer pinning keep the Step 69 rules. Closing a prefilled device cannot start it.

Nonpaced mode keeps the existing absolute `now + hold_ms` ownership deadline.
Paced mode also allows the fixed scheduled gap plus a maximum decoded block
before that backpressure allowance. That deadline is set once per accepted AU,
not renewed by partial chunks, empty polls or downstream busy responses. This
permits a scheduled wait without turning it into unlimited ownership. Errors
retire all adapter resources and propagate to the receiver as before.

## Step 5 - Enable explicitly and size the whole pipeline

The new fields default to zero; existing callers retain strict, unpaced behavior.
Rebuild consumers after the C structure changes; binary compatibility with old
headers is not asserted. For the sustained laboratory test, the explicit codec
configuration is `hold_ms=100`, `max_gap_ms=120`, `ahead_ms=40`, `paced=1`; SETUP
latency is 100 ms, and the audio owner has 64 slots of 8,192 bytes each. These are
test parameters, not validated settings for the car.

Wire the existing owned decoder provider between audio UDP and the explicit
WASAPI PCM provider, as in [Step 68](projection-decode.md#step-4---own-decoded-output-across-backpressure).
Use `projection_wasapi_clock_ns` throughout when binding the actual Windows
provider. The new policies require its feature flags; they do not select or open
a physical endpoint automatically.

Large latency values do not create storage. The caller must provision packet
slots, payload capacity, OS receive buffering and polling cadence for the
selected profile. A full queue still applies backpressure and can suffer kernel
UDP loss. Recovery is bounded, not a promise that any 60-second latency offer can
be sustained with a small ring. Nonpaced recovery also needs enough hold budget
for the chosen gap and downstream throughput.

Measured x64 owners: audio 5,320 bytes, audio services 16,400 bytes, PCM output
227,376 bytes. The latter includes three 65,536-byte queues and their bounded
provenance maps. The decoder bridge additionally owns one 8,192-byte pending AU
per stream. Caller buffers, codec/device allocations and stack are extra; these
are not QNX ARM measurements or embedded performance results.

## Step 6 - Verify scheduled startup, recovery, ownership and sustained delivery

Existing executables now contain seven decoder/adapter groups, nine PCM-output
groups and five decoder-service groups. Added coverage includes:

- Real Opus PLC output, PCM/AAC marked silence, AAC recovery matching a fresh
  decoder after priming, preserved nonce checks and exact duration limits.
- Copied future AUs, multi-chunk 500 ms gaps, busy output, expiry, wrong generation,
  oversized/overlapping/unsignaled gaps and unsupported sink capabilities.
- Exact before/at-deadline delivery, 44.1 kHz rounding over 50 AUs, RTP wrap,
  overflow refusal, a 60-second scheduled wait and nonrenewable busy deadlines.
- No early Start despite device prefill; concealed-to-genuine feedback boundaries,
  provenance ring reuse, timing mismatch and FLUSH of prefilled/pending recovery.
- Four 160-slot media timelines: AAC and Opus over actual IPv4/IPv6 encrypted UDP,
  five-packet bursts, two intentional losses and a late replay in each stream.
  Each sustains one device Start, emits the expected frame count and suppresses
  source feedback during replacement. The synthetic device advances on a 1 ms
  laboratory clock; this is approximately 3.2/3.7 seconds of simulated media,
  not a wall-clock speaker soak test. Leases/ports close and can be reused.

All 42 media-enabled, 40 combined, 22 ordinary and 25 TLS-only CTest suites pass,
along with 25 Python regressions. Both codec-enabled ASan/UBSan suites and the
13 hosted sanitizer checks pass. Strict C99/C++20 warnings and static analysis
pass for the changed production code, treating pinned vendor headers as system
headers. No instrumentation was disabled. Prior Windows privileged-symlink and
Clang named-catch limitations remain as documented.

The existing audio crypto checker and 33-packet/59,648-sample codec reference
checker pass unchanged. The original hybrid Opus/native-FFmpeg discrepancy is
still unresolved; PLC tests do not convert that into independent validation or
establish perceptual recovery quality. See [the codec report](projection-decode.md).
Reproduction uses the existing build, sanitizer and reference commands in
[the previous report](projection-flush.md#step-5---verify-the-integrated-state-changes-and-failure-boundaries).
No new dependency, device test or firmware input is needed.

## Step 7 - Remaining work toward actual CarPlay

Next address late-media/drop-resynchronization policy and clock drift, then
sender timing/A-V synchronization. A gap is currently recovered only when a
following authenticated packet establishes its duration. Trailing loss without
that evidence, unsignaled DTX/timestamp jumps, retransmission/FEC, adaptive jitter,
selective buffered FLUSH and perceptual smoothing remain unfinished. Delayed
packets already accepted by the decoder are not yet dropped/rebased by deadline.

Physical endpoint validation, microphone/video/display/input and control mode/
resource/audio-focus semantics remain. Factory module identity, installed-version
execution/recovery, native USB/network ownership, compatible existing Apple-chip
access and real iPhone acceptance are still required. No car, update USB, firmware,
real credential, default output device or audio preference was changed.
