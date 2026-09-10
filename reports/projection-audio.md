# Encrypted audio reception and session integration

Date: 2026-09-10. Continues [observed feedback](projection-feedback.md), CarPlay
progress Step 66. Audio now travels through actual loopback UDP sockets, real
decryption, bounded ordering and the session's explicit output-backend contract.
PCM byte conversion is implemented. No physical output device, compressed-audio
decoder, target QNX port or installable CarPlay update is supplied by this step.

## Step 1 - Trace the reference beyond the control stack

The pinned control implementation delegates audio reception to native code.
Its Rust audio module receives one encrypted RTP packet per UDP datagram,
decrypts it and passes the payload/sample timestamp onward. The separate player
uses GStreamer for decoding, pacing and output. A first-packet notification is
not an observation of audio leaving a device. [Native receiver](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/audio/src/lib.rs),
[native player](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/audioplayer/src/lib.rs).

All reference files remain pinned to commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Inspected blobs:

- `audio/src/lib.rs`: `5fad18c47aade941362ae1289a545095dbb657a2`.
- `audioplayer/src/lib.rs`: `18b32754f50c59ae33c96ee9587ff6a795cb7e45`.
- `mic/src/lib.rs`: `1fac2d16e911e450624a4fce3c992e3668f5a751`.
- `cpStack.ts`: `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9`.

## Step 2 - Define exactly which wire bytes are trusted

For a datagram of length N, the native receiver's framing is:

| Bytes | Meaning | Cryptographic treatment |
| --- | --- | --- |
| 0..3 | RTP flags, payload type, sequence | Not covered by this packet's tag |
| 4..11 | Sample timestamp and SSRC | Associated data |
| 12..N-25 | Audio payload | Encrypted and authenticated |
| N-24..N-9 | 16-byte tag | Verified before publishing plaintext |
| N-8..N-1 | Little-endian 64-bit counter | Zero-prefixed to form the 12-byte AEAD nonce |

This is the reference's audio-specific ChaCha20-Poly1305 envelope, not the
control/event record format. [Reference framing/decryption](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/audio/src/lib.rs#L35).
The RTP header's ordinary field meanings are specified separately in
[RFC 3550, section 5.1](https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1).

`projection_audio.c` accepts a fixed 12-byte RTP v2 header with dynamic payload
type 96..127 and optional marker; padding, extension and CSRC variants are
explicitly unsupported. These are local supported-profile bounds, not claims
that all RTP variants or all phones use them. Unprotected sequence/marker/type
fields remain diagnostic; they cannot select a decoder, authenticate a peer or
authorize replay/order changes. The configured SETUP format selects the codec.

This profile treats the nonce as an increasing uint64 packet counter. A
64-packet sliding replay window allows bounded reordering; counters do not wrap
or reset under a key. The reference's microphone packet writer also increments
one nonce per packet. That is supporting implementation evidence, not a capture
of this head unit's phone downlink. Actual phone behavior must still validate
the profile. [Reference counter writer](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/mic/src/lib.rs#L38).

Only successful authentication commits the replay ledger and first SSRC.
Changed SSRC, bad tags, malformed/oversized frames and old/duplicate counters
drop without publishing plaintext or resetting the stream. Keys come from the
owning session's directional HKDF result. Replacement resources get new IDs,
keys and packet owners; there is no reconnect/reset API under a reused key.

## Step 3 - Carry the selected format without guessing

The format helper recognizes 17 exact single-bit selections:

| Encoding | Selections and counter rates |
| --- | --- |
| PCM16 | Mono/stereo pairs at 8, 16, 24, 32, 44.1 and 48 kHz |
| AAC-LC | `0x400000`: 44.1 kHz stereo; `0x800000`: 48 kHz stereo |
| Opus | `0x10000000`, `0x20000000`, `0x40000000`: 48 kHz mono downlink clock; 16/24/48 kHz respective input rates |

In particular, Opus's negotiated microphone rate must not be substituted for
its 48 kHz downlink RTP/decode clock. PCM on this wire is interleaved S16BE.
These choices follow the pinned control/native format handling.
[Control format selection](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts#L883),
[PCM/codec representation](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/audio/src/lib.rs#L69).

Unknown or multiple bits are rejected, not mapped to a guessed fallback.
The helper supplies exact rates/channels and AAC AudioSpecificConfig values
`1210`/`1190`. `projection_audio_pcm16le` validates format, whole-frame alignment
and capacity before converting PCM byte order; it does not resample, adjust
volume or pretend to decode AAC/Opus. Compressed data remains an opaque raw AAC
access unit or Opus packet for a real codec backend. Supporting a format's
metadata and transport does not establish that its decoder is available.

## Step 4 - Own packet ordering, backpressure and startup

The pure owner uses 1..64 caller-buffered slots, each at most 8,192 payload bytes.
Defaults are eight 2,048-byte slots, a 20 ms reorder wait and a 1,000 ms held-output
budget; format stays unset until explicitly selected. Bounds are local policy.
There is no allocation, socket, callback, thread or implicit playback clock.

Packets sort by authenticated counter, not RTP sequence. Initial or gapped
output waits the configured interval; contiguous queued output is immediately
eligible. Delivery reports exact skipped-counter counts, the authenticated
sample timestamp, receipt time and SSRC. PCM also reports its payload frame
count; compressed frame counts remain unknown until decoding. An earlier packet
arriving after output has already been borrowed is late and drops, even before
that output's release, preventing backwards delivery or unsigned gap underflow.

`start` gates all output until the owning RECORD reply drains; pre-start packets
can fill only the bounded queue. `peek` borrows one immutable packet under a
generation/token, and release requires full downstream acceptance. A full queue
returns BUSY without consuming another datagram. Held output has an absolute
deadline that repeated peeks/submissions cannot renew. Expiry closes and wipes
keys, payloads and metadata. Stream silence itself is legal and has no new
media-idle timeout; outer control/timing lifetimes still apply.

This is a reorder queue, not a complete adaptive jitter buffer or audio clock.
UDP/kernel loss remains possible. Retransmission, concealment, timestamp-based
pacing and buffered-media behavior must be implemented by the remaining media
and control paths. Packet receipt, acceptance and PCM conversion never count as
played samples for feedback.

## Step 5 - Connect real Windows audio sockets to the receiver

`projection_audio_services.h` provides an optional media delegate for the existing
root timing/event service. Configure the same explicit local/peer address and
monotonic ns clock, storage and a real `projection_audio_sink`, then pass its
provider into the root service before root initialization. The sink must prepare,
start, atomically accept, poll, observe playback and close real codec/output
resources. Open validates actual support; there is no default device or dummy
success implementation. This audio-only provider rejects screen, iAP and
microphone requests; it does not replace those missing implementations.

Each audio stream obtains actual exclusive ephemeral data/control UDP ports,
nonblocking and non-inheritable, bound to a specific IPv4/IPv6 address. Data
source IP must match the control peer. The source port pins only after the first
authenticated accepted packet, so garbage cannot claim a port. Later data must
match both. Control packets currently receive only a bounded peer-IP-checked
drain: no RTCP parsing, retransmission, flush/sync semantics or automatic reply
is claimed. The reference also drains this port; broader behavior needs work.

One explicit poll performs at most one control receive, one data receive, one
sink poll and one atomic packet submission per live stream. Full queues stop
data reads. A sink returns OK after copying/accepting a whole packet, or MORE
after consuming nothing; it cannot retain borrowed pointers. Fresh clock checks
around callbacks and before submission enforce reversal/expiry cleanup. Sink
failure closes all of this provider's streams; root receiver poll/close then
retires remaining session resources. Partial start failure also closes prepared
and already-started siblings. All transferred sink leases close once.

Playback feedback comes only from the sink's explicit observation, at the
format's RTP clock rate. Pre-open, pre-start and future observations reject,
including an old timestamp returned after the stream has started. Root timing
still supplies synchronized NTP; this audio delegate supplies no competing clock.
No device sample position is manufactured from packet counters or submissions.

## Step 6 - Verify and publish the step

Six core groups exercise the 17 format mappings, independently sealed packets,
real AEAD verification, unauthenticated-prefix handling, SSRC/counter windows,
all 64 slots, reordering/loss, wrap, PCM conversion, empty packets, argument/
capacity/deadline/token bounds, wiping and 5,000 deterministic malformed cases.

Five service groups use actual IPv4/IPv6 UDP sockets, peer/source-port rejection,
oversized datagrams, non-inherited handles, real port release, pre-RECORD queueing,
output backpressure, observer errors, partial start and exact expiry. Full
known-controller pairing/MFi/session integration receives all three audio types,
converts PCM, synchronizes the actual timing sockets, queries feedback and
replaces a stream with a fresh key. An old-key packet cannot pin its new port.
The output sink and playback observations remain explicitly synthetic; the
compressed fixtures test transport, not successful decoding or audible playback.

The independent checker uses the existing pinned PyCA reference environment,
not the system Python installation. It reproduces 13 public crypto/plist fixture
values and compares four C-decrypted payloads/PCM conversion and all 17 exact
format descriptors. It caught a one-byte transcription error in the replacement
plist, which is corrected. The integration profile also needed its explicit
audio resource declaration; the capability validator correctly rejected its
initial omission. Neither check was weakened to make the fixture pass.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_audio.py build/crypto/Release/projection_audio_tests.exe tests/fixtures/projection-audio-vectors.txt
python -B -m unittest discover -s tests -p test_*.py
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
```

For a fresh reference environment, use the existing pinned setup in
[pair verification](pair-verification.md#step-5---test-against-external-vectors-and-actual-cryptography).
No new receiver dependency/version is added; Windows sockets and the existing
Monocypher adapter are reused. Both audio targets remain outside the existing
import-free ARM core and ten-unit crypto portability claims.

Validation passes 38 combined, 22 ordinary and 25 TLS-only CTest suites, 25 Python
regressions, the independent checker, strict Clang C99/C++20 warnings and static
analysis of the two new C modules. Eleven hosted suites pass ASan/UBSan with
instrumented crypto dependencies. Existing dependency deprecation warnings and
the privileged-symlink skip remain; actual junction rejection passes.

On x64, one audio owner is 4,288 bytes and the three-stream service context is
13,288 bytes. Caller packet storage is additional: with default slot sizes it
is 49,152 bytes for three streams plus a 2,084-byte datagram scratch area. Stack,
decoder/device allocations and kernel buffers are not included. These are host
sizes, not verified target memory or scheduling guarantees.

## Step 7 - Implement a real output backend next

Next implement PCM device output that returns actual played-frame observations,
then AAC-LC/Opus decoding and timestamp-based pacing/resampling/loss handling.
Microphone, video/display, physical input and explicit control mode/resource/
audio-focus semantics remain necessary. A larger codec ecosystem or playback
driver cannot be replaced by passing opaque compressed bytes to the test sink.

Factory Go-module identity, safe installed-version execution/recovery, native
USB-network ownership, compatible existing authentication-chip access and actual
iPhone acceptance remain unresolved. No phone, vehicle, firmware image, real
credential, speaker setting or microphone was changed in this step.
