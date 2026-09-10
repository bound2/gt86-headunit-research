# Initial sender-timestamp alignment

Date: 2026-09-10. Continues [local clock drift](projection-drift.md) and
[CarPlay progress, Step 73](carplay-progress.md#step-73---anchor-initial-audio-to-a-bounded-sender-timestamp).

## Step 1 - Establish the evidence boundary

The host prototype can now use an explicit sender sample/time pair to schedule
the first decoded PCM. This is an **opt-in classic-sync experiment**, not verified
CarPlay wire behavior, continuous sender-clock tracking, A/V synchronization or
an installable factory update. Receipt-relative pacing remains the default.

The pinned LIVI native receiver drains its audio-control UDP socket without
interpreting its contents. That code therefore does not establish a usable
sender-sync format for this project. [LIVI receiver, pinned commit](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/audio/src/lib.rs#L376).

Shairport Sync's classic audio-control receiver recognizes D4 synchronization,
reads NTP at offset 8, and reads sender and latency-subtracted sample timestamps
at offsets 16 and 4. It waits for a timing exchange before using this information.
Its flags/version-specific extra latency includes an explicitly guessed legacy
offset. This project does not copy that adjustment or infer that CarPlay uses
the same format. [Shairport Sync, pinned implementation](https://github.com/mikebrady/shairport-sync/blob/7bad231c18368dbd26f298577f6210e36e4b0797/rtp.c#L361).

No upstream implementation body, new dependency, private credential, phone
capture or recording is added. Existing GPL-3.0-only project and codec notices
remain applicable.

## Step 2 - Parse only the selected control form

`projection_audio_sync_parse` accepts this exact 20-byte form:

| Offset | Width | Accepted meaning |
| --- | --- | --- |
| 0 | 1 | 0x80 or 0x90; initial indication is metadata, never reset authority |
| 1 | 1 | 0xD4 |
| 2 | 2 | Big-endian value 4 only |
| 4 | 4 | Big-endian, latency-adjusted playback sample |
| 8 | 8 | Big-endian NTP64 timestamp |
| 16 | 4 | Big-endian sender sample before latency subtraction |

Wrong sizes/headers and legacy value 7 are rejected without changing the output.
Parsing establishes neither sender identity nor authenticity. This is not a
general RTCP parser, retransmission handler, buffered anchor or control FLUSH.

## Step 3 - Convert a synchronized timestamp without reentering the root

`projection_timing_to_local` performs a read-only inverse around an explicit
current monotonic nanosecond time. It requires an active, synchronized, unexpired
timing owner in the same domain. No wall-clock fallback or synchronization-
deadline renewal is performed. Missing/expired synchronization returns MORE;
out-of-window or unrepresentable times return INVALID with a zero output.

The signed modular NTP difference from the current mapped time must fit within
the caller's 1..60000 ms bound. Conversion rounds to the nearest nanosecond;
ambiguous half-era differences and local underflow/overflow are rejected.
The existing two-sample/filter policy is unchanged.

Audio services borrow the enclosing root's `projection_timing` directly as a
read-only object. They do not invoke a root callback that could fail/close the
parent while it is polling the child. The timing owner must remain alive, be
initialized before media polling, and use the same serial thread and ns clock.
The root still owns clock polling, freshness enforcement and session teardown.

## Step 4 - Gate delivery on explicit configuration and bounded evidence

The audio-service configuration adds:

- `timing`: borrowed root clock, null when disabled.
- `sync_ms`: 0 disables parsing; 1..5000 bounds distance from local now.
- `max_sync_latency_ms`: 1..60000 bounds the sender/play sample difference.
- An explicit downstream `anchor` callback; required when enabled.

Both numeric fields and the timing pointer must be zero when disabled. Config
validation invokes no callback, opens no socket and leaves invalid owners and
borrowed buffers untouched. Existing root/media setup and RECORD gates remain.

Each stream accepts control only from its configured peer IP and pins a separate
source port after the first accepted fresh sync. Subsequent NTP values must
advance strictly in modular order; sender samples cannot go backwards or by the
ambiguous half range outside a FLUSH fence. Implied latency must fit the configured
limit. Invalid/stale/unsynchronized packets do not pin a port or invoke the sink.

The callback copies a typed local-time/play-sample anchor. MORE means ignored,
including an already committed initial base. Other callback errors retire all
audio children. Accepted-control counters are diagnostic metadata, not received
authenticated media, observed playback or evidence of phone acceptance.

**Timing and control UDP are not cryptographically authenticated.** IP/port
checks and freshness/history bounds do not prevent spoofing by an attacker who
can send as the peer. Only the separate encrypted audio packets participate in
the existing AEAD/nonce replay state. No timing message resets it.

## Step 5 - Commit one initial playback base

Set `projection_decode_sink_config.paced=1` and `sender_sync_ms=1..5000` to
require an initial sender anchor. Use compatible bounds; the service's accepted
time window must not exceed the decoder's anchor window. Tests use 500 ms for
both and a 1000 ms maximum sync latency; these are test choices, not phone-derived
defaults. Otherwise leave sender sync disabled.

The first nonempty authenticated audio packet waits with MORE until a fresh
anchor exists. The decoder does not copy/consume that packet while waiting;
the outer audio queue owns it. Its own absolute `sender_sync_ms` wait starts
once. Later anchors do not renew it, and the outer queue's hold deadline can
expire earlier. No indefinite fallback to receipt time is supplied.

Once an anchor exists, a signed modulo32 sample difference, bounded to +/-60
seconds at the format's clock rate, determines the initial base:

```text
first_PCM_timeline_base = anchor.local_ns
                        + floor(signed(first_sample - anchor.play_sample)
                                * 1e9 / sample_rate)
later_due_time         = base + floor(accumulated_decoded_frames * 1e9 / rate)
```

Arithmetic is checked, including negative fractional offsets and local time
overflow. The anchor's sample is already latency-adjusted, so SETUP latency is
not added again. AAC priming still advances the decoded timeline before its
first actual PCM. Existing lookahead, copied-packet ownership, gap recovery,
late output handling and local device-drift policy are unchanged.

Later syncs **cannot rebase live audio**. Device playback observations remain
the only source of played-position feedback. An initial sender anchor is not
an observed output sample or an authorization to start before RECORD.

## Step 6 - Retire the anchor at the existing FLUSH boundary

The two-phase authenticated control FLUSH clears the decoder's anchor, wait and
timeline together with its codec/output history. Syncs are ignored while the
reply-drain gate is held. After resume, a new initial anchor is required.

The audio owner retains the control source port and NTP history as well as the
existing data port, keys and replay history. While its media FLUSH fence is held,
a new sender sample base at/after the requested boundary is allowed. The first
consumed replacement media retires that fence as before. Tests cover a backwards
RTP-base change, stale sync replay, real encrypted replacement packets and fresh
AAC priming/Opus playback.

A fresh in-flight control packet still cannot cryptographically prove which
FLUSH epoch produced it. This limitation must be resolved against actual phone
behavior before treating the policy as interoperable CarPlay synchronization.

## Step 7 - Verify the implementation

The focused checks now contain five timing, eight audio, nine audio-service,
eight decoder/adapter and eight decoder-service groups. New checks cover exact
wire bytes, header/length rejection, NTP wrap and inverse bounds, nonmutation,
expiry, signed fractional sample offsets, local overflow, configuration errors,
foreign peer/port, ignored and failing callbacks, bounded anchor waiting and
FLUSH retirement with unchanged replay history.

Real IPv4/IPv6 loopback UDP carries AEAD-encrypted AAC/Opus packets and the
explicit classic sync fixtures. A synthetic final device starts at the computed
sender-derived due time, including AAC priming, despite a conflicting 999 ms
SETUP latency. Subsequent anchors do not restart it. A new post-FLUSH anchor
starts the replacement epoch. A missing anchor closes at the original wait
deadline. The timing filter in these new codec tests is established through
two matched synthetic D3 replies; it is not a real phone clock. Earlier full
receiver tests continue to exercise actual UDP timing exchanges separately.

Verification commands and final results are recorded in Step 73 of the progress
log. The existing 12-value Python timing reference, 13 audio fixtures/17 formats
and 33-packet/59,648-sample codec comparison are unchanged; they do not independently
validate the new control format against a phone. The native FFmpeg hybrid-Opus
discrepancy (up to 1836 PCM16) remains documented, not treated as equivalence.

## Step 8 - Keep factory readiness separate

No physical output probe, phone connection, USB operation, authentication-chip
query, modified image or car update was performed. The host library still needs
a usable factory execution/recovery route, native transport and Apple-chip
provider, remaining display/microphone/input/focus/control integration and actual
handset acceptance. Bluetooth and an Apple USB port do not establish those facts.

The next synchronization work is to validate the actual handset's anchor form
and lifetime, then add continuous sender-clock/A-V policy against that evidence.
Do not enable this classic format automatically or describe these host tests as
software-only CarPlay installed on the Toyota unit.
