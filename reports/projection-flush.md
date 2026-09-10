# Authenticated audio FLUSH and media-state retirement

Date: 2026-09-10. Continues [compressed decoding](projection-decode.md) and
[CarPlay progress, Step 69](carplay-progress.md#step-69---own-authenticated-audio-flush-without-resetting-replay-state).

## Step 1 - Establish the supported form and its evidence limits

The hosted receiver now owns a two-phase audio FLUSH across encrypted control,
session leases, real UDP reception, optional AAC-LC/Opus decoders and PCM output.
This is a bounded classic AirPlay control form, **not verified CarPlay handset
behavior**. No physical audio device, phone, USB connection or car was exercised.
There is still no installable software-only update for the factory unit.

The existing LIVI reference remains pinned at
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Reinspection found no FLUSH/RTP-Info
command handler in the selected CarPlay stack. Its native audio control socket
drains packets, while the player delegates jitter buffering/clock synchronization
to GStreamer. Those facts do not specify a CarPlay FLUSH exchange. Examined files:

| Pinned LIVI file | Git blob |
| --- | --- |
| [cpStack.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts) | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` |
| [native audio](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/audio/src/lib.rs) | `5fad18c47aade941362ae1289a545095dbb657a2` |
| [native player](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-gst-video/rust/audioplayer/src/lib.rs) | `18b32754f50c59ae33c96ee9587ff6a795cb7e45` |

Two other primary implementations establish the narrower reference form:

- Shairport Sync commit `7bad231c18368dbd26f298577f6210e36e4b0797` reads
  `RTP-Info`/`rtptime` in its [FLUSH handler](https://github.com/mikebrady/shairport-sync/blob/7bad231c18368dbd26f298577f6210e36e4b0797/rtsp.c#L2165).
  Its [player boundary](https://github.com/mikebrady/shairport-sync/blob/7bad231c18368dbd26f298577f6210e36e4b0797/player.c#L4911)
  excludes the named timestamp from the discarded interval.
- OpenAirPlay commit `6c343d3679ddb561c61566985acaaf587d0a3bd3` parses
  `seq` and `rtptime`, delegates the flush and returns a correlated response in
  [do_FLUSH](https://github.com/openairplay/airplay2-receiver/blob/6c343d3679ddb561c61566985acaaf587d0a3bd3/ap2-receiver.py#L789).

The initial inclusive-boundary interpretation was corrected after checking
Shairport's player: the named timestamp is the first permitted packet timestamp.
Tests now explicitly accept equality and reject the immediately preceding value.
No upstream implementation bodies or new runtime dependencies were copied.

## Step 2 - Gate the exact authenticated request

An optional `projection_session_provider.flush` callback enables this form:

```text
FLUSH <already-bound-session-target> RTSP/1.0
CSeq: <request-number>
RTP-Info: seq=<uint16>;rtptime=<uint32>
Content-Length: 0
```

Actual wire lines use CRLF. Control must already be paired/verified/encrypted,
with the local MFi response and RECORD response fully drained. Exactly one owned
audio stream of type 100..102 is required; multiple audio streams are ambiguous
because their sample clocks may differ. No implicit stream selection is guessed.

The request must have an empty body and one RTP-Info header containing exactly
one unsigned decimal `seq` and `rtptime`. Either order and surrounding space/tab
are accepted. Missing/duplicate fields or headers, overflow, signs, unknown
parameters, trailing separators and a different target are rejected before the
flush callback. Content-Type does not interpret a body because bodies are
forbidden here. `FLUSHBUFFERED`, partial buffered ranges and microphone streams
are not implemented. Invalid/unsupported requests follow the existing fail-closed
session policy; they are not given a generic success response.

Final review exposed a dispatch interaction: early FLUSH parsing could reach the
special `/feedback` path without its normal POST check. New regressions failed
before the fix. That route now validates its exact method before parsing or
observing media; FLUSH cannot produce feedback or flush another target.

## Step 3 - Stop and clear before acknowledging, resume only on drain

The callback is finite, synchronous, serial and non-reentrant. A non-NULL
`projection_audio_flush_request` begins the operation; NULL resumes the same
generation/lease only after the encrypted response actually drains. Providers
without a flush callback do not advertise this capability through their API.

1. Session validation selects the existing audio lease. Root services remap it
   to the existing child lease and check the explicit clock around delegation.
2. PCM output calls the device's Stop/Reset operation. It wipes its entire owned
   queue and clears frame counts, timestamp origin and device-clock observations.
   The device and lease remain owned; no default endpoint or replacement opens.
3. The decoder adapter discards pending PCM and destroys/recreates its decoder
   at the original format. AAC must prime again; no guessed silence or played
   position is generated. Decoder-owned buffers are wiped as documented in
   Step 68; complete erasure of FAAD's opaque internal allocations is not claimed.
4. UDP audio wipes queued packets and held views, invalidates their tokens and
   suspends delivery. Existing sockets, peer pinning and cryptographic history
   remain. New authenticated packets may queue, but cannot decode or play yet.
5. Only after begin succeeds does control produce its empty correlated 200 reply.
   Consuming its bytes is not enough: the normal outer drain/release token must
   complete before the session invokes NULL/resume.
6. Resume re-arms reception/decoding/output. Actual device Start still waits for
   ordinary media prefill. Generic start calls cannot bypass the flush phase.

Failure of reset, a delegated callback, clock/deadline checks or reply delivery
retires the session's resources. Closing with a held reply cannot resume audio.
Root timing/event state and event/control nonce counters are not restarted by a
successful media flush. No packet arrival or local reset creates a feedback anchor.

Stop/Reset cannot recall sound already played or propagating through hardware.
This step tests the owned software state and a synthetic device seam; it does
not establish real endpoint latency, muting or acoustic behavior.

## Step 4 - Preserve replay protection across the new media state

The audio owner keeps its key, SSRC, highest authenticated nonce, replay bitmap
and monotonically increasing lifetime tokens. It floors delivery at the highest
nonce already received, including packets discarded from its queue. Previously
received packets cannot return after the flush, nor can an unseen lower nonce
be accepted merely because its timestamp appears new. A media reset is never a
cryptographic reconnect or permission to reuse a nonce.

After authenticating a new datagram, the temporary timestamp fence permits
`(packet_timestamp - boundary) mod 2^32 < 2^31`, including equality. It rejects
older and exactly half-range-ambiguous timestamps. Authentication must succeed
before this comparison can affect replay history; bad tags cannot advance it.
An authenticated timestamp rejected by the fence still consumes its nonce in
the replay history. RTP sequence numbers remain diagnostic only: that field is
not authenticated in the existing envelope.

The fence lasts until the first new packet is released after resume. Subsequent
delivery remains nonce-ordered, and decoder/PCM timestamp continuity checks still
reject unsignaled discontinuities. Timestamp wrap and stale held-token release
are covered without resetting lifetime counters.

This is deliberately **not selective buffered flushing**. All already-owned
queued/staged media is cleared, including packets at or beyond the boundary.
The retained nonce floor prevents retransmitting those discarded packets. This
can omit otherwise usable media and introduce an extra gap. New arrivals are
fenced as whole packets; an AU crossing the boundary is not partially decoded
and trimmed. These limits must be resolved or matched to an actual phone profile
before claiming complete flush/playout interoperability.

## Step 5 - Verify the integrated state changes and failure boundaries

Existing test executables were expanded; no new CTest target was needed:

| Test executable | Current groups | Added FLUSH coverage |
| --- | ---: | --- |
| `projection_session_tests` | 7 | Exact grammar/target, optional capability, single-stream/RECORD gates, repeated two-phase calls, callback failure and feedback-route isolation |
| `projection_audio_tests` | 7 | Held/queued wiping, nonce floor/window retention, stale tokens, bad tags, equality/half-range/wrap and repeated flush |
| `projection_pcm_output_tests` | 8 | Queued/running output, reset failure, suspended submit/start, same-device resume and new observed media origin |
| `projection_audio_services_tests` | 7 | Real encrypted control, synthetic MFi, actual timing/event/audio sockets, FLUSH reply drain, old/new UDP packets, timeout/close/reset failure and cleanup |
| `projection_decode_tests` | 5 | Pending decoded chunk retirement, stale calls, blocked submit/start, begin/resume failure with multiple resources and fresh decoder history |
| `projection_decode_services_tests` | 4 | Actual encrypted UDP to AAC 44.1/48 kHz and Opus 20/120 ms decoders to PCM engine, before/after device start, fresh-reference PCM and new playback origin |

The complete wire test uses real pairing/control/media cryptography with public
synthetic credentials, an explicit synthetic MFi provider and a synthetic final
device. The compressed tests use actual source-pinned decoders and real sockets;
they do not add a real iPhone or physical playback claim. The Step 68 hybrid
Opus/native-FFmpeg discrepancy remains unresolved, not weakened or hidden by
these additional comparisons against fresh instances of the selected decoder.

Verification: 42 media-enabled, 40 combined, 22 ordinary and 25 TLS-only CTest
suites; 25 Python regressions; the existing independent audio checker and the
33-packet/59,648-sample codec checker all pass. Thirteen hosted ASan/UBSan checks
and both codec-enabled sanitizer suites pass with their linked dependencies
instrumented. Strict Clang C99/C++20 warnings and static analysis pass for the
changed production units. The existing privileged-symlink skip and Windows Clang
named-catch limitation remain; no sanitizer suppression was introduced.

Reproduce with the existing scripts (no physical playback):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayMedia.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayMediaSanitizers.ps1
python -B -m unittest discover -s tests -p test_*.py
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_audio.py build/media/Release/projection_audio_tests.exe tests/fixtures/projection-audio-vectors.txt
./build/media-reference/Scripts/python.exe -B scripts/check_projection_decode.py build/media/Release/projection_decode_tests.exe tests/fixtures/projection-codec-vectors.txt
```

Reference environments/dependencies are prepared as documented in Steps 66/68.
Measured x64 owners: audio 4,296 bytes, audio services 13,320 bytes, root services
1,392 bytes, session 3,880 bytes and PCM output 197,016 bytes. Caller buffers,
codec/device allocations and stack usage are additional; none is a QNX ARM size.

## Step 6 - Continue toward usable playback and the factory target

Step 70 now adds [relative pacing and bounded loss recovery](projection-playout.md),
including timed prefill and concealment-aware feedback. The results above record
the Step 69 checkpoint. Adaptive drift/late-media policy and sender/A-V sync remain
unfinished. Selective buffering,
partial-packet boundaries, codec restart/priming and actual phone control forms
need interoperability evidence; the current FLUSH form is not a replacement for
that work. Physical output validation still requires an explicitly selected
endpoint and has not been run.

Video/display/input, microphone and control mode/resource/audio-focus semantics
remain. Factory Go-module identity, installed-version execution/recovery, native
USB/network ownership and compatible existing Apple authentication-chip access
remain unresolved. No firmware image, update USB, real credential or vehicle
configuration changed. Bluetooth and Apple USB alone do not establish that this
unfinished software can be installed or accepted as CarPlay on the factory unit.
