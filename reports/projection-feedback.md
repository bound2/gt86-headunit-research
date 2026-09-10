# Control feedback from observed playback

Date: 2026-09-10. Continues [event messages](projection-events.md) and CarPlay
progress Step 65. This implements the control feedback route and its connection
to the existing timing service. It does not implement a decoder/audio device,
prove iPhone interoperability, or provide an installable factory-unit update.

## Step 1 - Confirm the route and schema

The pinned LIVI implementation dispatches POST feedback on its control
connection. It reports an empty success when there are no audio streams;
otherwise it encodes a binary dictionary containing a streams array. Each entry
has a stream type and sample rate, with additional clock fields when an origin
exists. Its implementation extrapolates a playback counter using elapsed time
and configured latency, and can fall back to an unsynchronized wall clock.
These are reference behaviors, not measurements of our unit or proof that audio
has played. [Pinned control implementation](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts#L616).

Reference commit: `a76553fc941dcf378dd55c04da56aaf3d6911e08`.
The inspected `cpStack.ts` blob is
`d7b7511321a9da61d63a3c23a8e34cdd5523d7b9`; its test file blob is
`3cab10e6d69dac84fce0c79365a8efb517f78136`.
The reference's tests check response construction with mocked clocks; they do
not establish physical playback. [Pinned feedback tests](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/__tests__/cpStack.test.ts#L1182).

## Step 2 - Enable the owned route explicitly

`projection_session_config.feedback_max_age_ms` defaults to zero: disabled.
An explicit value from 1 through 60,000 enables feedback and requires both
provider callbacks, `playback` and `clock`. The integration tests select 1,000 ms;
this is a local freshness policy, not a negotiated CarPlay constant.
Configuration validates without invoking either callback. Rebuild providers
against the extended header; this is not a binary-compatible structure change.

Enable info and sessions before feeding the receiver, as already required.
Only exact `POST /feedback` on verified encrypted control, after local MFi reply
drain and initial session SETUP reply drain, reaches this handler. The feedback
target is independent of the opaque SETUP URI. Before RECORD, prepared audio
streams can supply descriptors but never playback anchors. No callback allocates
or starts media. An event-socket request does not invoke this control route.

An empty body is allowed. A nonempty body must have the unique binary-plist
content type and decode as a bounded dictionary using the existing projection
parser: at most 32,768 bytes and 640 nodes, subject to caller storage limits.
Malformed input, duplicate keys/headers and unsupported encryption fields fail.
Other bounded metadata is ignored, not interpreted as a stream selector.
When disabled, this optional route remains available only to an explicit
application handler; it does not automatically acknowledge unknown requests.

## Step 3 - Report observations, not simulated playback progress

The session enumerates its own live audio leases, types 100, 101 and 102, at most
one of each. It never accepts a caller-provided stream list or connection ID.
For each lease, the media callback supplies the negotiated sample counter rate
and optionally a sample counter actually played at a stated monotonic instant.
The rate bound of 1..384,000 is a local scalar limit, not format negotiation:
the real backend's `open` must already have validated the selected audio format
and must report its correct counter rate, including any resampling semantics.

The clock callback runs once after all audio observations. Its monotonic
nanoseconds must use exactly the same domain as the media observations, paired
with an NTP64 value and an explicit synchronized flag. A missing position uses
`has_position=0` and zero counter/raw time; zero itself remains a valid played
counter when the flag is set. Only `IAP2_OK` callback results succeed.

| Result | Response fields per audio stream |
| --- | --- |
| No owned audio streams | Empty 200 body; no observer calls |
| Prepared, missing, unsynchronized or stale position | `type`, `sampleRate` |
| Recording with a synchronized, fresh position | Above plus `streamConnectionID`, `timestamp`, `timestampRawNs`, `sampleTime` |

For an accepted observation, `sampleTime` remains the exact modulo-32-bit
observed counter. `timestampRawNs` remains its exact observation time, not the
request/reply time. The paired timestamp is computed as:

```text
age_ns = clock.raw_ns - observation.raw_ns
timestamp = clock.ntp - floor(age_ns * 2^32 / 1,000,000,000)   modulo 2^64
```

Quotient/remainder integer arithmetic avoids overflow; accepted age is bounded
to at most 60 seconds. Conversion truncates by less than one NTP fractional tick.
No receipt, decode, queue, socket send, configured latency or elapsed wall time
is converted into a played sample. Stale observations omit anchors, rather than
being extrapolated. Future times, invalid flags/rates, inconsistent missing
positions or callback failures close every owned lease without publishing a
partial reply. One missing stream need not suppress valid anchors on another.

The existing fixed-schema session writer supplies bounded replies using its
2,048-byte buffer; there is no new heap allocation, general graph encoder or
dependency. Full unsigned connection IDs, raw nanoseconds and wrapped NTP values
retain all bits, using positive 128-bit plist integer storage when necessary.
Replies use the normal encrypted control output, token and downstream-drain
ownership. Application code cannot replace a held feedback response. Retained
coalesced requests are processed only after release. Feedback does not start
resources or renew the timing service's synchronization lifetime.

## Step 4 - Connect the actual Windows timing service

The Windows provider exposes playback only when its explicitly supplied media
delegate implements the callback. It remaps a live audio lease to the delegate's
actual child lease, rejecting root, video, iAP, stale and unknown leases before
calling it. Each mapped lease records its own open-invocation time. Observations
before that time or beyond the freshly sampled clock close the service; this
also catches an old playback timestamp accidentally reused on a replacement.
Lease/generation provenance remains a trusted driver obligation, not something
timestamp bounds alone can prove.

The root clock snapshot comes from `projection_timing_now` and the timing
engine's synchronized flag, after normal deadline checks. The delegate's clock
callback is not used. There is no OS wall-clock fallback, clock adjustment,
socket I/O or hidden polling in these observer callbacks. Endpoint polling still
performs the actual peer-bound timing exchange. Receiver-owned failure cleanup
retires media as well as the event/timing sockets.

Media and clock callbacks remain synchronous, bounded and non-reentrant. A
frontend must refresh receiver time after synchronous callbacks and before
output/transport work. Direct terminal service-API results require immediate
owning receiver close/poll, as documented for the existing service APIs.

## Step 5 - Verify the implementation

The session suite now has six groups, the receiver suite thirteen and the
Windows service suite nine. New tests cover descriptors before RECORD, absent
audio/observations, mixed positioned/unpositioned streams, unsynchronized and
stale clocks, exact age boundaries, maximum age, future times, bad callback
output, third-stream validation failure, lease retirement/replacement and
integer/NTP wrap. Existing session allocation/key/teardown fixtures are unchanged.

Receiver tests run actual pairing crypto and encrypted control with synthetic
MFi/identity/media providers. They check authentication/session gates, disabled
dispatch, bad methods/tags, provider failure, held-response protection, drain
expiry and two coalesced requests. Socket integration additionally performs real
IPv4/IPv6 loopback timing exchanges to obtain synchronized snapshots, checks
delegate lease remapping and clock selection, then tears down/replaces streams.
No observation in these tests comes from a real audio device or phone.

The new independent Python checker uses `plistlib` to decode seven C outputs
and compare exact types/values against independently specified expectations:
empty, prepared, playing, retired, replacement, wrapped and missing. Body sizes
are respectively 0, 169, 490, 336, 490, 541 and 169 bytes.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py
python -B scripts/check_projection_feedback.py build/crypto/Release/projection_session_tests.exe tests/fixtures/projection-session-vectors.txt
python -B scripts/check_projection_session.py build/crypto/Release/projection_session_tests.exe tests/fixtures/projection-session-vectors.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
```

Validation passes 36 combined, 22 ordinary and 25 TLS-only CTest suites, 25 Python
regressions, both independent checkers, strict Clang C99/C++20 checks and static
analysis of the three changed C modules. Nine hosted suites pass ASan/UBSan,
including instrumented Monocypher/Mbed TLS and the changed session, receiver and
socket tests. The dependency deprecation warning and privileged-symlink test
skip remain; actual junction rejection passes. No new dependency is introduced.

On x64 the session context is 3,872 bytes, receiver 13,568 and service context
1,384, excluding caller buffers, stack, crypto heap and kernel allocations.
These hosted components remain outside the existing import-free ARM core claim;
that unchanged core's prior portability result is not a QNX integration test.

## Step 6 - Implement media reception and real playback next

Next implement bounded audio packet/record reception and sequence/timestamp
handling against the pinned reference, then connect a real decoder and output
device capable of returning a played-frame observation. Buffered audio, loss/
retransmission, microphone, video decoding/display and physical input also need
actual backends. Control `/command` modes and resource/audio-focus semantics
remain separate explicit work; feedback is not a generic control handler.

The actual factory Go-module identity, compatible existing authentication-chip
access, USB-network ownership and safe installed-version execution/recovery
remain unresolved. Host tests must not become a USB installation procedure.
No phone, vehicle, firmware image or real credential was modified in this step.
