# Owned event messages and typed commands

Date: 2026-09-10. Continues [real endpoint services](projection-services.md),
Step 63 of [CarPlay progress](carplay-progress.md). This step adds the event
message owner and outgoing command encoders, integrated with actual encrypted
Windows sockets. Tests use only PC loopback and public synthetic identities,
MFi results and media providers. No car, phone, USB device or firmware is changed.
CarPlay is still not installable on the factory head unit.

## Step 1 - Separate event commands from control feedback

The pinned LIVI checkout remains at commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Inspected files under
`src/main/services/projection/driver/cp/stack/`:

| File | Git blob |
| --- | --- |
| `cpStack.ts` | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` |
| `rtspMessage.ts` | `6ad23c144b3464c67cab71e6f206b32a28f69b4c` |

The reference sends `POST /command RTSP/1.0` with a binary-plist content type
and incrementing CSeq over the event connection. It also accepts requests from
the phone on that connection. HID, Siri, night mode, iAP messages and keyframe
requests are concrete outgoing command forms. `/feedback`, however, is an
incoming request on the **control** connection, not an event command. The earlier
next-step description conflated the two; this implementation keeps them separate.
[Session/event reference](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts).

The reference's framing helper echoes protocol/CSeq in replies. Our existing
strict parser is retained, and a matching explicit request encoder is added;
permissive parsing and automatic successful replies are not copied.
[Framing reference](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/rtspMessage.ts).

## Step 2 - Encode explicit supported commands

`projection_command.c/.h` produces bounded fixed-schema binary plists:

| Command | Fields | Local validation |
| --- | --- | --- |
| `hidSendReport` | `uuid`, binary `hidReport` | Exact advertised HID ID; report 1..4096 bytes |
| `setNightMode` | `params.nightMode` | Boolean 0/1, never an integer substitute |
| `requestSiri` | `params.siriAction` | Integer 2/3 for explicit button down/up |
| `iAPSendMessage` | `params.data` | Explicit iAP feature; binary data 1..16384 bytes |
| `forceKeyFrame` | `params.uuid` | Exact advertised display ID; alternate display also requires feature 8 |

The names/shape follow the session reference above. Size limits, strict unused-
field rejection and capability gates are local policies. The caller supplies the
same explicit capability profile and supported feature flags used for the
session; structural validation is not an actual driver availability attestation.
HID report bytes remain opaque, not a valid touch descriptor/input driver by
themselves. There is no default hardware ID, automatic gesture or Siri action.

Encoding validates and measures before writing; failure leaves the destination
unchanged and reports zero bytes. Binary data and booleans retain their types.
The encoder has fixed local scratch, no heap or device operations. It is not a
general-purpose plist graph encoder or an Apple conformance implementation.

## Step 3 - Own both directions of the event message stream

`projection_events.c/.h` is an allocation-free plaintext message owner placed
behind the authenticated event record layer. Explicit caller storage provides
one incoming message, one reply and 1..4 outgoing command slots. No default start,
unbounded queue, retry, route handler or success response is supplied.

Outgoing commands get independent monotonic lifetime tokens and nonzero CSeqs.
A batch of up to four bodies is validated for capacity before any is accepted;
button press/release can therefore be enqueued together. The transport may send
several commands before replies arrive. Each final response is correlated to its
own fully drained command, including out-of-order replies. CSeq/token exhaustion
ends the owner instead of wrapping or reusing identifiers.

The output lifecycle is explicit:

`queued -> sending -> ciphertext drain -> waiting for reply -> held result -> released`

Only one message owns the output stream at a time. An incoming-request reply has
priority over a not-yet-started command, but never interrupts an active message.
Plaintext retirement means the cipher copied it; the command response budget
starts only after the socket owner accepts the last encrypted record. This is
not TCP acknowledgement, phone acceptance of the command or media playback.

Incoming phone requests have their own namespace, so their CSeq may equal a
pending outgoing command's CSeq. Requests are exposed for explicit application
handling. Replies echo the request's protocol and CSeq; supported HTTP requests
may omit CSeq. Command responses require a matching CSeq and final status
200..599. Non-200 status is exposed to the caller, not silently accepted or
retried. Informational 1xx, unmatched, duplicate and premature replies terminate
this selected profile. This restriction is explicit, not a broad HTTP/RTSP
conformance claim.

One received message remains held until the caller responds or releases its
result. Retained tails are not discarded. Receive, held-message, queued/output/
drain and response budgets are absolute; unrelated traffic cannot renew them.
Defaults are respectively 10, 5, 5 and 5 seconds, with caller-selected bounded
values. Empty authenticated records do not create messages or renew receive
deadlines. Wrong keys/counts/generations and decreasing time are transactional.
No separate idle timer is added: outer control and timing still bound lifetime.

## Step 4 - Connect the owner to actual service sockets

`projection_services_enable_events` enables message ownership once, after service
initialization and before socket allocation. Raw event-record APIs then reject
use, preventing two consumers from sharing cipher counters/buffers. The service
owns the new child until close. Its start callback enables commands only after
the owning receiver's RECORD reply drains; explicit replies to phone requests
can be sent earlier.

Each service poll consumes at most one authenticated record prefix into the
message parser and queues at most one output record. Large messages span records;
coalesced input stays retained. Final socket-send drain is published before
parsing a possible response to that command. Message deadlines participate in
service/receiver scheduling and failure cleanup.

A frontend should encode explicit commands with the typed helper, enqueue
complete batches, call `projection_receiver_poll` with fresh time, then inspect
`projection_services_message`. For a request, dispatch a real handler and use
`projection_services_respond`; for a result, deliver its status/body to the
responsible operation before `projection_services_release`. No generic 200
handler or automatic report generation is appropriate. A terminal application-
API result requires immediate owning receiver close/poll so its delegated media
leases retire too; network/message/cipher state already closes immediately.

All buffers and profile/provider contexts remain exclusively borrowed until
close. This remains an optional Windows integration, not a QNX socket port,
control listener, physical input frontend or installable receiver program.

## Step 5 - Verify and correct the implementation before publishing

Six pure test groups cover request encoding, eight typed command values,
capability/type/capacity rejection, atomic batches, all four slots, out-of-order
and negative responses, independent inbound CSeqs, output priority, partial
retirement/drain, retained tails, stale callbacks, exact deadlines and identifier
exhaustion. Five thousand deterministic malformed/truncated message cases run
through the owner. An independent Python `plistlib` checker decodes eight C
outputs and verifies exact dictionary fields, boolean/integer types and binary
data against separately specified expectations.

The real service suite now additionally exercises known-controller pairing,
encrypted MFi/session setup, pre-RECORD explicit replies and command rejection,
post-drain command batches, actual IPv4/IPv6 event sockets, out-of-order replies,
bidirectional messages and whole-session cleanup. Outgoing records are limited
to 64 plaintext bytes and incoming messages split into 31-byte records. These
force multi-record handling without substituting fake socket writes. Missing
responses, bad correlation and held requests trigger cleanup. MFi credentials,
media support and user actions remain synthetic; no phone accepts these tests.

The first sanitizer pass found an intermediate out-of-bounds pointer calculation
when selecting slot four: adding the encoded slot selector before subtracting
its bias could temporarily exceed the array. Computing the index before pointer
addition fixes it. The all-four-slot test retains coverage; ordinary passing
tests alone did not prove this path free of undefined behavior.

Validation commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py
python -B scripts/check_projection_commands.py build/crypto/Release/projection_events_tests.exe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
```

Final validation passes 36 combined, 22 ordinary, 25 TLS-only CTest suites and
25 Python regressions. Eighteen ordinary and nine hosted suites pass ASan/UBSan,
including instrumented Monocypher and Mbed TLS. Strict Clang C99/C++ warnings
and static analysis of the four changed/new C99 modules pass. The refreshed
twenty-unit ARM core remains import-free, including the request encoder; the
new event/command and Windows service targets are outside that claim. No new
dependency is added. Existing dependency warnings and the privileged-symlink
skip remain; actual junction rejection passes.

The event owner occupies 392 bytes and the service context 1,320 on x64,
excluding caller queues, stack, cipher and kernel allocations. Four slots at
maximum configured message capacity are substantial additional storage; this
is not a target memory, scheduling, security certification or interoperability
guarantee.

## Step 6 - Implement control feedback and real media next

Next implement explicit control `/feedback` handling with typed active-stream
information and timestamps derived from actual media backend observations.
Do not manufacture a playback position from a successful socket send. The
reference's estimated playback clock is a protocol clue, not proof of a played
sample. Control `/command` resource/mode handling also needs explicit semantics.

Then connect media packet/record receivers, audio/video decoders, display/audio
focus, microphone and real input reports. The factory Go-module identity,
installed-version execution/recovery, USB-network ownership, compatible existing
Apple authentication-chip access, target persistence and real-phone validation
remain unresolved. This software-only goal is not yet complete.
