# Bounded transport adapter implementation

Updated: 2026-09-09. Continues the
[USB transport design contract](usb-transport.md#step-6---define-the-next-bounded-adapter)
and [CarPlay progress, Step 33](carplay-progress.md#step-33---specify-the-portable-transport-pump).

## Current result

The portable receiver now has a C99 byte-stream transport pump that connects a
caller-supplied backend to the existing link/control/authentication endpoint.
A complete synthetic authentication/application exchange passes with fragmented reads and
writes. Fifteen dedicated test groups cover progress accounting, backpressure,
failure, reconnects, queue pressure and deadlines.

This is **not a QNX USB backend or an installable CarPlay update**. The pump
contains no USB descriptors, HID encoder, role-switch command, device path,
authentication credentials or implicit CarPlay capability advertisement.
Nothing was opened or changed on the car. The selected approach remains
software-only on the factory hardware.

## Step 1 - Commit the previous investigation

Committed the USB ownership/report-framing investigation as `cec54b6`,
`Trace stock USB ownership and probe bounded iPod transfers`.
The implementation described below is the continuation after that checkpoint.

New source: [iap2_transport.h](../src/carplay/iap2_transport.h) and
[iap2_transport.c](../src/carplay/iap2_transport.c).
Existing protocol APIs and their source files were not changed. The pump reads
their documented read-only state to coordinate the current local timer profile.

## Step 2 - Define the backend boundary

The backend supplies synchronous, nonblocking `read`, `write` and `cancel`
callbacks. Each I/O result includes status, byte count and connection generation.

| Backend result | Pump behavior |
| --- | --- |
| Progress, positive count within request | Consume that count only |
| Progress with zero, or would-block with zero | Retain state and back off |
| Disconnected or fatal, with zero count | Cancel and close the connection |
| Oversized count, unknown status or non-progress with bytes | Reject the backend result and close |
| Result from another connection generation | Reject as stale and close without feeding RX or advancing TX |

Backend read/write buffers are borrowed only for the duration of the callback.
An asynchronous native backend must own its own USB/DMA storage and bridge its
completed operations into this interface. It must report the actual completed
operation's generation, not relabel old results with the new requested one.
`cancel` must synchronously quiesce the old generation before returning.

These are backend obligations, not a security sandbox. Count validation cannot
undo a callback buffer overrun, prevent a backend from lying about transmission,
or preempt a blocking callback. Providers and callbacks must be bounded and
non-reentrant. No real asynchronous USB completion handler is implemented here.

## Step 3 - Retain partial data and bound each poll

1. Own one 1024-byte output buffer and one 1024-byte receive buffer. Host pump
   state is 2,184 bytes, in addition to the 19,952-byte control endpoint and its
   caller-owned buffers. These are measured host layouts, not QNX ABI sizes.
2. Produce a link frame only when no output tail remains. Retain its total
   length and offset, and give the backend only the unsent tail. Do not produce
   another frame or interleave a retransmission until the tail is complete.
3. Permit at most one backend read, one buffered feed, one control poll, one
   output production and one backend write per pump call. The control poll
   retains its own eight-work-unit bound and explicit provider-callback policy.
4. Keep receive processing active while output is blocked. Do not replace
   buffered receive bytes until their consumed count is accounted for. A bad
   frame or RX-full rejection may consume one packet while leaving a following
   packet buffered; the next poll processes that tail before another read.
5. Preserve the link's recoverable checksum/unsupported-frame/RX-full policy.
   Record the most recent recoverable feed error. Do not ACK a rejected RX-full
   packet; the peer must retransmit it after space becomes available.
6. Surface held application messages through the existing endpoint API. The
   application may view, release or reply between pump calls, but must keep
   polling transport. Only the pump starts/feeds/polls/produces output from and
   closes its endpoint while active.

Completed buffers and failed connection tails are cleared. This is ordinary
state cleanup, not a secure-erasure guarantee. Physical write acceptance never
substitutes for an iAP2 cumulative ACK.

## Step 4 - Handle time and backpressure explicitly

Default total pending-output budget: **250 ms**. Positive partial progress does
not restart it. Default polling backoff after no progress: **5 ms**, separately
tracked for reads and writes. Repeated same-clock polling does not repeat a
blocked backend call. This is a polling interface, not a readiness-event API.

Control/handshake deadlines are checked before backend I/O. A retained tail
also closes the connection if it would block an existing marker, SYN or data
retransmission deadline. This includes a previously sent packet whose retry is
due while a different frame is partially written. Deadline expiry wins over a
late completion or ACK arriving in that poll; this is deliberately conservative.
If no tail is retained, normal link output drives retransmission and exhaustion.

The delay query includes pending-output and hard endpoint deadlines. Immediate
output readiness is suppressed when it merely describes an already-blocked
tail; a held application message alone also does not cause an immediate timer.
More actual bounded work may still return zero. The caller must service its
application between calls and use one monotonic clock throughout.

The pump's marker/SYN and data retry accounting is coupled to the current local
link profile. Any future timer-profile change must update these checks/tests.
These are experimental local scheduling choices, not Apple-required timings
or a demonstrated performance budget for the head unit.

## Step 5 - Make disconnect and reconnect explicit

Initialization requires an already initialized, idle endpoint and valid backend
callbacks/configuration. Invalid configuration is rejected before mutation.
Starting a connection requires a nonzero generation strictly greater than the
last successful start. Generations do not wrap or get reused within a pump's
lifetime; reinitializing the pump is not a way to bypass that requirement.

On failure or explicit close, the pump becomes inactive, cancels exactly once,
closes the endpoint, and clears pending transport data. Endpoint closure resets
auth/identification acceptance and partial messages. Diagnostic reasons persist.
Further closes/polls do not cancel again.

Reconnect sequence:

1. Finish closing/quiescing the old backend generation.
2. Reinitialize the same control endpoint with its explicit buffers/provider.
3. Re-enable identification only if explicit, truthful metadata is available;
   reinitialization disables it by default.
4. Start the pump with a higher generation and the same monotonic clock.

An old result returned after reconnect causes closure of the new generation;
it is not treated as valid progress. The fake-backend test verifies that a
partial old output tail is never carried into a new connection.

## Step 6 - Verify the implementation

[iap2_transport_tests.cpp](../tests/iap2_transport_tests.cpp) has 15 groups:

1. Configuration transactionality, callback requirements and clock/null bounds.
2. Exact partial-output tails and per-poll callback budgets.
3. Would-block/zero-progress backoff; zero reads are not EOF.
4. Invalid completion counts/status combinations on both directions.
5. Disconnect/fatal-stall handling after partial output and idempotent cleanup.
6. Reconnect, stale results in both directions and generation exhaustion.
7. Total output and handshake deadline boundaries.
8. One-byte reads, partial writes and coalesced control-message preservation.
9. Recoverable checksum/unsupported frames followed by a retained valid frame.
10. RX-full rejection, consumed counts, retained tails and no false ACK progress.
11. Continued receive/application handling while output is blocked.
12. Authentication timeout under backpressure and remote reset cancellation.
13. A negotiated retransmission deadline shorter than the pending-output budget.
14. Initial transmission plus three complete retries, then link exhaustion.
15. Complete synthetic certificate/challenge/signature/acceptance exchange and
    application roundtrip with three-byte reads and five-byte writes; provider
    callbacks occur once each and receive the exact challenge. Advancing the
    application clock also tests delay-query and backward-poll handling.

Verification commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

All nine CTest suites and all five sanitized protocol suites pass. All six C99
units compile/link into the freestanding Cortex-A8 relocatable object without
runtime imports. All 19 existing Python safety/regression tests still pass.
The synthetic certificate/signature bytes are not credentials; these tests are
neither a real authentication-chip test nor an iPhone interoperability result.

## Step 7 - Continue toward an actual CarPlay session

The subsequent [session-start investigation](carplay-session-start.md) traces
CarPlay establishment and transport handoff in the pinned reference and adds
bounded startup codecs with an explicit wired-start reply. It also finds an
identification/authentication ordering mismatch; implementing an explicit
identification-first profile is the next local interoperability task. Keep
unknown USB roles, network interfaces and CarPlay capabilities explicit; do not
turn them into guessed defaults or copy the stock HID path uncritically.

A real native backend still needs installed-version matching, physical port
ownership, a verified iAP2 profile, coordinated stock services and actual USB
completion/buffer handling. Real authentication compatibility, execution access
and recovery remain unresolved. CarPlay media protocols, decoder, display/input
and audio-focus integration are also unfinished. No installer is produced.
