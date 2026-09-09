# Bounded USBmux TCP connection layer

Updated: 2026-09-09. Continues [the packet-host report](usbmux-transport.md)
and [CarPlay progress](carplay-progress.md). Previous checkpoint:
`b933ebf`, committed and pushed. No USB device, phone trust record, native
service, firmware or vehicle is accessed by this implementation or its tests.

## Step 1 - Compare the connection references

Read the connection/send/receive paths in pinned LIVI
[mux.rs](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-usbmux/src/mux.rs)
and usbmuxd
[device.c](https://github.com/libimobiledevice/usbmuxd/blob/3ded00c9985a5108cfc7591a309f9a23d57a8cba/src/device.c).
The latter routes both ports and tracks outstanding bytes against the peer's
scaled receive window. LIVI's smaller connection engine does not validate
incoming acknowledgements and advances receive acknowledgement by payload size.
Both encode the wire window with an eight-bit scale. Their complete receive,
close and connection policies differ; neither is adopted wholesale here.

The new layer is a local bounded implementation of this TCP-style USBmux
stream, not an IP TCP stack or Apple conformance result. It relies on an ordered,
reliable packet transport. The existing pinned sources and GPLv3 license text
are unchanged; new connection files/tests select GPL-3.0-only. No upstream
implementation bodies or private Apple specification are copied.

## Step 2 - Implement explicit connection opening

Added [usbmux_connection.h](../src/carplay/usbmux_connection.h) and
[usbmux_connection.c](../src/carplay/usbmux_connection.c). Startup is:

```text
SYN_TX -- physically written --> SYN_WAIT -- valid SYN|ACK --> OPEN_ACK
OPEN_ACK -- physically written --> OPEN -- explicit finish --> CLOSING
CLOSING -- both FINs acknowledged --> DRAINED
```

Start requires explicit nonzero local/remote ports, an initial sequence number,
newer nonzero generation and monotonic time. Initial sequence zero is valid;
the tests also cover both peers wrapping through zero. A reply must route to
both ports, have exactly SYN|ACK with no payload/urgent data, and acknowledge
the sent SYN. The peer's initial sequence is not assumed to be zero. A repeated
established SYN|ACK requests a current ACK without resetting stream state.

Each object represents one connection. Unmatched tuples return UNROUTED for an
external dispatcher. No automatic port allocator or multi-connection scheduler
is included. The same tuple must not be reused against a live old connection:
generation checks apply to local events, not to a generation field on the wire.

## Step 3 - Separate ownership, physical writes and peer ACKs

Caller-owned RX storage is 256..65,536 bytes; TX storage is 21..65,520 bytes.
Default send limit is 16,384 and must fit TX storage after the 20-byte header.
The object occupies 360 bytes on this PC, including eight flight records;
these buffers are additional. There is no heap allocation, callback or I/O.

Three different events have different effects:

| Event | Effect |
| --- | --- |
| Application `write` accepts a prefix | Copies one bounded TCP packet into owned TX |
| Entire physical packet completes | Advances sent sequence; records the data flight and its original time |
| Peer cumulative ACK arrives | Advances acknowledged sequence and releases fully acknowledged flight records |

Repeated output views and partial writes preserve the packet. Overreported
completion counts terminate the stream. Matching input is retained while a
SYN/data/FIN/opening-ACK awaits physical completion, so an early peer response
cannot acknowledge bytes before local completion accounting. Pure ACK output
does not block receive processing; new ACK intentions do not rewrite its bytes.

Up to eight data packets can be outstanding. A new application prefix is bounded
by the configured send limit, free flight records and the peer's scaled window
minus already outstanding bytes. A zero peer window returns BUSY without
retaining application input. ACKs may cross sequence wrap and partially cover
a flight; future or exactly half-range ambiguous ACKs terminate the stream.
Old ACKs do not regress state or update the send window. Window updates also
respect the peer sequence/ACK ordering fields.

This layer has no TCP retransmission, congestion control, options or zero-window
probe scheduler. Missing acknowledgements expire instead of silently succeeding.
An application waiting to send into an idle zero-window connection still needs
its own operation deadline; no application request is owned by that BUSY result.

## Step 4 - Bound receiving and preserve old window credit

Incoming data is copied into a caller-owned ring. Contiguous input views remain
stable until consumed; append cannot overwrite unread bytes. Duplicate payload
is not delivered twice, partial overlap copies only its new suffix, and forward
gaps are discarded with the current contiguous ACK. ACK, PSH|ACK and FIN|ACK
are supported. Unsupported established flags/urgent data close the stream;
RST has its own refusal/reset path. Incoming checksum remains opaque.

The advertised wire window is the free buffer space rounded down to 256-byte
units. The receive right edge separately remembers credit already physically
advertised: a newly rounded-down window does not revoke an earlier grant.
No new credit is granted merely because a window-update packet was queued.
This both accepts traffic legitimately sent under an earlier window and rejects
traffic exceeding real granted capacity. Consuming bytes schedules a window
update when it can grant more credit.

The first test run exposed a test peer incorrectly sending 300 bytes after a
256-byte grant. The engine correctly closed it. The ring-wrap fixture now sends
200 bytes, retains some previous credit for concurrent ACK testing, and keeps a
separate explicit over-credit rejection test. No capacity gate was relaxed.

## Step 5 - Handle graceful close, reset and timing

An explicit `finish` refuses further application writes, waits for outstanding
data ACKs, sends FIN and completes both directions' FIN/ACK exchange. Peer FIN
alone closes only the receive direction: buffered bytes remain readable before
EOF and local writes remain allowed. DRAINED preserves unread final bytes;
restart refuses to discard them. Duplicate FIN/payload is not redelivered.

A routed reset during opening refuses the connection. Established reset needs
the current receive sequence; an out-of-sequence reset requests a current ACK.
Immediate local `close` discards state without sending RST. It is not graceful
teardown of a still-live peer tuple: integration must reset/quiesce transport or
supply its own appropriate reset handling before reuse. TIME-WAIT and automatic
anonymous resets for unknown tuples remain outside this layer.

Default local budgets, each configurable from 1 to 60,000 milliseconds:

| Budget | Default | Renewal policy |
| --- | --- | --- |
| Complete opening | 5,000 ms | Start through final handshake ACK write; never renewed by partial progress |
| Owned output packet | 250 ms | Starts when queued; partial writes do not renew |
| Peer ACK | 5,000 ms | Each data flight retains its original physical-send time; partial ACK does not renew |
| Pending local ACK intention | 5,000 ms | Starts on first intention; more incoming data does not renew |
| Unread data | 5,000 ms | First unread byte or last positive application consumption; incoming traffic/zero reads do not renew |
| Graceful close | 5,000 ms | Starts on first `finish`; repeated calls do not renew |

All timed APIs check deadlines before progress. Stale generations terminate
without accepting their time or bytes. A current-generation decreasing clock
is an argument error. Deadline arithmetic uses subtraction, with no clock wrap.
Diagnostics survive repeated close calls. Discarding state does not securely
erase backing storage. The caller must quiesce backend access before restart.

`next_delay` reports hard deadlines, not I/O or application readiness. Call
`poll` after input, write completion and application progress to queue required
ACK/FIN work; do not sleep to the deadline while protocol work is runnable.

## Step 6 - Exercise both layers together

The integration test starts a real library USBmux host, completes version/setup,
wraps connection SYN/ACK/data packets with that host, and transfers them through
five-byte simulated physical writes and three-byte simulated physical reads.
It advances TCP completion only after the entire mux packet has completed.
Incoming held mux payloads are routed to the connection before being released.

A synthetic length-prefixed request/response then verifies owned application
data, peer ACK release and receive delivery. Its `abc`/`ok` bodies are **not**
Lockdown plists, trust pairing, TLS or carkit messages. No phone participates.
The bridge logic currently lives in the test, not a production dispatcher or
backend. Input/output lifetimes and completion accounting must be preserved by
that next integration layer.

Fifteen groups cover independent handshake bytes, both-port routing, handshake
rejections, physical/peer-ACK separation, window/flight limits, ring and sequence
wrap, overlap/duplicates/gaps, credit reopening, half/graceful close, resets,
all deadline families, stale generations across seven timed APIs, invalid counts,
maximum storage and the layered mux exchange.

Verification passed:

1. `scripts/Build.ps1`: 13/13 CTest suites.
2. `scripts/Check-CarPlaySanitizers.ps1`: nine protocol suites under ASan/UBSan.
3. `scripts/Check-CarPlayArm.ps1`: eleven C99 units, relocatable ARM link without imports.
4. `python -B -m unittest discover -s tests -p test_*.py -v`: 19 tests.
5. `git diff --check` and local Markdown link checks.

## Step 7 - Continue toward the real receiver

Next implement the bounded host/connection dispatcher and byte-stream adapter,
then the Lockdown framing/plist/TLS trust-pairing path and carkit service startup.
These are needed to connect the existing iAP2/control components to a real phone.
The USB network/media path is separate and still unimplemented.

The actual Go module's part number/revision, USB ownership/profile support,
authentication provider, installed-version compatibility, QNX display/audio
integration and verified execution/recovery remain unresolved. Requested an
already accessible read-only label/screen from the owner; no disassembly or
service-setting changes were requested. There is still no installable or
vehicle-tested software-only CarPlay update.
