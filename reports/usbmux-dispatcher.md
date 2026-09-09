# USBmux runtime dispatcher and byte-stream integration

Updated: 2026-09-09. Continues [the connection layer](usbmux-connection.md)
and [CarPlay progress](carplay-progress.md). Previous checkpoint `dcfdb7f`
was committed and pushed. This step adds real library coordination code, but
all verification still uses a simulated backend, not a physical phone or car.

## Step 1 - Replace the test-only bridge with a dispatcher

Added [usbmux_dispatcher.h](../src/carplay/usbmux_dispatcher.h) and
[usbmux_dispatcher.c](../src/carplay/usbmux_dispatcher.c). One initialized
packet host and one to four initialized TCP connection objects are registered
with explicit caller-supplied read/write/cancel callbacks. The dispatcher owns
their mutation for its lifetime; applications use its handle-based stream APIs.

The data path is now library code:

```text
Application stream handles (up to four)
              |
      TCP connection objects
              |
 Dispatcher: routing, fair output, deadlines, lifetime ownership
              |
       USBmux packet host
              |
 Caller-supplied raw read/write/cancel backend
```

Initialization checks distinct connection objects, idle states, callbacks and
host capacity. Host TX must fit every configured send limit plus 36 bytes;
host RX must fit the advertised connection capacity plus framing, capped at
the wire layer's 65,536-byte limit. It does not silently advertise receive
capacity that the host cannot reassemble. All backing storage remains separate
caller-owned memory; arguments/storage must not overlap.

The dispatcher occupies 1,240 bytes on this PC, including a 1,024-byte read
scratch buffer. The host's 200 bytes, each connection's 360 bytes and all their
caller RX/TX buffers are additional. No allocation, hidden clock, OS call,
device descriptor or native USB implementation is supplied.

## Step 2 - Define the raw backend contract

Callbacks are synchronous, nonblocking and fill status/count/generation.
Progress accepts at most the requested extent. Zero progress means would-block;
all non-progress statuses require zero count. Unknown statuses, excessive counts
or inconsistent status/count combinations close the session. A stale result is
rejected before its bytes can feed the host or advance output.

Write counts mean physically completed bytes from the offered tail, not bytes
copied into another queue or merely submitted to an asynchronous API. Backend
buffers/results cannot be retained after callback return. An asynchronous USB
implementation needs its own memory, ordering and completion accounting.
`cancel` must synchronously quiesce the active generation before returning.
These are caller obligations, not a memory sandbox; the dispatcher cannot
interrupt a blocking or faulty callback.

Start requires a fresh already-established physical byte stream and strictly
newer nonzero generation. It queues version negotiation but invokes no backend.
Closure cancels exactly once per active generation, then clears host/connection
queues and retained input. Restart does not bypass monotonic clocks or reuse a
physical generation. Clearing state is not secure erasure of backing storage.

## Step 3 - Bound each poll and preserve physical completion

Each poll checks all shared hard deadlines, then does at most:

1. One backend read of at most 1,024 bytes.
2. One buffered host feed and one held-frame dispatch.
3. One TCP packet submission selected round-robin among connections.
4. One backend write of a physical packet tail.

Connection polling may also materialize one bounded ACK/FIN output per
registered connection; no unbounded receive-drain or send loop runs internally.
The caller repeatedly polls as indicated by progress/events and `next_delay`.

When a TCP packet is copied into host TX, the dispatcher retains its owner slot,
connection token, size and mux sequence. Partial physical writes advance only
the host. Only after the entire mux packet completes are those exact TCP bytes
credited to that connection. The dispatcher checks ownership/size/sequence
invariants before doing so. This still does not mean the peer acknowledged data.

Only complete packets share the physical output; none can interleave with
another packet's tail. Round-robin fairness is per packet, not equal byte rates.
Connection write budgets include time waiting for this shared queue. Default
no-progress backoff is five milliseconds, configurable from 1 to 1,000; hard
deadlines always take precedence over a later retry.

Buffered coalesced input survives version/setup write barriers and blocked TCP
delivery. A reply arriving before its connection's physical completion remains
held until it can be processed. A held control event or blocked write alone
does not force zero-delay busy polling. All connection deadlines remain active
even if another connection or a control handler is blocked.

## Step 4 - Allocate fresh ports and expose byte streams

Opening requires READY mux state, an explicit remote port/initial sequence,
and an available slot. Local ports advance from 1 through 65,535 without reuse
inside that physical generation. A slot can be reused only after graceful
protocol closure and complete receive draining. Counter exhaustion is reported,
not wrapped or worked around by silently reconnecting.

Handles carry physical generation, connection token and slot. After slot reuse
or physical reconnect, stale read/write/finish/state handles return STALE without
advancing the clock, releasing newer state or cancelling a newer session.
Connection tokens continue increasing across physical reconnects, while local
ports may restart only for the new physical stream.

Read copies at most one contiguous receive-ring prefix. MORE means no data;
END means peer FIN with all buffered bytes drained. Write copies a bounded
prefix and may return BUSY/zero accepted, leaving the unsent suffix with the
caller. Finish is graceful send-half shutdown. None of these results indicates
Lockdown acceptance, trust pairing, TLS success, iAP2 authentication or CarPlay.

Both TCP ports determine routing. Unmatched traffic is discarded with a
saturating counter; no anonymous RST is automatically sent. Retired tuples
cannot be routed into a newly allocated port. Any terminal connection error
conservatively cancels the entire shared physical session and every registered
connection, with the failing slot recorded. There is no isolated local-abort
reset scheduler; graceful finish is the supported per-stream shutdown path.

## Step 5 - Make CONTROL handling explicit

An opaque CONTROL packet is held in host RX, exposed with a new local token and
physical generation. It is not logged, executed, parsed or silently ignored by
the dispatcher. A matching release is required; an old token cannot release a
later event. Subsequent input is backpressured while existing TX continues.

Holding beyond the host receive budget closes/cancels the shared transport.
The caller must therefore keep polling while handling the event, and release
it deliberately. CONTROL semantics remain an application-level task.

## Step 6 - Test the library through a simulated peer

Thirteen groups exercise an independent synthetic peer through the callback API:
three-byte reads/five-byte writes, four simultaneous connections, copied payload
ownership, early responses, control tokens/coalesced tails, graceful drain/reuse,
retired ports, stale handles, physical reconnect/cancel, zero-window isolation,
retry backoff, shared deadline expiration before I/O, malformed physical input,
invalid/stale backend results, clock/generation wrap refusal and maximum packets.

Every poll asserts at most one read and one write callback. A maximum-sized
65,536-byte physical packet is received in at least 64 bounded scratch reads.
The peer echoes synthetic byte payloads; these are not captured phone data,
Lockdown plists, TLS records or carkit traffic. The maximum-size fixture initially
advertised only a 2,048-byte peer window, so its write was correctly shortened;
the fixture now explicitly grants sufficient credit. No flow-control check was
relaxed to make it pass.

Verification passed:

1. `scripts/Build.ps1`: 14/14 CTest suites.
2. `scripts/Check-CarPlaySanitizers.ps1`: ten protocol suites under ASan/UBSan.
3. `scripts/Check-CarPlayArm.ps1`: twelve C99 units, relocatable ARM link without imports.
4. `python -B -m unittest discover -s tests -p test_*.py -v`: 19 tests.
5. `git diff --check` and local Markdown link checks.

The new files/tests select GPL-3.0-only, using the same existing protocol
components and pinned references. Ownership, scheduling, cancellation and token
rules are local designs, not new claims about the upstream reference engines.
See [provenance](../third_party/README.md).

## Step 7 - Continue toward real phone services

Next implement bounded Lockdown/service framing and plist request/response
handling on these stream APIs, then the TLS/trust-pairing path and carkit
service startup. Only after establishing that service should its stream be
connected to the existing iAP2/control endpoint. The USB network/media path is
separate and still missing.

A real QNX USB backend, installed-firmware compatibility, Go-module identity,
authentication provider, display/audio integration and verified execution/recovery
remain unresolved. Callback simulations and ARM object generation do not prove
those requirements. No installable image, update USB or vehicle change was made.
