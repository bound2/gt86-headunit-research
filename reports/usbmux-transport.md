# Wired USBmux transport implementation

Updated: 2026-09-09. Continues [wired identification](wired-identification.md)
and [CarPlay progress](carplay-progress.md). All checks below run on the PC;
no USB device, phone trust record, service or vehicle has been accessed.

## Step 1 - Pin and compare the packet references

The wired LIVI path carries iAP2 through a carkit service over USBmux, separate
from its USB network/media path. Read its complete
[mux.rs](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-usbmux/src/mux.rs)
at the existing pin `a76553fc941dcf378dd55c04da56aaf3d6911e08`.
Cross-check against usbmuxd
[device.c](https://github.com/libimobiledevice/usbmuxd/blob/3ded00c9985a5108cfc7591a309f9a23d57a8cba/src/device.c)
and [usb.h](https://github.com/libimobiledevice/usbmuxd/blob/3ded00c9985a5108cfc7591a309f9a23d57a8cba/src/usb.h),
newly pinned to `3ded00c9985a5108cfc7591a309f9a23d57a8cba`.
The ignored `build/usbmuxd-reference` is a no-checkout source repository;
selected files were read with `git show`, not built or installed.

Git blob identities: LIVI `mux.rs` is
`19d28b78ee166bdabe2d5efa77ea5965317f1df9`; usbmuxd `device.c` is
`ce73718d37c69fc52b918067b8de1e995ff022f1`, and `usb.h` is
`4e44ccedfbc4581dcd685a216141bebe47224771`.

Important differences: LIVI ignores the version-read result and keeps its
outgoing second sequence slot at zero. usbmuxd checks the peer's version, starts
v2 setup with that slot at `0xffff`, and subsequently copies the incoming
second slot into its receive-sequence state. Both emit `0xfeedface` as host
magic without validating incoming magic. The wire layer must preserve these
fields without inventing peer-direction semantics. USBmux here means the raw
USB packet protocol, not the usbmuxd host-socket plist protocol.

## Step 2 - Implement bounded packet codecs

Added [usbmux_wire.h](../src/carplay/usbmux_wire.h) and
[usbmux_wire.c](../src/carplay/usbmux_wire.c), with these supported layouts:

| Packet | Outer header | Payload |
| --- | --- | --- |
| Initial VERSION (`0`) | 8 bytes | Exactly 12 bytes: major, minor, padding |
| SETUP (`2`) | 16 bytes | Exactly one byte |
| CONTROL (`1`) | 16 bytes | Opaque, possibly empty |
| TCP (`6`) | 16 bytes | Fixed 20-byte TCP header, then payload |

All multibyte fields are big-endian. The extended header preserves magic and
both 16-bit sequence slots. Version fields are decoded without selecting a
supported major version; negotiation belongs to the next layer. SETUP's byte
is preserved by the codec; the references send `0x07`.

The frame cap is a local 65,536-byte bound, not a discovered GT86 USB limit.
TCP payload is at most 65,500 bytes. The TCP codec preserves ports, sequence,
acknowledgement, flags, wire window, checksum and urgent fields. A short or
reserved-bit header offset is invalid; TCP options are explicitly unsupported.
The references interpret the 16-bit wire window as bytes shifted left by eight.
No SYN/ACK connection engine, flow control or checksum verification is supplied.

Decoders borrow input and consume exactly one frame; coalesced tails remain
with the caller. Incomplete/error results preserve the destination. Encoders
preflight all capacities, report zero bytes and leave output unchanged on
failure. Arguments/storage must not overlap. Unknown protocols are rejected.
There is no heap allocation, hidden clock, I/O or authentication operation.

## Step 3 - Reassemble partial input without unbounded storage

The stream uses caller-owned storage from 36 to 65,536 bytes. It validates the
eight-byte prefix before accepting the rest of a packet, rejects packets above
the supplied capacity, and returns at most one frame per call. Length/protocol
errors latch until explicit reset; it never scans for a magic value to recover.

The borrowed result lasts until the next push/reset/init. A caller must retain
unconsumed input and explicitly reset on EOF, timeout or a new connection.
Zero bytes mean no progress, not EOF. Reset discards assembly state but does
not securely erase backing storage. Deadlines and connection generations are
not part of this wire-only layer.

## Step 4 - Verify bytes, bounds and portability

Seven independently specified synthetic vectors cover version 1/2, the two
setup-slot conventions, a port-62078 SYN, sequence-boundary TCP data and opaque
control with deliberately different magic. These are not phone captures or
copied upstream fixture files. Ten test groups cover exact roundtrips, every
fixture split/truncation, short-output canaries, invalid prefixes, TCP offsets,
coalesced input, latched failures, reset, null arguments and maximum-size frames.

Verification passed:

1. `scripts/Build.ps1`: 11/11 CTest suites.
2. `scripts/Check-CarPlaySanitizers.ps1`: all seven protocol suites under ASan/UBSan.
3. `scripts/Check-CarPlayArm.ps1`: nine C99 units, relocatable ARM link without imports.
4. `python -B -m unittest discover -s tests -p test_*.py -v`: 19 tests.
5. `git diff --check`: no whitespace errors.

The new implementation/tests select GPL-3.0-only because the usbmuxd reference
offers GPL version 2 or version 3, not an unrestricted later-version option.
Existing iAP2 files retain their own notices. See
[provenance and license text](../third_party/README.md).

## Step 5 - Implement the version-2 host handshake

The wire checkpoint was committed/pushed as `d754aca`. Added
[usbmux_host.h](../src/carplay/usbmux_host.h) and
[usbmux_host.c](../src/carplay/usbmux_host.c), with this startup sequence:

```text
VERSION_TX -- all 20 bytes written --> VERSION_RX
VERSION_RX -- valid major-2 reply --> SETUP_TX
SETUP_TX   -- all 17 bytes written --> READY
```

Start queues version `2.0.0`. A valid reply must have major version 2; minor and
padding fields remain available for diagnostics without an invented zero-only
restriction. Unsupported major versions close the host without setup/fallback.
SETUP sends `0x07`. READY means only that the host has completed mux setup;
it is not a TCP connection, successful trust pairing or CarPlay session.

The explicit `config.sequence` selects `USBMUX_HOST_USBMUXD` by default:
setup's second slot is `0xffff`, then future packets use the incoming second
slot. `USBMUX_HOST_LIVI` instead keeps the outgoing second slot at zero.
Both send setup at TX slot zero and advance that slot modulo 65,536 only after
the complete pending packet is physically written. Incoming magic/slots remain
visible. This is selectable reference behavior, not an interoperability finding
or a claim about the slots' unverified peer-direction semantics.

## Step 6 - Preserve packet ownership and physical completion

Initialization requires distinct caller-owned RX/TX buffers, each 36..65,536
bytes, and makes no I/O call. The object is noncopyable and initialized once;
all exposed fields are read-only. Host state occupies 200 bytes on this PC,
plus buffers. It has no heap, backend callbacks, hidden clock or socket API.

`output` lends the pending tail without consuming it. `advance` reports only
the number of bytes actually completed from that tail. Copying/submitting a
buffer is not completion; partial/zero completion never changes the packet.
Overcounts or unexpected positive completions close the active host. No
subsequent packet can interleave with pending bytes. An asynchronous backend
must supply its own storage, serialized completions and quiescence mechanism.

`feed` consumes at most one frame and reports the exact count. During version
or setup output, input is blocked with zero consumed; the caller retains it.
After READY, CONTROL and minimal TCP frames become a single held packet.
Malformed/oversized input or a late VERSION/SETUP closes the host. Coalesced
tails stay at the caller until setup completes or the held packet is released.

The held view is stable until `release` or closure/restart. Explicit TCP sending
copies a validated encoded header/payload into separate TX storage; it may copy
from held RX, but must never overlap TX/state. Sending and physical completion
do not release RX. New RX may update sequence metadata while TX is pending,
but never rewrites the already queued header. Local malformed-TCP/capacity
errors leave the session and queues intact without consuming a sequence slot.

## Step 7 - Bound time and reject old connections

All timed operations check deadlines before accepting progress. Defaults are
local policies, configurable from 1 to 60,000 milliseconds:

| Budget | Default | Starts | Ends |
| --- | --- | --- | --- |
| Total handshake | 2,000 ms | Successful start | Setup fully written |
| Per-packet write | 250 ms | Packet queued | Packet fully written |
| Receive assembly plus hold | 5,000 ms | First input byte | Packet released/version accepted |

Partial/zero progress, repeated views, busy queues and newly completed assembly
do not renew the current budget. Exact deadline expiration closes before
processing a late completion, version response or release. The minimum delay
uses subtraction to avoid absolute-deadline overflow. Caller time cannot wrap
or decrease. `next_delay` reports hard deadlines, not backend readiness; an
idle READY host has none. The caller also waits on I/O/application events and
calls `poll` before acting on untimed borrowed output views.

Each successful start needs a nonzero generation greater than every previous
successful start. Every timed operation checks it. A stale event closes the
active host without accepting the stale clock or bytes; the reason survives
subsequent close calls. Decreasing time with the current generation is an
argument error with no state change. A reconnect resets negotiation, sequence,
partial/held input and pending output. The caller must synchronously quiesce
old I/O before close/restart; generation checks cannot prevent a backend from
writing through stale pointers. Zero-byte input is not EOF: signal EOF/failure
through explicit closure. Discarding state is not secure memory erasure.

## Step 8 - Verify host state and failure paths

Fifteen independent host groups cover both setup conventions and exact first
SYN bytes, one-byte physical writes, every version split, coalesced tails,
nonzero minor/padding, rejected versions, held/copy ownership, empty CONTROL,
malformed peer input, local send failures, invalid completion counts, deadline
boundaries, generation rejection across all timed APIs, sequence wrap through
every 16-bit value, near-maximum clocks and maximum-sized RX/TX packets.
The synthetic SYN requests port 62078 but never establishes a TCP connection.

Current verification passed:

1. `scripts/Build.ps1`: 12/12 CTest suites.
2. `scripts/Check-CarPlaySanitizers.ps1`: all eight protocol suites under ASan/UBSan.
3. `scripts/Check-CarPlayArm.ps1`: ten C99 units, relocatable ARM link without imports.
4. `python -B -m unittest discover -s tests -p test_*.py -v`: 19 tests.
5. `git diff --check` and local Markdown link checks.

The new host files/tests retain the USBmux step's GPL-3.0-only choice. These
host policies are local designs informed by the same pins, not source claims
that either reference supplies these guarantees. No device input is captured.

## Step 9 - Remaining integration

The subsequent [connection-layer report](usbmux-connection.md) now records
implemented TCP-style port routing, SYN/ACK/sequence validation, bounded windows
and graceful/half-close behavior, including a simulation through this packet
host. The host API itself remains packet-only. Production dispatch/byte-stream
integration, Lockdown/plist/TLS trust pairing and carkit startup remain next.
None of these layers is a USB backend or proof of iPhone acceptance/CarPlay.

Real USB ownership/profile support, the existing authentication provider,
network/media protocols, QNX display/audio integration and verified hardware
execution/recovery remain unresolved. No installable image is produced.
