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

## Step 5 - Remaining integration

Next implement a bounded version/setup host handshake with actual-write
completion, explicit sequence policy, packet ownership, deadlines and stale
connection rejection. Then add TCP connection/flow-control handling, the
Lockdown/plist/TLS trust-pairing path and carkit byte-stream integration.
The current codecs are not a USB backend or TCP connection, and do not make
an iPhone accept identification, authenticate, or start CarPlay.

Real USB ownership/profile support, the existing authentication provider,
network/media protocols, QNX display/audio integration and verified hardware
execution/recovery remain unresolved. No installable image is produced.
