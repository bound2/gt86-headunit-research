# Projection timing and encrypted event services

Date: 2026-09-10. Continues [session resources](projection-session.md), Step 62
of [CarPlay progress](carplay-progress.md). This step implements actual Windows
socket services, not simulated port numbers. All network validation uses IPv4
and IPv6 loopback on the PC. No phone, vehicle, USB device, real trust record or
firmware is accessed. Software-only CarPlay is still **not installable**.

## Step 1 - Pin the protocol reference and keep platform limits explicit

The existing LIVI checkout remains at commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Inspected Git blobs:

| File under `src/main/services/projection/driver/cp/stack/` | Git blob |
| --- | --- |
| `timingServer.ts` | `2eb385de51fd3ceda2e720bfa4687d277b467d70` |
| `cpStack.ts` | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` |
| `keepAliveServer.ts` | `38045f73097e8d3602db4287293143d42d78293b` |

The reference drives UDP timing probes from the receiver, uses request/response
types 210/211 and four timestamps, and filters clock observations with a
two-response minimum, eight-group delay window and small-residual correction.
Its initial clock mapping uses a wall-clock default. Our implementation requires
an explicit monotonic/NTP anchor and never changes the OS clock. This is a
selected interoperability profile, not an Apple conformance claim.
[Timing reference](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/timingServer.ts).

Session event transport uses separately derived event keys; optional low-power
traffic is consumed over UDP. No sleep/wake policy follows from consuming it.
[Session reference](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts),
[keepalive reference](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/keepAliveServer.ts).

## Step 2 - Implement the bounded local timing clock

`projection_timing.c/.h` implements an allocation-free C99 timing engine,
separate from sockets and authentication. The supported datagram is exactly
32 bytes: byte 0 is `0x80`, byte 1 is 210 or 211, and the big-endian length at
bytes 2..3 is 7. Reserved bytes 4..7 are ignored. Three big-endian NTP64 values
occupy offsets 8, 16 and 24: originate, receive and transmit respectively.

Only a successfully accepted UDP send commits a pending probe. A would-block
probe is discarded and freshly timestamped later. Responses must match its
originate value; stale/duplicate packets cannot renew the synchronization budget.
Invalid matching RTT retires that probe without destroying the last estimate.
Requests can be answered with explicit receive/transmit timestamps without
being treated as successful clock measurements.

The local implementation uses unsigned modular fixed-point arithmetic, avoiding
floating point, signed overflow and negative-time conversions. It rejects
negative/excessive RTT and the ambiguous half-era phase difference. Two samples
select the lowest RTT; an eight-group window rejects higher-delay observations
until older observations age out. Initial or sufficiently large phase changes
step the local anchor; smaller changes apply one eighth of the residual.
This estimates a peer clock; it does not authenticate that clock or measure
physical media playback. Zero RTT is allowed at timestamp resolution.

Defaults are local policy: 1-second probe interval, 3-second response budget,
30-second initial/resynchronization budget and 500-ms maximum RTT. Explicit
nondecreasing nanoseconds drive every check; exact synchronization expiry closes
the owner, while response expiry only retires the pending probe.
No local wall-clock query or OS clock setter is called. The pure engine is built
by the ordinary target, but was not added to either existing ARM portability claim.

## Step 3 - Bind real peer-specific Windows endpoints

`projection_services_win.c` supplies a real `projection_session_provider`:

| Resource | Actual transport | Accepted source |
| --- | --- | --- |
| Timing | Nonblocking UDP, ephemeral local port | Configured control peer IP **and** SETUP timing port |
| Events | Nonblocking TCP listener, then one accepted connection | Configured control peer IP; source port may vary |
| Optional low-power | Nonblocking UDP, ephemeral local port | Configured control peer IP |
| Media streams | Explicit delegated provider only | Delegate must implement the existing peer/lifetime contract |

The caller supplies binary local/peer addresses from the owned control transport,
not plist hostnames. The opaque RTSP target is never resolved. IPv4 and IPv6 are
separate, with IPv6-only sockets; wildcard, multicast and mapped-v4 addresses
are rejected. Link-local IPv6 requires an explicit scope. No interface discovery,
DNS, default endpoint, background thread or automatic capability advertisement
is introduced. Ordinary IPv4 subnet broadcast detection is not inferred without
interface metadata; the trusted caller must provide real unicast connection addresses.

Sockets use exclusive binding and non-inheritable handles; accepted handles are
explicitly made non-inheritable too. Microsoft documents exclusive binding and
the no-inherit creation flag. These policies are Windows-specific, not a QNX
socket compatibility claim.
[Exclusive binding](https://learn.microsoft.com/en-us/windows/win32/winsock/so-exclusiveaddruse),
[socket creation](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw).

Oversized UDP packets are discarded entirely, including the buffer prefix
returned with `WSAEMSGSIZE`. Empty UDP is not TCP EOF. Would-block and UDP ICMP
port-unreachable indications do not invent successful data transfer.
[Microsoft receive semantics](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom).

Initial allocation returns its lease only after all required sockets exist.
Partial failures close owned handles and wipe event state. Delegated leases are
remapped into one unique namespace; a delegate's lease 1 does not collide with
the root lease 1. Failed allocations with transferred leases remain owned until
cleanup. Winsock stays referenced while delegated resources require cleanup.
There is no media delegate by default: a media request then returns unsupported,
not a dummy listener. Nonzero feature flags require an explicit delegate and
the existing runtime capability attestation still applies.

## Step 4 - Own encrypted event records and explicit polling

The event socket accepts one matching peer and closes its listener. Wrong-peer
connections do not extend the 10-second default accept deadline. EOF, bad tags,
replayed records, counter exhaustion or budget expiry terminate the transport;
it cannot reconnect with counters reset under the same session keys.

Records reuse the existing real authenticated cipher: two-byte little-endian
length as AAD, directional counter nonce and 16-byte tag. Event read/write keys
retain the Step 62 event directions, separate from control keys. Caller-owned
bounded network storage retains coalesced tails; at most one record is decrypted
per poll and held plaintext prevents further reads until explicitly retired.
Empty authenticated frames still require explicit count-zero retirement.
Queued output is encrypted once; partial socket acceptance retires only that
prefix. Kernel acceptance is not phone acknowledgement or media playback.

This API exposes authenticated **records**, not a complete event RTSP command
sequencer. It sends no automatic 200 response. The frontend must classify and
correlate replies/commands and may not label unsolicited commands as replies.
Unsolicited output is gated on provider start after the outer RECORD reply drains;
replies may be queued earlier. Feedback/HID/iAP command handling remains next work.

`projection_receiver_poll` first enforces the control owner's generation and
deadlines, then invokes the optional paired provider poll/next-delay callbacks.
Failures close every session resource through the existing owner. A pending
full-teardown reply with no remaining leases needs no service poll. The Windows
provider uses its explicit nanosecond callback, not the rounded receiver timestamp;
the caller must use consistent monotonic origins and refresh time after callbacks.

One poll performs at most four timing receives, one keepalive receive, one TCP
accept/read/write, one cipher feed and one bounded delegate poll. The next-delay
calculation includes timing/cipher/accept/delegate deadlines and a default 5-ms
poll cadence. There is no OS wait inside it. Connected idle events have no separate
idle timer; control lifetime and synchronization expiry still apply. Low-power
traffic renews neither budget. Peer-IP pinning is not cryptographic UDP authentication.

## Step 5 - Verify actual sockets alongside synthetic protocol identities

Four pure timing test groups cover exact encoding, header/size validation,
pending-send ownership, duplicates, invalid RTT, signed phase, NTP rollover,
window eviction, exact deadlines, near-maximum monotonic values, transactional
configuration and 10,000 deterministic malformed packets. An independent
standard-library Python `Fraction`/unbounded-integer checker validates 12 C
clock/filter trace values, including negative phase and rollover.

Eight service groups use actual IPv4/IPv6 loopback UDP/TCP, exclusive-bind
collision/release, handle flags, wrong timing IP/port, wrong event peers, oversized
datagrams, synchronization, fragmented/coalesced encrypted records, empty frames,
held-data backpressure, partial plaintext retirement, bad tags/replay/EOF and exact
accept/sync/receive/hold/output budgets. The IPv6 record test uses a seven-byte
network buffer. Delegate mapping, failed open/start/poll and missing-media rejection
are explicit. The tests do not deterministically force every OS allocation error,
kernel send-buffer exhaustion or every possible partial TCP send length.

An integrated fixture performs real known-controller pair verification and
encrypted MFi/session requests before opening actual sockets. It verifies the
derived event key, RECORD drain/start ordering, partial/full teardown, stale
generation, provider deadlines and outer-control expiry before backend I/O.
Pairing keys are public synthetic fixtures; MFi results and media availability/
ports remain explicitly simulated. No actual phone enrollment or media is claimed.
The old receiver harness was extracted into a shared header without removing its
existing enrollment/receiver tests.

Commands used from the repository root:

```powershell
cmake --build build/crypto --config Release -- /verbosity:quiet
ctest --test-dir build/crypto -C Release --output-on-failure
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py
python -B scripts/check_projection_timing.py build/crypto/Release/projection_timing_tests.exe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
```

A fresh checkout first prepares/configures the optional dependencies using
`scripts/Build-CarPlayCrypto.ps1`. All 35 combined, 21 ordinary, 24 TLS-only and
25 Python regression tests pass. Seventeen ordinary protocol/capability/timing
suites and nine hosted TLS/carkit/enrollment/file/MFi/session/receiver/service
suites pass ASan/UBSan, with Monocypher and Mbed TLS instrumented. Changed C99
modules and C++ tests pass strict Clang warnings; static analysis reports no
finding in the four changed/new C99 modules. Review tightened post-receive
deadline checks and final delegated Winsock cleanup before publication.

The existing dependency CMake deprecation and privileged Windows symlink skip
remain; actual junction rejection passes. No dependency version changed. The
service context is 920 bytes, session 3,856 and receiver 13,552 on x64, excluding
caller storage, stack, socket buffers and crypto allocations. These are not target
memory or scheduling guarantees. The new Windows backend is outside both ARM
claims and cannot be installed on the QNX head unit.

## Step 6 - Continue with event commands and media integration

Next add a bounded event-message owner over authenticated records: explicit
RTSP framing, request/reply correlation, feedback clock payloads and unsolicited
input ordering. Then implement the media packet/record receivers and connect
actual decoder, display, audio, microphone and input drivers. Do not promote the
synthetic media provider or capability fixture into a production default.

Factory Go-module identification, installed-version execution/recovery, native
USB-network ownership, access to the compatible existing Apple authentication
chip, QNX sockets/persistence, real approval policy and phone interoperability
remain unresolved. No modified ISO or update USB is produced by this step.
