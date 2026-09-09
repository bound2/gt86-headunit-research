# iAP2 session engine over carkit

Date: 2026-09-09. Continues [carkit startup](carkit-startup.md) and
[CarPlay progress](carplay-progress.md). The preceding step is committed/pushed
as `7539981`. This step integrates existing protocol layers; it does not provide
an installable update or demonstrate CarPlay on the owner's head unit.

## Step 1 - Keep transport completion distinct from protocol success

The existing iAP2 pump retains partial output and starts link retransmission
clocks when the link produces a frame. Carkit writes, however, initially mean
only that plaintext was copied into TLS or a prefix into USBmux. Directly
treating that copy as a completed underlying transfer would hide pending bytes
from the iAP2 pump's retained-output deadline.

The new [carkit_iap2.c](../src/carplay/carkit_iap2.c) bridge deliberately uses a
stronger completion barrier:

```text
iAP2 output -> owned pending frame -> carkit/TLS submission
            -> physical USBmux output -> TCP-style acknowledgement
            -> pump write completion

iAP2 acknowledgement remains a separate event in the link engine.
```

`carkit_write_drained` checks that service TLS has no queued plaintext and its
USBmux connection has neither pending physical output nor unacknowledged data.
It performs no physical I/O. Exclusive service-write ownership associates this
barrier with the bridge's submitted frame; it is not a general multi-writer
completion token or a claim of iAP2/CarPlay acceptance.

## Step 2 - Add an owning bounded bridge

[carkit_iap2.h](../src/carplay/carkit_iap2.h) binds an unused OPEN carkit service
to the existing `iap2_transport` and caller-initialized control endpoint. The
endpoint's provider, metadata and startup order remain explicit. No default
identity, signer, pairing fallback, capability declaration or media activation
is added. Identification-first without metadata rejects start before accepting
an arbitrarily advanced lower-layer clock.

The bridge retains at most one 1,024-byte frame in its own storage. The first
write callback copies it but returns no completed bytes. Subsequent polls submit
any remaining prefix through carkit; explicitly permitted plain mode can accept
small prefixes, while TLS can retain a whole frame. The original pump bytes
remain pending and are compared against the bridge's owned copy on retries.
Only a completed drain barrier permits one upward completion for the full frame.
No callback retains pump input/output pointers or result pointers after return.

Partial progress never renews the pump's absolute retained-output budget
(250 ms by default), and does not bypass a shorter link retransmission deadline.
Both lower TLS/USBmux deadlines and upper identification/authentication/message
deadlines remain active. Provider callbacks retain their synchronous contract;
the event loop cannot interrupt a blocking hardware-provider callback.

One bridge poll performs deadline preflight, one carkit poll, at most one pending
write submission, and one iAP2 pump poll. There are at most two underlying
physical reads/writes. The new `iap2_transport_check` uses the same empty-feed
deadline checks already present in its poll, without invoking a provider,
producing output or calling backend read/write. Expiry may cancel. This check
runs before lower-layer I/O, so expired iAP2 work cannot flush queued bytes first.
`carkit_check` similarly exposes the existing timer/lifetime check without I/O.

## Step 3 - Preserve lifetime, input and application boundaries

Saved physical/service/Lockdown handles are checked before accepting time or
progress. Backend results carry the bridge's actual bound pump generation, not
an unverified callback argument. Wrong-generation callbacks/cancellation do no
device I/O. The bridge is one-shot: an active or closed object cannot be restarted
or silently rebound to a different service. Use a new lifetime after teardown.

Carkit now records external application use. A previously read/written service
cannot be attached as fresh; already decrypted but unconsumed peer data can be
preserved. This permits an early encrypted detection marker to survive attachment.
No drain operation discards inbound data merely to establish a frame boundary.

Any terminal lower-layer, endpoint, provider or deadline error tears down the
pump, resets authentication/identification progress, discards pending buffers and
closes both retained carkit/Lockdown owners. Shared cancellation is idempotent.
An old physical generation can release its old crypto resources but cannot tick
or cancel a replacement mux. This remains abortive teardown, not StopSession,
graceful TLS shutdown or automatic reconnect.

Application messages are still explicit held events on the control endpoint.
The application may inspect/release/reply or queue supported notifications
between bridge polls, using the same monotonic clock. Underlying USBmux CONTROL
events must also be inspected/released independently; they are not iAP2 messages.

## Step 4 - Exercise startup through the combined implementation

[carkit_iap2_tests.cpp](../tests/carkit_iap2_tests.cpp) starts with the actual
synthetic StartSession exchange, protected Lockdown TLS, encrypted StartService
and a separate carkit stream. It then drives the existing iAP2 link/control
engine through detection and negotiation, explicit wired identification,
certificate/challenge/result sequencing, an explicit zero-intent power
notification and a wired-start request/reply.

The encrypted path uses two real mutually authenticated TLS connections.
A second path tests the existing explicit permission for a plain service.
The accessory-auth provider and phone peer are **synthetic**: the test verifies
that the exact challenge reaches the provider once and the expected response
bytes reach the peer, not that an Apple authentication chip signed anything or
an iPhone accepted it. The wired-start address/public-key fixture is also
synthetic; no advertised listener or media server exists behind it.

Six groups cover:

1. Full integrated startup with fragmented 64-byte iAP2 frames, provider gates,
   exact CSM replies, explicit notifications/application replies and final ACKs.
2. Copied TLS/plaintext bytes remaining uncredited while TCP ACKs are missing,
   with inbound peer progress still serviced.
3. Retained-output and eligible identification deadlines preventing further
   physical I/O or provider work at expiry.
4. Decreasing clocks, generation reuse/staleness, missing metadata and teardown
   without affecting a replacement physical generation.
5. Either TLS connection closing, provider failure without retry/fake fallback,
   and independent USBmux CONTROL handling during iAP2 negotiation.
6. Three-byte plain write prefixes, preserved early encrypted input, invalid
   bind arguments, rejected used-service rebinding and stale callback labels.

The carkit fixture moved to [carkit_fixture.h](../tests/support/carkit_fixture.h)
for reuse. The first sanitizer run exposed a Windows test-stack overflow after
large local fixtures were combined by the compiler. The integrated test now
owns these fixtures with `std::unique_ptr`, keeping them off the test stack.
No production buffer limit, timeout, stack setting or sanitizer was weakened.

## Step 5 - Verify and record the actual scope

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

All 20 TLS-enabled CTest suites pass; the ordinary build still has 17.
All three hosted TLS/carkit/integration sanitizer suites pass, with the crypto
dependency instrumented too. The thirteen original protocol sanitizer suites,
seventeen-unit freestanding ARM check and 25 Python tests also pass. Changed C99
sources pass clang `-Wall -Wextra -Werror` syntax checks.

The bridge is 3,312 x64 bytes including its pump and 1,024-byte pending frame.
The carkit object is now 184 bytes after application-use tracking; the protected
client remains 312 bytes and each TLS context 7,984 bytes. Endpoint/caller
buffers and crypto heap are additional. Hosted integration is not part of the
freestanding ARM object claim, a measured QNX process or a hardware test.

## Step 6 - Continue with the separate session/network/media path

The pinned LIVI
[wired runtime](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/bin/livi-helperd/src/wired.rs)
(Git blob `bf2900569464e3fd99c3d62874ae749d30b4287a`) passes carkit into the
iAP2 session engine and maintains a separate USB-network interface for AV.
The integrated control exchange therefore does not replace USB-network access
or implement the projection server.

Next inspect/implement the bounded projection-session request path and actual
receiver identity/address/key provision, starting from the pinned
`cp/stack/rtspMessage.ts` and session stack. A fixture public key/address must
not become the default advertised receiver. Network/crypto session establishment,
video/audio/input delivery and native QNX integration still need implementation
and verification. Actual module identity, USB/network ownership, existing Apple
authentication-chip access and execution/recovery remain unresolved. No phone
trust records, head unit, firmware image or USB update were accessed or changed.

Follow-up: [projection-control.md](projection-control.md) now implements bounded
RTSP/HTTP framing and explicit request/response ownership. Actual identity,
pairing/control encryption, network listeners and media handlers remain separate.
