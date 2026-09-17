# Step 94 - Bind encrypted iAP input to session-owned TCP

Date: 2026-09-17. Continues [Step 93's input owner](projection-iap-stream.md).
Starting checkpoint: `3fffd36f402c6ab666c9613c66d845ccf8d93829`.

Follow-up: [Step 95](iap-stream-profile.md) traces the helper consumer and
corrects the route interpretation: wireless tunnel bytes are iAP2 link frames
for a separately owned session; active matching wired carkit blocks that tunnel.
The next-step suggestions below are historical, not permission to feed these
bytes into an existing wired application or a plain CSM parser.

## Result and boundary

The type-130 session resource now has an actual Windows TCP provider, owning its
listener, one peer connection, authenticated input and explicit application-relay
lease. Receiver SETUP/RECORD/TEARDOWN, other-media delegation and encrypted event
return traffic are exercised over real loopback sockets. This is implementation
of a missing transport boundary, not a working factory CarPlay installation.

The application relay and MFi certificate/signature providers in these tests are
synthetic. There is no default relay, automatic capability advertisement, new USB
link or new authentication exchange. No phone, car, service menu or update USB was
used. The implementation is Windows-only; it is not a QNX executable or driver.

## 1. Recheck source and lifecycle evidence

The ignored, clean LIVI checkout remains at
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. The two implementation blobs were
rechecked: `stack/iapTunnel.ts` is
`8f60416ff09170c5f8809cbad29372685714f0e9`; `stack/cpStack.ts` is
`d7b7511321a9da61d63a3c23a8e34cdd5523d7b9`. Full paths, framing and test-blob pins
are in [Step 93](projection-iap-stream.md#1-follow-the-references-actual-receive-and-return-paths).

The pinned [session integration](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts)
registers a receive callback that forwards tunnel bodies to `session.iapRelay`
if present. Important qualification: `_openIapMessageRelay` is called by its
RECORD handler, not the tunnel SETUP handler. A callback without a RECORD check
does **not** establish that the reference delivers to a live application before
RECORD. The helper connection receives a `tunnel` header with controller identity
and optional Bluetooth address; helper output becomes an event-channel
`iAPSendMessage`. Incoming event commands can also supply data to that relay.
These observations come from the immutable local source, not handset captures.

The new adapter's explicit successful relay `open` means a caller has prepared
the correct application route. It permits incoming control delivery/poll before
provider `start`; this is a **local contract**, not inferred phone behavior or a
claim to reproduce the reference's relay-creation timing. The callback may return
MORE without accepting bytes while its application is not ready, within the
existing hold budget. A real binding still must resolve readiness, identity,
message boundaries and handoff to the existing iAP lifecycle. No reset is implied.

Reverse commands keep the existing event owner's start gate. The test verifies
that output is busy before RECORD and succeeds after the encrypted RECORD reply
drains. Incoming transport bytes and permission to originate commands are
separate states.

## 2. Implement the session provider and explicit relay

[projection_iap_services.h](../src/carplay/projection_iap_services.h) exposes a C
interface; [the Windows implementation](../src/carplay/projection_iap_services_win.cpp)
owns all allocation and sockets. The composition is:

```text
receiver/session -> root timing + encrypted event services
                    -> iAP media provider -> type-130 TCP -> input -> explicit relay
                                          -> optional video/audio delegate
application output -> command encoder -> existing encrypted event owner
```

1. Creation validates explicit local/peer addresses, feature bit, stream ID,
   callbacks and limits, without opening sockets or invoking the clock.
2. SETUP binds the relay, initializes input with the session-derived read key and
   opens an exclusive, nonblocking ephemeral listener on the explicit local IP.
   No wildcard, DNS, inherited socket handle or `SO_REUSEADDR` is used. Microsoft's
   [exclusive-address documentation](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse)
   supplies the Windows option's binding semantics; this is not authentication.
3. Only the configured peer address is accepted. Wrong peers cannot extend the
   original accept deadline. After acceptance the listener is explicitly closed:
   Winsock `accept` creates a connected socket but leaves the original listener
   open unless the caller closes it. [Microsoft accept contract](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept).
4. Every delivered body still requires valid record AEAD. There is no reconnect
   or counter reset under the same key. Existing session seed-reuse tracking owns
   replacement-key epochs, not the socket adapter.
5. Relay receive borrows the authenticated header/body only during the callback.
   OK accepts a positive prefix, or zero for an empty body; MORE accepts nothing.
   Partial acceptance preserves the token and original hold deadline. Retained
   copies must be bounded and retired by the binding. Acceptance is not a phone
   ACK and a transport package is not assumed to be one iAP message.
6. Each outer lease is unique. Delegated leases are translated for start, close,
   polling and audio-only playback/FLUSH. The delegate's root-clock callback is
   not used. There is no new media playback gate in the iAP input owner.
7. Fatal input, callback or delegate failure closes all owned/delegated leases
   exactly once, retires buffers/keys and returns terminal state. The enclosing
   receiver must then close its root event/timing/control resources. Partial
   TEARDOWN closes the selected resource without silently closing other media.

Any nonzero child returned by relay open transfers cleanup responsibility even
on failure. Callbacks are synchronous, serial, non-reentrant and must not throw
or retain borrowed pointers. There is no output/write API for the type-130 socket.

## 3. Bound work, storage and deadlines

The service owns a 16 KiB network staging buffer plus the Step 93 input owner's
configured storage: `3 * record_payload_limit + 36 + package_limit` bytes.
The package bound remains 32 bytes through 4 MiB, including its header. Normal
tests select 256 KiB; the independent TCP test explicitly selects the 4 MiB bound.

A poll performs at most one relay poll, one held-prefix delivery, one accept,
one socket read and one input feed, plus one delegate poll. Cipher-owned plaintext
is drained even when the socket has no new data. Network tails remain owned and
keep their original receive budget; partial package/body progress does not renew
child deadlines. Clock checks also follow callbacks, but cannot preempt a callback
that blocks. There is no claim of a hard wall-time callback bound.

Clean EOF between packages reports END. EOF with an incomplete cipher record or
package reports INVALID. Both terminate the service; already authenticated input
can be delivered before `recv` observes an EOF pending in the kernel. There is no
invented ability to detect remote closure before the socket API reports it.

Copy-only status exposes counts for retained network/cipher/plain/package/body
bytes and connected/held/started flags for a live lease. It exposes no payload or
key and performs no I/O, clock callback, deadline renewal or readiness attestation.

## 4. Exercise real sockets and independent encrypted input

[The new test executable](../tests/projection_iap_services_tests.cpp) has seven
groups (IPv4 and IPv6 transport counted separately), plus a C translation-unit
ABI check:

- Configuration/argument rejection, side-effect-free creation/status and exact
  lease cleanup, including failed opens that return a child.
- Real IPv4/IPv6 TCP, wrong-peer rejection, OS-observed listener closure,
  fragmentation, coalesced/unknown/empty packages, a 70,001-byte body and replay.
- Observed-state deadline boundaries, backward time, clean/truncated EOF,
  retained network tails, partial acceptance, busy/invalid/failing callbacks.
- Audio delegate start/poll/playback/FLUSH and fatal cleanup/partial teardown.
- Actual encrypted audio UDP reception while the iAP relay is busy; the final
  PCM sink is synthetic, not a measured sound device.
- Four receiver scenarios: known-controller verification, encrypted MFi route
  with synthetic credentials, real timing/event/iAP sockets, RECORD reply-drain,
  encrypted return command and correlated reply, bad-tag propagation, partial
  TEARDOWN, rejected reused seed and fresh-key replacement.

The return-path scenario supplies explicit synthetic application output; it does
not claim that the relay produced a valid real iAP application reply. Three new
public synthetic SETUP/TEARDOWN fixtures were generated with Python `plistlib`
binary encoding, not captured from an owner's phone.

Two test timing assumptions were corrected during development. An initial test
assumed the first poll accepted the intended peer despite a wrong peer being
queued first. Repeated runs then exposed fake-clock advancement before partial
network input had actually arrived. Tests now wait for authoritative listener
or copy-only receive state before asserting or advancing the fake clock. These
were harness assumptions, not demonstrated production deadline defects.

The [independent PyCA checker](../scripts/check_projection_iap.py), using the
existing `cryptography==50.0.1` environment, now runs against both the memory
owner and this real TCP service. For **each executable**, six independently
encrypted wire cases reproduce **4,523,217 body bytes** exactly. Three tamper
cases and three new truncated-record/package cases exit unsuccessfully without
exposing a body. TCP stdin mode interleaves bounded sends and receiver polls;
it does not assume that an entire large wire stream fits kernel buffers.

Final results:

| Check | Observed result |
| --- | --- |
| Complete optional-video Release build/CTest | 50/50 suites passed |
| Python unittest discovery | 88 tests passed |
| Repeated new iAP service CTest | 20 consecutive passes |
| Expanded video/iAP ASan/UBSan run | 10/10 suites passed |
| Independent memory-input and TCP checks | Both passed all six valid, three tamper and three truncation cases |

The expanded sanitizer script instruments local adapters/tests, Mbed TLS,
Monocypher and generic OpenH264; Windows system DLLs remain outside instrumentation.
It reuses existing prepared dependencies. As previously documented, verification
of an archive does not independently rehash an already extracted dependency tree.
The earlier separate C99 ARM check remains historical evidence for that subset;
this Windows service is not added to its ARM/QNX claims.

## 5. Reproduce and continue toward the actual unit

```powershell
cmake --build build/video --config Release -- /verbosity:quiet
ctest --test-dir build/video -C Release --output-on-failure
ctest --test-dir build/video -C Release -R '^projection_iap_services_tests$' --repeat until-fail:20 --output-on-failure
python -B -m unittest discover -s tests -p 'test_*.py'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayVideoSanitizers.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_iap.py build/video/Release/projection_iap_services_tests.exe
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_iap.py build/video/Release/projection_iap_tests.exe
git diff --check
```

The existing `Build-CarPlayVideo.ps1` prepares the optional dependency-backed
configuration on a fresh checkout. `carplay_iap_services` is a Windows-only CMake
target using existing session/crypto libraries, not a new downloaded dependency.

Next, trace the pinned helper's `tunnel` consumer and implement the correct owned
application/message handoff, including controller identity, readiness around
RECORD, bounded output and the alternate incoming event-command route. Do not
feed arbitrary DataStream bytes to a fresh reliable-link/authentication engine.
The current callback interface is not that missing live binding.

The [factory integration gates](factory-integration-gates.md) still require
installed-version execution/recovery, matching QNX runtime/ABI, coordinated
USB/MFi ownership, factory display/input/audio/microphone and actual phone/unit
acceptance. Exact navigation-module part/revision and the installed 6.9.0WL image
remain unknown/unavailable here. The later offline corpus and host loopback
results cannot prove those requirements. No installable update was produced.
