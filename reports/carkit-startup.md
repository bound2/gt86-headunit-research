# Protected Lockdown RPC and carkit stream startup

Date: 2026-09-09. Continues [the TLS implementation](lockdown-tls.md) and
[CarPlay progress](carplay-progress.md). Host-only implementation/testing;
no phone, trust record, car, update USB or firmware image was changed.

Follow-up: [carkit-iap2.md](carkit-iap2.md) connects this stream to the existing
iAP2 engine. It adds timer/drain helpers and application-use tracking; carkit is
now 184 x64 bytes. Counts/sizes below otherwise record the earlier startup step.

## Step 1 - Revalidate the reference and current starting point

The previous TLS step is committed/pushed as `aa418e1`. Its tests encrypted
service fixture bytes but did not own a protected RPC or open its returned port.

The locally pinned LIVI reference remains commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Its
[carkit.rs](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-wired/src/carkit.rs)
has Git blob `58bd611ffdc984d55eacb0bcf6f8128ed0c9b8bc`.
It starts `com.apple.carkit.service` on a protected Lockdown session, connects a
second USBmux stream to the returned port, optionally upgrades that stream to
TLS, and carries raw iAP2 bytes there. It does not add another plist length
prefix to iAP2. The existing record lookup, automatic pairing/re-pairing and
storage fallback are not adopted here; no upstream function bodies were copied.

## Step 2 - Own a complete protected request/response exchange

[lockdown_client.h](../src/carplay/lockdown_client.h) and
[lockdown_client.c](../src/carplay/lockdown_client.c) own a newly authenticated,
unused Lockdown TLS session. The TLS object now records whether any application
write was queued or plaintext read. A previously used session cannot be rebound
as a fresh framed client. Ownership is a caller contract, not a memory sandbox:
objects are noncopyable, read-only to callers, and accessed without concurrency.

Only explicit GetValue and StartService methods are supplied. There is no
opaque arbitrary-RPC method, second StartSession, Pair, record lookup or retry.
The caller supplies the label and disjoint request/response/parser buffers.
Request scratch is 5..4,096 bytes including the four-byte length prefix;
response storage is 5..65,540 bytes. Existing plist node/arena limits apply.

A request is encoded, copied into TLS-owned retry storage and assigned its
expected reply command/type. One exchange is outstanding at a time. Polling
performs one TLS/dispatcher poll and at most one exact-needed plaintext read
of 512 bytes, first filling the prefix and then only its declared body.
Zero/oversized frames, exhausted buffers, malformed plists, duplicate keys and
mismatched reply commands fail closed.

A decoded reply is held only after the complete request has been accepted by
TLS **and** its TCP-style data has physically drained and been acknowledged.
An early valid encrypted response does not waive outstanding request ACKs.
Each successful reply or explicit remote error receives a fresh nonzero token.
Views expire on exact-token release or closure; a wrong token is rejected before
accepting a clock value. The request's absolute exchange deadline and the
reply's absolute hold deadline each remain configurable within 1..60,000 ms.

Following plaintext bytes are not consumed as part of the owned response.
Known buffered unsolicited bytes cannot be reassigned to a newly queued RPC.
Errors retain only validated error metadata, not a usable port. No automatic
retry follows release. Timed methods check shared transport/TLS lifetimes;
an old owner cannot advance or cancel a replacement physical generation.

## Step 3 - Open the separate carkit stream with explicit policy

[carkit.h](../src/carplay/carkit.h) and [carkit.c](../src/carplay/carkit.c) retain
the protected client while owning the new service stream:

```text
explicit carkit_open
  -> protected StartService -> typed reply / held remote error
  -> validate port and service-TLS policy
  -> open second USBmux stream
  -> service TLS handshake if requested
  -> READY: raw iAP2 byte stream
```

`carkit_open` explicitly queues only `com.apple.carkit.service`. It performs no
physical backend I/O. The complete startup has an absolute 15-second default
budget, configurable within 1..60,000 ms, including waiting for a connection
slot, opening TCP and performing service TLS. The request, connection and TLS
layers also retain their own deadlines; progress does not renew those budgets.

The existing validator checks integer ports in 1..65,535 before narrowing.
Carkit additionally refuses 62078, preventing the returned service endpoint
from being treated as another Lockdown connection. Malformed or failed replies
never allocate a service connection. Valid remote errors remain inspectable
through the owned client's event API; the caller may close, not externally
release/retry the client while carkit owns it. The hold deadline still applies.

Service policy is explicit:

| Reply | REQUIRE_TLS (default) | ALLOW_PLAIN_IF_REPORTED |
| --- | --- | --- |
| `EnableServiceSSL=true` | Perform real service TLS | Perform real service TLS |
| false or absent | Fail before opening port | Open explicitly permitted plain stream |
| wrong type or invalid port | Fail | Fail |
| TLS handshake/certificate failure | Fail | Fail; never downgrade |

The service-TLS initializer accepts only a fresh non-Lockdown TCP stream with
no application sequence advance, incoming data or FIN. It does not fabricate
a SessionID or replay StartSession on the service port. It uses the same pinned
TLS 1.2/ECDHE/AES-GCM policy, CA verification and exact device-certificate pin
as the control session. Parsed host and device certificates must match the
retained Lockdown session before a service ClientHello is sent.

Credential buffers and the random-provider context are caller-owned and must
remain valid/unchanged through close. No credential files are read or saved.
The service TLS context owns its own parsed key/certificates, rather than
borrowing the control TLS context's internal allocations. This avoids dangling
crypto references when either stream fails. Pairing remains a separate task.

## Step 4 - Expose raw iAP2 without confusing copy and completion

READY is reported only after the second TCP connection is established and, if
requested, its separate cryptographic handshake succeeds. Writes before READY
return BUSY with zero accepted bytes. The stream API adds no plist envelope.

One write is at most 4,096 bytes. TLS copies the whole request into stable retry
storage or returns BUSY; explicitly plain mode may accept only a transport-sized
prefix. Read calls consume a prefix of the service's available bytes. Accepted
write bytes are not evidence of physical completion, a peer ACK or CarPlay
session success. Keep polling to progress both retained streams and deadlines.

Each carkit poll drives one protected-client poll and, when initialized, one
service-TLS poll: at most two physical reads/writes in total. Other dispatcher
streams and CONTROL inspection/release remain available. READY can take priority
over the CONTROL return value, so applications must still inspect/handle CONTROL.

Either stream's closure, protocol failure or expiry terminates the shared mux
once and frees both crypto contexts. Stale closure cannot cancel a new physical
generation. Plain EOF, TLS failure and retained Lockdown failure are propagated;
neither transport silently reconnects. Close remains an abort, not orderly
close_notify/StopSession, a per-stream reset scheduler or service shutdown RPC.

## Step 5 - Verify the integrated path and failures

The existing ephemeral certificate/TLS peer helpers moved to
[tls_fixture.h](../tests/support/tls_fixture.h), shared by the original TLS tests
and new [carkit_tests.cpp](../tests/carkit_tests.cpp). Credentials are still
generated in RAM with host entropy; no reusable private-key fixture is saved.

Seven new groups cover protected XML/binary requests/replies, one-byte TLS
records, tokens and command sequencing, early replies without request ACKs,
coalesced following frames, bad lengths/ports/types/commands/duplicate keys,
response/parser capacity, explicit service policy and remote errors, real dual
TLS and raw iAP2 round trips, absent/false SSL under explicit plain permission,
certificate mismatch without fallback, wrong selected pairing identity,
startup/exchange/hold deadlines, stale generations, rebind/configuration bounds,
and closure of either stream. Raw service data is compared byte-for-byte with
an encoded iAP2 frame, and the TLS test checks it is absent from raw ciphertext.

Verification commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

The TLS-enabled build now has 19 CTest suites; the ordinary build still has 17.
TLS sanitizer verification instruments both TLS/carkit suites, the adapter,
protocol dependencies and Mbed TLS. The thirteen original sanitizer suites,
seventeen-unit freestanding ARM check and 25 Python tests remain separate.
No new dependency or fixture format was introduced in this step.
All listed checks pass. The three hosted C99 sources also pass clang
`-Wall -Wextra -Werror` syntax checks. The optional hosted TLS/client/carkit
sources are not included in the freestanding ARM claim.

Measured x64 struct sizes: protected client 312 bytes, carkit owner 176 bytes,
TLS context 7,984 bytes each, plus caller buffers and crypto heap. The TLS size
changed from Step 51 when application-use tracking was added. The two-stream
test does not establish total heap/stack bounds, QNX compatibility, side-channel
hardening, correct real pairing certificates or acceptance by an actual iPhone.

## Step 6 - Continue toward the actual receiver

Next connect this carkit stream to the existing iAP2 transport/link/control
engine, including correct write-completion and cancellation accounting. Its
backend must not call copied TLS plaintext physically complete. Exercise real
iAP2 startup over this service, then connect the broader CarPlay session and
network/media paths. A raw frame round trip is not identification/authentication
or a working CarPlay session.

Native QNX USB/network ownership, an authorized pairing provider, existing
authentication-chip access, display/input/audio/media integration, exact Go
module identity and verified execution/recovery remain unresolved. No
installable software-only CarPlay update exists for the owner's head unit yet.
