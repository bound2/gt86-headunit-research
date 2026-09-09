# Authenticated projection-control stream

Date: 2026-09-09. Continues [pair-verification.md](pair-verification.md) and
[projection-control.md](projection-control.md); progress Step 56.

## Step 1 - Establish what this step implements

The receiver now owns the known-controller pair-verification exchange, its
plaintext replies, the one-time transition to encryption, and subsequent
encrypted RTSP request/response framing. Cryptography is real; transport and
controller traffic in the tests are synthetic. This is not yet an installable
CarPlay update or a connection to the owner's iPhone.

New code:

- [control_cipher.h](../src/carplay/control_cipher.h) and
  [control_cipher.c](../src/carplay/control_cipher.c): bounded duplex records.
- [projection_control.h](../src/carplay/projection_control.h) and
  [projection_control.c](../src/carplay/projection_control.c): owning integration
  of fresh pair verification, RTSP and record-cipher state.
- [control_cipher_tests.cpp](../tests/control_cipher_tests.cpp),
  [projection_control_tests.cpp](../tests/projection_control_tests.cpp), public
  [control vectors](../tests/fixtures/control-cipher-vectors.txt) and an
  [independent checker](../scripts/check_control_vectors.py).

The modules join the optional `carplay_pairing` target. They do not add a TLS,
socket, heap, filesystem, default RNG or actual trust-store dependency. The
existing Monocypher 4.0.3 pins and license selection remain unchanged.

## Step 2 - Pin the wire evidence

The inspected LIVI tree remains commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`:

| Source | Git blob | Evidence used |
| --- | --- | --- |
| [controlCipher.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/controlCipher.ts) | `6d01411f191594dc60146e95756f496ba2e212b1` | LE16 length, authenticated header, directional counters and 16 KiB transmit chunks |
| [cpStack.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts) | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` | Serial requests; M4 reply remains plaintext; later control traffic uses derived keys |

The frame is a two-byte little-endian ciphertext length, ciphertext and a
16-byte Poly1305 tag. The length bytes are AEAD additional authenticated data.
Counters start at zero independently for each direction, advancing per record,
including an empty record. Nonces are four zero bytes followed by the eight-byte
little-endian counter, using the already inspected `crypto.ts` helper. These
are reference-derived protocol choices, not an Apple conformance certificate.

The adapter uses the existing fresh-context IETF ChaCha20-Poly1305 wrapper.
Monocypher documents the 12-byte-nonce IETF initializer, authenticated decryption
and its incremental context's rekeying behavior. We initialize a new context
for each independently numbered record; we do not use its incremental ratchet
as the protocol's counter scheme. Nonce uniqueness still belongs to the owner.
See the [official AEAD manual](https://monocypher.org/manual/aead).

Strict route matching, bounded receive size, terminal overflow, held-data
ownership, time limits and drain attestation below are local policies. In
particular, upstream accepts path suffixes; the local plaintext path must be
exactly `/pair-verify`. Compatibility with other path forms is untested.

## Step 3 - Implement bounded authenticated records

`control_cipher_init` validates configuration/storage transactionally and starts
dormant. The low-level `start` copies explicit directional keys once. This
primitive does not prove pairing: the projection owner is responsible for
their origin. There is no restart, automatic key generation or implicit rekey.

Caller-owned storage has three disjoint buffers: encrypted RX, authenticated
plaintext RX and encrypted TX. The configured payload limit is 1..16,384 bytes;
RX/TX each need limit+18 bytes and plaintext needs limit bytes. Only these
prefixes are owned. Encrypted receive and transmit queues are independent.

Receive handling proceeds step by step:

1. Accept at most one record, retaining a fragmented length header/body/tag.
2. Reject an oversized declaration as soon as both header bytes arrive.
3. Authenticate the complete record before exposing any plaintext.
4. Hold even an empty authenticated frame with its generation/counter key.
5. Retire plaintext prefixes explicitly, wiping the retired bytes. Only full
   retirement permits reception of the next record; unread wire remains outside.

An outgoing record is encrypted exactly once when queued. Partial writes only
retire the retained ciphertext prefix; they never re-encrypt or advance the
counter again. A pending output cannot be replaced with another record. Empty
plaintext still produces an 18-byte authenticated record.

Each counter can use `UINT64_MAX` once, then sets an exhausted flag. A subsequent
record closes both directions without wrapping to zero. This prevents local
nonce reuse; it does not establish a recommended production rekey interval or
prove target side-channel behavior. Callers cannot change the read-only fields
or reuse these keys in a new counter-zero stream.

Receive, plaintext hold and output budgets default to 10/5/5 seconds and allow
1..60,000 ms. Each is absolute from the applicable phase's beginning. Partial
traffic does not renew it. A standalone idle cipher has no timer; the enclosing
RTSP owner enforces connection idle time. Bad tags, oversized records, exhausted
counters, deadlines and EOF terminate and clear both keys and all owned buffer
prefixes. No resynchronization or fallback to plaintext occurs.

## Step 4 - Own the plaintext-to-encrypted boundary

`projection_control_init` creates all three children together, with the same
fresh, nonzero generation. It cannot attach an unrelated already-successful
pair-verification object to an arbitrary RTSP response. The children are private
to this owner by contract; callers must not invoke their APIs, reinitialize them,
copy the owner, mutate its fields, reenter it or use it concurrently.

The implemented startup path is deliberately limited to a provisioned identity
and a controller already recognized by the supplied read-only lookup:

```text
plaintext M1 request -> real pair verification -> plaintext M2 reply
  -> retire output -> explicitly attest downstream drain -> accept M3
  -> authenticate controller proof -> plaintext M4 reply
  -> retire output -> explicitly attest downstream drain
  -> take same-exchange keys once -> encrypted application requests/replies
```

Only plaintext `POST /pair-verify` with one
`Content-Type: application/pairing+tlv8` reaches the responder. The existing
RTSP/HTTP framing validation still applies. Wrong/ambiguous content type, wrong
method/path, malformed proof, unknown controller or failed provider closes;
there is no automatic success/error body for an unimplemented route. Initial
`/info`, first-time `/pair-setup` and `/auth-setup` remain unimplemented here.

Internal M2/M4 responses preserve the validated request's protocol/CSeq. They
are not exposed as application requests. Until explicit final M4 release, the
cipher remains dormant even if keys have been derived and all plaintext output
has been copied downstream. Bytes after the M3 request are not consumed. The
final release takes keys once, wipes the temporary exported copy and leaves the
pair responder detached. The owner retains the shared secret/controller ID for
future session-derived keys; it clears them on termination. There is no public
raw-key binding or "mark secure" API on this owner.

Output retirement is only acceptance by the caller's exclusive downstream
owner, not physical transmission or peer acceptance. `release` is the caller's
explicit attestation that this response has actually drained. Real transport
completion accounting must implement that contract later; these memory-only
modules cannot observe a socket or USB queue themselves.

## Step 5 - Keep encrypted requests and replies correlated

Once encrypted, one complete validated application request is held with its
RTSP generation/token. The application must explicitly construct a final
response or close. No GetInfo, SETUP, RECORD, TEARDOWN or media command is
automatically accepted. Tests use an explicit 501 response where no handler is
implemented; it is not a hard-coded universal acknowledgement.

An authenticated record may contain several RTSP messages, or a message may
span multiple records. The owner copies only the first request into RTSP
storage and retains the authenticated plaintext tail across its response.
After release, `feed(NULL,0)` processes that tail; feeding the unconsumed wire
also first processes an existing plaintext tail with wire-consumed count zero.
Each call processes at most one record and one RTSP message. A caller must
retain external tail bytes and honor held events, rather than assume that a
zero-consumption call means there was no internal progress.

Responses can span multiple encrypted records. Each `output` call creates at
most one record, and each partial consume retires only its current prefix.
All records retain the same enclosing RTSP request token. Calls are synchronous;
this token is not a transferable asynchronous transport-job completion token.
The whole response has one absolute RTSP output budget, including downstream
drain; creating another record does not renew it. Release is rejected while
any plaintext or ciphertext remains queued.

Wrong generations/tokens and decreasing clocks cannot mutate a newer lifetime
or advance its deadlines. Invalid response/count/capacity arguments also fail
transactionally. Valid timed calls check all applicable child deadlines before
progress. The timer-only check and minimum-next-delay helper support a future
event loop without treating a held request as a zero-delay polling event.

## Step 6 - Verify independently and under failure

Five record-test groups cover twelve public independent fixture values, every
split point of a sample frame, one-byte output retirement, duplex counters,
empty frames, maximum payload, nontrivial nonce byte order, every bit of every
byte of a sample frame, replay, swapped directions, every truncation/EOF,
oversized declarations, stale keys, transactional failure, deadline boundaries,
clearing and both counter-exhaustion directions. Counter-edge tests explicitly
fault-inject otherwise read-only counters; no production setter was added.

Five integration groups exercise actual pairing proofs and encryption, all
split points of an encrypted request, byte-fragmented handshake, retained wire
after M3, retained authenticated second requests, messages split across records,
multi-record binary responses, plaintext M4/drain gating, rejected routes and
proofs, unknown controllers, provider failure, stale tokens, invalid responses,
encrypted-channel plaintext rejection, unexpected responses, replay, EOF,
idle/partial-message/held-tail/output timeouts and whole-owner clearing.

The new checker reproduces every control fixture with PyCA's independent
ChaCha20-Poly1305 implementation, including a SHA-512 digest of a complete
16,384-byte-payload record. It reuses only the existing public deterministic
pairing inputs, not local C outputs. The same ignored, version-pinned host venv
is used; no new receiver dependency or production credentials are introduced.

Reproduction commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayCrypto.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_pair_vectors.py tests/fixtures/pair-verify-vectors.txt
./build/pair-reference/Scripts/python.exe -B scripts/check_control_vectors.py tests/fixtures/control-cipher-vectors.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

The combined build passes 25 CTest suites, standard build 19 and TLS-only 22.
Four pairing/control suites pass ASan/UBSan with Monocypher and all composed
modules instrumented. The 25 Python regressions and both independent vector
checkers pass. All fifteen existing protocol and three hosted TLS/carkit
sanitizer suites also pass, with both crypto dependencies instrumented.

The first ARM check detected `__aeabi_memcpy8` from copying the large initializer
struct. The copy now uses the existing explicit byte-copy style, removing that
new import without expanding the allowlist. A conservative MSVC uninitialized-
key warning was fixed with explicit zero initialization. A fixture transcription
error was corrected before validation. Final local source builds have no new
compiler warnings; the existing dependency CMake compatibility warning remains.

All nine optional crypto/control units compile and relocatable-link for ARM,
with the same four required runtime symbols as Step 55: `__aeabi_memclr8`,
`__aeabi_uidiv`, `__aeabi_uidivmod`, `__aeabi_uldivmod`. The separate twenty-unit
core still links import-free. Neither is a QNX executable or target execution
test. x64 cipher/owner sizes are 240/1,952 bytes, plus caller buffers and stack
temporaries. Fully sized maximum RTSP and record buffers plus owner total
198,596 bytes; smaller explicit capacities are supported. Target memory, stack,
timing, runtime helpers and CSPRNG suitability remain to be measured.

## Step 7 - Continue toward an actual receiver

Next implement first-time pair-setup with explicit enrollment authorization and
trust-commit ownership. Do not trust/save an unknown key merely because it
arrived over USB. Then integrate pre-session capability/auth routes and typed
session handlers with real listeners, endpoint identity and stream lifetimes.
The event connection, media-derived keys, screen/audio/input and native USB
network path still require implementation/integration. The carkit/iAP2 service
and this projection-control stream remain separate protocol paths.

Do not advertise test endpoints or fixture identities. Native head-unit
execution/recovery, installed-version matching, the actual Go-module identity
and usable Apple authentication-chip interface remain unresolved. No real
phone, trust record, head unit, firmware image or update USB was accessed or
changed. Passing these tests does not prove software-only CarPlay compatibility
on the owner's factory hardware.

Follow-up: [pair-setup.md](pair-setup.md), Step 57, now implements real first-time
pairing, explicit candidate approval/commit handling and an owning RTSP route
that transfers to this control owner after M6 drains. The actual durable store,
approval UI and common initial-route dispatcher remain work. The combined build
now passes 26 suites; counts above record Step 56.
