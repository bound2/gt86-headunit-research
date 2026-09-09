# First-time pairing and enrollment ownership

Date: 2026-09-09. Progress Step 57; continues
[encrypted-control.md](encrypted-control.md).

## Step 1 - Establish the new result and its limits

First-time pair-setup now has real SRP-6a, authenticated Ed25519 identity
exchange, explicit enrollment permission, candidate approval, a trust-commit
contract and an owning plaintext RTSP route. After the committed final reply
drains, ownership can transfer to a fresh pair-verification/control receiver
without discarding following wire bytes. Tests also prove that the newly
enrolled synthetic controller can reach encrypted request/response handling.

This is receiver implementation, not an installable head-unit update. Tests use
public deterministic keys and a synthetic in-memory provider that models a
successful durable commit. Step 57 did not create an actual durable trust store
or approval UI. [Step 58](pair-store.md) adds a real Windows store and file-based
integration; no real phone or existing trust record was accessed in either step.

New files:

- [pair_srp.h](../src/carplay/pair_srp.h) /
  [pair_srp.c](../src/carplay/pair_srp.c): one-shot SRP arithmetic adapter.
- [pair_setup.h](../src/carplay/pair_setup.h) /
  [pair_setup.c](../src/carplay/pair_setup.c): M1-M6 exchange and approval/commit.
- [pair_setup_channel.h](../src/carplay/pair_setup_channel.h) /
  [pair_setup_channel.c](../src/carplay/pair_setup_channel.c): owning enrollment
  route and explicit transfer to `projection_control`.
- [pair_setup_tests.cpp](../tests/pair_setup_tests.cpp),
  [public fixture](../tests/fixtures/pair-setup-vectors.txt) and
  [independent checker](../scripts/check_setup_vectors.py).

## Step 2 - Pin the evidence and resolve byte conventions explicitly

The main CarPlay reference remains LIVI commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`:

| Source | Git blob | Role |
| --- | --- | --- |
| [srp.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/srp.ts) | `0a198ac52c23b0e90b382a1a5f52594f566bbd43` | SRP group, hashes and integer serialization |
| [pairSetup.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/pairSetup.ts) | `5ec82d52770cb6bc7dd60d79e0c4180f9aeaeb5c` | Fixed code, M1-M6 fields and signed/encrypted identity exchange |
| [pairings.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/pairings.ts) | `b93a23d76719685e3aa2bca9f6d6a40b84ba0836` | Controller-ID/public-key storage relationship |

The selected profile uses the RFC 5054 3072-bit group with generator 5, SHA-512,
username `Pair-Setup`, compatibility code `3939`, salt16 and server secret32.
The modulus/generator were cross-checked with
[RFC 5054 Appendix A](https://www.rfc-editor.org/rfc/rfc5054#appendix-A).
This is not the RFC's TLS-SRP cipher-suite implementation or its SHA-1 example.

SRP derives `x` from salt and the username/password hash, verifier `v=g^x`,
multiplier `k=H(N || PAD(g))`, public `B=(k*v+g^b) mod N`, scrambling
`u=H(PAD(A)||PAD(B))`, and shared `S=(A*v^u)^b mod N`. The session key hashes
minimal unsigned big-endian S. In this selected LIVI profile, the client proof
hashes `H(N) XOR H(g)`, `H(username)`, salt, padded A, padded B and K; the server
proof hashes padded A, client proof and K. PAD is exactly 384 bytes.

A cross-check found a real serialization difference: Music Assistant's
[AirPlay client at bdee878e18fe6e859830ed20499fc87497ae53a1](https://github.com/music-assistant/airplay-cli/blob/bdee878e18fe6e859830ed20499fc87497ae53a1/src/ap2_hap.c)
hashes minimal A/B in proofs, while also padding k/u inputs. We retain the
explicit pinned CarPlay reference profile, not a guessed automatic fallback.
Leading-zero A, B and S fixtures exercise the choice. Interoperability with an
actual iPhone at these edges is still unverified; neither a matching local
transcript nor the other project's real-device claim resolves that here.
No permissive signature-failure behavior from that cross-check source is used.

## Step 3 - Use real arithmetic without claiming a target crypto port

The new optional `carplay_enrollment` target requires both existing prepared
dependencies: Monocypher 4.0.3 for SHA-512/HKDF/Ed25519/AEAD, and Mbed TLS 3.6.7
for MPI arithmetic. It links `mbedcrypto`, not a new TLS protocol or SRP library.
Dependency versions, archive pins and selected licenses are unchanged; see
[third-party notices](../third_party/README.md).

The inspected Mbed TLS
[bignum source](https://github.com/Mbed-TLS/mbedtls/blob/068ff080b369adfac81509f9b57b2afabaf82dc5/library/bignum.c)
routes the public `mbedtls_mpi_exp_mod` API through its secret-exponent core,
and frees/zeroizes arithmetic temporaries. We do not call the public-exponent
unsafe variant. `bignum.c`, `bignum_core.c`, `bignum_core.h` and `bignum.h` in the
prepared tree matched the pinned tag after UTF-8 decoding and line-ending
normalization. An initial apparent mismatch was PowerShell's default decoding
of an accented comment; no dependency source was changed.

The existing Mbed preparation script verifies its archive, but does not
revalidate every existing extracted source on each invocation. The four-file
comparison above is a read-only check for this step, not a new full-tree
verification mechanism. Monocypher retains its existing used-file checks.

This adapter is not a constant-time or target side-channel proof. MPI uses
heap allocations, and conversions/comparisons plus the complete integration
still need target review. RNG callbacks must provide fresh CSPRNG bytes; tests
intentionally do not. No QNX runtime, allocator, stack sizing or secure entropy
provider was supplied. The new enrollment target is not included in the
import-free ARM claim or the separate nine-unit pairing portability object.

SRP state retains only fixed-size byte arrays between calls. Start requests
salt16 then secret32 from the supplied RNG, rejects a zero secret and never
retries silently. Verification requires a 384-byte A and 64-byte proof. It
rejects A outside 2..N-2, zero u, and degenerate shared base/secret. Proof
comparison uses the existing constant-time 64-byte comparator. A verification
attempt consumes the server on success or failure, wipes retained arithmetic
secrets and exposes K/server proof only on success. Public argument/state errors
are transactional. These checks are local policies in addition to the reference.

## Step 4 - Separate proof, authorization and durable trust

The compatibility code is public. Proving knowledge of it cannot identify the
owner's intended phone. The implemented sequence therefore has two explicit
local authorization boundaries:

```text
local enrollment permission (one attempt, fresh generation/audit ID)
  -> M1/M2 SRP challenge -> drained reply
  -> M3/M4 real SRP proof -> drained reply
  -> authenticated M5 controller identifier/public key/signature
  -> candidate held for explicit local approval
  -> atomic durable insert-or-confirm callback succeeds
  -> M6 signed/encrypted accessory identity reply -> drained reply
  -> separate pair verification -> encrypted control
```

`pair_setup_init` starts disabled and invokes no provider. `authorize` requires
a nonzero caller-issued audit ID representing genuine user/administrative
permission, not USB presence or a wire field. It enables one attempt and cannot
reopen failed/completed state. The library does not implement the UI or prove
the provenance of a caller-supplied authorization ID; the future frontend must.

M1 supports method0, state1 and absent/zero flags. Transient enrollment and
MFi-method variants are rejected. M3 checks SRP public/proof lengths and actual
proof. M5 decrypts with `PS-Msg05`, validates unique TLV dictionary fields,
requires a printable ASCII identifier of 1..64 bytes and a 32-byte public key,
and verifies the 64-byte Ed25519 signature bound to the setup session.
HKDF labels and the `PS-Msg06` reply follow the pinned setup source.

The resulting candidate is held with a generation/token. No M6 response is
available through the API at this point. Explicit denial closes without a
storage call. Approval calls the supplied commit provider exactly once. Its
contract is acknowledged durable insertion, or confirmation that the exact same
ID/key is already durably stored. It must refuse replacement of a different key
under the same ID. Step 58 corrects the earlier blanket no-change-on-failure
requirement: validation/conflict failures leave storage unchanged, but physical
I/O can be indeterminate. All failures close without M6 success; no fallback,
silent overwrite, rollback or retry is implemented. See [pair-store.md](pair-store.md).

The provider owns filesystem format, locking, permissions, flush/durability and
synchronous execution policy. The original tests model this contract with a map;
Step 58 adds a real Windows backend and file/enrollment integration. OS disk I/O
has no hard latency bound and must be isolated from real-time work. A trusted
callback's false success would violate the integration contract and cannot be
detected by the cryptographic state machine.

Commit precedes the final reply. If the connection subsequently fails, an
authorized committed entry is not automatically deleted. The `committed`
audit flag survives close, but does not assert that the peer received M6. False
after an indeterminate provider error does not prove that no bytes reached disk.
Repeated enrollment must be independently authorized and may confirm only the
same mapping. Complete setup does not expose control keys or mark a stream
secure; pair verification remains mandatory.

## Step 5 - Own the RTSP route and transfer without losing bytes

`pair_setup_channel` initializes fresh setup/RTSP children and holds the
immutable identity/providers. It consumes no wire before local authorization.
Its explicit enrollment mode accepts only `POST /pair-setup` with one expected
content type, using the existing strict RTSP/HTTP parser. It is not yet a common
first-request dispatcher for enrollment, reconnect and capability routes.

Each accepted request produces a correlated plaintext reply or a held approval
event. Repeated header names, unsupported paths, invalid proofs and provider
failures cannot become automatic success. Partial output retirement preserves
the response token; receiving stays paused through approval, output and drain.
Following wire bytes remain with the caller, including pair-verify bytes
coalesced after M5. Copying the reply downstream is not physical completion.
`release` is an explicit whole-response downstream-drain attestation.

After committed M6 is released, `take` validates a fresh `projection_control`
destination/configuration, requires a new nonzero generation different from
enrollment's generation and the final enrollment token, then detaches the source.
It can transfer the cleared RX/TX buffers. Old-owner close/check/take operations
cannot clear data subsequently held by the new owner. No peer data is consumed
by transfer, and the new control owner starts in pair verification, not encrypted
state. Invalid handoff arguments leave source/destination unchanged; expired
valid operations still close as required by the deadline policy.

Exchange budget defaults to 60 seconds from initialization, response holds to
10 seconds and approval to 30 seconds. The enrollment RTSP reply/output defaults
are 30/10 seconds; idle/receive retain 30/10 seconds. Each configurable value is
1..60,000 ms and the earliest applicable deadline wins. Fragmentation, polling
and output retirement never renew a phase. The drained handoff has the RTSP
idle budget. There is no background timer, hidden socket operation or restart.
Caller callbacks cannot be preempted by this synchronous API; their boundedness
must be enforced by integration. Global enrollment/rate-limit policy is still
a frontend responsibility, not supplied by a per-connection timer.

## Step 6 - Verify complete transcripts and failure behavior

The 51 public fixture values are independently generated using Python integer
arithmetic for both SRP client and server formulas, checked for agreement, plus
PyCA for the Ed25519/AEAD/HKDF exchange. They include all M1-M6 bodies, prior
pair-verify inputs and leading-zero A/B/S cases. The tiny edge-case client
exponents are explicitly test-only. No output from the local C implementation
is used to calculate expected values.

Nine C++ groups cover normal/edge SRP agreement, all-zero/one/N-1/N/N+1 client
public values, every-byte SRP-proof corruption, RNG failure/zero secret,
malformed/duplicate/separator TLV fields, unsupported methods/flags, encrypted
tag/signature/public-key/identifier failures, authorization and approval denial,
store failure/collision/idempotence, stale tokens/generations/clocks, absolute
deadlines, response clearing and committed-but-undrained failure. They also
exercise fragmented owning RTSP enrollment, retained next-request wire,
transactional handoff validation, same-buffer ownership transfer, inert stale
owner teardown and a newly enrolled controller's real encrypted control exchange.

Commands used:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayCrypto.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_setup_vectors.py tests/fixtures/pair-setup-vectors.txt
./build/pair-reference/Scripts/python.exe -B scripts/check_pair_vectors.py tests/fixtures/pair-verify-vectors.txt
./build/pair-reference/Scripts/python.exe -B scripts/check_control_vectors.py tests/fixtures/control-cipher-vectors.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

All 26 combined CTest suites, 19 standard suites and 22 TLS-only suites pass.
The enrollment suite and three existing TLS/carkit suites pass ASan/UBSan with
Mbed TLS, Monocypher and the composed modules instrumented. All four existing
pairing/control sanitizer suites pass, as do the 25 Python regressions and
all three independent vector checkers. The new C99 modules pass Clang's
`-Wall -Wextra -Wpedantic -Werror` syntax check. No new compiler warning was
introduced; the existing dependency CMake compatibility warning remains.

The existing twenty-unit core and nine-unit optional crypto ARM checks remain
unchanged and pass with their documented import limits. New x64 object sizes
are SRP824, setup2144, candidate104 and enrollment channel2392 bytes; MPI heap,
caller RTSP buffers and stack temporaries are additional. None is evidence of
head-unit memory/timing suitability or a linked/executed QNX enrollment process.

## Step 7 - Continue toward usable CarPlay

Step 58 now implements a portable snapshot and actual explicit Windows identity/
controller store, with strict journal/flush behavior and corruption/conflict/
interruption tests. See [the persistence follow-up](pair-store.md); target QNX
storage, revocation/recovery policy and provisioning remain separate. Step 59
adds [encrypted MFiSAP](mfi-sap.md) and `pair_setup_channel_take_auth`, transferring
this owner after M6 drain into fresh verification/encrypted authentication on the
same transport. Real chip access is not supplied. Next connect enrollment policy/
first-request mode selection, capability declarations, typed session handlers
and real endpoints. Native USB networking, video/audio/input and target execution/
recovery still require implementation or verification.

Actual Go-module identity, installed-version compatibility, authentication-chip
access and a safe recovery path remain unresolved. No real trust record, phone,
head unit, firmware image or update USB was read or changed by this step. This
does not establish software-only CarPlay running on the factory hardware.
