# Initial receiver routing, enrollment policy and continuous ownership

Date: 2026-09-10. Progress Step 60; continues [mfi-sap.md](mfi-sap.md).

## Step 1 - State what now works

One hosted C99 receiver now accepts the initial pairing request, selects either
first-time enrollment or known-controller verification, and owns the connection
through encrypted MFi authentication. The application no longer has to choose
an enrollment versus verification object before reading the request or manually
transfer the objects after enrollment. This is implemented in
[projection_receiver.h](../src/carplay/projection_receiver.h) and
[projection_receiver.c](../src/carplay/projection_receiver.c), not just a plan.

Local permission to attempt enrollment and approval of the verified candidate
remain separate requirements. Tests run real SRP, Ed25519, X25519, encrypted
pairing/control and MFi response calculations with public fixture keys, a
memory-only trust-commit simulation and an opaque synthetic MFi provider.
No real phone, Apple credential, factory chip or vehicle was accessed.

This is not an installable update or a working media receiver. Capability
responses, session/resource handling, real endpoints and target integration
are still incomplete. Software-only CarPlay on the factory hardware remains
unproven.

## Step 2 - Separate reference evidence from local policy

The existing LIVI reference remains pinned at commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`; `cpStack.ts` is blob
`d7b7511321a9da61d63a3c23a8e34cdd5523d7b9`. Its per-connection dispatch includes
pair setup, pair verification and MFi authentication; it sends pair-verify M4
in plaintext before activating control encryption. Its broader route matching
and fallback replies are not adopted as an authorization policy here.
[Pinned connection handling and dispatch](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts).

This step adds no new cryptographic byte profile or dependency. It composes the
existing verified primitives and channel owners. Exact origin-form targets,
explicit local permission, separate candidate approval, stable public tokens,
bounded storage, deadline enforcement and no automatic success for unknown
commands are local implementation choices, not Apple conformance claims.

The selected initial routes are exactly `POST /pair-setup` and
`POST /pair-verify`, with one `Content-Type: application/pairing+tlv8`.
Absolute URIs, case-folded paths, suffix matching, query variants, other initial
commands and plaintext `/auth-setup` close the connection. This means an actual
phone requiring a different initial sequence, including capability discovery
before pairing, is not supported yet. No real-phone trace establishes that the
currently supported initial sequence is sufficient.

## Step 3 - Initialize one explicit owner without I/O

`projection_receiver_init` accepts explicit configuration, storage, identity,
RNG, trusted-controller lookup, MFi provider and two distinct nonzero generations.
A commit provider is required only when enrollment is enabled. Enrollment is
disabled by default; enabling it does not authorize an attempt or a candidate.
No identity is generated, default credential read, listener opened or provider
called by initialization.

The initializer validates all enabled children using temporary fresh objects,
then discards those validation-only objects without closing/wiping caller
buffers. They have not allocated cryptographic state or performed I/O. Invalid
initialization leaves the destination and supplied storage unchanged.

An independent first-request staging buffer must hold at least 64 bytes and
must not exceed the active request buffer capacity. All storage is disjoint
except the intentional sequential ownership of the active request/response
buffers. The initial parser borrows the response buffer but never writes a
response. It consumes exactly one complete request, without subsequent-message
read-ahead. Only a selected child receives that exact staged wire image; the
staging bytes are then cleared. No request is reconstructed from a partial view.

The owner and children are noncopyable and serial; external calls or mutations
on children are not allowed. The identity and provider bindings remain stable;
mutable provider contexts must remain alive until the receiver is closed.
This is not a concurrent listener, worker queue or platform credential service.

## Step 4 - Keep permission, verification and commit distinct

For a known-controller first request, the receiver starts fresh pair verification.
It does not authorize enrollment when lookup later fails, change modes after
failure, retry a failed exchange or accept plaintext MFi authentication.

For first-time setup, enrollment must be explicitly enabled. The application
may grant a nonzero local audit/authorization ID before the initial request or
after receiving `PROJECTION_RECEIVER_AUTHORIZE`. In the latter case the complete
initial request is held without RNG, lookup, commit or MFi-provider calls.
Repeated input consumes no further wire while permission is pending. Denial
uses explicit close; permission cannot be supplied by the wire or renewed by
calling authorize again.

Once locally authorized, actual SRP setup proceeds. Verified M5 produces
`PAIR_SETUP_APPROVAL` and an immutable candidate containing the controller's
identifier and public key. `projection_receiver_pending` exposes that candidate
with the public lifetime token. `projection_receiver_decide` must explicitly
approve it before the commit callback can run. An authorization ID alone never
skips this second decision.

Commit denial/failure suppresses M6 and terminates the receiver. A provider must
still satisfy the durable/uncertain-write contract from [pair-store.md](pair-store.md);
the router cannot turn a failed store acknowledgement into success or roll back
a physically uncertain write. The new tests simulate this interface in memory;
Step 58's actual Windows store is tested separately, not presented as a QNX store.

## Step 5 - Preserve one public connection lifetime across child transfers

The caller reserves a stable connection generation and a separate verification
generation. Every public feed/check/output/consume/release call continues to
use the connection generation. Enrollment commit sees that generation; the
internal verification/MFi owner uses the separately reserved generation.
Neither generation may be reused for a replacement owner.

Public response tokens increase across both children, rather than restarting
when verification replaces enrollment. For the tested enrollment transcript:

| Enclosing response | Public key | Internal child key |
| --- | --- | --- |
| Setup M2 | generation 91, token 1 | generation 91, token 1 |
| Setup M4 | generation 91, token 2 | generation 91, token 2 |
| Setup M6 | generation 91, token 3 | generation 91, token 3 |
| Verify M2 | generation 91, token 4 | generation 92, token 1 |
| Verify M4 | generation 91, token 5 | generation 92, token 2 |
| Encrypted MFi reply | generation 91, token 6 | generation 92, token 3 |

The values above are public test generations, not production allocation defaults.
Token zero is invalid; exhaustion closes without wrapping or accepting another
request. Callers use only public keys. A late setup callback cannot retire a
new verification response even when the internal child token starts at one.
Wrong keys/counts and premature drain calls do not advance time or retire bytes.

Partial output consumption still acknowledges only bytes accepted by the
exclusive downstream owner. Actual downstream drain must be attested separately.
On final committed-M6 drain, the router atomically invokes the existing owned
handoff, reuses the emptied active buffers, detaches setup and creates fresh
verification/MFi state. It returns `PAIR_SETUP_COMPLETE`, not secure control.
Unconsumed following wire remains with the caller throughout this transition.

Only pair-verify M4 drain activates encryption. Later encrypted records,
authenticated plaintext tails and MFi output/drain gates use the existing
`projection_auth` owner. `MFI_SAP_DRAINED` still means local reply drained,
not iPhone acceptance, MFi licensing or running CarPlay media. Closing after an
acknowledged commit preserves its audit flag and does not delete stored trust.

## Step 6 - Bound waiting and verify failure paths

The initial idle budget defaults to 30 seconds; once the first byte arrives,
the absolute receive budget is 10 seconds. Local authorization of a held first
request has a separate 30-second budget. Fragmentation and repeated authorization
cannot renew these phases. Setup/verification budgets start when their fresh
owner is selected or transferred. Subsequent candidate, output, encrypted-record
and MFi deadlines remain those of the existing children.

`projection_receiver_next_delay` reports the currently active child's minimum
applicable delay. There is no hidden timer or busy polling. Applications must
supply monotonic time and bound synchronous provider work. No admission-rate
limiter, cross-connection permission manager, approval UI or worker scheduler
has been added.

[projection_receiver_tests.cpp](../tests/projection_receiver_tests.cpp) adds
seven groups covering:

1. Every two-piece split of the initial verify request; byte-fragmented real
   verification, encrypted MFi, retained next-request tail and explicit 501 reply.
2. Both preauthorized and deferred-authorized enrollment, verified candidate
   approval, commit/M6 drain, automatic same-connection transfer, real verification
   and encrypted MFi, with stale pre-transfer callbacks rejected.
3. Disabled enrollment, waiting without provider calls, denial, simulated
   uncertain commit, unknown controller, RNG failure and MFi provider failure.
4. Wrong initial method/route/type, duplicate framing/type headers, response
   instead of request, unsupported URI variants, malformed first message and
   attempted mode switching after selection.
5. Exact initial idle/receive/permission deadlines, nonrenewal, decreasing time,
   near-`UINT64_MAX` time and EOF.
6. Transactional invalid initialization, wrong generation/key/count/decision,
   premature release, clearing and repeated close.
7. Deliberate test-only token exhaustion, lost final MFi drain and expired M6
   drain after commit, preserving the commit audit but never starting verification.

Commands used:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py -v
./build/pair-reference/Scripts/python.exe -B scripts/check_mfi_sap_vectors.py tests/fixtures/mfi-sap-vectors.txt
./build/pair-reference/Scripts/python.exe -B scripts/check_setup_vectors.py tests/fixtures/pair-setup-vectors.txt
```

All 31 combined, 19 ordinary and 22 TLS-only CTest suites and 25 Python regressions
pass. The seven hosted TLS/carkit/enrollment/file/MFi/router suites pass ASan/UBSan
with both crypto dependencies instrumented. Latest split-test additions were
rebuilt and rerun against the instrumented objects. Strict Clang C99/C++ warnings
pass; Clang static analysis reports no finding in the new C99 module. The existing
five pairing/control/store sanitizer suites and ten-unit optional ARM relocatable
check also pass with the same four allowed runtime helpers. The existing
39-value MFi/pairing and 51-value setup checkers reproduce their public vectors.
An initially mistyped setup-checker filename was corrected; the command above
is the successfully executed existing checker, not a newly invented script.

The new `carplay_receiver` target links hosted enrollment/MFi dependencies. Its
owner occupies 9,632 bytes on x64, plus caller buffers, stack temporaries and
dependency allocations. It is not part of the earlier twenty-unit import-free
ARM core or ten-unit optional ARM crypto claim. Nothing here proves a linked
QNX receiver, target memory/timing suitability or actual phone interoperability.

## Step 7 - Continue with capabilities and session resources

Next implement capability response encoding and route handling tied to explicitly
available display/audio/input resources. Resolve required pre-pairing discovery
routes and acceptable target forms from evidence rather than inventing broad
success replies. Follow with typed session/resource negotiation, real network
endpoints and actual media/input integration. Enrollment approval/rate limiting,
target persistence/revocation and safe provider scheduling remain necessary.

Actual Go-module identity, installed-version execution/recovery, native USB-network
ownership and access to a compatible existing Apple authentication chip remain
unresolved. No firmware image, update USB, real trust record or vehicle state
was changed. These host-side results are not a vehicle installation procedure.
