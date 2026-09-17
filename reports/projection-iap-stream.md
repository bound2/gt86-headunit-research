# Step 93 - Receive encrypted iAP DataStream packages

Date: 2026-09-17. Continues the [clock/configuration review](projection-video-clock.md)
and [session resource owner](projection-session.md).

## Result and scope

The receiver now has a bounded, receive-only C99 input layer for the iAP
DataStream selected by session type 130. It decrypts real ChaCha20-Poly1305
records, assembles authenticated transport packages across arbitrary record
boundaries and retains iAP bytes until an explicit consumer accepts them.

This fills a missing protocol component, not the complete integration. The
existing session layer already recognizes this type and derives its key, but
there is still no session-bound iAP socket provider or live application relay.
No new feature is advertised automatically. No USB/Bluetooth connection, factory
authentication provider, phone pairing or vehicle execution occurred.

## 1. Follow the reference's actual receive and return paths

The existing LIVI checkout remains at
`a76553fc941dcf378dd55c04da56aaf3d6911e08`, with a clean worktree at review.
Reviewed immutable Git blobs:

| Source | Git blob SHA1 |
| --- | --- |
| `stack/iapTunnel.ts` | `8f60416ff09170c5f8809cbad29372685714f0e9` |
| `stack/__tests__/iapTunnel.test.ts` | `7efbdb150f066e9216b69f2220bf82002eacccbd` |
| `stack/cpStack.ts` | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` |

The [tunnel implementation](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/iapTunnel.ts)
and [tests](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/__tests__/iapTunnel.test.ts)
establish the selected framing. The
[session integration](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts)
selects the iAP UUID `E9459FD0-BCAD-4C45-820F-1E72447EF2F2`, constructs a tunnel
from the session secret and decimal SETUP seed, and relays received bodies.
Its return path encodes `iAPSendMessage` on the separate event channel. This is
not evidence of a duplex data socket or of restarting the USB reliable link.
These files were available locally; the web fetch returned cache misses, so the
immutable local Git objects, not a search snippet, supplied the reviewed code.

Selected wire layout:

| Layer | Fields used |
| --- | --- |
| Encrypted record | LE16 plaintext length, ciphertext, 16-byte tag; length is AAD; nonce is zero32 plus increasing LE64 counter |
| Authenticated package | BE32 total size at offset 0; 32-byte header; BE32 message type at offset 16; remaining bytes are body |
| Delivered package | Message type `0x636f6d6d` (`comm`); other types are ignored after bounded assembly |

The reference's opening comment says `cmnd`, but its executable constant and
tests both use `comm`. The implementation follows the latter. Other header
fields are preserved as opaque bytes, not guessed package/reply semantics.
No acknowledgement, group interpretation or reply-token handling is invented.

The existing [session key derivation](../src/carplay/projection_session.c) supplies
the phone-to-receiver DataStream Output key from the verified shared secret and
seed. The new input layer accepts only an explicit read key; its tests use a
public synthetic key. This step does not claim a new independent key-derivation
check or handset verification.

## 2. Implement owned input without conflating package and link boundaries

[projection_iap.h](../src/carplay/projection_iap.h) and
[projection_iap.c](../src/carplay/projection_iap.c) implement:

1. An explicitly initialized, noncopyable generation-bound owner, with caller
   storage and no heap allocation, OS calls, callback or worker thread.
2. The existing record codec's authentication, replay/counter-exhaustion and
   exact absolute receive/held-record budgets. No plaintext is assembled before
   its complete record has authenticated.
3. A 32-byte package header and caller-selected total-package bound, from 32
   bytes through 4 MiB inclusive. The default is 64 KiB **including** header;
   larger accepted packages require explicit larger storage/configuration.
4. At most one new encrypted record and one complete package per feed call.
   Coalesced network input remains with the caller; extra authenticated package
   bytes stay in the cipher owner and can be drained with empty input.
5. Held `comm` header/body views with nonreused generation/token identity,
   partial prefix consumption, input backpressure and secure prefix retirement.
   Empty bodies are represented explicitly and consumed with count zero.
6. Absolute package assembly and body-hold deadlines. Partial progress, empty
   authenticated records and unknown message types do not renew an existing
   package's budget. A retained encrypted-record tail keeps its own deadline.
7. Terminal cleanup on bad tags, oversized/invalid packages, deadline expiry,
   counter/token exhaustion or EOF. All owned storage prefixes and read keys
   are wiped; wrong generation/token/count and backward time are transactional.

The full authenticated header stays available until final consumption. Its
authentication does not establish semantics for fields we have not interpreted.
The body remains opaque: it may split or combine iAP bytes. No body is fed to a
new iAP link, and no authentication/identification state is reset automatically.
An application must establish the correct live relay and delivery lifecycle;
this is control transport, not a claim that RECORD starts a new iAP session.

The shared record codec requires a transmit scratch buffer even though this
adapter is receive-only. It has an internal zero write key and no output API;
that key is not an available output credential. Storage is two record buffers of
`payload_limit + 18`, one `payload_limit` plaintext buffer, package capacity and
the owner structure. Only these configured prefixes are owned/wiped; tests check
that adjacent sentinels remain intact. No transport idle policy is added here.

## 3. Verify against independent wire generation and hostile input

The new [C++ tests](../tests/projection_iap_tests.cpp) contain nine groups:

- Transactional configuration/argument rejection and idempotent cleanup.
- Every wire split and every package split across encrypted records.
- Coalesced packages/records, unknown types, empty bodies and empty records.
- Partial body consumption, stale tokens/generations and time regression.
- Exact capacity limits, reduced record limits and a complete 4 MiB package.
- Partial-record/package, held-body and retained-record-tail deadlines.
- Every bit of a small encrypted record mutated, replay/wrong counter and EOF.
- Injected terminal nonce/token boundaries, with no wrap or restart.
- 2,500 deterministic authenticated malformed-package cases.

The [independent PyCA checker](../scripts/check_projection_iap.py), using the
existing pinned `cryptography==50.0.1` environment, produces six wire cases with
different record/package boundaries. The executable returns exact authenticated
headers/bodies for comparison: **4,523,217 delivered body bytes match**, and
three independent length/ciphertext/tag mutations fail without exposing a body.
These packages are synthetic, not phone captures.

The dedicated [sanitizer/ARM check](../scripts/Check-CarPlayIapSanitizers.ps1)
instruments the input owner, record codec, crypto adapter, both Monocypher units
and the tests with ASan/UBSan. All nine groups and the intentional assertion-
reporting check pass. The same five C units compile and relocatably link for
`armv7-none-eabi`/Cortex-A8, requiring `__aeabi_memclr8`, `__aeabi_uidiv`,
`__aeabi_uidivmod` and `__aeabi_uldivmod`. This is **not a QNX executable** and
does not extend the earlier core's import-free claim.

Two test-development issues were corrected before the final runs:

- A helper initially assumed all supplied bytes were consumed even when a
  preflight deadline/nonce limit had already closed the owner. It now permits
  a bounded unconsumed tail on terminal failure, matching the public contract.
- The local Windows clang 19.1.5 sanitizer build crashed while reporting a C++
  exception. An intentional throw before receiver initialization reproduced it;
  separating the catch frame and compiling the test at O0 did not resolve it.
  This C99 component's test assertions now print and exit without exception
  unwinding. No receiver instrumentation is suppressed. A subprocess check
  verifies the exact diagnostic and failure exit status, not merely any crash.

## 4. Reproduce and continue integration

```powershell
cmake --build build/video --config Release -- /verbosity:quiet
ctest --test-dir build/video -C Release --output-on-failure
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayIapSanitizers.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_iap.py build/video/Release/projection_iap_tests.exe
python -B -m unittest discover -s tests -p 'test_*.py'
git diff --check
```

The existing video build configuration supplies the pinned crypto dependency;
a fresh checkout can use `scripts/Build-CarPlayVideo.ps1` first. The new
`carplay_iap` CMake target depends on `carplay_pairing`, not the video codec.
Final full-suite results are recorded in the Step 93 progress entry.

Next, bind this owner to a peer-pinned, single-connection type-130 session
provider with real ephemeral TCP ports, explicit relay ownership, bounded
retained input, teardown and fatal-error propagation. Keep other media delegated
and route the return path through the existing event command encoder. A live
iAP application handoff still needs evidence; do not substitute a new USB link
or guessed success response for that contract.

The [factory gates](factory-integration-gates.md) remain: verified installed-
version execution/recovery, a matching QNX runtime/toolchain, USB/MFi ownership,
physical display/input/audio and actual phone/unit acceptance. No installable
CarPlay update or vehicle modification was produced by this step.
