# Encrypted MFi authentication and enrollment handoff

Date: 2026-09-10. Progress Step 59; continues [pair-store.md](pair-store.md).

## Step 1 - Establish the result and correct the ordering

The receiver now implements the MFiSAP v1 response calculation and owns its
`POST /auth-setup` exchange over verified encrypted control. An approved first-time
enrollment can transfer directly into this new owner on the same transport,
complete pair verification and then handle the MFi exchange without dropping
following bytes or borrowing an unrelated authenticated session.

This is real X25519, SHA1/SHA256 and AES128-CTR, with the existing real encrypted
control layer. Certificate/signature providers in tests are explicitly synthetic.
No real Apple credential, authentication chip, phone or head unit was accessed.
This neither proves MFi licensing/handset acceptance nor creates an installable
software-only CarPlay update.

The previous next-step wording grouped capability/auth routes together as
"pre-session." Inspection refined that plan: the selected reference places
MFiSAP inside already encrypted control, after pair verification. This step
implements that concrete authentication stage first; initial routing and actual
capability declarations remain next. It does not move MFi requests into an
unauthenticated plaintext branch.
[Pinned LIVI authSetup.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/authSetup.ts).

## Step 2 - Pin the protocol and cryptographic dependencies

The inspected LIVI checkout remains commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Relevant Git blobs:

| Reference file under `src/main/services/projection/driver/cp/stack/` | Blob |
| --- | --- |
| `authSetup.ts` | `4953733c289eb18c46275e6d7778ea6e688f8829` |
| `mfiSigner.ts` | `86b8432dbb055540892fa0842ef74701f9326c2f` |
| `crypto.ts` | `0b2d9738608d14c27039301315ea556f2fcf3900` |
| `cpStack.ts` | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` |
| `getInfo.ts` (inspected for subsequent work) | `4a6fc95d3deabc4c24731e909d1aed2bff7911ec` |

The local C99 implementation uses the existing Monocypher 4.0.3 X25519 adapter
and Mbed TLS 3.6.7 SHA/AES APIs. AES encryption-key setup is used for CTR, with
a fresh context/counter/stream block per response and cleanup on every exit.
No new dependency version, copied implementation body, default signer or
software replacement for an MFi private key is introduced.
[Pinned Mbed TLS AES API](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6.7/include/mbedtls/aes.h),
[SHA1 API](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6.7/include/mbedtls/sha1.h),
[SHA256 API](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6.7/include/mbedtls/sha256.h).

Nine prepared AES/SHA source/header files matched the pinned Mbed TLS tag after
UTF-8/newline normalization: `library/aes.c`, `aesni.c`, `aesce.c`, `padlock.c`,
`sha1.c`, `sha256.c`, and the three corresponding public AES/SHA headers. An
initial read-only archive comparison stalled in Windows tar/bzip2; that exact
helper process was inspected and stopped, then the comparison used the pinned
upstream tag directly. No prepared source was overwritten. Preparation still
does not claim to reverify the entire existing extracted Mbed TLS tree.

Local modules/tests select GPL-3.0-only, with the dependency/license selections
already recorded in [third_party/README.md](../third_party/README.md).

## Step 3 - Implement one bounded MFiSAP attempt

[mfi_sap.h](../src/carplay/mfi_sap.h) and
[mfi_sap.c](../src/carplay/mfi_sap.c) accept exactly a version 1 byte followed by
the controller's 32-byte X25519 public value. They generate a fresh explicit-RNG
ephemeral key, reject an all-zero ECDH result, and calculate:

```text
shared = X25519(new accessory secret, controller public)
AES key = first 16 bytes of SHA1("AES-KEY" || shared)
AES IV  = first 16 bytes of SHA1("AES-IV"  || shared)
signed input = accessory public || controller public
protocol major 2: digest = SHA1(signed input)
protocol major 3: digest = SHA256(signed input)
encrypted signature = AES128-CTR(key, IV, provider.sign(digest))
reply = accessory public || BE32(cert length) || cert
        || BE32(encrypted signature length) || encrypted signature
```

The selected byte profile comes from the pinned authentication/crypto reference;
there is no additional version byte in the reply. SHA1 remains here because
these protocol derivations and the legacy major 2 profile require it, not as a
recommendation for a new general-purpose authentication design.
[Reference crypto helpers](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/crypto.ts).

The certificate and signature have local bounds of 4,096 and 512 bytes; maximum
reply is 4,648 bytes. These are implementation limits, not Apple conformance
claims. Empty/overreported provider output fails. Only major 2 and major 3 are
accepted; an unknown major does not silently select SHA256 as in the reference's
broad fallback. The fresh MFi ECDH secret is not the previous pair-verify secret.

The provider returns a complete certificate and protocol major from one stable
chip identity, then signs the prepared digest with that same identity. Its
context/generation is explicit. It owns complete certificate validation, bus
coordination, key/certificate consistency, finite I/O behavior and real chip
operations. Certificates/signatures are opaque bytes to the framing adapter:
length checks are not Apple chain validation, and arbitrary nonempty data does
not establish a usable credential. There is no default callback or production
certificate/signature byte pattern.

This provider contract differs from merely forwarding an iAP2 challenge: it also
needs reliable chip-protocol metadata and must not hash the prepared digest a
second time. The existing iAP2 success notification and the MFiSAP exchange are
not interchangeable evidence. A real adapter for the factory chip remains absent.

State is one-shot `WAIT -> HELD -> DONE`, or terminal `DEAD`. Init performs no
RNG/provider I/O. Malformed requests, invalid ECDH, provider failures and expired
holds clear the response/providers and cannot retry. Ephemeral private/shared
values, AES key/IV, plaintext signature, digest and temporary contexts are wiped
after response construction. Only the bounded wire reply remains held.

## Step 4 - Own the authenticated route and output boundary

[projection_auth.h](../src/carplay/projection_auth.h) and
[projection_auth.c](../src/carplay/projection_auth.c) initialize and own fresh
`projection_control` and `mfi_sap` children. Callers use the wrapper APIs, not
external child mutations. No API attaches an unrelated verified session or
imports raw control keys.

Before real known-controller verification and plaintext M4 drain, a plaintext
`/auth-setup` request is rejected without MFi provider or RNG activity. After
encryption activates, only exact `POST /auth-setup` with one
`Content-Type: application/octet-stream` invokes the internal MFi handler.
Wrong method/type, duplicate content type, invalid body/provider or repeated
authentication closes both children. Cipher authentication failure never reaches
the provider. URI prefixes, case folding, suffix matches and query normalization
are not introduced: these remain exact origin-form routes, and broader target
handling/interoperability requires separate implementation/evidence.

The response is correlated to the held RTSP/HTTP request and copied into the
existing protected output owner. Response storage must accommodate the maximum
MFi body plus 256 bytes of framing before any chip operation is possible. The
caller cannot substitute an application response while the internal reply is
pending. Output encrypts/fragments normally; partial retirement does not re-sign,
regenerate the MFi ephemeral or restart the response budget.

The wrapper's final release requires all encrypted output to be retired and the
caller to attest actual downstream drain for the matching request. Only then
does it return `MFI_SAP_DRAINED` and wipe the held MFi reply. That result means
**local reply drained**, not phone acceptance, active media or Apple certification.

Other encrypted application requests remain held for explicit application
policy/replies, including `/info`. There is no automatic success, advertised
display/audio/HID capability, fake endpoint or session-command state machine.
Future typed handlers must enforce their own session/resource requirements;
this wrapper does not interpret a held `SETUP` as permission to start media.
[Inspected reference routing](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts).

Generation/token validation, monotonic time, receive/output bounds, retained
authenticated plaintext tails and external wire tails continue to use the
existing control owner. The MFi response/drain budget defaults to five seconds
and is absolute, alongside the control deadlines. Synchronous provider calls
cannot be preempted here; the provider must bound its I/O, and integration must
refresh/check time after it returns before exposing later output.

## Step 5 - Connect first-time enrollment on the same transport

`pair_setup_channel_take_auth` extends the existing committed-M6 transfer. It
requires the final enrollment key, complete M6 drain, a fresh different generation,
explicit MFi provider, valid destination configuration and adequate storage. Failed
validation does not retire the source or initialize the destination. The old
control-only transfer remains available.

On success it initializes a fresh verification/MFi owner, transfers the borrowed
identity/RNG/lookup lifetimes and detaches the enrollment owner. It may reuse the
exact now-cleared RX/TX buffers. Following wire remains external until fed to the
new owner. Old-source close or repeated transfer cannot erase the receiving
owner's data. No provider call or secure/MFi status is implied by transfer.

The exercised sequence is:

```text
local enrollment permission -> SRP + verified candidate approval -> trust commit
-> M6 drain -> fresh owner / pair-verify -> plaintext M4 drain
-> encrypted /auth-setup -> actual crypto + explicit synthetic provider
-> encrypted reply drain (not handset acceptance)
```

The new handoff test uses a memory-only trust-provider simulation. Actual private
Windows persistence/reopen is independently exercised by Step 58's unchanged
file suites; this step does not claim a real chip or phone was added to them.

## Step 6 - Validate independent vectors, failures and ownership

[check_mfi_sap_vectors.py](../scripts/check_mfi_sap_vectors.py) independently
reproduces 39 public values using PyCA/hashlib: 21 existing pairing values plus
18 MFi ECDH/digest/KDF/cipher/framing values. The certificate and signature bytes
are deliberately synthetic, not valid Apple credentials or software-generated
MFi licensing signatures. No C output is used to calculate expected vectors.

[mfi_sap_tests.cpp](../tests/mfi_sap_tests.cpp) has seven groups covering both
protocol profiles, AES partial-block lengths 1/15/16/17/511/512, maximum reply,
every shorter request length, unsupported version/major, zero/low-order ECDH,
RNG failure, empty/overreported/error provider results, stale generation/token,
decreasing/edge clocks, response deadlines, clearing and no retries.

Owned tests perform real pair verification, byte-fragmented encrypted input,
partial output across records, maximum-size encrypted replies, retained same-record
next-request tails, explicit 501 application responses, plaintext-auth refusal,
unknown-controller rejection, cipher tampering, malformed/repeated auth, provider
failure, premature/stale releases, lost/expired final drain and EOF. The enrollment
test additionally verifies approval/commit/M6 gating, invalid-transfer transactionality,
same-buffer handoff, preserved next wire, inert old-owner teardown and the complete
verification-to-MFi sequence under a new generation.

Commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayCrypto.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_mfi_sap_vectors.py tests/fixtures/mfi-sap-vectors.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

All 30 combined, 19 ordinary and 22 TLS-only CTest suites pass, as do 25 Python
regressions and the independent 39-value checker. The new seven-group suite,
enrollment, actual file suite and three TLS/carkit suites pass ASan/UBSan with
both crypto dependencies and the composed code instrumented. The five existing
pairing/control/store sanitizer suites also pass. New/changed C99 modules and
the test pass strict Clang warnings; Clang static analysis reports no finding.
No compiler warning beyond the existing dependency CMake compatibility warning
was introduced. The file suite still explicitly skips its separate privileged
symlink-creation case while executing actual directory-junction rejection.

The optional `carplay_projection_auth` target is hosted and uses Mbed TLS;
enrollment links it for the new transfer. It is not included in the ten-unit
optional ARM relocatable claim or the twenty-unit import-free core. Those
portable components remain unchanged; the optional ARM check still passes its
four-runtime-helper policy. New x64 objects are MFiSAP 4,744 and owning wrapper 6,728
bytes, plus caller buffers and nested stack temporaries. Target stack, side-channel,
allocator/runtime and performance suitability remain unverified.

## Step 7 - Continue toward an actual receiver

Step 60 adds [initial routing and continuous receiver ownership](receiver-routing.md),
including explicit enrollment permission and automatic post-M6 transfer. Next
implement capability response encoding tied to declared, available display/audio/input resources, then typed
session handling and real endpoints. Do not copy LIVI's complete default feature
mask or acknowledge unsupported commands as if this head unit already had those
features. Enrollment approval/rate limiting, target persistence/revocation and
safe provider scheduling also remain necessary.

Actual Go-module identity, installed-version execution/recovery, native USB-network
ownership, existing authentication-chip access and display/audio/input integration
remain unresolved. No firmware image, update USB, real trust record or vehicle
state was changed. Software-only CarPlay on the factory unit is still unproven.
