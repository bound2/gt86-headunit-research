# Receiver identity and cryptographic pair verification

Date: 2026-09-09. Continues [projection-control framing](projection-control.md),
committed/pushed as `68f7c83`, and [CarPlay progress](carplay-progress.md).
This step implements real cryptography for an already provisioned controller.
It is not first-time pairing, an installable update or iPhone acceptance evidence.

## Step 1 - Separate receiver identity, pairing and accessory certification

The pinned LIVI [pairVerify.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/pairVerify.ts)
uses an accessory Ed25519 identity and an explicitly known controller key.
It exchanges ephemeral X25519 public keys, signs proofs binding both ephemeral
keys and the relevant identity, protects inner TLV8 with authenticated encryption,
and derives directional control keys after verifying the controller's proof.
The Git blob is `fe2fb8850e1e4f6bd3b4250e39c8db5d0181ea06`.

The corresponding [TLV8 reference](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/tlv8.ts)
uses one-byte type/length fields and adjacent 255-byte fragmentation; its blob
is `2c64d0511aa90bf9a0bc3c331c7a6ff2e3683ba4`. The local implementation below
adds bounded storage, duplicate rejection and explicit lifecycle policies.
No upstream implementation bodies were copied or executed.

This receiver identity is neither a Lockdown TLS client certificate nor the
existing Apple authentication chip's certificate. First-time trust enrollment
and MFi authentication remain separate, as do the actual installed module's
chip identity/interface and iPhone acceptance. No fixture key can replace them.

## Step 2 - Select and pin a supported crypto implementation

Inspection of the pinned Mbed TLS 3.6.7 source found Ed25519 identifiers but
no usable Ed25519 signing/verification implementation in the selected library.
The existing TLS target remains unchanged. The new optional `carplay_pairing`
target uses Monocypher's actual Ed25519/SHA-512 module, not its incompatible
BLAKE2b-based EdDSA interface.

[Monocypher 4.0.3](https://github.com/LoupVaillant/Monocypher/releases/tag/4.0.3),
released 2026-06-15, fixes a signing timing leak affecting earlier releases;
the maintainer's [bug record](https://monocypher.org/bugs) identifies 4.0.2 and
below as affected under particular compiler settings. This version choice is
not a measurement of this project's target binary or a blanket safety claim.

- Tag/commit: `ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f`.
- Archive: `https://monocypher.org/download/monocypher-4.0.3.tar.gz`.
- Archive SHA256: `8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`.
- Selected dependency licence: BSD-2-Clause, from the offered BSD-2-Clause /
  CC0-1.0 alternatives. Source notices, `LICENCE.md` and `AUTHORS.md` are retained.

[Prepare-CarPlayCrypto.ps1](../scripts/Prepare-CarPlayCrypto.ps1) checks the
archive and all six used source/licence files on every run. Missing files are
extracted from an exact allowlist; existing mismatched files reject instead of
being overwritten. A first full-archive extraction failed on Windows documentation
symlinks; the script now avoids those members. The partial documentation tree
was left in ignored build storage and is not required or shipped.

All four release source/header files were compared in memory against the
pinned official GitHub tag. They match after substituting only the release
version marker for `__git__`. SHA256 pins are recorded in the preparation script;
CMake independently checks all four compiled source/header pins at configure.
This records publisher HTTPS provenance and reproducibility, not an independently
authenticated release signature. No crypto source archive/binary is committed.

## Step 3 - Implement bounded TLV8 and explicit key ownership

[pair_tlv.h](../src/carplay/pair_tlv.h) / [pair_tlv.c](../src/carplay/pair_tlv.c)
support complete bodies up to 8,192 wire bytes and 32 logical items. Decoding
copies values into caller-owned arena storage, joining only consecutive
same-type fragments after a full 255-byte predecessor. A zero-length `ff`
separator breaks adjacency; another `ff` length rejects. Distinct repeated
types remain ordered and a lookup rejects ambiguity. Encoding emits separators
between adjacent distinct same-type values and fragments large values.
Validation precedes writes, so failures leave item/arena/output storage unchanged.

[pair_crypto.h](../src/carplay/pair_crypto.h) / [pair_crypto.c](../src/carplay/pair_crypto.c)
add explicit raw-seed identity import/generation, Ed25519 sign/verify, X25519,
HKDF-SHA512 and IETF ChaCha20-Poly1305. The identity identifier is explicitly
provided, 1..64 printable non-space ASCII bytes. No default identifier, public
key, UUID, file path, persistent store or automatic regeneration exists.
Import derives the complete bundled signing key and checks an optional expected
public key; it never accepts an independent public half for a signing secret.

Generation requires a synchronous caller-supplied CSPRNG. Callback failure
does not trigger retry or fallback. Tests use publicly known deterministic
seeds, not a production entropy source. The caller must provision persistent
identity securely and supply a verified platform CSPRNG before real use.

Primitive wrappers validate pointer/length/capacity contracts and cap data at
65,536 bytes. KDF inputs are each at most 8,192 bytes and output 1..16,320 bytes
(255 SHA-512 blocks), preventing an HKDF expansion-counter wrap. Null/zero
input conventions remain explicit. X25519 rejects an all-zero shared secret.

The [Ed25519 API](https://monocypher.org/manual/ed25519) supplies standard
SHA-512 signatures. Verification adds canonical public-key/R encodings and
low-order rejection to the backend's checks. For public points only, the
[documented verification equation](https://monocypher.org/manual/eddsa)
with identity R, zero s and unit h identifies on-curve low-order points;
normal signature verification still checks curve membership and scalar bounds.
This is not a new signing algorithm or a full prime-subgroup membership test.
Variable-time verification handles public proof material, not private scalars.

AEAD initializes a fresh IETF context for each 12-byte nonce and performs one
authenticated operation before wiping the context. It does not reuse the
library's incremental rekeying mode. This matches the
[IETF compatibility interface](https://monocypher.org/manual/aead); callers
must guarantee nonce uniqueness per key. The adapter returns ciphertext plus
tag, exposes no unauthenticated plaintext and clears output on a bad tag.
It does not yet implement the counter/length framing of the control stream.

## Step 4 - Verify a known controller and hold the plaintext handoff

[pair_verify.h](../src/carplay/pair_verify.h) / [pair_verify.c](../src/carplay/pair_verify.c)
provide a one-shot responder borrowing an immutable identity and read-only
trusted-controller lookup callback. There is no trust-on-first-use, pairing-store
write, automatic enrollment, generic success provider or mark-secure API.

```text
M1 -> fresh X25519 + signed/encrypted accessory proof -> held M2
   -> caller drains outer plaintext reply and releases M2
M3 -> authenticated decrypt -> known-controller lookup -> Ed25519 proof check
   -> directional key derivation -> held M4 (still plaintext)
   -> caller drains/release M4 -> one-time key handoff -> detached

Malformed input / authentication / provider / deadline failure -> wiped, DEAD
```

The M1 proof binds accessory ephemeral key, accessory identifier and controller
ephemeral key. The M3 proof binds controller ephemeral key, controller identifier
and accessory ephemeral key. Lookup is performed only after the M3 tag and
inner field sizes validate; an unknown controller or failed lookup cannot
produce a success reply. Both proof signatures are real, not synthetic callbacks.

Handshake bodies are capped at 1,024 bytes. Required state/key/signature lengths
are exact. Duplicate logical fields and separators reject; unique unknown fields
are ignored for forward compatibility. Wrong-phase M1/M3 requests fail instead
of silently restarting. Failures wipe ephemeral/session material and output;
the caller decides whether to send an explicit outer error or close transport.

The complete exchange has an absolute 10-second default budget starting at
initialization, and held responses/key handoff have a 5-second budget. Values
are configurable within 1..60,000 ms. Partial outer writes and response releases
do not renew the exchange clock. Synchronous RNG/lookup calls cannot be preempted
by this component; their production implementations must not block/reenter.

A fresh nonzero generation and exact response token are required for release
and key handoff; stale values reject before clock acceptance. M2 release enables
M3, while M4 release enables one-time key transfer, never plaintext resume.
Release is the caller's explicit assertion of downstream drain, not proof that
this memory-only component sent anything. Export copies controller identity,
shared secret and directional keys, then wipes/detaches the responder. The caller
must bind the keys to the same connection and clear its own copy after use.

## Step 5 - Test against external vectors and actual cryptography

[pair_tlv_tests.cpp](../tests/pair_tlv_tests.cpp) has three groups covering
fragmentation/separators/duplicates, capacity/truncation/atomicity and 6,000
deterministic mutations. [pair_crypto_tests.cpp](../tests/pair_crypto_tests.cpp)
has seven groups:

1. Ed25519 test 1/2 from [RFC 8032 section 7.1](https://www.rfc-editor.org/rfc/rfc8032.txt),
   X25519 Alice/Bob keys/shared secret from [RFC 7748 section 6.1](https://www.rfc-editor.org/rfc/rfc7748.txt),
   and independently generated multi-block HKDF-SHA512 output.
2. Exact [RFC 8439 section 2.8.2](https://www.rfc-editor.org/rfc/rfc8439.txt)
   ciphertext/tag, every-byte ciphertext/tag corruption, wrong AAD/nonce,
   empty messages and capacity failure.
3. Expected-key mismatch, RNG failure and success, low-order/noncanonical
   Ed25519 points, all-zero X25519 result and KDF length limits.
4. Exact independently reproduced M1/M2/M3/M4 bytes and directional keys,
   deferred handoff, lookup count, one-shot export and secret clearing.
5. Bad tags, valid-tag forged signatures, unknown/wrong controller keys,
   lookup/RNG failure, low-order ECDH and duplicate inner identity fields.
6. Generations/tokens, phase errors, every M1 truncation, duplicate/separator
   rejection, unknown-field handling, invalid initialization, deadline edges,
   near-UINT64_MAX clocks and idempotent closure.
7. The existing RTSP channel composed with the real responder: fragmented
   plaintext requests, three-byte output retirement, reflected CSeq, held M4
   handoff and untouched ciphertext-shaped tail. It is a memory-only transport
   simulation, not a socket or completed encrypted control channel.

The 21 values in [pair-verify-vectors.txt](../tests/fixtures/pair-verify-vectors.txt)
contain **public test seeds**, never deployable credentials. The
[independent checker](../scripts/check_pair_vectors.py) reproduces the full
transcript with PyCA cryptography 50.0.1. This is separate from Monocypher and
from the C implementation's fixture peer. The checker emits only to stdout or
reads the named fixture; it does not create key files or access the car.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

Optional independent reference, installed only in ignored workspace storage:

```powershell
python -m venv build/pair-reference
./build/pair-reference/Scripts/python.exe -m pip install --only-binary=:all: -r scripts/pair-reference-requirements.txt
./build/pair-reference/Scripts/python.exe -B scripts/check_pair_vectors.py tests/fixtures/pair-verify-vectors.txt
```

The tested reference environment pins cryptography 50.0.1, cffi 2.1.1 and
pycparser 3.0; none is a receiver dependency. Package metadata was checked at
[PyPI](https://pypi.org/project/cryptography/50.0.1/). The downloaded Windows
cryptography wheel's published SHA256 is
`aed8db4f6d71c51efb89530e12d9464e7bf2923d46c3205dc794a2a93f8c0648`.
The requirements file pins versions, not hashes for every platform/dependency.

All 23 combined crypto/TLS CTest suites, 19 standard suites and 22 TLS-only
suites pass. Fifteen protocol sanitizer suites, both new pairing suites with
Monocypher instrumented, and the three existing hosted TLS suites pass.
All 25 original Python tests and the independent 21-vector checker pass.
Initial test build/fixture issues were a missing `<string>` include, an incorrect
vector count and a mistyped RFC AEAD key literal; these were fixed without
changing expected cryptographic results or relaxing checks.

The core ARM check now covers twenty import-free C99 units, including TLV8.
The separate crypto check compiles/relocatable-links seven units including
Monocypher, but reports four required runtime symbols: `__aeabi_memclr8`,
`__aeabi_uidiv`, `__aeabi_uidivmod`, `__aeabi_uldivmod`. It rejects unexpected
imports. No implementations of these runtime helpers or QNX executable were
added. x64 object sizes are identity 176, responder 1,400 and exported keys 168
bytes, plus stack temporaries. Target stack, CPU, CSPRNG, linker/runtime and
side-channel suitability are not verified by these host checks.

## Step 6 - Continue to a working receiver

Next connect authenticated control-frame encryption/counters to the RTSP
request owner and this key handoff, then implement first-time pair-setup with
explicit trust/persistence policy. The known-controller branch is implemented;
an unpaired iPhone still has no enrollment path here. MFi auth-setup, real
capability/identity/address advertisement, network listeners, typed session
handlers and video/audio/input remain incomplete.

Do not advertise any fixture identity or assume this bypasses the authentication
chip. Native USB-network access, actual Go-module identity, installed-version
execution/recovery and authentication-chip interface remain unresolved. No real
phone, trust record, head unit, firmware image or update USB was accessed or
changed. This is not yet software-only CarPlay running on the owner's hardware.

Follow-up: [encrypted-control.md](encrypted-control.md), Step 56, now implements
authenticated control records/counters and owns the actual pair-verify/RTSP
handoff, including the plaintext-M4 downstream-drain barrier. The historical
test counts above describe Step 55; the combined build now has 25 suites.
First-time pair-setup/trust persistence and real network/media integration remain.
