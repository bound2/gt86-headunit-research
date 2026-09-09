# Lockdown TLS stream implementation

Date: 2026-09-09. Continues [the startup/handoff step](lockdown-bootstrap.md)
and [CarPlay progress](carplay-progress.md). This is host-side implementation,
not an installable head-unit update or demonstrated iPhone interoperability.

Follow-up: [carkit-startup.md](carkit-startup.md) implements the protected RPC
owner and separate service stream. It adds a fresh-service TLS initializer,
timer-only check and application-use tracking; current TLS context size is
7,984 x64 bytes. Counts/sizes below otherwise record this earlier TLS step.

## Step 1 - Review the pinned receiver's TLS behavior

The existing idevice 0.1.65 reference uses HostCertificate/HostPrivateKey to
upgrade the existing stream after StartSession. Its OpenSSL branch disables
certificate verification; its Rustls `NoServerNameVerification` also accepts
the peer certificate and handshake signatures without verification. These
behaviors are **not** copied into this implementation.

Reference: [pinned idevice sni.rs](https://github.com/jkcoxson/idevice/blob/2bc6a05c80daaf8583884cf7f2d2563be17e6c2d/idevice/src/sni.rs),
local SHA256 `87c21b18d2ef2e7ad0b5ea5598714db29a1b144289530a3440d88ddd3baa992f`.
The original crate SHA256 remains
`7484b3a39a089068167a8ab0b3da6a05b5f6f8969daf1a893da1c7087cb2e09a`.
No upstream function bodies, phone records or credentials were copied.

## Step 2 - Pin a maintained cryptographic dependency

The optional hosted target uses [Mbed TLS 3.6.7](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7),
released July 7, 2026, on the 3.6 LTS branch supported until at least March 2027.
Its release includes security fixes, so an older cached release is not substituted.

- Tag object: `627361b09e6f6e3eac756297a370a591cf310ab9`.
- Commit: `068ff080b369adfac81509f9b57b2afabaf82dc5`.
- Official release archive: `mbedtls-3.6.7.tar.bz2`.
- SHA256: `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`.

[Prepare-CarPlayTls.ps1](../scripts/Prepare-CarPlayTls.ps1) downloads the exact
release asset if absent and verifies the pinned SHA256 before extraction into
ignored `build/mbedtls-3.6.7`. This matches GitHub's release-asset digest, not an
independently authenticated maintainer signature. Existing extracted sources
are preserved, not overwritten or independently hash-verified. Keep them pristine;
the script's archive verification is not proof of an unchanged extracted tree.
There is no system-wide library installation or automatic CMake network fetch.

Mbed TLS is dual Apache-2.0 OR GPL-2.0-or-later; this project's integration selects
GPL-2.0-or-later, with local adapter/tests under GPL-3.0-only. Bundled third-party
code retains its own notices in the release source. Source and binaries stay
outside Git; see [dependency provenance](../third_party/README.md).

## Step 3 - Make credentials and trust explicit

[lockdown_tls.h](../src/carplay/lockdown_tls.h) requires root certificate(s),
host certificate/key, an exact DER device leaf certificate and a caller-supplied
seeded cryptographic random generator. PEM inputs include their terminating NUL.
Root and host certificate inputs are each capped at 32,768 bytes; private key
and device DER at 16,384 bytes. Partial PEM parse failures are rejected, not
treated as progress. The host public/private key pair is checked before binding.

The initial profile is TLS 1.2 with ECDHE-RSA or ECDHE-ECDSA and AES-128/256-GCM.
It requires normal CA chain, validity, usage and signature checks **plus** exact
device leaf DER equality. The verification callback only adds failures; it never
clears the library's flags. USB pairing identity is pinned instead of checked as
a DNS name, so hostname/SNI are explicitly unset. There is no verify-none switch,
legacy SSL/TLS fallback, CBC suite, resumption, renegotiation or early data.
The [versioned API](https://mbed-tls.readthedocs.io/projects/api/en/v3.6.7/api/file/ssl_8h/)
and downloaded headers were used to check these configuration and retry contracts.

This is a conservative local policy, not proof that a real iPhone's pairing
certificates meet these constraints. Device-certificate availability, signature
algorithms, chain structure, negotiated suites and system clock remain actual
compatibility questions. No automatic Pair, record discovery, trust-store
modification, UUID creation or persistent credential storage is supplied.

## Step 4 - Connect the actual TLS engine to the existing handoff

Successful init consumes the bootstrap's handoff, preserves its SessionID in
the TLS object, and owns the existing USBmux stream. Init parses credentials and
checks keys but does not call the backend or perform a handshake. Failed init
frees partial crypto state and leaves the handoff/transport with the caller.
Abandoning a failed upgrade requires aborting that stream, not plaintext reuse.

The final plaintext TCP receive ACK may still be queued by handoff. It contains
no application payload and drains through the normal dispatcher. Pending
plaintext payload or unacknowledged flights are refused. Already buffered TLS
bytes remain on the same stream; there is no new socket or framing reset.

Each poll performs at most one dispatcher poll and one TLS handshake step,
application write or application read. Each TLS BIO direction can make at most
one dispatcher byte-stream call, capped at 512 ciphertext bytes, per poll.
`WANT_READ`/`WANT_WRITE` yield to the event loop. The transport retains its own
physical-completion and TCP-ACK accounting. Other streams and explicitly held
USBmux CONTROL messages remain available.

The TLS state becomes OPEN only after Mbed TLS completes the cryptographic
handshake and peer verification succeeds. There is no mark-secure callback.
Application writes before this point return BUSY. One 1..4,096-byte application
write is copied into stable storage and retried with the same pointer/length,
as required by Mbed TLS. Clearing `tx_size` means the TLS engine accepted the
plaintext, not that the peer acknowledged or acted on it.

Reads expose only verified decrypted bytes, in held chunks up to 512 bytes.
Prefix consumption zeroes consumed storage and never extends the original
hold deadline. A large TLS record can span many app reads and USBmux packets.
Handshake defaults to 10 seconds; pending write and plaintext hold each default
to 5 seconds. All three are caller configurable within 1..60,000 milliseconds.
Clock values are explicit monotonic milliseconds. Timed calls also check shared
dispatcher deadlines, after rejecting stale generations.

Fatal errors cancel the shared physical generation once. A stale TLS owner
cannot tick or cancel its replacement generation. Authenticated close_notify,
raw EOF without close_notify and damaged ciphertext have distinct reasons.
Local close is an abort: orderly TLS shutdown, StopSession and isolated
per-service abort are not implemented. Crypto state is freed and local app
buffers zeroed; original credentials, OS copies and swap are not erased by us.

## Step 5 - Verify real encryption on a simulated transport

[lockdown_tls_tests.cpp](../tests/lockdown_tls_tests.cpp) creates ephemeral
EC/RSA keys and CA-signed certificates entirely in RAM using host entropy.
Nothing is saved as a pairing record or reusable private-key fixture. The
synthetic validity interval is 2020-2040, with a separate intentionally expired
certificate. Tests need a correctly dated host clock and entropy provider.

Seven groups cover:

1. Full plaintext StartSession/reply/token handoff, then real mutual TLS and
   encrypted StartService fixture bytes; raw USBmux data does not contain that
   plaintext frame. Decrypted binary reply bytes match their independent fixture.
2. EC and RSA client/server certificates; negotiated ECDHE/AES-GCM policy.
3. Wrong device pin, wrong CA, expired leaf, rejected client and incompatible
   CBC-only peer: no accepted session or application plaintext.
4. One-byte TCP sends, partial physical/BIO I/O, 256-byte receive rings,
   4,096-byte app records, another active stream, CONTROL and shared ACK deadlines.
5. Malformed/bounded credentials, mismatched keys, failed entropy, no init I/O,
   unchanged failed handoffs and stable pending-write ownership.
6. Handshake/write/held-plaintext deadlines, decreasing clocks, stale ownership
   and idempotent cancellation/freeing.
7. Damaged AEAD records, unannounced raw EOF and authenticated close_notify.

The fixture models receive credit and TCP acknowledgements; it does not use a
USB driver or a phone. Both TLS endpoints use Mbed TLS, so this is not an
independent-library interoperability or Apple conformance test. The encrypted
StartService bytes prove transport, not a complete protected RPC client: no
returned port is yet used to open carkit and no service TLS policy is applied.

Run from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

The ordinary build remains dependency-free for TLS and has 17 CTest suites;
the optional TLS build has 18. Existing thirteen protocol sanitizer suites,
seventeen-unit freestanding ARM check and 25 Python tests remain separate.
All of these checks pass, including the seven-group TLS suite under ASan/UBSan.
The new sanitizer script recompiles the adapter, protocol dependencies and
Mbed TLS itself, not just the C++ test executable. It uses installed clang
directly because this host lacks the Visual Studio ClangCL project toolset;
Windows host entropy additionally links BCrypt. Local adapter compilation also
passes clang C99 `-Wall -Wextra -Werror`. MSVC reports a zero-length-array warning
in an upstream PSA header; CMake reports the upstream old minimum-version
deprecation. Neither is a suppressed test failure or evidence of target readiness.

## Step 6 - Keep hosted crypto distinct from target readiness

The TLS object is 7,976 bytes on the tested x64 host, **plus Mbed TLS heap** and
underlying dispatcher/connection storage. Input and BIO limits do not establish
a total allocator bound or a hard CPU-time bound on a certificate/key operation.
The optional `carplay_tls` target is not part of the import-free ARM check.
It requires a working allocator, time, crypto/random support and platform review.

The selected configuration removes network/file APIs, persistent PSA storage,
DTLS, TLS 1.3, tickets and renegotiation. This is still a hosted test profile,
not a minimized QNX port. Mbed TLS documents timing risks in its software AES
lookup tables; target deployment needs suitable constant-time/hardware crypto
and RNG choices, not an assumption that Cortex-A8 has modern AES instructions.
See the pinned [security guidance](https://github.com/Mbed-TLS/mbedtls/blob/068ff080b369adfac81509f9b57b2afabaf82dc5/SECURITY.md).

Next implement a framed protected RPC owner using this TLS stream and the
existing plist validator, then explicit StartService/port/SSL policy and carkit
stream startup. Pairing-record provision, native QNX USB/network access,
authentication-chip access, display/audio/media, exact Go-module identity and
verified execution/recovery remain unresolved. No phone, car, USB update,
firmware image or real trust record was accessed or changed in this step.
