# Vendored dependency

`lzo-2.10/` contains unmodified miniLZO sources, two support headers and COPYING
from Markus F. X. J. Oberhumer's official LZO 2.10 archive:

- Source: https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz
- Archive SHA256: `c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072`
- License: GNU GPL version 2 or later; see [COPYING](lzo-2.10/COPYING) and the
  notices in each source file. Preserve those notices. This dependency is linked
  into `qnxinspect` and the QNX tests; its GPL terms apply when distributing the
  linked program. No project-wide permissive license is asserted here.

Only the five files needed for miniLZO and its license were retained. The archive
itself is in the ignored `downloads/` directory. The existing `fwinspect` target
does not link miniLZO. Building requires no dependency download.

The QNX parser is local research code reading observed byte fields. It does not
vendor QNX headers or vendor firmware. Format references are recorded in the
[second-pass report](../reports/qnx-analysis.md).

## CarPlay protocol reference and fixtures

The C99 iAP2 implementation in `src/carplay/` and its tests are informed by
[LIVI](https://github.com/f-io/LIVI), Copyright (C) 2025 Lasse Heitgres, under
GPL-3.0-or-later. Those new files use that license; the full license is preserved
in [LIVI-COPYING](LIVI-COPYING). This does not change the license of unrelated
project files or vendor firmware.

Reference commit: `a76553fc941dcf378dd55c04da56aaf3d6911e08`.

- `native/livi-helperd/crates/iap2-link/src/lib.rs`: link header, detection
  marker, checksum and synchronization payload format; reference link behavior
  for the new bounded `iap2_link.c` engine.
- `native/livi-helperd/crates/iap2-link/tests/engine.rs`: golden ACK/SYN frames
  and synchronization payload used by `tests/iap2_tests.cpp`.
- `native/livi-helperd/crates/iap2-csm/src/lib.rs` and
  `src/messages/authentication.rs`: control-message and authentication fields.
- `native/livi-helperd/crates/iap2-csm/tests/vectors.txt`: copied unchanged to
  `tests/fixtures/iap2-csm-vectors.txt`; 33 synthetic vectors, SHA256
  `df49ff644461471533854b0d15df8ee21c4e1a093355e595c8ece828767b7d97`
  for the LF version. These contain example data, not captured credentials.

The source is available at the
[pinned revision](https://github.com/f-io/LIVI/tree/a76553fc941dcf378dd55c04da56aaf3d6911e08).
Only the vectors and license text are copied verbatim. The C implementation
uses caller-owned buffers and explicit size/error handling, and rejects malformed
parameter tails and out-of-sequence authentication. It is not a port of the
complete LIVI receiver. No upstream installer or service was executed.

The reliable-link implementation keeps fixed queues and an exact send-window
bound, validates acknowledgement ranges and negotiated session/size limits,
and uses monotonic caller-supplied time. It deliberately does not reproduce all
upstream engine behavior: EAK and zero-ACK modes are unsupported, retries count
retransmissions after the initial send, and pure ACK frames do not trigger ACKs.
The new tests retain the pinned LSP golden bytes but independently exercise
these bounded-state choices. No private Apple specification is bundled or
claimed as a conformance reference; real-device interoperability is untested.

The `iap2_control.c` adapter uses the same pinned CSM/authentication fields.
Its incremental CSM stream, caller-buffer bounds, reply-ACK serialization,
application-message hold, deadlines and owned-link lifecycle are local design
choices, not a claim that upstream implements or validates these policies.
`tests/iap2_control_tests.cpp` contains independent synthetic transport/provider
fixtures. Its deterministic certificate/signature patterns are not credentials
or an authentication-chip emulator; no real provider or private key is supplied.

`iap2_identification.c` uses field IDs from the pinned
`native/livi-helperd/crates/iap2-csm/src/messages/identification.rs` and common
fields/Accepted/Rejected fixtures from the existing 33-vector file. Its minimal
encoder does not reproduce the rich upstream Information fixture: it omits all
transport/vehicle/application components and CarPlay flags, and its message lists
contain only implemented auth/identification IDs. Tests compare the common field
bytes separately, not a purported full upstream-vector match. Printable-ASCII
limits, opt-in metadata, auth-before-identification ordering, ACK barriers,
rejection-mask bounds and deadlines are local policies, not Apple requirements.

`iap2_transport.c` and its fake-backend tests use the same GPL-3.0-or-later
license. The byte-stream pump's pending-tail storage, completion validation,
generation/cancellation contract and polling/deadline policy are independent
local implementation choices. No QNX USB headers, driver code or credentials
are copied into this implementation, and no native transport is supplied.

`iap2_carplay.c` uses the pinned `iap2-csm/src/messages/car_play.rs` schemas and
`iap2-csm/src/lib.rs` parameter/list encoding. Its tests reuse four exact fixtures
from the existing 33-vector file; no new upstream fixture file is copied. The
wired address-list field is decoded into separate borrowed string views even
though its strings share one parameter. Printable-ASCII limits, rejecting
unknown/duplicate fields, exact terminator checks and transactional outputs are
stricter local policies, not a reproduction of all upstream decoder behavior.

The explicit wired-start reply helper is informed by the pinned
`native/livi-helperd/crates/livi-runtime/src/bringup.rs` builder. Requiring an
accepted identification/authentication exchange, a valid explicitly available
wired offer and complete caller-provided receiver metadata are local gates.
No runtime networking, pairing, keys or USB code is ported. In particular, the
upstream runtime identifies before authenticating, unlike our existing local
profile. This is a documented compatibility gap, not an upstream requirement
already met. See [the session-start report](../reports/carplay-session-start.md)
for exact source links and the remaining capability-advertisement gap.

The control endpoint now supports the pinned runtime's identification-first
order through explicit configuration; the original authentication-first mode
remains the default. Phase budgets, provider gating, ACK barriers, fail-closed
rejection and the absence of automatic fallback are local policies. New tests
use synthetic peers with both orders and deliberately lost packets; no new
upstream source or credentials are copied. See
[startup-order.md](../reports/startup-order.md).

The later identification payload audit applies the same pinned `[list str]`
encoding rule to SupportedLanguage: field 13 contains all NUL-terminated
elements, not repeated parameters. The new multi-language expected bytes are
independently specified test data derived from that rule; the original upstream
single-language fixture remains unchanged. This corrects a local implementation
and test error, and does not add an upstream dependency or capability claim.

`iap2_power.c`/`.h` use the same GPL-3.0-or-later license and pinned
`iap2-csm/src/messages/power.rs` PowerSourceUpdate schema. Tests reuse the
existing `PowerSourceUpdate` vector unchanged; its 2400 mA example is not a
hardware default. The explicit notification API shares the local control
queue/deadline policies, informed by wired `livi-runtime/src/bringup.rs` sending
this message without a request. No power-control, USB or networking code is
copied, and actual electrical capabilities are not inferred from the fixture.

The opt-in wired identification extension uses the pinned
`iap2-csm/src/messages/identification.rs` USBHostTransportComponent fields and
the runtime's wired profile as references. It reproduces the fixture's entire
USB-host payload, including the transport macro's repeated empty iAP2 flag in
field 5. Explicit ID/name/interface values replace upstream runtime fallbacks;
only implemented CarPlay/power messages are added to the local message lists.
Aggregate bounds, profile activation/ownership/reset and typed-helper declaration
gates are local policies. No hardware configuration, broader subscriptions or
media support is inferred or copied. See
[wired-identification.md](../reports/wired-identification.md).

## USBmux packet references

`usbmux_wire.c`/`.h`, `tests/usbmux_tests.cpp` and the independent seven-vector
fixture select **GPL-3.0-only**. The full GPLv3 text is already preserved in
[LIVI-COPYING](LIVI-COPYING). Existing iAP2 file notices remain unchanged;
no project-wide permissive license or license for vendor firmware is asserted.

Two primary sources inform the wire layout:

- LIVI at the same pin above,
  [iap2-usbmux/src/mux.rs](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-usbmux/src/mux.rs),
  GPL-3.0-or-later.
- usbmuxd at `3ded00c9985a5108cfc7591a309f9a23d57a8cba`,
  [src/device.c](https://github.com/libimobiledevice/usbmuxd/blob/3ded00c9985a5108cfc7591a309f9a23d57a8cba/src/device.c)
  and [src/usb.h](https://github.com/libimobiledevice/usbmuxd/blob/3ded00c9985a5108cfc7591a309f9a23d57a8cba/src/usb.h).
  Its source notices offer GPL version 2 or version 3; these new files select
  version 3. The source notices credit Hector Martin and, for `device.c`,
  Mikkel Kamstrup Erlandsen. No upstream function bodies are copied verbatim.

The new fixture is manually specified synthetic data, not an upstream fixture
file, capture or credential. It records both setup sequence-slot conventions
and deliberately opaque peer magic. Fixed capacity, transactional outputs,
minimal TCP-header policy, borrowed views and fail-closed streaming are local
design choices, not upstream guarantees or Apple conformance claims. Source
blobs and behavior differences are recorded in
[usbmux-transport.md](../reports/usbmux-transport.md).

The ignored `build/usbmuxd-reference` is a no-checkout source repository read
with `git show`; no daemon or installer was run. No USB library, platform API,
private specification or actual device transport is bundled by this step.

`usbmux_host.c`/`.h` and `tests/usbmux_host_tests.cpp` also select GPL-3.0-only
using these same pins. Initial version/setup bytes and selectable sequence-slot
conventions follow the two references. Requiring major version 2, physical
write-completion barriers, single owned TX/held RX packets, bounded deadlines,
generation rejection and no automatic fallback are independent local policies.
The tests specify first-version/setup/SYN bytes independently and use synthetic
completion events; no upstream function bodies, daemon, backend or real trust
records are included. TCP connection/window/ACK behavior is not implemented here.

`usbmux_connection.c`/`.h` and its synthetic tests select GPL-3.0-only using the
same LIVI/usbmuxd pins. Their connection functions inform port routing, SYN/ACK
packet fields, scaled windows and FIN/reset handling. Bounded flight records,
ACK/sequence validation, arbitrary peer initial sequences, overlap suppression,
receive-credit preservation, caller-buffer ownership and timing/generation
contracts are independent local policies. No upstream implementation bodies or
new reference fixtures are copied. The integrated `abc`/`ok` exchange is test
data, not real Lockdown/TLS/carkit traffic or a captured phone session. See
[usbmux-connection.md](../reports/usbmux-connection.md) for the intentionally
limited reliable-transport profile and missing production integration.

`usbmux_dispatcher.c`/`.h` and their independent fake-backend tests also select
GPL-3.0-only. They coordinate the existing host/connection modules without new
protocol schemas, upstream fixture copies or dependency downloads. Callback
completion/cancellation validation, fresh-port and handle lifetimes, held
control tokens, whole-session failure policy and round-robin scheduling are
local designs. The tests use synthetic echoes through explicit callbacks, not
native USB, real trust records or carkit sessions. See
[usbmux-dispatcher.md](../reports/usbmux-dispatcher.md).

## Lockdown service references

`lockdown_wire.c`/`.h`, `lockdown_channel.c`/`.h`, their synthetic tests and
XML fixtures select GPL-3.0-only. The dispatcher test peer was factored into
`tests/support/usbmux_fixture.h` under the same license; its optional service
callback is test-only. No native backend, trust record or TLS code is included.

The same LIVI pin's `iap2-wired/src/carkit.rs` supplies service startup order.
Its lockfile selects `idevice 0.1.65`, whose package manifest declares MIT and
credits Jackson Coxson. The exact downloaded crate SHA256 is
`7484b3a39a089068167a8ab0b3da6a05b5f6f8969daf1a893da1c7087cb2e09a`;
VCS metadata identifies `jkcoxson/idevice` at
`2bc6a05c80daaf8583884cf7f2d2563be17e6c2d`, package subdirectory `idevice`.
The archive contains no LICENSE file found by the inspection. It remains an
ignored source reference, not a vendored or executable dependency.

The pinned `src/lib.rs` and `src/services/lockdown.rs` inform the four-byte
big-endian body length and GetValue fields. No upstream function bodies or
fixtures were copied. Local frame/metadata limits, transactional encoding,
opaque-response ownership, exact-needed reads, serial tokens, deadline policy,
shared cancellation and explicit detach are independent implementation choices.
The XML fixtures are synthetic and independently checked using Python plistlib;
they are not phone captures, trust records or evidence of Apple conformance.
See [the service report](../reports/lockdown-service.md) for exact source links,
file hashes, security boundaries and missing response parsing/pairing/TLS.

The later `service_plist.c`/`.h`, `lockdown_reply.c`/`.h`, tests and seven
synthetic binary vectors also select GPL-3.0-only. They retain the idevice
reference for response fields and use Apple's public plist DTD plus
[CPython plistlib v3.14.7](https://github.com/python/cpython/blob/v3.14.7/Lib/plistlib.py)
for XML/binary layout cross-checking. Python is a host tool/source reference
under its own [PSF and historical license notices](https://github.com/python/cpython/blob/v3.14.7/LICENSE),
not a bundled receiver dependency; no Python implementation bodies were copied.
The installed plistlib source matches that tag after line-ending normalization;
its raw SHA256 is
`a2507c4c70e0c29eca3332917334d36f525b506ca3d61ee846626eec0804587d`.

Python serialized the new independently specified synthetic dictionaries.
They contain no captured phone information or actual pairing secrets. Local
caps, owned expanded trees, duplicate/cycle rejection, restricted XML syntax,
numeric/Unicode checks, strict response correlation, error/TLS policy and
explicit channel-release boundaries are independent implementation choices,
not claims of full Apple conformance. No external DTD/entity is loaded by the
receiver. See [the response report](../reports/lockdown-responses.md).

`lockdown_bootstrap.c`/`.h`, its tests and the extracted service-test helper
also select GPL-3.0-only. The StartSession/StartService encoders use the same
pinned idevice request fields; their independent XML fixtures contain synthetic
identity/session values and no private keys. The pre-TLS state machine, exclusive
ownership/fresh-stream gates, token-bound terminal handoff, shared timer-only
check and lack of automatic pairing/retry are local implementation policies.
No new upstream bodies, dependency, TLS code or credential records were copied.
See [the startup report](../reports/lockdown-bootstrap.md).

### Optional Lockdown TLS dependency

The new `lockdown_tls.c`/`.h`, TLS configuration and synthetic cryptographic tests
select GPL-3.0-only. The separate hosted target links
[Mbed TLS 3.6.7](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7),
commit `068ff080b369adfac81509f9b57b2afabaf82dc5`. Its release archive SHA256 is
`a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`.
Mbed TLS offers Apache-2.0 OR GPL-2.0-or-later; this integration selects the
latter. Bundled third-party notices remain in the unmodified extracted release;
redistribution must retain applicable source/license obligations. No source
archive or compiled crypto binary is committed here.

Preparation downloads only the pinned official archive into ignored storage and
checks its hash. The adapter uses documented Mbed TLS APIs, without copying
implementation bodies. It does not reproduce the pinned idevice reference's
disabled peer verification. Tests generate ephemeral synthetic credentials in
RAM and never load/save actual trust records. See the
[TLS report](../reports/lockdown-tls.md) for exact policies and portability limits.

The subsequent `lockdown_client.c`/`.h`, `carkit.c`/`.h`, hosted integration tests
and extracted shared TLS fixture also select GPL-3.0-only. They reuse the same
pinned LIVI/idevice service sequence and Mbed TLS dependency. Owned protected
RPCs, exact-token/ACK gates, explicit service policy, same-identity checks and
two-stream lifetime handling are local implementation choices; no new upstream
bodies or actual pairing credentials were copied. See
[the carkit startup report](../reports/carkit-startup.md).

The later `carkit_iap2.c`/`.h`, integrated tests and shared carkit test fixture
select GPL-3.0-only. They compose the existing GPL-3.0-or-later iAP2 engine with
the GPL-3.0-only carkit layers and the same pinned Mbed TLS dependency. No new
upstream bodies or credentials were copied. Drain accounting, ownership checks
and pre-I/O deadline integration are local policies. The accessory-auth provider
in tests remains explicitly synthetic, unlike the real TLS cryptography. See
[the integrated iAP2 report](../reports/carkit-iap2.md).

The separate `rtsp_wire.c`/`.h`, `rtsp_channel.c`/`.h` and synthetic tests select
GPL-3.0-only. They use the same pinned LIVI tree for projection framing/sequence
reference and RFC 2326 for RTSP length/CSeq cross-checks. No upstream code bodies
or device captures were copied. Strict ASCII/length/header limits, transactional
encoding, serial tokens, caller-owned plaintext retirement, explicit handoff and
deadline policies are local implementation choices. No new dependency or actual
credential was introduced. See [the projection-control report](../reports/projection-control.md)
for source links and exact Git blobs.

### Optional identity/pair-verification crypto

`pair_tlv.c`/`.h`, `pair_crypto.c`/`.h`, `pair_verify.c`/`.h`, tests and the
independent vector checker select GPL-3.0-only. The same pinned LIVI source is
the protocol reference; no implementation bodies were copied. The optional
`carplay_pairing` target uses [Monocypher 4.0.3](https://github.com/LoupVaillant/Monocypher/releases/tag/4.0.3),
commit `ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f`, selecting BSD-2-Clause from
its dual BSD-2-Clause / CC0-1.0 offer. Original source notices and the release's
full `LICENCE.md` / `AUTHORS.md` are retained in ignored prepared storage.
Any distribution must retain the applicable dependency notices; no source
archive or compiled crypto binary is currently committed.

The archive SHA256 is
`8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`.
Preparation checks the archive and six used files without overwriting existing
files; CMake checks the four compiled source/header hashes. Release/tag source
comparison differs only in the release version marker. Local validation,
lifetime, trust lookup and key-handoff policies are not supplied by Monocypher.

Public RFC 8032/7748/8439 vectors and an independently specified synthetic
pairing transcript exercise actual cryptography. The optional PyCA checker
uses cryptography 50.0.1 with cffi 2.1.1 / pycparser 3.0 in an ignored host venv;
these packages retain their own installed notices and are not linked, bundled
or required by the receiver. No actual credentials or captured phone traffic
are used. See [the pair-verification report](../reports/pair-verification.md)
for exact sources, commands, dependencies and the ARM runtime limitations.

`control_cipher.c`/`.h`, `projection_control.c`/`.h`, shared test helpers, tests
and the independent control-vector checker also select GPL-3.0-only. They use
the same LIVI commit for record layout and plaintext-M4/encrypted-control order,
and the same pinned Monocypher dependency. No upstream implementation bodies,
device captures or actual credentials were copied. Bounded storage, explicit
drain ownership, exact route matching, generation/token checks, deadlines and
terminal counter exhaustion are local policies. Twelve public synthetic values
are independently reproduced with the existing host-only PyCA environment.
See [the encrypted-control report](../reports/encrypted-control.md) for Git blobs,
wire evidence, validation commands and remaining target limitations.

`pair_srp.c`/`.h`, `pair_setup.c`/`.h`, `pair_setup_channel.c`/`.h`, setup tests
and the independent setup checker select GPL-3.0-only. They use the pinned LIVI
SRP/setup protocol profile and RFC 5054's 3072-bit group, without copying upstream
implementation bodies. The optional `carplay_enrollment` target links the
existing Monocypher and Mbed TLS `mbedcrypto` dependencies under the selections
above; it adds no new dependency version. The checked MPI API takes its
secret-exponent path; target side-channel/heap/runtime suitability remains
unverified. Explicit enrollment authorization, candidate approval, insert-only
durable-commit contract, ownership transfer and deadline policies are local.
Music Assistant's Apache-2.0 AirPlay source was inspected only to cross-check
integer serialization; no bodies or permissive verification behavior were
copied. Python integer/PyCA fixtures are public synthetic data, not phone
captures. See [pair-setup.md](../reports/pair-setup.md) for source pins and limits.

`mfi_sap.c`/`.h`, `projection_auth.c`/`.h`, their tests and the independent MFiSAP
checker select GPL-3.0-only. The same pinned LIVI `authSetup.ts`, `mfiSigner.ts`,
`crypto.ts` and `cpStack.ts` are protocol references; no implementation bodies
were copied. The optional `carplay_projection_auth` target uses the already
pinned Monocypher and Mbed TLS SHA/AES APIs with the license selections above.
Enrollment also links that target for its explicit same-transport transfer.
No new dependency, real MFi certificate, private key, signature capture or default
signer is distributed. Opaque synthetic provider results are test-only; independent
PyCA/hashlib values validate actual ECDH/hash/AES/framing, not Apple licensing.
Unknown-major rejection, exact routing, output/drain ownership, deadlines and
bounded provider output are local policies. See [mfi-sap.md](../reports/mfi-sap.md)
for source blobs, validation commands and the remaining hardware/provider boundary.

`projection_receiver.c`/`.h` and its tests select GPL-3.0-only. The initial router
composes the existing locally implemented enrollment/verification/MFi owners;
the same pinned LIVI connection dispatch is a protocol reference, with no copied
implementation body or new dependency. Explicit permission, exact initial routes,
stable public tokens and downstream-drain transfer are local ownership policies,
not conformance claims. All new end-to-end tests use public synthetic credentials
and an in-memory trust-provider simulation. See
[receiver-routing.md](../reports/receiver-routing.md).

`projection_info.c`/`.h`, its synthetic fixtures/tests and independent Python
checker select GPL-3.0-only, as do the receiver extensions and projection-only
plist decoder changes. The same pinned LIVI `getInfo.ts`, `hid.ts`, `bplist.ts`
and `cpStack.ts` provide schema/format references; Apple CoreFoundation and
CPython plistlib were read only to cross-check binary serialization. No upstream
implementation bodies, usable HID descriptors/images, actual identity or
credentials were copied. The encoder and decoder changes are local code; no new
receiver dependency or version is introduced. Runtime availability, explicit
plaintext opt-in, exact routes, finite-real/node limits and output/deadline
ownership are local policies, not Apple conformance claims. The public synthetic
test profiles do not establish actual hardware capabilities. Exact source blobs,
independent checks and limitations are in
[projection-capabilities.md](../reports/projection-capabilities.md).
