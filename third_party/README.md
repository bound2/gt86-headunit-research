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
