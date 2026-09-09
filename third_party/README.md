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
