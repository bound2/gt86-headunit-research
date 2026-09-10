# Explicit projection capabilities and bounded discovery

Date: 2026-09-10. CarPlay progress Step 61; follows
[receiver-routing.md](receiver-routing.md).

Follow-up: [Step 62](projection-session.md) now implements typed session/resource
ownership in this receiver. Counts and size measurements below describe Step 61.

## Step 1 - Add capability responses without claiming a working receiver

`projection_info` now encodes a typed, caller-supplied capability profile as a
bounded binary plist. The existing `projection_receiver` can optionally own
exact `/info` requests before pairing and over verified encrypted control.
Its responses use the same public tokens, output ownership and downstream-drain
barriers as pairing and MFi authentication.

This is host-side protocol implementation, not an installable CarPlay update.
No actual display/audio/input backend, listener, phone, authentication chip,
head unit, real trust record, firmware image or update USB is used by this step.
Software-only CarPlay on the owner's factory hardware remains unproven.

## Step 2 - Pin the schema and independently check the binary format

The protocol reference remains LIVI commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`:

| Source | Git blob | Use |
| --- | --- | --- |
| [getInfo.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/getInfo.ts) | `4a6fc95d3deabc4c24731e909d1aed2bff7911ec` | Identity, capability, display, audio, mode and optional OEM fields |
| [hid.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/hid.ts) | `c414c38900ccbdd3f28d2cdf8683084855629afc` | HID metadata and display association |
| [bplist.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/bplist.ts) | `3329659c7506cac6a51372d64c06a60fc3a2b963` | Binary object layout and negative-number encoding |
| [cpStack.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts) | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` | Request dispatch and full-profile response behavior |

The reference describes main/alternate display types 110/111 and screen/audio
resource IDs 1/2. Its latency entries need not use the same audio-type label as
their stream's format entry; local validation therefore requires a matching
stream, not an invented exact label match. Its fixed feature mask, identities,
dimensions and descriptors are not factory-head-unit evidence or production
defaults in this implementation.

The binary layout was also cross-checked against Apple's
[CoreFoundation binary plist source](https://raw.githubusercontent.com/apple/swift-corelibs-foundation/main/Sources/CoreFoundation/CFBinaryPList.c)
(mutable main branch, inspected on the date above) and
[CPython 3.13.7 plistlib](https://raw.githubusercontent.com/python/cpython/v3.13.7/Lib/plistlib.py).
These are read-only format references, not new receiver dependencies or copied
implementation bodies. The independent local checker actually runs Python
3.14.7; the reference tag does not describe that installed interpreter.

## Step 3 - Require explicit, structurally consistent profiles

[projection_info.h](../src/carplay/projection_info.h) exposes the typed profile
and pure encoder. It has no heap allocation, runtime discovery, default identity,
default feature mask, provider or I/O. Measurement validates the entire profile
and returns the required size; any validation or capacity error leaves output
untouched and reports zero bytes written.

The current local bounds are:

| Area | Bound and consistency policy |
| --- | --- |
| Identity | Explicit printable ASCII names/version/model/manufacturer, 1-64 bytes; explicit device MAC and optional Bluetooth MAC |
| Displays | Up to two, ordered main/alternate; unique canonical lowercase UUIDs; 1-16,384 pixels per dimension, 1-10,000 physical millimeters, 1-240 FPS |
| View/safe areas | Nonempty contained rectangles; safe area requires a view area; optional ASCII initial URL up to 256 bytes |
| HID | Up to four; unique lowercase hexadecimal IDs without redundant leading zeroes, advertised display association, 1-1,024 opaque descriptor bytes |
| Audio | Up to nine format and nine latency entries; streams 100-102, explicit masks and audio types, no duplicate stream/type entries |
| Resources | At most screen and audio; their presence must match advertised display/audio presence |
| Extensions | Up to eight distinct explicit ASCII names, each 1-64 bytes |
| OEM icons | Up to two, each 1-8,192 opaque bytes and explicit 1-4,096 dimensions; require an explicit label |
| Wire | At most 640 internal objects and 32,768 bytes |

Feature flags, format masks, primary input, mode/arbitration values and optional
HEVC support require external backend validation. Descriptor bytes and icons
are not parsed to prove they are valid HID reports or image files. Structural
validation alone does not establish any capability's real availability.

Serialization builds its own bounded object table; callers cannot supply an
arbitrary graph. Dictionaries emit separate key/value references and use wider
references/offsets when needed. Positive integers through `UINT64_MAX` retain
their sign, using a 16-byte positive representation above `INT64_MAX`.
The reference's `speechMode = -1` is encoded as an eight-byte real, matching its
JavaScript writer rather than silently changing the wire type to an integer.

## Step 4 - Keep the Lockdown parser strict while supporting projection data

The full synthetic profile exposed a concrete integration mismatch: it has
310 objects and a real-valued speech mode, while the existing Lockdown decoder
accepts at most 256 objects and no reals.

The separate `service_plist_decode_projection` API now accepts binary `bplist00`
with at most 640 objects/expanded nodes and finite 32/64-bit IEEE reals. Real
values retain their raw bits in a distinct node type; they are never coerced to
integers or booleans. NaN/infinity, unsupported real widths, XML and the existing
unsupported date/UID/set extensions are rejected. Depth remains 16 and the
decoder's byte limit remains 65,536. It introduces no floating-point execution.

The existing `service_plist_decode` API still limits objects/nodes to 256 and
rejects every real value. Existing Lockdown schema validation is not loosened.
Both APIs retain caller-owned bounded storage and publish no partial document
on failure. The `/info` route imposes its narrower 32,768-byte body/scratch limit;
caller staging/request/scratch capacity can impose an even smaller bound.

## Step 5 - Enable one optional route with a runtime availability contract

After receiver initialization and before any initial input, call
`projection_receiver_enable_info` once with an immutable profile, separate
scratch buffer and explicit synchronous `available` callback. Initialization
and enablement perform no provider I/O. Invalid configuration leaves owner,
time and buffers unchanged. Scratch must hold the encoded profile; the normal
response buffer must hold that profile plus 256 bytes of framing allowance.
All borrowed profile data, provider context and scratch remain alive and
disjoint until close; the owner is serial and noncopyable.

The trusted callback must attest that all described features, descriptors,
formats, modes and resources currently have backend support. Tests supply an
explicit synthetic attestation; there is no default or real driver-backed
implementation. The callback may not reenter, mutate the profile, retain
borrowed pointers or perform unbounded I/O. Refresh monotonic time afterward,
before output. Resource loss after a response cannot retract already sent
bytes: an eventual frontend must close or revalidate subsequent session work.

Exact `GET /info` accepts only an empty body. Exact `POST /info` accepts an empty
body or a bounded decoded binary-plist dictionary; a nonempty body requires a
unique `Content-Type: application/x-apple-binary-plist`. A supplied content type
on an empty request must also match. Invalid method, type, duplicate header,
malformed dictionary or unauthenticated encrypted record cannot call availability.
Request selectors are not implemented: a valid request receives the full
configured profile, as in the pinned reference. Unknown URI variants are not
broadened into this route.

After validation and encoding, availability runs once per request. Success
queues a correlated 200 binary-plist response in the existing owned output and
clears scratch. Failure closes without a fake success or automatic retry.
An application cannot replace an internally pending info reply. Encrypted info
can run before or after MFiSAP; metadata delivery neither authenticates a phone
nor allocates or authorizes media. Other encrypted application requests remain
held for explicit handling. Disabling this optional route preserves that policy.

Plaintext discovery additionally requires `allow_initial = 1`. The default is
disabled, with a configured limit of four initial replies and a 60-second total
budget; accepted configuration ranges are 1-16 replies and 1-60,000 milliseconds.
The total budget starts at receiver initialization, is not renewed by discovery,
and also bounds a held initial authorization request. Existing per-phase budgets
still apply. Selecting setup or verification starts the existing child's budgets.

The initial reply must fully drain before returning to routing or selecting
pairing. There is no `/info` interleaving inside enrollment or pair verification.
Following input remains with the caller, and public response tokens increase
across discovery, enrollment, verification and encrypted replies. Supporting
this optional sequence is not evidence that a real iPhone requires it or that
all phone discovery variants are now supported.

## Step 6 - Verify small, full and large profiles independently

All identities, keys, descriptors and icon bytes in these tests are public
synthetic data. HID/icon byte patterns are deliberately opaque, not usable
device descriptors or images. The full fixture's reference-like feature mask
and the large fixture's all-bits-set mask are test inputs, not deployable offers.

| Synthetic profile | Encoded bytes | Objects |
| --- | ---: | ---: |
| Minimal metadata, no resources | 580 | 50 |
| One display, four HID entries, nine audio/latency entries | 4,056 | 310 |
| Two displays, long descriptors, two large icons and optional fields | 25,777 | 415 |

The third profile is large, not the largest possible combination of every
allowed field length. [check_projection_info.py](../scripts/check_projection_info.py)
executes only the explicitly supplied local fixture executable, reads three
wire values and compares Python `plistlib` results to independently constructed
expected objects. It checks exact types, dictionary order and values, including
real `-1.0` and positive `UINT64_MAX`, then reserializes independently. It writes
no files and uses no network or credentials.

Four codec groups cover deterministic encoding, 42 invalid profiles, every short
capacity of the minimal profile, integer-width boundaries, both decoder modes,
finite-real bit patterns, truncated/nonfinite/unsupported reals, 640/641-node
limits, canaries and 600 deterministic full-profile mutations/truncations.
The receiver suite now has ten groups: its seven existing lifecycle groups plus
discovery/encrypted routing, policy/error and configuration/budget groups.
They include real verification and enrollment handoffs, full-profile POSTs
split over cipher records, a 25,777-byte plaintext POST and an encrypted response
spanning more than 100 records, retained tails, provider failure, scratch clearing,
stale keys, blocked response replacement and exact nonrenewable deadlines.

Commands used successfully:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py -v
python -B scripts/check_projection_info.py build/crypto/Release/projection_info_tests.exe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
```

All 32 combined, 20 ordinary and 23 TLS-only CTest suites and 25 Python
regressions pass. All three independent capability profiles pass. Sixteen
protocol/capability sanitizer suites and seven hosted TLS/carkit/enrollment/
file/MFi/router suites pass ASan/UBSan, with both crypto dependencies instrumented
in the hosted check. Changed C99 modules and C++ tests pass strict Clang warnings;
Clang static analysis reports no finding in the three changed C99 modules.
The twenty-unit import-free ARM core check passes after the decoder extension.

Dependency builds still report Mbed TLS's CMake compatibility deprecation and
MSVC C4200 for its zero-sized array in `include/psa/crypto_struct.h:254`.
The existing Windows file suite skips privileged symbolic-link creation on
this host but passes actual directory-junction rejection. Neither is hidden as
a successful target test. No dependency version was changed.

On x64, the profile occupies 1,224 bytes and the receiver owner 9,696 bytes,
excluding caller buffers and dependency allocations. Clang `-O2` reports
individual static frames of 28,392 bytes for `projection_info_encode`, 20,712
for `info_reply`, 9,880 for receiver initialization and 1,272 for receiver feed.
These are individual function measurements, not maximum combined call-stack
usage. Nested work requires substantial additional stack planning. The new
capability library and hosted receiver are excluded from both existing ARM
portability claims; no QNX stack size, timing, linking or execution is proved.

## Step 7 - Continue with typed session/resource negotiation

Typed `SETUP`/`RECORD`/`TEARDOWN`, capability validation, derived keys and
allocation/rollback ownership are implemented in [Step 62](projection-session.md).
Its resource provider remains synthetic, not a real endpoint/backend. Next
implement actual peer-bound timing/event/stream services and media/input backends;
synthetic availability must not become a production default. Actual phone interoperability,
approval/rate limiting, target persistence/revocation and bounded provider
scheduling still need implementation and validation.

Actual Go-module identity, installed-version execution/recovery, native USB-network
ownership and a compatible existing Apple authentication-chip interface remain
unresolved. These PC results are not instructions to install or flash the car.
