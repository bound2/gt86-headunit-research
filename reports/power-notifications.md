# Wired power-source notifications

Updated: 2026-09-09. Continues [the identification payload audit](identification-wire-audit.md).

## Step 1 - Verify the prerequisite and reference

The preceding packed-language fix is committed/pushed as `8dae42e`; the worktree
was clean before this step. At pinned LIVI commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`, wired bringup sends PowerSourceUpdate
after identification and authentication, before its subscription messages.
It is unsolicited, so a reply-only application API could not express that step.
[Pinned bringup](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/livi-runtime/src/bringup.rs).

The message is `0xae03`: optional field 0 is a big-endian u16 available current;
optional field 1 is a one-byte charging-intent boolean. The unchanged fixture
contains 2400 mA and true. That is synthetic reference data, not the GT86's USB
rating, and it is never used as an implementation default.
[Pinned power schema](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/messages/power.rs).

## Step 2 - Implement the typed power message

New [iap2_power.h](../src/carplay/iap2_power.h) and
[iap2_power.c](../src/carplay/iap2_power.c) provide allocation-free encoding and
decoding. Exactly one CSM is accepted, with a 1024-byte input bound and a maximum
encoded length of 17 bytes. Unknown fields are unsupported; duplicate fields,
bad widths and non-boolean values are rejected. Failed operations preserve the
destination/output; failed encodes report zero written bytes.

The codec distinguishes absent fields from explicit zero current or false charge
intent. Presence values must be 0/1 and absent scalars zero. These are strict
local validation rules, not an Apple conformance result. No hardware I/O or
measurement, current fallback, charging control or provider credential is added.

## Step 3 - Add explicit unsolicited application output

`iap2_control_notify` shares validation, owned-copy, authentication/identification
gates, fragmentation, queue pressure and TX-to-ACK deadlines with the existing
reply path. It neither needs nor consumes a request. A held input view, partial
assembly and coalesced receive tails remain intact; their original deadline is
not renewed by outgoing notifications. Both output forms use one bounded queue.

Reserved authentication/identification IDs remain forbidden. Only an explicit
application call queues a notification, and it invokes no provider callback.
Disconnect clears it, and a final ACK before expiry cancels its deadline just as
for a reply. Success means queued, not received or acted upon by a phone.

`iap2_power_source_notify` additionally requires accepted identification and
both power fields explicitly supplied. Zero current is permitted. Callers must
use truthful values and declare this outgoing message in their actual identity;
this checkpoint still has only the minimal identification encoder. The helper
does not itself advertise power/CarPlay support or alter physical charging.

## Step 4 - Verify byte and lifecycle behavior

Three new codec groups bring the CarPlay/power suite to 12, including a fifth
exact pinned roundtrip. Tests cover all optional-field combinations, scalar
extremes, malformed/duplicate/unknown fields, every fixture truncation, trailing
bytes, nulls and every output capacity from 0 through 17.

Five new control groups bring that suite to 35: unsolicited ownership under
fragmentation, held-input preservation, authentication/identification/reserved-ID
gates, invalid/oversized input, independent TX/hold deadlines, immediate ACK
completion, partial/coalesced receives, disconnect/reset and typed power output
before a held CarPlay offer is answered. Existing reply tests remain unchanged.

The identification-first transport simulation now completes identification,
authentication, an explicit zero-current power notification and an application
roundtrip over three-byte reads/five-byte writes. This remains one of 17 pump
groups; neither the backend nor the peer is a physical device.

All ten CTest suites, six sanitized protocol executables, the now eight-unit ARM
portability check and 19 Python tests pass. Endpoint/pump storage remains
19,960/2,184 host bytes plus caller buffers. Reproduction:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

## Step 5 - Continue with explicit wired identification

Follow-up: power notifications are published as `52f1ec1`. The subsequent
[wired profile implementation](wired-identification.md) provides the declaration
proposed below and tightens the typed power helper to require its acceptance.

Next add opt-in USB-host transport metadata and exact implemented-message lists,
preserving the existing minimal encoder. Use explicit component identity/name,
interface number and power capability; do not copy the reference's hardware
fallbacks. Match the pinned nested-field bytes and test profile capacity,
ownership, activation and reset. This is still protocol implementation: real
USBmux/pairing/network/media, authentication, QNX integration and execution/
recovery access are unfinished. No car-side state or update USB was changed.
