# CarPlay session-start investigation and implementation

Updated: 2026-09-09. Continues the
[bounded transport adapter](transport-adapter.md) and
[CarPlay progress, Step 36](carplay-progress.md#step-36---verify-portability-and-define-the-next-session-task).
The selected goal remains software-only CarPlay on the factory hardware.

## Current result

Follow-up: the startup codecs/reply work is published as `ccd89dd`.
The [subsequent startup-order implementation](startup-order.md) adds the explicit
identification-first profile proposed below. This report otherwise records the
startup-message checkpoint and its original sequencing gap.

Four CarPlay-related control-message codecs and an explicit wired-start reply
helper are implemented and tested on the PC. The helper queues receiver metadata
only after a valid wired offer and accepted authentication and identification.
It does not advertise capabilities, connect to a phone, open networking, perform
USB reconfiguration or start media. No installable CarPlay update exists yet.

The pinned reference exposes two important gaps: its wired route needs USBmux,
pairing and USB networking, while our stock-firmware trace established an iPod
HID route; it also identifies the accessory before authenticating, whereas our
current experimental profile requires authentication first. Neither gap is
resolved by adding these codecs.

## Step 1 - Publish the previous checkpoint

Committed the bounded transport pump and its lifecycle tests as
`cecd732da9753860f5581257fd6dbca9dab6e7ff`,
`Add bounded byte-stream transport pump and lifecycle tests`.

Added `origin` for
[bound2/gt86-headunit-research](https://github.com/bound2/gt86-headunit-research)
and pushed `master` with upstream tracking. A read-only remote-ref check returned
that same full commit ID. No force push was used. Raw firmware, extracted vendor
files, the reference checkout and generated build products remain ignored.
The implementation below is the local continuation after that published checkpoint.

## Step 2 - Pin the source evidence

Reference: LIVI commit `a76553fc941dcf378dd55c04da56aaf3d6911e08`, already present
at `build/livi-reference`. The checkout is sparse: `livi-runtime` is not
materialized, but its sources are present in the Git tree and were read with
`git show`. Missing working-tree paths must not be mistaken for absent source.
The pinned reference worktree was not modified and no upstream service was run.

| Source | Git blob ID |
| --- | --- |
| `iap2-csm/src/messages/car_play.rs` | `1d6a5b3e764c3d42213417f1436cf55e4fa8be98` |
| `iap2-csm/src/lib.rs` | `87cff5f1fb1f6cf56e2ebd4503db5dca0dc6d346` |
| `livi-runtime/src/bringup.rs` | `84dbb71e485d60b0d6805e6705f6bf38a5df4ca7` |
| `livi-runtime/src/ident.rs` | `6c80dee3c9daebb90691c55d2c6da69228ccc364` |

Paths above are relative to `native/livi-helperd/crates/`. Git blob identities
avoid differences caused by checkout line endings. Read-only reproduction:

```powershell
git -C build/livi-reference rev-parse HEAD
git -C build/livi-reference sparse-checkout list
git -C build/livi-reference show a76553fc941dcf378dd55c04da56aaf3d6911e08:native/livi-helperd/crates/livi-runtime/src/bringup.rs
git -C build/livi-reference show a76553fc941dcf378dd55c04da56aaf3d6911e08:native/livi-helperd/crates/livi-runtime/src/ident.rs
```

Message fields come from the pinned
[CarPlay schemas](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/messages/car_play.rs)
and [CSM encoding macros](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/lib.rs).
These are implementation references, not an Apple conformance specification.
Provenance and GPL-3.0-or-later licensing remain in
[third_party/README.md](../third_party/README.md).

## Step 3 - Trace the actual wired startup path

The reference's dependencies are broader than a raw HID byte stream:

1. Select the phone's CarPlay USB configuration and open its USBmux transport.
   The Linux implementation includes phone re-enumeration/configuration writes;
   these routines were inspected only, never executed here.
   [Device setup](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-usbmux/src/device.rs),
   [Linux configuration](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-usbmux/src/linux.rs).
2. Establish or reuse trust pairing, start a lockdown session and request
   `com.apple.carkit.service`. Connect its returned USBmux port, using TLS when
   the service response requests it. Pairing records and actual device access
   are outside this continuation; no phone or pairing files were accessed.
   [Carkit channel](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-wired/src/carkit.rs).
3. Provide a separate USB network path for audio/video. The wired helper starts
   an NCM bridge as well as opening the carkit channel; the iAP2 channel alone
   is not the media transport. Its OS-specific setup is not a QNX backend.
   [Wired helper](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/bin/livi-helperd/src/wired.rs).
4. On the iAP2 channel, the runtime performs identification, then authentication,
   then power/subscription setup. Its message loop receives CarPlayAvailability
   (`0x4300`) and sends CarPlayStartSession (`0x4301`). The wired builder obtains
   a local receiver IPv6 link-local address from the audio/video interface and
   supplies the configured receiver port, device identifier, public key and
   source version. These are not values to invent or copy from the phone.
   [Bringup and start builder](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/livi-runtime/src/bringup.rs).
5. The projection stack subsequently handles pairing/authentication, encrypted
   control, SETUP, RECORD and teardown, with timing/event/media endpoints.
   Sending `0x4301` is not equivalent to reaching an active media session.
   [Projection stack handlers](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts).

The runtime's identification builder declares `0x4301` as sent and
`0x4300`/`0x4e0d`/`0x4e0e` as received, along with other messages. Its wired
profile advertises a USB host component supporting iAP2 and CarPlay with an
interface-number setting. Our minimal encoder deliberately supplies none of
those components or CarPlay declarations. Do not copy its fallback interface
number or sample accessory identity into a supposed hardware profile.
[Reference identification builder](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/livi-runtime/src/ident.rs).

Inference: the stock host-only driver label alone does not rule out every
software-only route, because this reference also uses a host-based wired route.
It does not establish the GT86's port wiring, supported phone configurations,
QNX USBmux/NCM drivers or installed-version compatibility. The
[stock USB evidence](usb-transport.md) remains a different, insufficient path.

## Step 4 - Implement the bounded message subset

New source: [iap2_carplay.h](../src/carplay/iap2_carplay.h) and
[iap2_carplay.c](../src/carplay/iap2_carplay.c).

| Message | Implemented fields |
| --- | --- |
| `0x4e0e` DeviceTransportIdentifierNotification | Required Bluetooth and USB identifier strings |
| `0x4e0d` WirelessCarPlayUpdate | Required one-byte availability value, exactly 0 or 1 |
| `0x4300` CarPlayAvailability | Optional wired/wireless groups, each with optional availability and identifier |
| `0x4301` CarPlayStartSession | Wired group/address list, optional u32 port and device-ID/public-key/source-version strings |

Wireless or mixed wired/wireless StartSession is explicitly unsupported. A
wireless availability scalar is just a message codec, not wireless provisioning
or a wireless receiver. The wired codec preserves optional fields, an empty
wired group, and the port's full 32-bit wire range; operational reply gates are
stricter than this serialization schema.

The address list is **one parameter containing concatenated NUL-terminated
strings**. The pinned wired fixture contains `10.0.0.1` and `169.254.5.5` in that
one field, with port 5000. The new decoder exposes two separate borrowed views,
and the encoder reproduces the exact bytes. It does not treat the packed list
as a single string with an embedded NUL.

Local safety/compatibility policy:

- Exactly one complete CSM, at most 1024 bytes; no trailing bytes at this typed
  boundary. The existing control stream handles fragmentation/coalescing first.
- At most four addresses of 63 bytes each and nonempty printable-ASCII text of
  at most 127 bytes. Text must have its exact wire NUL terminator. These are
  conservative local limits, not established Apple limits.
- Reject unknown fields, duplicate fields, malformed nested TLVs, invalid
  booleans and inconsistent presence metadata. Upstream accepts some inputs
  more permissively; rejecting them is intentional, not proof of conformance.
- Decoder views borrow the input lifetime. Failures leave destination structs
  unchanged. Encoders build in bounded local storage before copying, leaving
  output unchanged and setting `written=0` on failure. No heap or OS calls.
- Address and identity strings remain opaque text; no IP syntax validation,
  interface lookup, key validation or automatic connection occurs. IPv6-like
  strings, including zone text, are preserved within the same bounds.

The largest supported wired profile occupies 674 encoded bytes. Callers must
provide enough endpoint reply storage; an undersized buffer is not truncated.

## Step 5 - Add an explicit, gated wired-start reply

`iap2_carplay_reply_wired_start` is called by the application between transport
polls. It is not wired into automatic dispatch or capability advertisement.

1. Require an existing held application message and an open endpoint.
2. Require accepted authentication and enabled, accepted identification.
3. Decode the held `0x4300`; require a wired group whose availability is
   explicitly present and true. Wireless-only, unavailable and malformed offers
   do not produce a reply.
4. Require one to four caller-provided addresses, a port in 1..65535, and all
   three receiver identity/key/source strings. The caller must ensure these
   describe a real listening receiver and owned network path. This function
   cannot validate that obligation or supply the corresponding private key.
5. Encode, then delegate to the existing atomic application-reply API. It owns
   a copy, releases the held request only on success, and retains existing
   monotonic-clock, buffer, ACK and reply-deadline rules.

Invalid input, unsupported offers or insufficient reply capacity retain the
held request so the application can handle it explicitly. Terminal endpoint
closure still clears state. A successful call means **queued**, not sent,
acknowledged, accepted, paired or streaming. Keep polling transport.

This helper handles one held request per call; it is not a session manager and
does not suppress future duplicate offers for an entire session. It supplies
no socket, key generation, USB command, media state or automatic retry policy.

The default minimal identification message lists still contain only
authentication/identification IDs. These new application messages are not yet
declared to a phone. Tests supply synthetic offers explicitly and do not prove
that a real phone would send one or accept our incomplete identification.

The existing authentication-before-identification order is unchanged. Adding
an explicit identification-first profile, as used by the pinned runtime, is
the next local task; this helper does not by itself solve startup sequencing.

## Step 6 - Verify codecs, integration and portability

[iap2_carplay_tests.cpp](../tests/iap2_carplay_tests.cpp) adds nine groups:

1. Four exact pinned message roundtrips; explicit wireless-start refusal.
2. Empty wired group, optional fields and full-width port preservation.
3. Text terminators, ASCII policy, packed lists and IPv6-like address text.
4. Duplicate/unknown nested fields and unsupported mixed transport starts.
5. Invalid scalars, malformed TLVs and missing required fields.
6. Every fixture truncation, trailing bytes, wrong ID/marker and oversized input.
7. The 674-byte maximum profile, every output capacity from 0 through 674,
   unchanged output on failure and over-limit metadata.
8. Invalid encoder presence/boolean metadata and text bounds.
9. Borrowed-view lifetimes/pointers and null-argument handling.

Three new [control test groups](../tests/iap2_control_tests.cpp) bring that suite
to 23 groups. They cover an explicitly enabled synthetic identity/authentication
exchange, no automatic reply, caller-metadata mutation after queueing, exact
fragmented output at a 29-byte MTU, unavailable/malformed offers, missing
acceptance, invalid operational profiles and clocks, held-request preservation,
reply-capacity failure, deadline closure and clean reinitialization. All
credentials, addresses and keys in these tests are synthetic examples.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

Results: **10/10 CTest suites**, all **six** protocol executables under host
AddressSanitizer/UndefinedBehaviorSanitizer, and **19** Python tests pass. All
**seven** C99 units compile/link to a freestanding Cortex-A8 relocatable object
with no unresolved runtime imports. The codecs add bounded stack storage, not
persistent endpoint state; the host endpoint remains 19,952 bytes and the pump
2,184 bytes, plus caller buffers. No QNX executable or installation package is
generated, and these tests are not an iPhone interoperability result.

## Step 7 - Continue with startup-order compatibility

The next bounded implementation task is an explicit identification-first
endpoint profile with synthetic peer tests matching the pinned runtime order.
Keep configuration opt-in, preserve existing profile behavior, bound both phases
with deadlines, prevent provider work before the selected phase, and test
rejection, disconnect, backpressure and reconnect reset. Update transport timer
checks if phase/deadline ownership changes.

Then design explicit, truthful transport metadata and supported-message
declarations before expecting a real CarPlay availability exchange. Do not
advertise unsupported subscriptions, guessed USB components or CarPlay flags
merely because the encoder can serialize them.

A usable receiver additionally needs real authentication compatibility, an
installed-version-matched native transport, trust pairing/network/media
implementation, display/input/audio integration, and verified execution and
recovery access. None is established by the local start-message helper. No
firmware, update USB, service setting or vehicle state was changed.
