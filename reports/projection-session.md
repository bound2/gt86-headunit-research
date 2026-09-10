# Typed projection sessions and resource ownership

Date: 2026-09-10. CarPlay progress Step 62; follows
[projection-capabilities.md](projection-capabilities.md).

## Step 1 - Implement the session lifecycle inside the receiver

The existing receiver now optionally owns typed encrypted `SETUP`, `RECORD` and
`TEARDOWN` requests after pair verification and local MFi reply drain. A new
`projection_session` child validates requests against the exact profile used for
`/info`, derives resource-specific keys, owns provider leases and replies with
validated provider port results. It handles initial session setup, all six
supported stream types, playback start, partial stream removal and full teardown.

This is implemented code, but **the endpoint provider used in tests is synthetic**.
No real listener, timing/event server, media decoder, input driver or QNX backend
was added in this step. No real phone, chip, head unit, trust record, firmware or
update USB was accessed. CarPlay on the owner's factory unit is not installable.

## Step 2 - Check the source sequence and key domains

The local read-only LIVI checkout is clean at commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Relevant source blobs were checked:

| Source | Git blob | Reference use |
| --- | --- | --- |
| [cpStack.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts) | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` | Session/stream replies, events, audio/screen keys and teardown |
| [iapTunnel.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/iapTunnel.ts) | `8f60416ff09170c5f8809cbad29372685714f0e9` | iAP seed-based receive-key derivation |
| [keepAliveServer.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/keepAliveServer.ts) | `38045f73097e8d3602db4287293143d42d78293b` | UDP low-power endpoint, unlike TCP events |

The reference distinguishes session timing/event setup from stream setup. It
echoes audio connection IDs, returns an iAP stream ID, and derives event keys
differently from media/tunnel keys. Its coercions, guessed audio defaults,
unknown-command success, ignored stream failures and malformed-body full-teardown
fallback are not adopted as local validation/authorization policy.

The local key mapping uses the verified pairing shared secret and the existing
Monocypher-backed HKDF-SHA512 adapter:

| Resource/direction | Salt | HKDF info |
| --- | --- | --- |
| Event receive | `Events-Salt` | `Events-Read-Encryption-Key` |
| Event send | `Events-Salt` | `Events-Write-Encryption-Key` |
| Screen/audio/iAP receive | `DataStream-Salt` plus unsigned decimal connection ID/seed | `DataStream-Output-Encryption-Key` |
| Main-audio microphone send | Same stream salt | `DataStream-Input-Encryption-Key` |

Output is 32 bytes per enabled direction. Event directions are not control-key
swapped. Unsigned conversion preserves zero, `2^63` and `UINT64_MAX`, without
JavaScript-number precision loss, leading zeroes or signed conversion. Unused
write keys remain zero. Key temporaries are wiped after provider return.

## Step 3 - Require explicit configuration and authenticated ownership

Call `projection_receiver_enable_session` once, after enabling info but before
any initial input/discovery. Enablement validates without I/O or changing caller
buffers. Wrong generation, invalid configuration, partial initial input, a prior
discovery response or repeated enablement cannot silently attach a new child.
The same immutable profile, availability callback/context and separate info
scratch are reused serially. A normal response buffer of at least 2,304 bytes
is required before enabling this route.

Only encrypted application requests from this receiver's actual verification
exchange reach the child, and only after `MFI_SAP_DONE`. A public key/secret
cannot be attached through the receiver API. This is a local sequencing gate,
not an assertion that the phone accepted an MFi credential. Existing enrollment
permission, separate candidate approval and durable-commit requirements remain.

Configuration supplies explicit enabled-feature bits for view areas, iAP,
HEVC and alternate screen. HEVC/alternate screen must fit the info profile;
the provider must additionally attest implementation of every enabled feature.
There is no production feature default, default port or default backend.

The first session setup binds a 1-256-byte opaque request target. All subsequent
session commands must match it exactly. This permits origin-form and absolute
RTSP targets already accepted by the framing layer without interpreting either
as a network destination. Backend context must instead bind the actual control
peer and connection generation, reject unrelated/duplicate transport owners and
never reset authenticated framing counters under reused keys after reconnect.

## Step 4 - Validate complete typed requests before allocation

Bodies use the bounded projection binary-plist decoder: at most 32,768 bytes,
640 expanded nodes and depth 16, with caller scratch/request limits potentially
lower. There must be one binary-plist content type for a nonempty body. A supplied
type on an empty request must also match. Duplicate decoded keys, malformed
containers and type coercions cannot become successful setup requests.

| Request | Required local semantics |
| --- | --- |
| Initial `SETUP` | No `streams` field; integer timing port 1-65,535; optional timing protocol must be `NTP`; low-power request must be a bool and advertised |
| Stream `SETUP` | Nonempty array, at most six entries, one entry per type, all preflight before allocation |
| Screen 110/111 | Advertised matching display, explicit unsigned 64-bit connection ID; alternate screen also requires enabled feature |
| Audio 100/101/102 | Explicit audio type and single nonzero 32-bit format bit present in advertised output mask; explicit unsigned connection ID |
| Main-audio microphone | Nonzero peer data port only for type 100; same format bit advertised for input; frames per packet 1-65,535 |
| iAP 130 | Enabled iAP feature, matching iAP client UUID (hex letter case ignored) and explicit unsigned 64-bit seed |
| `RECORD` | Empty body, initial setup and at least one stream ready, not already recording |
| Partial `TEARDOWN` | Nonempty typed stream list referring to live streams; optional connection ID must match |
| Full `TEARDOWN` | Empty body or valid dictionary without a stream list; malformed input is never substituted for this request |

Audio latency, if supplied, is an integer from 0 to 60,000 milliseconds.
Optional initial phone name/model/deviceID/macAddress/sessionUUID fields must
be strings of at most 256 decoded UTF-8 bytes. They are untrusted metadata, not
controller trust identity or destination addresses. Other bounded unknown
metadata is ignored, not granted as functionality. Explicit `eiv`/`ekey`/`et`
negotiation is unsupported in this verified-shared-secret profile; PTP and other
timing modes are not implemented. This is a documented protocol subset, not
evidence of interoperability with every iPhone session variant.

One live stream per type is allowed. A 128-entry lifetime ledger retains every
stream connection ID and iAP seed, including removed streams; reuse across types
or after teardown fails before provider allocation. Exhaustion closes instead
of reusing a key/counter domain. Full session teardown ends the connection after
its reply drains; it cannot restart an event channel with the same keys in place.

## Step 5 - Own allocation, rollback, start and cancellation

[projection_session.h](../src/carplay/projection_session.h) defines the explicit
resource provider contract. `open` must reserve all endpoints for one resource,
validate actual format/support, install copied directional keys and return real
bound ports with a nonzero unique lease. Session results contain timing/event
ports and a low-power port only when requested. Audio needs data/control ports;
screen needs a data port; iAP additionally needs an explicit nonzero stream ID.
Fields irrelevant to the resource must be zero. Numeric validation does not
independently prove that a returned port is actually listening.

Port numbers alone do not identify an endpoint's transport/address ownership.
In particular, the reference's low-power socket is UDP while events use TCP;
an earlier cross-field numeric-inequality assumption was removed. Equal port
numbers are allowed when the actual backend can reserve the required services;
the backend must reject real binding/protocol conflicts. Tests cover this boundary.

On any provider result, including failure, a nonzero unique lease transfers
cleanup to the owner. If it returns no lease, the provider must already have
cleaned partial work. Invalid/duplicate results fail closed; a duplicate is not
recorded twice and its already-owned resource is closed once. Any failed setup
closes the entire session, including previously prepared streams, instead of
publishing a partially successful stream array. Leases close in reverse order.

Listening, required timing synchronization and event transport may operate
during preparation. Media playback and unsolicited input forwarding wait for
`start`. Initial `RECORD` invokes start only after its exact outer reply fully
drains. Streams added while recording start only after their own setup reply
drains. Failed start closes all leases, including partially started resources.
Local reply drain/start is not phone acceptance or proof of video/audio output.

Valid teardown closes selected leases before queuing its response and does not
depend on a successful availability check. EOF, authentication/framing errors,
provider failures, response construction failure, output/held deadlines and
explicit close also release owned resources. Availability is checked once for
each valid setup/record request, not repeatedly under output backpressure.
The serial synchronous callbacks must be bounded, cannot reenter/retain argument
pointers, and must finish cancellation without failure. Refresh monotonic time
after callbacks before further output or transport work.

Responses use a private fixed-schema plist writer, not a caller-supplied opaque
success body or arbitrary graph. Its six-stream schema fits the fixed 80-object,
24-child-per-container and 2,048-byte storage bounds, with explicit overflow
guards even for these internally constructed schemas. Audio IDs are echoed as
full unsigned values. The receiver copies the response into its normal encrypted
queue and wipes intermediate output. The application cannot replace an internal
session reply; public tokens and retained authenticated tails remain owned by
the existing receiver across discovery, enrollment and verification transfers.

## Step 6 - Test schemas, cryptography and the enclosing receiver

All endpoint leases/ports, identities and credentials here are public synthetic
fixtures. The provider records allocation/start/close calls without opening any
sockets or performing media I/O. The new standalone suite has four groups:

1. All six stream types, both event directions, microphone direction, delayed
   record/start, partial teardown, replacement stream and full teardown.
2. Typed invalid input, every truncation of initial setup, tiny scratch, oversized
   bodies, UUID case, state/target/ID reuse and ledger exhaustion, plus 600
   deterministic stream-dictionary mutations/truncations.
3. Failure at each of seven allocation positions; invalid, absent and duplicate
   leases; invalid endpoint fields; availability failure; initial/replacement
   start failure; cleanup even when availability is lost.
4. Transactional configuration and advertised display/audio/input/feature gates.

The receiver suite grows from ten to twelve groups. New exchanges use actual
SRP/verification/control encryption with synthetic trust/MFi/resource providers,
covering both enrollment and known-controller routes through setup, all streams,
record, stream replacement and teardown. They check plaintext and pre-MFi denial,
fragmented encrypted dictionaries, stale/premature callbacks, blocked response
replacement, retained same-record tails, authentication failure, failed/late
drain, EOF, exact ownership cleanup and late enablement rejection.

[check_projection_session.py](../scripts/check_projection_session.py) independently
reproduces all 42 committed public fixture values with Python `plistlib`, checks
16 directional key values with standard-library HMAC-SHA512, and decodes three
C-generated replies. Reply bodies measure 178 bytes for session setup, 450 for
all streams and 158 for the replacement audio stream. The latter checks
`UINT64_MAX` correlation and key derivation. Zero unused directions are included
in the 16 values; they are not 16 independently active cryptographic channels.
The script reads supplied files/runs the explicit trusted fixture executable;
`--fixtures` prints only, and neither mode writes files or uses network access.

Commands used:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py
python -B scripts/check_projection_session.py build/crypto/Release/projection_session_tests.exe tests/fixtures/projection-session-vectors.txt
python -B scripts/check_projection_info.py build/crypto/Release/projection_info_tests.exe
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
```

All 33 combined, 20 ordinary and 23 TLS-only CTest suites and 25 Python
regressions pass, as do the independent session/capability checkers. Eight hosted
TLS/carkit/enrollment/file/MFi/session/router suites pass ASan/UBSan with both
crypto dependencies instrumented. Changed C99 modules and C++ tests pass strict
Clang warnings; static analysis reports no finding in either changed C99 module.
The initial test build caught an oversized capability fixture in the smaller
router buffer and a throwing-destructor warning; the integration fixture now
omits the separate large-icon stress data, and the test destructor explicitly
declares its exception contract. Existing large capability tests are preserved.
Latest validation refinements are recompiled and rerun against the instrumented
dependencies. The existing dependency CMake deprecation and Windows privileged-symlink skip
remain; actual directory-junction rejection passes. No dependency version changed.

The session child occupies 3,840 bytes and the receiver 13,536 bytes on x64,
excluding caller scratch and dependency allocations. Individual Clang `-O2`
static frames include 20,680 bytes for session parse, 4,168 for reply encoding,
13,720 for receiver initialization and 3,912 for session enablement. These are
not combined maximum call-stack measurements or QNX stack/timing guarantees.
The new hosted session target and receiver remain outside both prior ARM claims;
those portability checks were not expanded by this step.

## Step 7 - Implement real endpoint services and media paths next

Next provide actual peer-bound endpoint allocation and cancellation, initially
with local-loopback integration tests: timing synchronization, encrypted event
transport and stream receivers must back the advertised ports/features. Wire
the derived keys into bounded record/packet owners, then implement video/audio/
microphone/iAP handling and actual display/input/audio backends. The current
synthetic provider must not become a default production implementation.

Target execution/recovery, actual Go-module identity, native USB-network ownership,
compatible existing Apple authentication-chip access, target persistence,
approval/rate limiting and real-phone validation remain unresolved. No vehicle
installation or firmware modification is authorized or proved by these tests.
