# Lockdown service framing and explicit GetValue exchange

Date: 2026-09-09. Continues [the USBmux dispatcher](usbmux-dispatcher.md) and
[CarPlay progress, Step 48](carplay-progress.md#step-48---add-bounded-lockdown-service-framing).

Result: a C99 service-frame codec, explicit GetValue XML encoder and bounded
request/response channel now run over the actual dispatcher in a synthetic
peer test. The channel is not a complete Lockdown client: it does not parse
response dictionaries, pair a phone, establish TLS or start carkit. No real
device, trust record, vehicle setting or firmware was accessed or changed.

Follow-up: [Step 49](lockdown-responses.md) adds a separate bounded XML/binary
decoder and typed response helper. The framing channel itself remains opaque;
the Step 48 implementation and verification record below are historical.

## Step 1 - Pin the service dependency before implementing its framing

The existing LIVI pin is `a76553fc941dcf378dd55c04da56aaf3d6911e08`.
Its [Cargo.lock](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/Cargo.lock)
selects `idevice 0.1.65`. The crate was downloaded from the
[versioned crates.io archive](https://static.crates.io/crates/idevice/idevice-0.1.65.crate),
and its SHA256 matches that lockfile:

`7484b3a39a089068167a8ab0b3da6a05b5f6f8969daf1a893da1c7087cb2e09a`.

Archive members were checked for an expected package-root prefix and absence of
absolute/traversing paths before extraction into a fresh ignored directory.
The archive remains at `downloads/idevice-0.1.65.crate`; extracted source is at
`build/idevice-reference/idevice-0.1.65`. Neither is a build dependency.
No upstream executable, daemon, library build or phone-service call was run.

The package's VCS metadata identifies
`2bc6a05c80daaf8583884cf7f2d2563be17e6c2d`, subdirectory `idevice`, in
`jkcoxson/idevice`. Its manifest declares MIT and credits Jackson Coxson.
No LICENSE file was found in this crate; that observation is not a substitute
license grant. No implementation bodies or upstream fixture files were copied.
The new local C files and tests select GPL-3.0-only consistently with the
dispatcher. See [provenance](../third_party/README.md).

Inspected primary sources:

| Source at the pinned revision | Local file SHA256 or Git blob |
| --- | --- |
| [idevice/src/lib.rs](https://github.com/jkcoxson/idevice/blob/2bc6a05c80daaf8583884cf7f2d2563be17e6c2d/idevice/src/lib.rs) | SHA256 `f91a600f7c8429902d12dd21f7caeb0b86376088e9d199d93f269ddae818676f` |
| [idevice/src/services/lockdown.rs](https://github.com/jkcoxson/idevice/blob/2bc6a05c80daaf8583884cf7f2d2563be17e6c2d/idevice/src/services/lockdown.rs) | SHA256 `9c514d2e937d0b99f8f00d442bf765b6329c07d7fbf0c75b280b60928f638bb5` |
| [LIVI iap2-wired/src/carkit.rs](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-wired/src/carkit.rs) | Git blob `58bd611ffdc984d55eacb0bcf6f8128ed0c9b8bc` |

The versioned [published lib.rs source](https://docs.rs/idevice/0.1.65/src/idevice/lib.rs.html)
was also accessible. The checksum-verified local package, not a moving latest
version or inferred API, supplies this step's detailed evidence.

## Step 2 - Separate framing, request semantics and security transitions

The dependency prefixes XML or binary plist bodies with four big-endian bytes
containing the body length only. It reads the exact prefix and declared body.
Its generic dictionary reader interprets an Error field separately from framing.
GetValue carries Label, Request and optional Key/Domain fields.

LIVI connects Lockdown on TCP port 62078, obtains or creates a pair record, starts
a Lockdown session, requests `com.apple.carkit.service`, then opens the returned
port. Service TLS is a separate conditional upgrade before raw iAP2 traffic.
Its pairing fallback can create and save a new record automatically. This
project has not implemented or executed that fallback.

The inspected StartSession path requires EnableSessionSSL and upgrades security;
StartService obtains Port and an optional EnableServiceSSL flag. Future local
code must validate field types and port range without narrowing an unchecked
integer. Pairing, certificate generation and key-material handling need a
separate audit and explicit application policy; no reference pairing routine
was ported by this step.

These are pinned reference behaviors, not proof that this head unit can expose
the required USB transport or that an actual phone will accept the implementation.

## Step 3 - Implement bounded framing and a read-only request builder

[`lockdown_wire.h`](../src/carplay/lockdown_wire.h) defines opaque borrowed bodies
and transactional frame size/decode/encode operations. The local body limit is
1..65,536 bytes, giving frames of 5..65,540 bytes including their prefix.
Zero-length and oversized bodies are rejected before payload access/allocation.
This cap is an implementation policy, not a stated Apple limit.

Decoding consumes exactly one complete frame and leaves any coalesced tail with
the caller. Incomplete/error decoding preserves the destination view and
zeroes the consumed count; encoders preflight bounds before writing anything.
The frame layer deliberately does not recognize XML, binary plist, Request,
Value, Error or TLS contents.

`lockdown_get_value_encode` constructs only an explicit GetValue XML body.
The caller supplies a 1..64-byte label and 1..128-byte key, plus an optional
0..128-byte domain. Printable ASCII is the local subset; all five XML
metacharacters are escaped. NULL domain omits the field, while an empty domain
encodes an empty string. There is no default host identity, all-values query,
pair request, settings mutation or automatic I/O.

Four independently specified LF-terminated
[XML fixtures](../tests/fixtures/lockdown/README.md) cover a ProductType request,
synthetic response, Error response and escaped fields. ProductType's example
value is invented test data, not evidence about the owner's iPhone.

## Step 4 - Bind one explicit exchange to an owned dispatcher stream

[`lockdown_channel.h`](../src/carplay/lockdown_channel.h) binds an OPEN,
TX-drained stream at a caller-established plain-service frame boundary. Separate
caller-owned RX/TX frame buffers are required. Binding performs no callbacks.
The object is noncopyable and initialized once; only this channel may use its
bound stream's read/write/finish APIs until detach. Other dispatcher streams
and CONTROL handling remain available.

| Channel state | Allowed progression |
| --- | --- |
| IDLE | Explicitly copy/frame one request, detach ownership, or abort |
| EXCHANGE | Poll until one complete response and drained, acknowledged request |
| HELD | Borrow response with current token; explicitly release, keep polling |
| DETACHED | Original handle belongs to caller again; local close is a no-op |
| DEAD | Retain failure reason; no implicit retry, reconnect or rebind |

Each poll checks the channel deadline before one dispatcher poll, then performs
at most one bounded stream write and one exact-needed read, each at most 512
bytes. It reads only the four prefix bytes first, validates length against RX
capacity, then reads exactly the declared body. A following plist or TLS-looking
tail stays in the underlying stream. RX progresses even while request TX is
pending; a response is not published until all request bytes are physically
sent and TCP-acknowledged. Pending connection output can conservatively delay
publication further.

The response is an opaque borrowed view, not a successful RPC result. A local
token protects release from consuming a newer response. Wrong tokens do not
advance time. An idle detach returns the original stream without reading more
bytes, shutting it down or beginning TLS. It does not supply a TLS engine:
a future decrypted-stream adapter/security transition remains separate.

## Step 5 - Bound failure, ownership and timing

Exchange and response-hold budgets each default to 5,000 ms and accept explicit
values from 1..60,000 ms. The exchange budget starts when the request is queued;
partial writes, peer zero windows and trickled response bytes do not renew it.
Correct-token release at the hold deadline fails instead of extending the view.
Monotonic, nonwrapping caller time and nonwrapping local response tokens are
required.

Malformed lengths, incomplete EOF, timeout or an explicit bound-channel abort
cancel the still-current SHARED dispatcher. Other streams are closed as part of
that conservative failure policy. A stale physical/connection handle invalidates
only the old channel and cannot cancel a replacement session. Buffers are not
claimed to be securely erased. No trust records or private keys are loaded.

Applications must keep polling, including while holding a response. Channel
request/release/detach calls check their own budgets and handle lifetime; shared
transport timers are serviced by polling and dispatcher operations. Untimed
views are not a replacement for those timed calls. CONTROL is returned when
there is no held response; when both exist, callers inspect/release dispatcher
CONTROL independently.

## Step 6 - Verify the whole simulated path and record the next gap

Seventeen C++ groups cover exact XML/prefix bytes, all fixture truncations and
all split positions of the synthetic response, insufficient capacities, metadata
bounds/escaping, request copy ownership, serial tokens, opaque Error bodies,
coalesced handoff tails, request-ACK gating, malformed prefixes, incomplete EOF,
exact deadlines, zero-window backpressure, stale sessions, bounded callbacks,
other-stream/CONTROL progress and a maximum-sized service body.

The maximum case sends 65,540 service bytes across multiple mux packets while
respecting receive credit; each channel poll consumes at most 512 bytes. A
shared test-only peer fixture now supports both the unchanged dispatcher suite
and service simulations. No physical backend or upstream runtime is linked.

Verification:

1. `scripts/Build.ps1`: 15/15 CTest suites.
2. `scripts/Check-CarPlaySanitizers.ps1`: eleven protocol suites under ASan/UBSan.
3. `scripts/Check-CarPlayArm.ps1`: fourteen C99 units and a relocatable ARM link
   without runtime imports; this is not a QNX executable.
4. `python -B -m unittest discover -s tests -p test_*.py -v`: 23 tests, including
   four independent standard-library plist semantic checks.
5. Whitespace and local Markdown link checks.

Channel state is 160 bytes on the tested x64 host, plus caller frame buffers
and existing dispatcher/host/connection objects. No ARM ABI size or installed
hardware footprint is inferred from the x64 measurement.

Next implement bounded typed plist response validation, then explicit trust
policy, credential-provider/storage boundaries, TLS and carkit startup. The
current channel is directly bound to a plain dispatcher stream; TLS requires
an explicit adapter, not merely another framed message. Attach the iAP2 endpoint
only after the carkit stream and security state are established.

Actual QNX USB ownership, installed-version compatibility, Go-module identity,
authentication-chip access, network/media/display/audio integration and verified
execution/recovery are still unresolved. The software-only approach remains
unverified on the owner's hardware. No installable CarPlay image, modified ISO
or update USB was produced.
