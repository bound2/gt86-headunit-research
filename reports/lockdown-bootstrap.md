# Explicit Lockdown startup and TLS handoff

Date: 2026-09-09. Continues [response validation](lockdown-responses.md) and
[CarPlay progress, Step 50](carplay-progress.md#step-50---add-explicit-lockdown-startup-and-tls-handoff).

Result: a bounded pre-TLS client now sends explicit GetValue/StartSession
requests, validates their responses and hands off the original stream only
after an accepted TLS-required session reply. A separate StartService request
encoder is ready for the future secure-session layer. No TLS engine, pairing
fallback, real phone session or installable CarPlay image is supplied.

## Step 1 - Confirm request fields against the pinned reference

The existing idevice 0.1.65 package remains the reference; its pinned
[Lockdown source](https://github.com/jkcoxson/idevice/blob/2bc6a05c80daaf8583884cf7f2d2563be17e6c2d/idevice/src/services/lockdown.rs)
constructs StartSession with Label, Request, HostID and SystemBUID. Its
non-escrow StartService form carries Request and Service.

The pinned [LIVI carkit startup](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-wired/src/carkit.rs)
requests the service after starting the Lockdown session. This step does not
port its automatic pairing fallback. Existing source hashes and licenses remain
in [the service report](lockdown-service.md); no new dependency was downloaded,
compiled or run.

## Step 2 - Encode explicit requests without choosing an identity

The [wire API](../src/carplay/lockdown_wire.h) now adds two transactional XML
body encoders:

- StartSession: caller Label of 1..64 bytes and HostID/SystemBUID of 1..128
  bytes each, all printable ASCII.
- StartService: caller service name of 1..128 printable-ASCII bytes. No Label,
  EscrowBag, default service name or credentials are inserted automatically.

XML metacharacters are escaped and output capacity is checked before writing.
These functions only construct bytes: they do not send requests, open ports,
generate UUIDs, read trust records or assert that the supplied identity is valid.
The new fixtures use explicit synthetic IDs and a carkit service-name example.
No private keys are serialized.

The caller must select the correct pairing identity and establish the required
secure session before sending StartService. A pure encoder is not a security
boundary; the owning client enforces its own allowed transitions.

## Step 3 - Own the plaintext startup sequence

[`lockdown_bootstrap.h`](../src/carplay/lockdown_bootstrap.h) binds an unused,
idle framing channel on a fresh OPEN TCP 62078 connection. Previous application
traffic, unread input, pending output, FIN state, wrong port or stale handles
prevent binding. This is a protocol-state check, not proof of phone identity.

The caller supplies request scratch, parser storage and a label. Initialization
copies the label but performs no callbacks or automatic request. The object
exclusively owns its channel until closure/handoff; other dispatcher streams
and explicit CONTROL handling remain available.

| State | Permitted progression |
| --- | --- |
| IDLE | Explicit typed GetValue or StartSession |
| PENDING | Poll bounded transport; decode/validate the new response once |
| VALUE_HELD | Inspect owned data, then explicitly release back to IDLE |
| ERROR_HELD | Inspect remote error; acknowledge explicitly before any new request |
| TLS_HELD | Keep polling; explicitly transfer to TLS or abort |
| DETACHED | Terminal; original stream belongs to the next layer |
| DEAD | Terminal; reason retained, no implicit restart/rebind |

Request inputs are copied into the channel. The client records the expected
command/type itself, so a mismatched reply is not accidentally validated as a
different operation. Malformed, incorrectly typed or downgraded session replies
close the shared dispatcher; a well-formed remote rejection remains a bounded
held error. Acknowledging it does not queue Pair, retry or generate a new identity.

## Step 4 - Make TLS a required ownership transition

A valid StartSession reply enters TLS_HELD only after the existing physical-
completion/peer-ACK barrier and typed response checks. Ordinary event release
cannot return this state to plaintext IDLE; further GetValue/StartSession calls
are blocked. The bootstrap client has no StartService dispatch path.

The exact event token is required to take the TLS handoff. It checks the live
stream, refuses peer/send FIN, checks deadlines, releases/detaches framing and
copies SessionID into the caller's handoff record. It performs no backend reads
or writes. Any bytes after the framed reply remain unread in the stream.
Malformed/expired/stale handoffs clear their output rather than exposing a
usable handle.

After transfer the bootstrap object is terminal, and closing it cannot cancel
the transferred stream. There is no resume or mark-secure bypass API. The caller
must install a real TLS engine, supply the matching credentials and enforce the
new handshake's deadline before any protected service request. Returned
SessionID or TLS-required metadata is not evidence that TLS/trust succeeded.
The existing raw dispatcher APIs remain trusted-caller interfaces, not a sandbox
against deliberate violations of exclusive ownership.

## Step 5 - Enforce shared deadlines during release and handoff

The previous channel checked its own exchange/hold budgets during non-poll
operations, but another stream's expired deadline could wait until the next
dispatcher poll. The new usbmux_dispatcher_check exposes the existing bounded
timer pass without backend read/write calls. It may queue ACK/FIN output and
cancel an expired shared generation.

Timed request/poll/release/detach operations validate their handle before that shared
check. An old owner therefore cannot advance or cancel a replacement generation.
Release and detach cannot rescue an expired shared transport. Wrong event
tokens still leave time/state unchanged; untimed views remain no substitute
for polling. Unsuitable client transitions return without advancing its state,
so callers must continue to poll rather than repeatedly submitting invalid work.

## Step 6 - Verify through the actual dispatcher and simulated peer

Eleven new groups exercise exact request fixtures, all insufficient output
capacities, maximum/invalid metadata, fresh-stream ownership, request copies,
query-to-session progression, every XML/binary session-reply split, held errors
without retry, malformed responses, TLS downgrade rejection, EOF, stale
generations, clock/capacity limits, explicit CONTROL handling and handoff tails.

Tests separately expire the channel hold deadline and another stream's peer-ACK
deadline during release/handoff. The initial latter fixture still had an
unfinished physical ACK write; that correctly triggered its earlier write
deadline. The fixture now drains those writes before isolating the intended
peer-ACK deadline. No production deadline was extended or disabled.

The shared test helper was extracted to
[lockdown_fixture.h](../tests/support/lockdown_fixture.h). It uses synthetic
peer bytes only. The three new XML fixtures are independently checked with
Python plistlib; their IDs and TLS-looking tail bytes are not real credentials
or a TLS handshake.

Verification:

1. Build.ps1: 17/17 CTest suites.
2. Check-CarPlaySanitizers.ps1: thirteen protocol suites under ASan/UBSan.
3. Check-CarPlayArm.ps1: seventeen C99 units and an import-free relocatable ARM link.
4. `python -B -m unittest discover -s tests -p test_*.py -v`: 25 tests.
5. Whitespace and changed-document local-link checks.

Bootstrap state is 248 bytes on the tested x64 host, plus its channel, request
scratch (1..4,096 bytes), parser storage and underlying transport objects/buffers.
This is not a measured QNX runtime footprint. New code/tests select GPL-3.0-only;
no upstream function bodies or real pairing records were copied.

## Step 7 - Continue with real TLS and protected carkit startup

Follow-up: [lockdown-tls.md](lockdown-tls.md) now implements and tests the actual
cryptographic stream upgrade. The counts above record this earlier bootstrap
step; protected RPC/carkit startup and target integration remain incomplete.

Subsequent follow-up: [carkit-startup.md](carkit-startup.md) now implements the
protected RPC and service stream; target integration remains unverified.

The follow-up supplies explicit credentials, peer validation, cancellation and
handshake deadlines and tests actual cryptographic handshakes on this handoff.
Next own framed RPC exchanges over that protected session, validate returned
StartService port/SSL policy, and establish the carkit stream.

User-authorized pairing/storage remains separate from loading an existing
identity; neither is an automatic recovery path. Real QNX USB/network ownership,
authentication-chip access, media/display/audio integration, exact Go-module
identity and verified execution/recovery remain unresolved. Software-only
CarPlay has not been demonstrated on the owner's hardware, and no update USB,
modified ISO, installable receiver or vehicle change was produced.
