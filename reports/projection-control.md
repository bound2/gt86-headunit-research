# Bounded projection-control framing and request ownership

Date: 2026-09-09. Continues [carkit/iAP2 integration](carkit-iap2.md),
committed/pushed as `27db539`, and [CarPlay progress](carplay-progress.md).
This is a protocol implementation step, not an installable head-unit update.

## Step 1 - Trace the separate projection control connection

The pinned LIVI tree remains at
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Its
[rtspMessage.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/rtspMessage.ts)
parses a text start line, CRLF-delimited headers and a length-delimited binary
body. Responses reflect the request protocol/CSeq and state their body length.
This is different from Lockdown's four-byte length prefix and iAP2 link frames.

The selected connection/handler sections of
[cpStack.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts)
show serialized requests, separate pairing/auth/info handlers, and a switch to
encrypted control framing after the plaintext pair-verify M4 response. They
also show event-channel requests and responses sharing text framing. A parser
must not consume the next connection bytes before that layer transition.

[RFC 2326 sections 4.4, 12.14 and 12.17](https://www.rfc-editor.org/rfc/rfc2326.html#section-4.4)
cross-check length-delimited bodies, zero body length when the field is absent,
and a required matching CSeq for RTSP request/response pairs. This project's
restricted framing profile is not a complete RFC or Apple conformance claim.

Exact Git blobs read locally from the pinned tree:

| Source | Git blob |
| --- | --- |
| `rtspMessage.ts` | `6ad23c144b3464c67cab71e6f206b32a28f69b4c` |
| `cpStack.ts` (selected connection/handler sections) | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` |
| `identity.ts` | `82ebfae7ca9199453105e912c50c420a7a76afa0` |
| `pairVerify.ts` | `fe2fb8850e1e4f6bd3b4250e39c8db5d0181ea06` |

No upstream program ran. Local buffers, validation, tokens and deadlines below
are independently implemented; no upstream implementation bodies were copied.

## Step 2 - Implement bounded text/binary framing

[rtsp_wire.h](../src/carplay/rtsp_wire.h) and
[rtsp_wire.c](../src/carplay/rtsp_wire.c) provide:

1. A one-message request/response decoder returning immutable borrowed views.
   It consumes exactly one frame and leaves all following bytes to the caller.
2. A caller-buffer incremental stream. It scans incoming header bytes once,
   validates the header at its delimiter, then copies only the declared body.
   Completed input stays held until explicitly cleared. It does not repeatedly
   rescan a fragmented body or resynchronize after a framing error.
3. A transactional response encoder with an explicit status, extra headers
   and opaque binary body. It generates Content-Length and echoes the numeric
   CSeq and protocol. A size-only pass permits validation before state changes.
   Insufficient capacity or invalid arguments leave output unchanged.

The local profile permits RTSP/1.0 and HTTP/1.0 or 1.1 start lines. It requires
CRLF and ASCII text, token header/method names, a nonempty target, at most
32 method bytes, 32 headers, 8,192 header bytes including the delimiter, and
65,536 body bytes. Caller receive storage is 64..73,728 bytes; a smaller
allocation imposes a smaller effective message limit. There is no heap use.

RTSP requires exactly one decimal CSeq in 0..UINT32_MAX; HTTP may omit it.
Leading zeroes are accepted and normalized in generated CSeq output. Lengths
are whole decimal values, not signed/prefix-parsed numbers. Duplicate
Content-Length/CSeq, overflow, oversized frames, header folding, bare LF,
control/high bytes in text, Transfer-Encoding and interleaved `$` packets
reject. Arbitrary binary body bytes remain valid. EOF-delimited bodies, chunked
HTTP, HTTP/2 and RTSP/2 are not supported.

Unknown incoming headers retain original order and casing, including repeats.
The case-insensitive lookup helper rejects an ambiguous repeated name. Extra
outgoing header names must be unique and cannot override length/CSeq/transfer
encoding; values and reason phrases cannot inject new lines. No content-type,
plist/TLV schema, route or authorization decision is inferred by this layer.

## Step 3 - Own one explicit request/response transaction

[rtsp_channel.h](../src/carplay/rtsp_channel.h) and
[rtsp_channel.c](../src/carplay/rtsp_channel.c) compose the stream with separate
caller-owned response storage and an explicit lifetime generation:

```text
RECEIVING -> complete request HELD -> explicit response SENDING
          -> caller retires output -> SENT
          -> caller drains downstream / handles verified layer transition
          -> explicit release -> RECEIVING

Any framing error, deadline, EOF or local close -> DEAD
```

Each held request has a nonzero generation/token key. Stale keys/generations
reject before advancing time or changing buffers. A token cannot wrap and
silently identify a future request. The caller must use a fresh generation and
new initialized lifetime for a replacement connection; these are not reconnect
or discovery APIs.

Only the application can supply a response. It must explicitly choose a final
status (200..599) and body, or close. There is no automatic 200 response to an
unknown/unimplemented command. Response protocol/CSeq come from the held
request, and validation/capacity errors do not consume that request or accept
an arbitrarily advanced timestamp. A response body may borrow held request
bytes because encoding copies into separate TX storage.

The caller may retire output prefixes as its exclusive downstream owner copies
them. `OUTPUT_DONE` means only that this plaintext queue is empty: it is not
physical completion, TCP ACK, successful encryption, verification or peer
acceptance. The channel deliberately stays SENT. The integration owner must
drain its downstream queue and make any verified cipher transition before
releasing the request. No plaintext/ciphertext boundary is guessed here.

Input is not consumed while HELD, SENDING or SENT. In particular, bytes
coalesced after a pair-verify request remain with the caller. Tests use a dummy
ciphertext-shaped tail to verify ownership only; no pair verification or
control encryption is implemented by this step.

## Step 4 - Enforce time and teardown without hidden I/O

Default absolute budgets are 30 seconds idle, 10 seconds from the first request
byte, 5 seconds awaiting an explicit response, and 5 seconds from queuing that
response through output retirement and release. Each config value is 1..60,000
ms. Neither fragmented input nor partial output renews its phase budget.
The caller supplies monotonic milliseconds and must keep checking deadlines
before its transport work. Decreasing clocks reject transactionally; unsigned
elapsed-time checks avoid deadline-addition overflow.

Expiry, bad framing, EOF and local close clear retained RX/TX bytes, invalidate
the token and leave a terminal reason. Prefix retirement also clears retired
output bytes. There is no automatic retry, reconnect, pairing-store access,
certificate/key generation, socket, USB operation or credential logging.
Closing this component does not itself close a socket: the eventual transport
owner must act on the terminal state.

## Step 5 - Verify the implementation and its limits

[rtsp_tests.cpp](../tests/rtsp_tests.cpp) contains nine synthetic groups:

1. RTSP/HTTP requests and responses, CSeq/header views, opaque binary bodies,
   truncation at every byte and exact consumption of coalesced messages.
2. Malformed lines, protocol versions, folding, control bytes, repeated framing
   headers, ambiguous numeric values, overflow and unsupported transfer framing.
3. Exact header/body/count limits, smaller caller storage and terminal errors.
4. Every two-part split and one-byte streaming, held input, unconsumed tails
   and clearing of used bytes without touching unused storage.
5. Exact response bytes, size-only/capacity checks, header injection/override
   rejection, explicit status handling and output header-count limits.
6. Serial explicit responses, three-byte output prefixes, SENT handoff barrier,
   RX-backed response body, stale request tokens and an explicit 501 response.
7. Idle, receive, handler and output deadlines including partial progress,
   delayed release and clock values close to UINT64_MAX.
8. Invalid generation/clock/arguments, output capacity/retirement bounds, token
   exhaustion, EOF/error closure, zeroing and transactional invalid init.
9. 6,000 deterministic mutated/truncated/random/valid inputs comparing
   fragmented-stream and stateless results. This is a regression campaign,
   not exhaustive fuzzing or a substitute for iPhone interoperability testing.

Reproduction:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

The standard build has 18 passing CTest suites; the TLS-enabled build has 21.
All fourteen protocol sanitizer executables and three hosted TLS/carkit suites
pass. The first strict test build found an unused helper; removing it fixed
the warning without relaxing `-Werror` or any sanitizer. All 25 Python tests
pass. The ARM check now covers nineteen C99 units and a relocatable link with
no runtime imports, including both new units. It remains no QNX executable.

Measured x64 sizes: message view 1,112 bytes, stream 48 bytes, channel 152 bytes
(including the stream). Caller RX/TX storage and transient parser views are
additional. No target process memory/stack/timing or native I/O was measured.

## Step 6 - Add actual identity, authenticated session and network/media paths

The pinned [identity.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/identity.ts)
uses a persistent Ed25519 identity and pairing identifier. Its public key is
advertised and its private key signs session proofs. This is not the Lockdown
TLS client certificate, nor a replacement for the accessory authentication chip.
The pinned [pairVerify.ts](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/pairVerify.ts)
requires a known controller key, X25519 shared-secret derivation, signed proofs,
authenticated TLV8 data and directional control-key derivation. The local
RTSP channel has not implemented or bypassed any of that verification.

Next implement bounded TLV8 and the actual identity/cryptographic pairing path,
then connect authenticated control encryption to this channel with a tested
handoff. Confirm the selected crypto backend's required primitive support and
use real cryptographic vectors/negative tests, not a signer that always succeeds.
The pinned `controlCipher.ts` and `crypto.ts` were also read for this next step.
Pair-setup/trust provision, MFi auth-setup, GetInfo capability construction and
typed SETUP/RECORD/TEARDOWN/media handlers remain work; wire parsing is not them.

A bound network listener/interface and real receiver key/address must precede
any advertised projection endpoint. The existing wired-start fixture is still
synthetic. Native USB-network access, head-unit execution/recovery, actual Go
module identity and usable authentication-chip access remain unresolved. No
head unit, phone, actual trust record, firmware image or update USB was changed.
