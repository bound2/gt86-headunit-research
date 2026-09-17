# Step 89 - Session-bound video TCP reception

Date: 2026-09-17. Continues [owning video input](projection-video-stream.md).

## Result and boundary

The optional Windows video service now connects session screen resources to
real peer-bound TCP sockets, authenticated input, the source-built H.264 decoder
and an explicit output-sink interface. It preserves concurrent audio through
delegation, including playback observations and two-phase FLUSH. Full receiver
tests exercise encrypted SETUP/RECORD/TEARDOWN and replacement keys through
actual IPv4/IPv6 loopback video reception.

This is implemented host infrastructure, **not working CarPlay on the car**.
The tests use public synthetic phone keys, synthetic MFi and output providers,
and public compressed media. There is no physical renderer, real phone session,
ARM/QNX port or installable update. No firmware, USB media, service-menu setting
or vehicle state changed. Software-only operation on the owner's existing
Panasonic TAS400/Harman navigation hardware remains the goal.

## 1. Connect the existing owners without bypassing authentication

Public contract: [projection_video_services.h](../src/carplay/projection_video_services.h).
Implementation: [projection_video_services_win.cpp](../src/carplay/projection_video_services_win.cpp).

Use the following composition, with immutable contexts that outlive their owners:

1. Supply explicit local/control-peer IPs, the shared monotonic nanosecond clock,
   bounded video configuration and all six sink callbacks. There are no default
   display capabilities. Creating the service performs no I/O or clock callback.
2. Optionally bind the existing audio provider as `video_config.other`. Its
   clock domain must match. Screen requests never fall back to this delegate.
3. Install `projection_video_services_provider(video)` as the root
   `projection_services_config.media` before root initialization. The root still
   owns timing, event and optional low-power endpoints and timing observations.
4. Enable the existing receiver session with the root provider and the same
   explicit feature contract. `/info` availability must attest actual usable
   backends; successful construction of this library is not that attestation.
5. Feed authenticated control through the receiver and poll its owner. The
   existing pair-verify/MFi gates and stream-ID lifetime ledger remain in force.
   The session supplies directional keys derived from its verified shared secret,
   not keys obtained from media input or a reconnect.

The selected wire profile, primary LIVI commit/blob pins and HKDF labels remain
those documented in [Step 88](projection-video-stream.md#1-establish-the-selected-wire-profile-from-primary-source).
This step adds transport/lifetime integration, not a new interpretation of
unidentified header timing fields or a claim of Apple protocol conformance.

## 2. Bind one transport to each screen lifetime

- Screen types 110 and 111 get separate real ephemeral TCP ports. Type 111
  requires the explicit alternate-screen flag. HEVC remains rejected.
- Use explicit-address exclusive binding, nonblocking I/O, noninheritable
  handles and IPv6-only sockets where applicable. No wildcard bind, URI/DNS
  routing or address reuse is requested.
- Compare the accepted IP/scope against the verified control peer. Close wrong
  peers without renewing the accept deadline. After accepting one matching
  peer, close that listener and never accept another connection for the key.
- Child decoder/sink handles and delegated media leases are remapped into one
  monotonic parent namespace. Zero, duplicate or partially failed child output
  is handled under the existing cleanup-transfer contract. A duplicate child
  handle is closed once, not treated as a second independently owned resource.
- A partial TEARDOWN closes only its selected lease. Replacement must come
  through a fresh session stream ID/key; the session ledger prevents reusing an
  earlier ID. Configuration changes do not reset a frame counter.
- Authentication, decoder, socket, deadline or callback failure closes all
  this owner's video and delegated media. The receiver/root polling path then
  retires timing/event/control resources too. Direct callers must immediately
  propagate a terminal service result to their owning receiver.

IP matching does not authenticate configuration or prove which process owns a
same-address connection. The explicitly accepted clear AVC configuration still
has unauthenticated provenance; valid frame AEAD does not authenticate SPS/PPS.
No real-phone validation is implied by the selected one-record/complete-AU model.

## 3. Bound input, output ownership and deadlines

Each live screen owns its Step 88 decoder/input queue, a 16 KiB network staging
buffer and at most one additional frame awaiting sink acceptance. Each poll
performs at most one accept, one read, one record feed, one sink submission and
one sink poll per screen, plus one optional delegate poll. A read's unconsumed
coalesced tail stays owned; partial consumption never refreshes its deadline.

| Lifetime | Absolute budget starts at | Expiry behavior |
| --- | --- | --- |
| Unaccepted screen | Resource-open clock sample | Close all media |
| Staged network tail | The read's clock sample | Close all media |
| Child partial record | First record byte, as in Step 88 | Close all media |
| Child queued picture | Queue admission, as in Step 88 | Close all media |
| Frame held for a busy sink | Frame metadata `received_ms` | Close all media |

The held-frame rule includes time already spent inside decode/queue; handing a
frame to this layer does not grant a new hold budget. Clocks are checked after
codec work and external callbacks. Rollback is terminal. `next_delay` performs
no I/O or clock sampling; the caller must continue polling. Bounded work counts
are not a hard real-time guarantee or a bound on all decoder/sink allocations.
While a held frame is backpressured, later input (including a configuration
record) waits; configuration does not jump ahead of that ordered lifetime.

Sink behavior is explicit:

1. `open` validates the actual resource/output and prepares it without display.
   Nonzero child handles transfer cleanup even when `open` returns an error.
2. Configuration may arrive before RECORD. `configure` must synchronously
   invalidate copied old-epoch output before acknowledging the new epoch.
3. The existing reply-drain gate calls `start`; only then may sink `poll` and
   frame `submit` run. Connecting, decrypting or decoding alone never starts
   output. A replacement added while recording still waits for its SETUP reply.
4. `submit` receives a borrowed tight-I420 view and metadata, valid only during
   that callback. `OK` means atomic copy/accept; `MORE` means nothing accepted.
   The sink must own and bound any retained copy. Neither return means displayed.
5. `close` synchronously invalidates output/cancels work and cannot fail. All
   callbacks are serial, bounded and non-reentrant, with no retained argument
   pointers or exceptions across the C boundary.

This service does not invoke the memory-input layer's clean-EOF drain. Once
`recv` observes EOF, no subsequent tail is presented; the stream fails and its
resources close. A queued picture can have been delivered earlier in that poll,
before `recv` observes EOF already waiting in the socket. No reconnect or nonce
reset follows EOF. Network/key buffers are wiped during cleanup; opaque codec
and pixel allocations retain Step 88's lack of secure-erasure guarantees.

## 4. Preserve audio and receiver lifecycle behavior

The optional non-video provider handles types 100/101/102 and explicitly enabled
130. It remains responsible for validating/implementing those formats; no iAP
backend is supplied here. All live child leases are remapped for batch start,
partial close, playback and audio FLUSH. Screen leases cannot be passed as audio
playback/flush handles. Audio resume still requires the FLUSH reply-drain path,
not a generic start call. Root timing remains authoritative; the delegate's
clock callback is not used as a replacement.

The mixed test uses the real audio UDP provider concurrently with video TCP,
decrypting a public PCM packet and decoding a real H.264 picture. Its final
audio/video outputs are synthetic. Separate delegate-contract tests exercise
partial-open/start/poll/feedback failures, duplicate handles, FLUSH/resume and
partial close. They are not physical playback or acoustic synchronization tests.

## 5. Verify reproducibly

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayVideo.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayVideoSanitizers.ps1
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_video.py build/video/Release/projection_video_tests.exe build/openh264-2.6.0/res
./build/media-reference/Scripts/python.exe -B scripts/check_projection_h264.py build/video/Release/projection_h264_tests.exe build/openh264-2.6.0/res
python -B -m unittest discover -s tests -p 'test_*.py'
git diff --check
```

The optional build now also selects the existing Mbed TLS 3.6.7 dependency so
receiver/session integration is included alongside Monocypher 4.0.3 and OpenH264
2.6.0. Preparation verifies the Mbed TLS archive, not an already extracted tree.
Monocypher used source files are hash-verified; the OpenH264 pinned checkout is
cleanliness/commit-verified. Independent Python environment setup/pinning remains
as recorded in Steps [87](projection-h264.md#4-verify-reproducibly) and
[88](projection-video-stream.md#5-verify-with-real-compressed-data-and-independent-encryption).

Recorded results on this host:

- **44/44 CTest suites pass**, including the new real-socket video service suite.
  The service suite also passes ten consecutive normal and three consecutive
  sanitizer reruns after the listener-state test correction.
- **4/4 video/decoder/limit/service suites pass ASan/UBSan.** The linked local
  sources, generic OpenH264, Monocypher and Mbed TLS sources are instrumented.
  No sanitizer check is disabled; Windows system DLLs are not instrumented and
  no leak-sanitizer or target-device claim is made.
- **740 independently encrypted/decrypted/decoded frames pass** across nine
  synthetic wire variants; **395 independent FFmpeg frames** again match both
  adapter drain variants (790 adapter frames).
- All **83 Python regression tests pass**.
- C-compiled API linkage/invalid-argument checks, IPv4/IPv6 streaming, fragmented
  and coalesced input, wrong peer, two concurrent screens with distinct keys,
  closed listeners, fresh-key replacement, reconfiguration, replay/tag failure,
  accept/fragment/staged-tail/held-frame expiry, clock rollback and callback
  failure cleanup pass. Pre-RECORD output remains gated.
- Real receiver crypto/session integration passes SETUP/RECORD/partial/full
  TEARDOWN and terminal tag-failure propagation. MFi and final output remain
  explicitly synthetic, never a claimed authentication-chip or display test.

### Issues found while making the checks meaningful

1. The root session fixture requested low-power keepalive, but its synthetic
   `/info` profile did not declare it. Corrected the fixture to declare the root's
   actual keepalive endpoint; no production capability gate was relaxed.
2. This Windows host did not report connection refusal within the test's assumed
   two seconds after closing an exclusive listener with a live accepted socket.
   Replaced that inference with an actual before/after kernel listener check,
   and still reject any successful reconnect. The test uses the PID listener
   table, supported for both address families, rather than IPv6's unsupported
   BASIC table class. See Microsoft's
   [GetExtendedTcpTable contract](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable).
   IP Helper is test-only; it is not used by the service.
3. Adding Mbed TLS exposed the earlier sanitizer script's GNU-style driver/MSVC
   flag mismatch. The script now uses actual `clang-cl`, the static CRT and the
   matching ASan/C++ runtime archives, in `build/video-service-sanitized`.
   Compiler/dependency identities are not spoofed or patched. This host's Clang
   exception-handler issue could mask failed assertions with a secondary ASan
   access violation; local assertions now print and abort before unwinding, and
   the final catch does not access a named exception object. Production exception
   support and sanitizer checks remain enabled.
4. Two existing private-file ACL tests failed with access denied in the restricted
   sandbox and passed on the authorized unrestricted rerun. The final complete
   44-suite run passed with full access; no ACL checks were weakened.

## 6. Next implementation and factory requirements

Follow-up: [Step 90](projection-video-render.md) implements owned colour conversion
and an explicit Windows GDI sink, verified with real offscreen pixels. Physical
presentation timing, sender metadata and factory display integration remain open.

Implement a real, explicitly selected display sink with owned output,
configuration-epoch invalidation, resizing/color handling and measurable
presentation/teardown behavior. Establish sender presentation timing and A/V
mapping from evidence; do not repurpose record counters as timestamps or call
copy acceptance a presentation event. Keep unverified phone variants and B
slices distinct from supported behavior. A Windows renderer is a host test
vehicle, not completion of factory CarPlay.

For the actual car, matching ARM/QNX compilation/runtime, a safe installed-version
execution/recovery path, USB/authentication-chip ownership, display/input routing,
audio focus/microphone access and measured performance remain necessary. The
navigation module's exact part/revision remains unknown; the owner has no more
identification information. Do not substitute later-corpus assumptions, private
AIR offsets, service-menu changes or an added receiver module. Nothing here
authorizes installing the 6.17.0WL research corpus over installed 6.9.0WL.
