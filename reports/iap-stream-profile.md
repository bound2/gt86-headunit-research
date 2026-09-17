# Step 95 - Correct iAP route ownership and add the reliable-stream profile

Date: 2026-09-17. Continues [Step 94](projection-iap-services.md).
Starting checkpoint: `86abbd2e6c69e21e5251b769141f8564b2a8de94`.

## Result

Tracing the relay consumer changed the implementation plan. The reference's
wireless tunnel contains **iAP2 link frames**, not plain control-session messages
(CSMs). It starts a separately owned link/accessory session. Its wired carkit path
already owns another link and explicitly blocks a matching wireless tunnel.
Blindly feeding type-130 bodies to the wired application or a plain CSM parser
would therefore be incorrect.

Both reference paths select control-session version 2, immediate negotiation
and zero link-level ACK/retry parameters. The existing local engine rejected
that profile. It now supports an explicit reliable-stream opt-in, including
bounded no-drop receive backpressure and honest output-handoff semantics. The
existing default and strict legacy LSP codec are unchanged.

This closes a specific source-backed wired compatibility gap. It does not
implement a wireless session owner, native USB-network backend, actual MFi
provider, installed-version execution/recovery or an installable CarPlay update.
Tests use real TLS but simulated USB/phone peers and synthetic accessory credentials.

## 1. Trace the complete consumer, not just the TypeScript forwarding callback

All source observations use the already pinned LIVI commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. The clean ignored checkout's immutable
Git objects were read, including files outside its sparse working tree. No
upstream helper, device watcher, pairing operation or reference executable ran.

| Source within the commit | Git blob SHA1 |
| --- | --- |
| `native/livi-helperd/crates/livi-runtime/src/livi_sock.rs` | `08b8e25070b47b5cb0aaea08f10a98ef6fa6aae2` |
| `native/livi-helperd/crates/livi-runtime/src/driver.rs` | `4c36c1fe6520047c1ab9c24d921e4ddf907aa9c4` |
| `native/livi-helperd/crates/livi-runtime/src/state.rs` | `a3deff4221693f9d2e77554b9cacf06fe5ca266d` |
| `native/livi-helperd/bin/livi-helperd/src/wired.rs` | `bf2900569464e3fd99c3d62874ae749d30b4287a` |
| `native/livi-helperd/crates/iap2-link/src/lib.rs` | `c64c8949718bdcd20e96d77b59fd70293bcc7a1e` |
| `native/livi-helperd/crates/livi-runtime/src/bringup.rs` | `84dbb71e485d60b0d6805e6705f6bf38a5df4ca7` |
| `native/livi-helperd/crates/iap2-wired/src/carkit.rs` | `58bd611ffdc984d55eacb0bcf6f8128ed0c9b8bc` |
| `src/main/services/projection/driver/cp/stack/cpStack.ts` | `d7b7511321a9da61d63a3c23a8e34cdd5523d7b9` |

1. The [projection stack](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/src/main/services/projection/driver/cp/stack/cpStack.ts)
   opens its helper relay at RECORD. It forwards incoming type-130 bodies and
   incoming event `iAPSendMessage` data to that connection. Helper output becomes
   an outgoing event command, not a write on the receive-only DataStream socket.
2. The [helper socket consumer](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/livi-runtime/src/livi_sock.rs)
   parses controller identity and optional Bluetooth MAC, consults carkit state,
   then calls `spawn_link` and `run_accessory` for an allowed tunnel.
3. The [driver](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/livi-runtime/src/driver.rs)
   creates a new `LinkEngine`, feeds raw socket bytes into it, and only then
   assembles CSMs from control-session events. Thus the opaque body contract in
   Steps 93-94 was appropriate, but an existing-application-only interpretation
   of the reference relay was incomplete.
4. The [ownership guard](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/livi-runtime/src/state.rs)
   blocks a tunnel matching a known carkit phone MAC; with no MAC supplied, any
   active carkit session blocks it. A supplied MAC cannot match an unlearned
   identity in this implementation. This is reference policy, not proof that
   controller IDs and physical USB identity are securely correlated on our unit.
5. The [wired runtime](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/bin/livi-helperd/src/wired.rs)
   registers its carkit session while it runs and retires it on exit/unplug.
   Both this path and `run_tunnel` select `control_version: 2`, `zero_ack: true`
   and initiated negotiation. Wired AV separately uses the phone's USB-network
   function; carkit TLS does not carry the projection video/audio TCP/UDP itself.

The [offline evidence checker](../scripts/inspect_iap_routes.py) verifies all
eight blob hashes and selected reviewed markers through the existing bounded
Git reader. Lazy fetch and network protocols are disabled. Four Python tests
cover its pin/marker/failure/result contract. This is source reproducibility,
not execution of the helper or a whole-program proof.

## 2. Implement the explicit stream profile without changing defaults

The reference [link implementation](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-link/src/lib.rs)
sets retransmit timeout, ACK timeout, retransmission count and cumulative ACK
count to zero for this profile. It does not retain emitted data for link retries
or schedule normal data ACKs. Handshake ACKs and sequence fields still exist.
The LSP format's version byte remains **1**; the control-session triplet's version
is **2**. These are distinct fields, not a new LSP layout.

[iap2_link.h](../src/carplay/iap2_link.h) and
[iap2_link.c](../src/carplay/iap2_link.c) now provide:

- `iap2_link_default_config`: unchanged version-1 control, positive timers,
  ACKs/retransmissions and peer-marker detection.
- `iap2_link_stream_config`: explicit `IAP2_LINK_STREAM_NO_ACK`, version-2
  control and all four zero fields. It emits marker then SYN without waiting
  for a returned marker, while retaining the existing total handshake budget
  and SYN retry interval. A returned marker can still be consumed during negotiation.
- Profile-aware LSP encode/decode functions. The original functions still reject
  zero fields. Mixed zero/nonzero profiles, unselected versions and unsupported
  peer resources do not trigger silent fallback.
- No application/physical transport starts merely by selecting the profile.
  Existing identification/authentication ordering and explicit provider gates
  continue to apply through the control endpoint.

The local offer is bounded to 1,024-byte packets, four advertised outgoing slots
and only the implemented control session. Its encoded LSP is
`010404000000000000000a0002`. The reference default offers 65,535-byte packets
and additional EA/file-transfer sessions; the codec can inspect that LSP but our
engine does **not** silently claim those capacities or handlers. A peer selecting
beyond the explicit local offer is rejected. Compatibility with an actual
phone's chosen parameters remains unverified.

## 3. Preserve ownership when link ACKs are disabled

For this opt-in only, successful link output retires one queued payload after
copying its whole frame into caller-owned output. It does not advance the
`tx_acked` peer-ACK observation. A short output buffer changes neither sequence
nor queue. No automatic data retry or delayed-data-ACK timer is created.

The control layer's reply serialization consequently waits for complete link
output handoff in this profile, not a nonexistent peer data ACK. The transport
pump still owns any partially written output and its absolute deadline. The
carkit bridge still requires its whole copied prefix to drain through TLS and
USBmux/TCP-style acknowledgement before reporting pump-write completion. Neither
barrier proves accessory authentication or application acceptance; those require
their separate received protocol results.

With no link retry, dropping a full-queue packet would lose data permanently.
The new receive path therefore returns BUSY **before consuming the next frame**
when its eight-slot queue is full. The pump retains the wire tail and retries
after the application drains input. Nonconsecutive payload sequences, corrupt
framing/checksums and unsupported normal-state frames terminate this reliable
stream instead of discarding them and awaiting a retry that cannot happen.
This stricter error policy is local; the reference has different duplicate/gap
handling. The default lossy-link profile retains its existing behavior.

Normal-state pure ACK fields do not release queues or create an ACK loop in the
no-ACK profile. Sequence numbers still wrap modulo 256. Changed SYN state, reset,
EOF and explicit cancellation retain terminal ownership semantics. There is no
new generation bypass, USB reset, authentication restart or default advertisement.

## 4. Verify the changed protocol and its actual layered use

The existing link suite grows from 16 to **21 groups**:

1. Full pinned-reference zero-profile LSP and bounded local-offer goldens,
   strict legacy rejection, mixed-field rejection and transactional invalid init.
2. Immediate SYN with/without a peer marker, required handshake ACK, short-output
   transaction, retained handshake deadlines and no invented peer acknowledgement.
3. Eight queued receive frames plus a retained ninth frame, exact once/in-order
   delivery after space becomes available, and bounded output without ACK credit.
4. Corruption, garbage, gaps, duplicate payloads, unsupported session/control and
   version-mismatch handling without fallback.
5. Six hundred byte-fragmented exchanges through multiple sequence wraps, with
   no unsolicited data ACKs or automatic retries.

The carkit suite grows to **seven groups**. Full identification, synthetic MFi
certificate/challenge/results, explicit power notification and wired-start reply
now run for both link profiles over either real dual TLS or an explicitly allowed
plain service. Both profiles retain copied-but-undrained marker bytes until
lower transport completion. A new no-ACK test blocks an identification data frame
below TLS and verifies its retained-write deadline closes the complete stack
before further physical-backend I/O or certificate-provider calls.

The [independent Python wire checker](../scripts/check_iap2_stream.py) separately
constructs LSP, header/body checksums, marker, SYN, handshake ACK and data frame;
all six returned values match, including absent automatic retry output. It is
a synthetic wire sample, not an independently executed reference engine or phone.

Observed final results:

- Full Release CTest: **50/50 suites** passed.
- Python discovery: **92 tests** passed.
- Link and carkit integration suites: **10 consecutive passes each**.
- Existing protocol ASan/UBSan script: **18 suites** passed, including 21 link groups.
- TLS ASan/UBSan script: **3 suites** passed, with Mbed TLS and the full carkit
  chain instrumented; final USB/phone/accessory provider remains synthetic.
- Twenty freestanding C99 units compile and relocatably link for Cortex-A8/ARM
  without runtime imports. This is not a QNX executable or on-unit speed/RAM test.

Host link storage is 17,696 bytes and control storage 19,976 bytes, excluding
caller buffers. The carkit bridge remains 3,312 bytes excluding its endpoint,
carkit/TLS contexts and cryptographic heap. No new dependency was introduced.
The TLS script reuses an existing extracted Mbed TLS tree: its archive is checked,
but that tree is not independently rehashed, as its output explicitly records.

## 5. Reproduce and choose the factory-relevant next step

```powershell
python -B scripts/inspect_iap_routes.py
cmake --build build/video --config Release -- /verbosity:quiet
ctest --test-dir build/video -C Release --output-on-failure
ctest --test-dir build/video -C Release -R '^(iap2_link_tests|carkit_iap2_tests)$' --repeat until-fail:10 --output-on-failure
python -B scripts/check_iap2_stream.py build/video/Release/iap2_link_tests.exe
python -B -m unittest discover -s tests -p 'test_*.py'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
git diff --check
```

The next wired task is to trace the separate USB-network/NCM path and the later
QNX corpus's native interface/IPv6 ownership requirements. The wired-start fixture
address must become a real owned interface/listener before it is advertised.
Do not substitute the optional type-130 socket or a PC network address for that
missing physical path. Existing factory USB/HID handling is not proof of NCM.

Follow-up: [Step 96](factory-usb-network.md) identifies a separately shipped native
NCM driver and its descriptor/parameter path. The selected factory stack has no
built-in IPv6 domain. Next audit driver insertion/removal and interface ownership,
then determine whether a compatible isolated IPv6 runtime is available; the
physical interface and listener remain unimplemented.

A future wireless tunnel owner would separately need explicit phone/transport
ownership, link/control startup at the correct RECORD lifecycle, bounded event
output completion and actual providers. The new profile enables its link behavior
but does not create that owner or reset an active wired session. Source evidence
does not establish Wi-Fi availability or wireless CarPlay on this head unit.

The [factory gates](factory-integration-gates.md) remain unresolved: installed
6.9.0WL execution/recovery, matching QNX runtime, coordinated USB/MFi access,
factory video/audio/input/microphone and actual phone/unit acceptance. No vendor
program, phone pairing record, service menu, firmware image or vehicle was changed.
