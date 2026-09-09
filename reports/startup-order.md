# Explicit identification-first startup

Updated: 2026-09-09. Continues [CarPlay session startup](carplay-session-start.md).

## Step 1 - Publish and recheck the reference

The preceding startup-message codecs/reply work was committed and pushed as
`ccd89dd`, `Add bounded CarPlay startup codecs and explicit wired reply`.
`master` continues to track `origin/master` at the requested
[repository](https://github.com/bound2/gt86-headunit-research).

Read the existing pinned LIVI runtime again: `run_accessory` calls
`run_identification`, emits its identified event, then calls `run_auth`.
This is the specific ordering implemented here, not a claim of complete runtime
compatibility. Source:
[bringup.rs at a76553f](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/livi-runtime/src/bringup.rs).

## Step 2 - Select the order explicitly

New `iap2_control_config.startup_order` accepts exactly two values:

| Configuration | First phase at normal link | Second phase after first acceptance |
| --- | --- | --- |
| `IAP2_CONTROL_AUTHENTICATION_FIRST` (default) | Authentication | Identification, only if enabled |
| `IAP2_CONTROL_IDENTIFICATION_FIRST` (opt-in) | Identification | Authentication |

The new mode requires explicit identification metadata before start. Missing
metadata rejects start without starting the link, advancing its clock or
consuming a transport connection generation. Invalid configuration leaves the
endpoint unchanged. Every reinitialization disables identification, so callers
must enable it again even when they reuse an identification-first configuration.
There is no automatic fallback between orders.

The existing default remains source-compatible for callers using
`iap2_control_default_config`; aggregate zero initialization also selects the
original order. Callers must rebuild against the changed public struct layout.
No actual hardware identity, interface number or transport capability is inferred.

API: [iap2_control.h](../src/carplay/iap2_control.h).
Implementation: [iap2_control.c](../src/carplay/iap2_control.c).

## Step 3 - Gate provider work and phase budgets

In identification-first mode, authentication IDs `0xaa00` through `0xaa05`
received before identification acceptance fail closed without certificate or
signature callbacks. Unrelated messages remain explicit held application events;
they cannot bypass reply authentication gates or stop the phase deadline.

Each phase uses its own configured total budget, including waiting for its first
request, fragmented output, queue pressure and the peer's result. The second
budget begins when `poll` processes first-phase acceptance, not when those bytes
enter the receive queue. Partial progress never renews a phase budget. The
existing message assembly/hold and application reply budgets still apply.

Subsequent CSM processing remains behind the complete reply's cumulative ACK.
A coalesced IdentificationAccepted + AuthenticationCertificateRequest therefore
waits until the entire identification reply has been acknowledged. Only then
does the authentication budget start and the certificate provider run.

The transport pump already reads both active phase timers. Its timer algorithm
needed no change; new tests verify first-phase timeout while output is blocked
and full phase transition through fragmented backend reads/writes. Provider
callbacks are still synchronous and cannot be interrupted by caller-time checks.

Rejection, protocol failure, disconnect and timeout clear both acceptance states,
active timers and pending messages. Rejection field diagnostics remain available
until reinitialization. No stale success can authorize a new connection.

## Step 4 - Verify both profiles and the wired reply

Seven additional [control test groups](../tests/iap2_control_tests.cpp) bring
that suite to 30:

1. Explicit configuration, invalid-order transactionality, required metadata,
   start-clock preservation and reinitialization.
2. Premature authentication/result messages, rejection diagnostics and early
   application/CarPlay reply gates.
3. Waiting-start, blocked-output and waiting-result timeouts; independent second
   phase; exact boundaries, held messages and arithmetic near `UINT64_MAX`.
4. Split identification requests and coalesced acceptance/authentication input
   behind queue pressure and the reply ACK barrier.
5. Reset at four phases, stale acceptance and provider failure after identification.
6. Two library endpoints in reference order with byte-fragmented transport,
   deliberately lost identification/certificate frames and exact-once providers.
7. The explicit wired-start reply after reference-order startup at a 29-byte MTU.

Two additional [transport test groups](../tests/iap2_transport_tests.cpp) bring
that suite to 17. They cover missing-metadata startup refusal, blocked-output
identification timeout/cancellation, and a complete identification-first
authentication/application exchange through three-byte reads and five-byte writes.
All provider bytes, identity strings and network metadata remain synthetic.

The first deadline assertion incorrectly expected no link ACK timer after only
51 ms of its 100 ms delay; servicing that ACK corrected the fixture. The expanded
sanitized suite also exposed a test-runner stack overflow from combining large
fixtures in an optimizer-inlined `main`. Indirect iteration over independent
test functions corrected that lifetime/layout issue without increasing the
stack limit or disabling sanitizers.

Verification commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

All ten CTest suites, six host-sanitized protocol executables and 19 Python tests
pass. All seven C99 units compile/link into the freestanding ARM relocatable
object without runtime imports. The host control endpoint now occupies 19,960
bytes (eight more after layout alignment); transport storage remains 2,184 bytes,
plus caller-owned buffers. This is not QNX linking or an iPhone test.

## Step 5 - Audit the remaining identification payload

Review found another concrete compatibility defect: the current identification
encoder emits one SupportedLanguage parameter per language. The pinned CSM
encoder concatenates all language strings inside one parameter. Our existing
golden identity has only one language, so it did not expose the difference;
the multi-language test incorrectly asserted the local repeated-field behavior.
Next correct that encoding and add an independent packed-list regression before
extending transport/message declarations.

The runtime's USB-host component and message declarations still exceed our
minimal profile. No CarPlay capability is automatically advertised. Real
authentication, USBmux/pairing/networking, media, QNX display/audio/input,
installed-version matching and verified execution/recovery remain unfinished.
The end goal is still an actual software-only receiver, not these host tests.
