# CarPlay investigation progress

Started: 2026-09-09. Continues [installation-path.md](installation-path.md).
Goal confirmed by the owner: add CarPlay functionality to the existing GT86
head unit. A Toyota map/software refresh alone is not the requested outcome.
The owner subsequently confirmed **software only on the factory hardware**;
the unit already provides Bluetooth and wired Apple USB connectivity. Added
receiver modules and replacement head units are outside the selected approach.

## Current result

No installable CarPlay update exists in this project yet. Portable C99 receiver
components now implement iAP2 framing, control messages and authentication
sequencing, validated against 33 upstream vectors. A new experimental reliable-
link profile adds negotiation, ACKs, retransmission and bounded queues with
16 link test groups. A bounded control-session adapter now connects link payloads
to authentication, including split/coalesced messages and larger replies. It
now also supports atomic application replies and opt-in minimal accessory
identification, with 38 control and 11 dedicated identification test groups.
The new bounded byte-stream transport pump retains partial writes, accounts for
receive tails and closes failed/stale connections, with 17 dedicated test groups.
CarPlay/power codecs now round-trip five pinned fixtures, with 12 dedicated
groups, an explicit wired-start reply and unsolicited power notifications that
preserve held input. A separate explicit wired identity now declares the
implemented message IDs and a caller-supplied USB-host component; typed wired
helpers require that accepted profile. The minimal default remains unchanged.
This iAP2 startup engine does not automatically advertise capabilities or open
network/media sessions. The pinned
runtime's identification-first order is now supported through explicit opt-in
configuration, with independent phase budgets and provider gating. The original
authentication-first default remains available. See [startup-order.md](startup-order.md).
The new USBmux packet/stream layer adds 10 groups and seven independent wire
vectors. Its bounded version/setup host adds 15 groups, actual-write completion
barriers, explicit sequence conventions, deadlines and stale-generation rejection;
the host remains packet-only. A separate bounded TCP-style connection engine
now adds port routing, sequence/ACK/window handling and close behavior, with
15 groups and a layered host/connection simulation. A new dispatcher now
coordinates up to four connections through explicit backend callbacks, with
bounded stream APIs and 13 additional groups. Bounded Lockdown service framing,
explicit GetValue XML encoding and an owned request/response channel now add
18 groups. A bounded XML/binary plist decoder and typed response validation
add 13 groups and seven synthetic binary fixtures. A pre-TLS startup client
now adds 11 groups, explicit session/service request encoders and token-bound
TLS handoff, with no plaintext resume or automatic pairing. An optional hosted
TLS adapter now performs real mutually authenticated TLS 1.2 over the handoff,
with explicit CA/device-pin validation and seven cryptographic test groups.
An owning protected RPC client and carkit startup layer now add seven groups:
validated service ports, explicit SSL policy, a separate service connection,
real dual TLS and raw iAP2 round trips over simulated USBmux. A new owning bridge
now connects that stream to the existing iAP2 session engine, with six integrated
groups covering identification, synthetic accessory authentication, explicit
wired-start replies and completion/lifetime gates. A separate projection-control
framing/channel layer now adds nine groups, including 6,000 deterministic
mutations, strict RTSP/HTTP framing, explicit responses and token/deadline/output
handoff gates. Bounded TLV8 adds three groups; real receiver identity and
known-controller pair verification add seven cryptographic groups with RFC and
independent PyCA vectors. Authenticated control records and an owning
pair-verification-to-encrypted-RTSP handoff now add ten groups, including retained
tails, plaintext-M4 drain gating, replay/tampering and counter exhaustion.
Real first-time SRP/setup, explicit enrollment/candidate approval, trust-commit
handling and an owning RTSP-to-pair-verify transfer now add nine groups. A portable
identity/trust snapshot and real private Windows file store now persist approved
enrollment through reopen/process restart, with corruption/uncertain-write tests
and encrypted-control integration. MFiSAP response calculation and an owning
encrypted `/auth-setup` route now add seven groups, including same-transport
enrollment-to-verification-to-MFi handoff. Cryptography is real; the explicit
certificate/signature test providers are synthetic, not Apple credentials or
proof of handset acceptance. An initial receiver router now has thirteen groups,
explicit local permission and separate verified-candidate approval, automatic
same-connection post-M6 transfer and public tokens stable across child phases.
An explicit typed capability encoder adds four groups and three independent
Python-decoded profiles, including a 25,777-byte response. Optional exact `/info`
handling requires an explicit runtime availability check; pre-pairing plaintext
discovery additionally requires opt-in and has count/absolute-time bounds.
A separate projection plist decoder supports 640 nodes and finite real values
without loosening the existing Lockdown parser. Typed session/resource handling
now adds seven groups and optional owned SETUP/RECORD/TEARDOWN/FLUSH routes: advertised
capability gates, explicit endpoint leases, event/media key derivation, ID-reuse
prevention and rollback/teardown/drain-start ownership. A real Windows endpoint
provider now supplies peer-bound UDP timing, encrypted TCP events and optional
UDP keepalive, with explicit polling, deadlines and cleanup. Four pure timing
and nine real IPv4/IPv6 loopback service groups pass; media delegates and MFi
providers in the integrated tests remain synthetic. An owned bidirectional
event-message layer now adds atomic command batches, correlated replies,
explicit request handling and typed HID/Siri/night/iAP/keyframe encoders, with
six pure groups and expanded real-socket tests. Optional typed control feedback
now reports owned audio descriptors and fresh observed playback anchors using
the real timing clock, with seven independently decoded output states. No
played sample is inferred from a received packet or socket send. Encrypted audio
RTP reception now adds seven core and seven actual UDP-service test groups, with
17 explicit format mappings, nonce replay/reordering, gap reporting, PCM byte
conversion and session/feedback integration. An explicit Windows WASAPI PCM sink
now adds bounded queues, prefilled startup and device-clock observations, with
nine output groups and separate COM/thread/clock checks. The final device in
automated playback tests remains synthetic. Optional real AAC-LC/Opus decoders
and an owning PCM bridge now add seven decoder and five loopback integration
groups, 33 synthetic packets and 1,000 mutation checks. A separate reference
compares 59,648 samples, with explicitly documented noise/hybrid limitations.
An optional two-phase authenticated FLUSH now retires queued media and codec/
device history without resetting keys or replay state, and resumes only after
encrypted reply drain. Its single-audio classic AirPlay form is not verified
CarPlay behavior. Explicit relative pacing and bounded nonce-gap recovery now
add Opus PLC, marked PCM/AAC silence, timed startup and concealment-aware feedback.
Four sustained real-UDP timelines pass with a synthetic progressing device;
adaptive drift, late-media policy, sender/A-V sync and selective buffering remain work.
Physical playback verification, video/mic/input, control modes,
target QNX storage, approval/revocation UI, broader discovery/phone
interoperability and hardware integration remain missing.
Python regression checks total 25, plus independent
checkers for 21 pair-verification, 12 control-frame, 51 setup and 39 combined
MFi/pair-verification fixture values, plus 42 session fixture values, 16 session
directional key/zero values and three independently parsed session replies,
plus 12 independent timing-clock/filter values, eight decoded event commands
and seven feedback output states, plus 13 independent audio fixtures and 17
audio format descriptors.
Native USB and actual phone pairing remain absent.
All twenty-two ordinary, twenty-five TLS-only and forty combined crypto/TLS
CTest suites pass; the optional codec-enabled configuration passes forty-two.
Both new media suites pass ASan/UBSan with codec dependencies instrumented.
All eighteen protocol/capability/timing/event suites, five pairing/control/store suites,
the enrollment, real-file, MFiSAP, projection-session, receiver-router, real-socket
service, two audio suites, PCM output/Windows argument checks and three TLS/carkit/integration suites pass under host
address/undefined-behavior sanitizers, including both crypto dependencies.
The twenty freestanding C99
components also compile to 32-bit ARM objects without runtime imports; see
Steps 22-70, [the persistent-store report](pair-store.md),
[the encrypted MFi report](mfi-sap.md), [receiver routing](receiver-routing.md)
and [projection capabilities](projection-capabilities.md) /
[session resources](projection-session.md), [real endpoint services](projection-services.md)
and [event commands](projection-events.md) / [observed feedback](projection-feedback.md)
/ [audio reception](projection-audio.md) / [PCM output](projection-pcm-output.md)
/ [compressed decoding](projection-decode.md) / [authenticated FLUSH](projection-flush.md)
/ [relative playout](projection-playout.md). Hosted TLS
uses heap/platform services and is not included in that ARM claim. The new
separate ten-unit pairing/control/store crypto object compiles/links for ARM but needs four runtime
helpers; it is not an import-free target or verified QNX port.
The new SRP/enrollment target uses hosted Mbed TLS MPI heap allocation and is
not included in either ARM claim. The new capability encoder, hosted MFi/AES and
receiver/session targets, new timing/services/events/audio/PCM/codecs and Windows-only filesystem backend are also
excluded; its file checksum is not encryption or rollback protection.
No real Apple-chip authentication provider or device transport is connected.
Accessory identification describes the endpoint to a phone; it does not read
the existing Apple authentication chip's identity or prove its compatibility.
All 13 earlier host-side
manifest/dispatch/authentication checks pass. They confirm additional weaknesses
in resident update control flow, with explicit mock assumptions. Adobe AIR also
contains H.264 decoder class references worth investigating. Neither result
establishes a working CarPlay receiver or a demonstrated recovery method. All
work below is on the local PC.

The Apple-authentication path is now traced through both stock ARM modules:
17 synthetic-bus checks pass, including cached identity reporting, certificate
paging and challenge/signature transfers. `acp_ver` proved to be a fixed plugin
entry, not a chip-version reading; see Steps 13-15. The cached-description path
is now connected to `<actual iPod mountpoint>/.FS_info./info.xml` in the later
corpus, with 19 additional native media-information checks and eight tool-safety
tests passing. This is a filesystem export, not an established means of reaching
the unit. The actual mountpoint, real chip identity, installed-version behavior
and iPhone acceptance remain unknown; see Steps 16-18.

The first diagnostic/export investigation is complete for the candidates
examined: none establishes a read-only collection route to the PC. Insight
logging has a separate USB-trigger path and configured uploads; the stock
snapshot is only a screenshot. A stock Apple script reads the information file
but forwards product/vendor names, not chip fields. Ten modeled MCD paths,
seven mocked stock Lua scenarios and five new safety/regression tests pass;
see Steps 19-21. No diagnostic trigger was activated.

The later corpus's USB ownership configuration and stock HID read/write paths
are now traced. Seventeen simulated USB scenarios and six new tool-safety tests
pass (19 Python tests total); see Steps 31-33 and the new
[USB transport report](usb-transport.md). The host-only USB driver description
does not establish the silicon's complete capabilities or the physical port's
ownership in the owner's car. No usable iAP2 USB backend is established yet.

## Step 1 - Establish the target and limits

Status: complete for the information already available.

The owner's recorded identifiers are display/audio `13TFDAEU-DA05`, audio
software `0101B0`, navigation `6.9.0WL`, and maps `2017 v1`. These identify two
software targets: the display/audio device and the Go navigation module.
The extracted research corpus is navigation `6.17.0WL`, not the owner's
installed image. The Go module's exact part number and hardware revision remain
unknown. All seven photos in the owner's `Pictures/headunit` folder were
subsequently inspected directly; Step 11 records their evidence and limits.

The previous same-Adler manifest experiment changed only memory on the PC. Its
successful mock execution does not establish acceptance by the car, reliable
native-program launch, or a way to restore the unit after failure.

## Step 2 - Check whether an official update supplies CarPlay

Status: source checked; no applicable GT86 update established.

Toyota Estonia's published retrofit describes RAV4 and Corolla systems from
the MM17/CY17 family. It does not establish compatibility with this GT86 or
`13TFDAEU-DA05`. Therefore that retrofit cannot be treated as this unit's update
path. [Toyota's retrofit information](https://www.toyota.ee/owners/connected-services/multimedia-updates).

Apple distinguishes iPhone apps that appear in CarPlay from vehicle systems
that receive CarPlay. Its vehicle integration guidance points to the MFi
program. An iPhone CarPlay app entitlement or simulator is not a receiver
implementation for QNX. [Apple's CarPlay developer information](https://developer.apple.com/carplay/).

Both pages checked on 2026-09-09. This is not proof that a custom implementation
is impossible; it establishes that the public iPhone app SDK is insufficient.

## Step 3 - Read the complete stock installer manifest

Status: complete; original bytecode disassembled and both manifests evaluated
with empty guest environments and an instruction budget.

The existing local Lua 5.1.5 host is built for Win32. Its bytecode layout matches
the observed 32-bit QNX Lua chunks, so the original installer manifest can be
read without converting or patching it.

`extracted/swdl/etc/manifest.lua` is a plaintext manifest with no parts. The
separate `extracted/install/etc/manifest.lua` is compiled Lua and specifies this
ordered set:

| Order | Component | Installer |
| --- | --- | --- |
| 1 | System | `ifs` |
| 2 | System Data | `mmc` |
| 3 | Cleanup | `cleanup` |
| 4 | Apps Cleanup | `cleanup` |
| 5 | Apps | `etfs` |
| 6 | Navigation | `nav-sync` |
| 7 | Speech | `mmc` |

Its external entry point is
`usr/share/scripts/nav-activation/nav-activation-install.sh`. This is an update
of system components and persistent data, not a standalone CarPlay app package.
No installer has been run against real storage.

## Step 4 - Trace resident dispatch and authentication

Status: source trace and 12 mocked resident/authentication scenarios complete.

The resident loader authenticates `swdl.iso`, and also `swdlInstall.iso` when it
is present, using the fast digest. It prefers mounting the installer ISO when
both files exist. Its subsequent `verifyISO` call specifically names
`/fs/usb0/swdl.iso`; that call's return value is ignored.

Correction to the earlier report's sequence: this `verifyISO` call occurs
**before** mounting, not after mounting. Manifest execution follows mounting.

The resident dispatcher `swdlMediaDetect.lua`, lines 112-133, applies
`loader.validateISOSignature()` only when `external.start_script` is exactly
`usr/share/scripts/app-install/eu-app-install.sh`. The stock navigation entry
point takes the external-script branch without this particular check. The
navigation script and update-mode boot flow have their own checks; this is not
proof that they accept a modified firmware image.

The application helper indexes Lua strings numerically and sets `misMatch` but
tests `mismatch`. In the stock Lua 5.1.5 host, numeric string lookups return nil,
so the byte loop does not compare the bytes; the subsequent variable-name
mismatch also prevents the intended failure branch. With SAM success mocked,
the original helper accepts different mock hashes (`A` repeated 32 times versus
`B` repeated 288 times) and reaches the intercepted app script. Mocked SAM
failure blocks that script. No actual SAM check or modified app image was used.

The compiled update-mode `authISO.lua` requires a verifier output success marker.
Explicit error output, empty output and output missing the marker all return
failure in the harness. Success text followed by a nonzero mocked pipe-close
status is still accepted. This establishes dependence on stdout; it does not
establish a way to make the native verifier print success for an invalid image.

| Test | Observed result in mocks |
| --- | --- |
| Complete stock manifests | Empty updater parts; seven ordered installer parts |
| Both ISOs present; full verifier returns 256 | Installer manifest loads; navigation external script requested; no application SAM call |
| Only updater ISO; full verifier returns 256 | Empty manifest loads and update-available status is emitted |
| First fast signature fails | No mount, manifest load or script request |
| Second fast signature fails | No mount, manifest load or script request |
| Mount fails | No manifest load or script request |
| Application SAM mock rejects | Application script blocked |
| Application SAM mock accepts; mock hashes differ | Application script requested |
| Update-mode verifier prints success | Authentication exits 0 |
| Update-mode verifier prints an error | Authentication exits 6 |
| Update-mode verifier omits success | Authentication exits 6 |
| Update-mode verifier returns no output | Authentication exits 6 |
| Success text but nonzero mocked close status | Authentication exits 0 |

The two application tests pass a synthetic manifest table directly to the
dispatcher to isolate its branch. They do not claim that table passed ISO
authentication. The other resident scenarios use the original stock manifests;
fast-signature results are also mocked here. The earlier integrity experiment
performed separate cryptographic checks on its fixed harmless marker.

New reproduction files:

- `scripts/probe_update_path.py`: validates SHA256 identities of five vendor
  inputs and runs the harness with a 20-second timeout.
- `tests/update_path_probe.lua`: evaluates stock manifests and replays resident
  dispatch/authentication using intercepted guest filesystem, shell and service
  calls. Guest execution has an instruction budget.

These tests model selected control-flow paths. They do not emulate QNX, the SAM
chip, the HMI, flash devices, or complete native installers.

## Step 5 - Establish the remaining CarPlay requirements

Status: available local interface evidence inspected; runtime capability unknown.

Existing evidence identifies QNX Screen, 800x480 graphics, a Toyota touch driver,
and Toyota audio services in the later corpus. A successful loader test alone
does not establish usable display ownership, touch delivery, microphone input,
audio focus, or real-time video decoding for a receiver.

A binary-content search found H.264-related matches in media configuration,
the MP4 parser, `io-media-generic`, and Adobe AIR. Follow-up inspection narrows
what these mean:

| Evidence in extracted system | Finding and limit |
| --- | --- |
| `image-380000/etc/io_media_generic.conf` | MP4 entries select `qnx_raac_decoder` (audio). A `ce_video_decoder` entry is commented out. Configuration does not establish active H.264 decoding. |
| `image-380000/lib/dll/mmedia/mp4_parser.so` | H.264 profile, level and bitrate limits occur as parser constants. Parsing a video container is not evidence that frames can be decoded. |
| `image-380000/lib/air/runtimeSDK/Adobe AIR/Versions/1.0/libCore.so` | Contains `H264MMFPlaneCodec`, `H264VideoDecompressor`, `H264DecompressorInstance`, and `H264 - MainConcept`. Messages include decoder acquisition failure and hardware-AV unavailability. These are concrete decoder implementation clues, but availability, performance and a callable external interface remain unverified. |
| `image-380000/usr/lib/graphics/jacinto5/graphics.conf` | 800x480 at 60 Hz, Toyota touch driver, and an initially invisible `mlc` window class. Graphics support does not establish display ownership for a new application. |
| `image-380000/usr/share/lua/requestScreen.lua` | Disassembly shows an IPC channel-2 request/response handshake before closing the channel. Drawing a window alone may not be sufficient to display it on the audio unit. Meaning and recovery of this handshake require further tracing. |
| `image-380000/etc/system/config/toyotaAudioCtrlSvc.conf` | Defines separate media, microphone and PCM muxes. The media mux starts with input `NONE` and gain `-INF`; microphone is configured as `Mic In`. A receiver needs deliberate audio routing and focus integration, not just PCM writes. |

No CarPlay/iAP2 receiver was identified by the targeted content and filename
searches. This is a limited negative result, not proof that every vendor binary
lacks related functionality. `qcc` and `arm-unknown-nto-qnx6.5.0-gcc` were not
found on the host's PATH. A compatible native build toolchain has not been
established; the Windows Lua host is not such a toolchain.

## Step 6 - Reproduce and preserve the evidence

Status: 13 checks passed on 2026-09-09. The documented Win32 Lua configure/build
commands also succeeded. Separate driver checks confirmed that a changed input
hash is rejected before guest execution and an existing output file is refused.

From the project root, with the existing Win32 Lua host:

```powershell
python scripts/probe_update_path.py
```

To save a new machine-readable record, specify an output file that does not
already exist:

```powershell
python scripts/probe_update_path.py --output extracted/carplay-update-path.json
```

The JSON records all five input SHA256 identities, the complete stock installer
manifest, each scenario's events, and explicit limits. The driver refuses
changed vendor inputs and refuses to overwrite an evidence file. See the
[README](../README.md) for the Lua host build commands.

The current run is saved at `extracted/carplay-update-path.json` (ignored by
Git). Use another new filename for subsequent saved runs. This Markdown report
preserves the findings even when the ignored development artifacts are absent.

## Step 7 - Select a software receiver foundation

Status: reference source inspected; first portable protocol components implemented
and tested. Full receiver integration remains unfinished.

The public [LIVI project](https://github.com/f-io/LIVI) now implements native
wired and wireless CarPlay. The inspected source is pinned at
`a76553fc941dcf378dd55c04da56aaf3d6911e08` in the ignored local directory
`build/livi-reference`. No installation scripts or receiver services were run.

Its full application requires a modern Node/Rust/GStreamer stack and OpenGL ES
3.x. The Toyota corpus is QNX 6.5/32-bit ARM with an SGX530 graphics configuration;
the complete LIVI application is not a drop-in package for it. Its isolated iAP2
link and control-message implementations nevertheless provide a concrete
protocol reference for a small native port. This replaces the earlier absence
of an identified public receiver implementation with a specific source target.
[Pinned source](https://github.com/f-io/LIVI/tree/a76553fc941dcf378dd55c04da56aaf3d6911e08).

Implemented in `src/carplay/iap2_wire.c` and `iap2_auth.c`:

1. Encode/decode the nine-byte iAP2 link header and separate payload checksum.
   Preserve the distinction between no payload and an empty checksummed payload.
2. Reassemble fragmented link frames using caller-owned bounded storage. Preserve
   unconsumed coalesced data, resynchronize past bad headers, and reject bad
   payload checksums or packets exceeding the configured receive capacity.
3. Encode/decode `0x4040` control messages and length-prefixed parameters. Reject
   malformed parameter tails instead of accepting partially valid messages.
4. Handle certificate/challenge requests through provider callbacks. Validate
   message order, challenge size, duplicate fields, provider errors and reply
   sizes. Only an in-sequence phone success notification advances the accessory
   authentication state. The tests use fake bytes, not real signatures.

There is no default authentication provider; the code cannot authenticate a real
iPhone yet. Link negotiation/retransmission, USB transport, CarPlay session and
media protocols, and QNX integration are still required. A successful auth state
in a test is not a running CarPlay session. The library has no operating-system
calls or dynamic allocation and does not depend on LIVI's application runtime.

## Step 8 - Trace the existing Apple hardware connection

Status: additional static evidence found; physical chip identity unknown.

The owner's wired Apple connection is relevant: the corpus explicitly starts
`/dev/i2c0` for the iPod authentication chip. USB device enumeration configures
`io-fs-media` with `acp=i2c:speed=40000`, and `iofs-i2c-ipod.so` contains the
default `/dev/i2c0` path and an `authcoproc` interface marker. This is stronger
evidence of an existing authentication path than USB audio support alone.

However, `etc/ipod.cfg` describes legacy iAP lingoes, USB audio and external
accessory communication. It does not identify the authentication coprocessor's
version or prove that an iPhone will accept it for a new CarPlay session. The
LIVI reference uses actual certificate/challenge operations on a coprocessor;
the Toyota SAM firmware-verification service is a different interface and must
not be substituted for Apple accessory authentication.

The AIR library's dynamic symbols import `MmCreateGraph`, `MmAcquireInputChannel`
and related QNX media-graph APIs. No H.264-named decoder entry point was found in
its dynamic symbols. The decoder class names found previously are not, by
themselves, an exported native decoder API.

## Step 9 - Validate the first native components

Status: PC tests and ARM object compilation passed on 2026-09-09.

`tests/iap2_tests.cpp` checks all 33 unmodified upstream control-message vectors,
the published ACK/SYN frame bytes, every truncation point, every single-byte
mutation of the SYN frame, fragmentation, coalescing, header resynchronization,
maximum lengths, overflow rejection and authentication sequencing/failure cases.
The fixture SHA256 matches the checked-out upstream file exactly. These are
source-project vectors, not a session captured from this car or an iPhone.

All five CTest suites pass with MSVC Release builds. Both C99 translation units
also compile for Cortex-A8/32-bit ARM with Clang warnings treated as errors.
The wire object has no undefined symbols; the auth object references only the
three local wire-codec functions. The combined relocatable object check is
reproduced by `scripts/Check-CarPlayArm.ps1`. These are object files without a
program entry point, not QNX executables or USB update payloads.

The portable implementation and tests use GPL-3.0-or-later, with source
attribution and the upstream license retained in `third_party/`. No proprietary
Toyota firmware is bundled with these components.

## Step 10 - Try to obtain the original software image

Status: exact 6.9.0WL image remains unavailable locally.

Two candidate paths on Toyota's known public update host were checked with HTTP
HEAD, using the existing corpus's naming pattern:

- `Updates/Toyota/6.9.0L_EU/6.9.0L_EU.zip`
- `Updates/Toyota/6.9.0L/6.9.0L.zip`

Both returned HTTP 403 on 2026-09-09. They are guessed candidate paths, not
verified package links. A 403 does not prove that an archive never existed or
is unavailable through Toyota's customer/dealer channels. No substitute version
was presented as the installed image, and nothing was downloaded from these
paths. The 6.9-versus-6.17 loader comparison is still outstanding.

## Step 11 - Inspect the owner's existing head-unit photographs

Status: all seven JPEGs inspected directly on 2026-09-09. No new photos are
needed to reconfirm the displayed software versions.

Source folder: `C:/Users/donjulio/Pictures/headunit`. The original photos remain
outside this repository and were not copied into Git or uploaded to a search
service. The navigation identification/request-code strings are not reproduced
here; they do not provide a labelled module part number or hardware revision.

| Photo | Visible evidence |
| --- | --- |
| `IMG_5867.jpeg`, `IMG_5869.jpeg` | Navigation software `6.9.0WL`, maps `2017 v1`, and navigation device-ID/request-code fields. |
| `IMG_5868.jpeg` | Audio software `0101B0`, audio device ID `13TFDAEU-DA05`. |
| `IMG_5870.jpeg` | Open-source information: `http_streamer`, `lua`, `sideStreamer`. |
| `IMG_5871.jpeg` | `wavePrompter`, `wms_streamer`, `dbus`, and the `hashCalc` package heading. |
| `IMG_5872.jpeg` | `hashFile`, `HMI`, `jvm_cdc_common`, and the `jvm_cdc_eu` package heading. |
| `IMG_5873.jpeg` | `jvm_cdc_eu` with Harman/Apache/LGPL attribution, `TMEClient`, `toyotaAudioCtrlSvc`, and the `verifyISO` package heading. |

All fourteen package names appear in the same order in the later corpus's
`image-380000/etc/license.txt`. The visible licence labels also agree. This is
additional evidence linking the installed navigation software to the researched
software family, not proof that its binaries, loader checks or board revision
match 6.17. In particular, a `verifyISO` licence entry does not reveal which
authentication checks the installed version performs.

None of these pictures shows a physical module label, a labelled Go hardware
revision, or the Apple authentication coprocessor's identity. The audio device
ID must not be relabelled as the Go module's part number. Keep the original
6.9 image and physical/runtime identity as separate outstanding evidence.

## Step 12 - Narrow the existing authentication-chip identification route

Status: driver metadata inspected on the PC; no native driver or bus operation
was executed.

The later corpus's `lib/dll/iofs-i2c-ipod.so` contains these exact strings:

- File offset `0x0b1c`: `/dev/i2c0`.
- File offset `0x0b80`: `=Iacp_ver`.
- File offset `0x0b8c`: `=Sauthcoproc`.
- File offset `0x16d5`: `VERSION=20.26.53`; the embedded build date is
  `2015/10/06-10:39:27-EDT`.

QNX's own release notes describe this module as the interface to the iPod
authentication chip, independently supporting the interpretation of the Toyota
boot configuration. [QNX Aviage Multimedia Suite release notes](https://www.qnx.com/developers/articles/rel_3503_5.html).

The initial hypothesis was that `acp_ver` might offer a runtime metadata query.
**Superseded by Step 13:** its descriptor value is fixed; the actual runtime
identity follows a different path. The module's own
`VERSION=20.26.53` is a software build identifier, not the Apple chip generation.
Its exported `iofs_module` object is a plugin interface, not an established
standalone certificate/signing API. These clues do not yet justify a new
program taking ownership of `/dev/i2c0` alongside the stock iPod service.

Reproduce the string inspection without executing the vendor library:

```powershell
./build/Release/fwinspect.exe strings extracted/qnx-system-v3/image-380000/lib/dll/iofs-i2c-ipod.so
```

## Step 13 - Separate plugin metadata from the actual chip identity

Status: disassembled and exercised with synthetic identity bytes on 2026-09-09.

Two original binaries are now pinned by SHA256:

| Module in `image-380000/lib/dll/` | SHA256 |
| --- | --- |
| `iofs-i2c-ipod.so` | `f7791854a0fd94a9eaa85159291007ffb49c07ea49a7e66253c5aa07df8919e6` |
| `iofs-ipod.so` | `f0598ab13b10ad77fca2a309a484453512c0c9094ff726de77d54416c74cf629` |

All addresses below are module-relative virtual addresses, not runtime process
addresses. The executable segments start at file offset/address zero. Writable
segment addresses differ from file offsets by `0x1000` in both modules.

The I2C module's descriptor at `0x1c28` pairs `=Iacp_ver` with the literal
integer `1`, followed by `=Sauthcoproc` and `0x858`. The main iPod module has
the same descriptor values at `0x359b8`. These are fixed plugin declarations.
Interpreting the first as an interface-version declaration is an inference;
it is definitively not a value fetched from the physical chip.

The actual identity path is in `iofs-ipod.so` at `0x3db8`:

1. Initialize the configured I2C provider.
2. Read four bytes starting at register `0x00`.
3. Cache byte 0 as `device`, byte 1 as `firmware`, and bytes 2-3 as the
   big-endian chip `protocol` version.
4. Branch on those values. This legacy code handles device values 1, 2 and 3,
   and chip-protocol major values 1 and 2. Unknown values return failure in the
   tested paths. These are software branches, not the identity of this car.

The numbers must not be conflated:

| Value | Meaning / limit |
| --- | --- |
| `acp_ver = 1` | Fixed plugin metadata; not a hardware measurement. |
| Register `0x00` | Live chip device-version byte, still unknown on the car. |
| Registers `0x02`-`0x03` | Chip register-protocol version; major 2 is not proof of iAP2 link support or CarPlay. |
| Driver `VERSION=20.26.53` | QNX software build identifier. |

The cached-description routine at `0x2f90` emits `authcoproc` metadata with
`type`, `device`, `firmware`, `protocol`, `devno` and `x509/size`. It delegates
I2C details to the provider's `0x600` callback: `addr`, `path`, and `speed`.
With a synthetic identity of `03 05 02 00`, the original routines report device
3, firmware 5 and protocol 2.00. **These are test inputs, not readings from the
owner's unit.** Description alone generated no bus operations in the harness.

A higher-level description callback at `0x29008` calls `0x2f90` at `0x290a0`.
Separately, the extracted `io-fs-media` contains `.FS_info.` and `info.xml`
strings. An existing media-information pseudo-file is therefore a candidate
read-only route, but its complete path, callback dispatch and availability on
6.9.0WL have not been established. Do not present a guessed path as a working
command or assume it is accessible from the ordinary head-unit menus.

Update: Step 16 resolves the callback dispatch and relative path in 6.17.0WL.
Collection from the owner's installed 6.9.0WL remains unestablished.

## Step 14 - Trace certificate and challenge-response transfers

Status: native callback table and register sequences reproduced with mocks.

The I2C provider's callback table starts at `0x1d68`:

| Table slot | Routine | Observed responsibility |
| --- | --- | --- |
| `0x1d98` | `0x8d4` | Parse options, open `/dev/i2c0`, optionally set bus speed. Default slave address is `0x10`; an `addr` option can override it. |
| `0x1d9c` | `0x840` | Lock/unlock control through `devctl`. |
| `0x1da0` | `0x798` | Register read using `devctlv`, command `0xc0140507`, with one register-select byte followed by a receive. |
| `0x1da4` | `0x6e4` | Register write using `devctlv`, command `0x80100505`, sending register selector and payload. |
| `0x1da8` | `0x6cc` | Unsupported readiness callback: sets errno 89 and returns -1. |
| `0x1dac` | `0x600` | Emit cached I2C configuration metadata. |

The read/write layouts match QNX's `DCMD_I2C_SENDRECV` and `DCMD_I2C_SEND`
interfaces. QNX documents combined send/receive as an atomic register-read
operation and provides bus-lock commands. This supports using the existing
QNX bus interface, but does not establish correct arbitration with Toyota's
running media service. [QNX 6.5 I2C framework](https://www.qnx.com/developers/docs/6.5.0SP1/neutrino/technotes/i2c_framework.html).

In the main iPod module, the chip-protocol-major-2 branch uses:

| Operation | Register sequence verified in the harness |
| --- | --- |
| Identify | Read 4 bytes at `0x00`; later read 4 bytes at `0x04` for `devno`. |
| Certificate | Read 2-byte big-endian length at `0x30`; read at most 128 bytes per page starting at `0x31`, incrementing the register for each page. Cache at context offset `0x58`. |
| Submit challenge | At routine `0x3944`, lock the bus and write a combined 2-byte big-endian length plus challenge payload starting at `0x20`. Write `01` at `0x10` to request signing. |
| Retrieve signature | Read status at `0x10`, signature length at `0x11`, then signature bytes at `0x12`. An error-status path reads `0x05`. |
| Deliver / release | Calls the legacy iPod command sender with command `0x18`; the harness intercepts this. The caller cleanup routine at `0x371c` releases the lock. Calling only the inner signing routine is not a complete transaction. |

The certificate/signing register addresses overlap the pinned LIVI MFi
implementation's operations. LIVI instead selects separate challenge-length
and challenge-data registers (`0x20`/`0x21`) and uses a different read/polling
strategy. The overlap is concrete support for investigating reuse; it does
not prove that all transaction forms work on the installed chip.
[Pinned LIVI I2C implementation](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-mfi/src/linux.rs).

Two important limits emerged:

- The legacy core's accepted chip-protocol versions do not constrain what a
  new provider could implement through the lower-level register interface.
  Conversely, copying the legacy core does not add CarPlay negotiation. Its
  signature output is a legacy iPod message, not an iAP2 authentication CSM.
- The certificate reader accepts lengths 1-2048, but its page loop stops after
  reading the page at offset 1792: at most 1920 bytes total. With a declared
  length of 2048 it returns success after only 1920 bytes, leaving the final
  128 bytes untouched in the test context. Any reused certificate path needs
  an exact-length check; the old reader must not be treated as generally sound.

No certificate, private key or real signature was extracted. No real chip was
contacted, and no iPhone authenticated. The hardware-reuse question is now a
specific interface/identity test, not simply whether Bluetooth or USB exists.

## Step 15 - Preserve and validate the native-driver trace

Status: 17 native ARM scenarios and five tool-safety tests pass on 2026-09-09.

New tools:

- `scripts/inspect_ipod_auth.py`: verifies each binary's SHA256, reads dynamic
  relocations and provider metadata, and optionally disassembles a bounded
  range using LLVM. Because these ELFs retain only non-code section headers,
  it clears their section-directory fields **in memory only**, so LLVM can
  disassemble the load segments. Original files, code and data remain intact.
- `scripts/probe_ipod_auth.py`: loads the two pinned modules into Unicorn,
  resolves their relocations, and executes selected native routines together.
  All filesystem/device calls, timing, logging, XML emission and phone-message
  dispatch are intercepted. Each native call has a 300,000-instruction and
  five-second limit; unexpected imports, code paths or interrupts fail.
- `tests/test_ipod_auth_tools.py`: checks hash mismatch rejection, exclusive
  output creation, bounded disassembly ranges, unchanged input files and the
  precise analysis-only header adaptation.

The 17 native scenarios cover a complete synthetic identity/certificate/signature
sequence, cached metadata without bus I/O, certificate lengths 1/128/1920 with
cached reinitialization, the protocol-1 identity branch, rejected device/protocol
values, certificate lengths 0/2049, the 2048-versus-1920 paging mismatch, bus
failures/timeouts, open/speed-setup failures, signature error status, oversized
signature, and temporarily unavailable signature status. Success uses arbitrary
synthetic certificate/signature bytes; it tests byte transport, not cryptography.

Reproduce from the project root using the existing Unicorn 2.1.4 dependency in
`build/python-libs` (LLVM is only needed for disassembly):

```powershell
python -B scripts/inspect_ipod_auth.py
python -B scripts/inspect_ipod_auth.py --module ipod --disassemble
python -B scripts/probe_ipod_auth.py
python -B -m unittest discover -s tests -p test_ipod_auth_tools.py -v
```

The latest 17-scenario record is `extracted/ipod-auth-probe-v2.json` (ignored by
Git); the earlier 13-scenario exploratory run is `extracted/ipod-auth-probe.json`.
Both tools accept `--output NEW_PATH` and refuse existing output files. Use a
new filename for another saved run. These corpus-dependent tests are separate
from the five CTest suites and the earlier 13 Lua update-path checks.

## Step 16 - Connect cached chip details to the media-information file

Status: static dispatch/path trace established for the pinned 6.17.0WL corpus;
selected native routines reproduced with synthetic state on 2026-09-09.

The additional input is
`extracted/qnx-system-v3/image-380000/usr/sbin/io-fs-media`, SHA256
`92c92ef5a41c1a4ed15ab7bc89167b94def45a31d526afe5ca6c6f4214f4a6c5`.
It is an ARM executable whose text begins at virtual address `0x100000`.
Addresses below are ELF virtual addresses, not all file offsets.

QNX documents `io-fs-media` as a filesystem interface to media devices. Its
documentation is background only: the Toyota-specific path and callback
addresses below come from this pinned binary, not a guarantee from newer QNX
documentation. [QNX io-fs-media reference](https://get.qnx.com/developers/docs/7.0.0/com.qnx.doc.io-fs-media/topic/io-fs-media.html).

1. **Register the iPod interface.** In `iofs-ipod.so`, exported `iofs_module`
   at `0x356f8` points through its `+0x24` field to the `drvr` interface at
   `0x38a20`. Interface `+0x3c`, address `0x38a5c`, contains `0x29008`.
   The service's `iface_find` writes the module pointer to interface `+0x0c`
   at `0x1152f8`-`0x1152fc`. These are dynamically initialized interface
   fields, not immutable chip identity values.
2. **Build the cached description.** In `mount_create` (`0x1160cc`), the
   device-description block opens a `device` XML element, emits the driver
   name, and calls the interface's `+0x3c` callback at `0x116980`, passing
   `(device, mount)`. This is the device-driver branch, not the separate
   volume-provider callback at `0x116918`. The mount's XML buffer starts at
   `mount + 0x80`.
3. **Append chip details.** The iPod callback `0x29008` calls its cached
   authentication-description function `0x2f90` at `0x290a0`. That function
   emits the `authcoproc` subtree and delegates the I2C settings to the
   provider's description callback. A null authentication-context pointer
   omits the subtree. Description is not a new chip-identification query.
4. **Expose a filesystem node.** The service creates a `.FS_info.` directory
   under the mount root in the code around `0x116000`-`0x1160a4`. Its
   `hier_build` special-directory branch (`0x110534`) links the `info.xml`
   node as a child. `node_get` (`0x1170ac`) uses internal index `N+1` for the
   directory and `N+3` for `info.xml`, where `N = *(mount + 0x11c)`. The
   file node reports mode `0x8124` (regular file, permission bits `0444`)
   and the cached byte length at `mount + 0x88`. An empty cache returns 2
   for the file node instead of exposing an empty information file.
5. **Read the cached bytes.** In `attr_attach`, the `N+3` branch loads
   `mount_info_io` from the literal at `0x10caa4` and installs it as the
   attribute's callback at `+0x6c` (`0x10ca5c`-`0x10ca60`).
   `mount_info_io` (`0x115870`, 192 bytes) copies from the cached buffer at
   `mount + 0x80`, in descriptor units of 512 bytes, clamped to its stored
   length. The selected native read callback contains no chip polling or
   authentication callback. This is not a full resource-manager or access-
   permission test.

The resulting **derived path**, with its unresolved component kept explicit, is:

```text
<actual iPod mountpoint>/.FS_info./info.xml
```

It is inside the unit's media filesystem, not automatically a file exported
to a plugged-in USB drive or shown by the normal user interface. No mountpoint
such as `/fs/ipod0` has been measured on this unit. No on-car command is supplied.
The name lookup tests also show that case sensitivity depends on a mount flag;
preserve the exact `.FS_info.` and `info.xml` spelling.

The expected chip fields remain `type`, `device`, `firmware`, `protocol`,
`devno`, `x509/size` and `i2c/{addr,path,speed}`. The tested callback emits
certificate **size**, not certificate bytes or any private key. These cached
fields could be absent, stale or uninitialized; their presence alone does not
prove current chip health, CarPlay capability, or acceptance by an iPhone.

## Step 17 - Preserve and validate the cached-export trace

Status: 19 native media-information scenarios and eight tool-safety tests pass.

The previous state was committed before this investigation as `4167001`,
`Trace Apple authentication drivers with bounded ARM probes`. This step's
new analysis is subsequent working-tree work, not part of that checkpoint.

`scripts/inspect_ipod_auth.py` now also pins the media executable and reports
its relevant exported functions and path components. The iPod metadata output
now identifies the driver-description table and callback. Optional media
disassembly defaults to the complete `mount_info_io` routine.

New `scripts/probe_media_info.py` executes these 19 scenarios:

- The actual iPod `0x29008` callback, selected through its relocated table,
  forwards a synthetic cached identity to `authcoproc` XML emission with no
  bus calls during description. The optional transport-description branch
  is not exercised.
- A bounded slice of `mount_create`, `0x116938`-`0x116984`, calls a **mocked**
  driver callback with the observed `(device, mount)` arguments. It does not
  execute the whole mount routine. XML emission is mocked in both tests;
  these are separate checks, not an end-to-end native XML serialization test.
- The special `.FS_info.` hierarchy branch links the `info.xml` child node.
  Its name hash is mocked; generic directory traversal is not exercised.
- Two built-in node cases verify directory/file names and modes, three
  lookup cases verify exact/wrong-case/configured-insensitive matching, and
  an empty-cache case verifies file-node omission.
- Eight read cases verify one-block copying, length clamping, the final
  partial block, offset beyond EOF, a large non-wrapping offset, disabled
  operation flags, a non-special descriptor, and zero requested blocks.
  Two more cases verify multiple descriptors and an empty cache. Destination
  canary bytes after each copy must remain unchanged.

Every native call is bounded to 300,000 instructions and five seconds. All
guest imports are intercepted; unhandled imports, out-of-scope execution and
interrupts fail. Libc COPY-relocation storage is synthetic zeroed memory and
unused by the selected paths; the QNX process initializer is not executed.
No guest operation can open a host device, file, process or network connection.
These are bounded behavioral checks, not a security audit of the media service.

The extended safety tests cover all three input pins, the media read-callback
literal and driver table, existing-output refusal for all three tools,
forbidden process initialization/imports/interrupts, and the explicit slice
gate. The earlier 17 authentication scenarios still pass, as do all five CTest
suites. Native authentication and media probes remain separate from CTest.

Reproduce from the project root with the existing Unicorn dependency:

```powershell
python -B scripts/inspect_ipod_auth.py --module media --disassemble
python -B scripts/inspect_ipod_auth.py --module media --disassemble --start 0x116938 --stop 0x116984
python -B scripts/inspect_ipod_auth.py --module ipod --disassemble --start 0x29008 --stop 0x290a8
python -B scripts/probe_media_info.py
python -B scripts/probe_ipod_auth.py
python -B -m unittest discover -s tests -p test_ipod_auth_tools.py -v
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
```

The first saved 19-scenario record is `extracted/media-info-probe.json`, ignored
by Git. Optional `--output NEW_PATH` creates a new file and never overwrites
previous evidence. All identity and cached-content bytes in this test are
synthetic. No real chip identity, certificate, signature or phone data was read.

## Step 18 - Define the remaining read-only collection task

Status: collection target identified; an access mechanism on the car is not.

The next local investigation is to look for an existing diagnostic/log-export
route that can read the media-information file without installing code or
changing service flags. Do not assume such a route exists. The owner's current
photos do not provide it, and no live QNX connection is available in this work.

If a supported read-only route is established, collection should proceed in
this order:

1. Confirm the actual Go-module part number/hardware revision and that the
   installed 6.9.0WL has the same export. Resolve the real iPod mountpoint
   from observed state, not the later corpus's naming conventions.
2. Retrieve an existing information file through that route. Do not reset the
   chip, issue signing requests, write directly to I2C, restart the media
   service, or alter firmware just to obtain identity. If no such route exists,
   stop collection and resolve safe execution/recovery separately.
3. Inspect only the needed `authcoproc` fields: device version, firmware,
   register-protocol version, provider type, certificate length and bus
   configuration. Keep full exported documents out of Git: they may also
   contain phone/device identifiers. `devno` is not needed in a public report.
4. Treat the values as evidence for a provider implementation, not a CarPlay
   verdict. Verify complete certificate retrieval, bus ownership and finally
   real iPhone authentication in separately authorized tests. A cache-only
   read cannot answer those questions.

This completes the planned cached-export trace on the PC, not the software-only
CarPlay receiver. No diagnostic payload, modified firmware, update USB or car
change has been created.

## Step 19 - Inspect existing diagnostics without activating them

Status: candidate inspection completed on the PC for the later 6.17.0WL corpus;
no read-only export to the owner's PC established.

The preceding cached-export state was committed as `90d26f1`,
`Trace cached Apple chip metadata through media information export`, before
this investigation. Findings below are subsequent working-tree work.

Searches covered the extracted boot/configuration files, Lua services, media
consumers and diagnostic binaries. A referenced script missing from the earlier
selective extraction was read directly from the checksum-pinned installation
ISO. This does not constitute a complete audit of every HMI/diagnostic path.

| Candidate | Evidence examined | Result and constraint |
| --- | --- | --- |
| Insight snapshot | `etc/acp-toyota.conf` and ISO member `usr/share/MMC_PROG_DATA/usr/share/scripts/snapshot.sh` | The script copies a screen bitmap to `/tmp/ScreenShot.bmp` and prints success/failure. It does not collect `info.xml`. It was read, not executed. |
| Insight/ACP logging | `insightDetect.lua`, `mcd.conf`, `mcdLossless.conf`, `runacpclient.sh`, `secondary-boot.sh`, `acp-toyota.conf` | A separate media trigger can request logging startup. The configuration includes HTTPS uploads, database storage, attachments and periodic location/CPU/memory events. This is not a read-only identity query; see Step 20. No server was contacted. |
| Crash dumping | `misc.sh`, `dumper.sh`; supporting strings in `fdumper` | The boot path is conditional on internal `START_DUMPER`. The shell script launches a process dumper and creates an output directory on USB or internal MMC. It does not select the chip-information file. `fdumper` references process-death notifications and a DBus ring-buffer log. Do not provoke a crash or enable dumping to identify the chip. |
| Telnet and service gateways | `misc.sh`, `inetd.conf`, `pre-hmi.sh` | Telnet startup remains gated by internal `ENABLE_TELNET`; DBus/Trace gateways default to `--localonly` unless internal `ALLOW_SVC_ACCESS` exists. Neither flag has been observed on this unit. No network probe or flag change was attempted. |
| USB serial login | `misc.sh`, `etc/system/config/pgetty.cfg` | The stock configuration names `serusb1` and `/bin/login`. This establishes a configuration entry, not a working connection, credentials or an owner-accessible console. It is not a software-only collection route already available to us. |
| Existing Apple metadata consumer | `usr/share/connmgr/AppleAppIns.lua` | Reads the derived information-file path using the mountpoint in a session record. It updates connection-manager product/vendor labels and emits an insertion event; it does not forward `authcoproc`. Running the whole script is not a read-only export operation. |

The snapshot member was read using **Windows'**
`C:/Windows/System32/tar.exe -xOf`, after validating the ISO's SHA256. The
unqualified `tar.exe` in this environment resolves to a GNU tar that rejected
the ISO; its failed list operation did not alter anything. No further firmware
download or persistent vendor-file extraction was needed.

## Step 20 - Distinguish logging triggers from chip-information collection

Status: boot/media paths distinguished statically; stock Lua callbacks reproduced
with mocks. Earlier reports' internal-flag-only emphasis is incomplete.

1. **Internal boot path.** `secondary-boot.sh` checks
   `/fs/etfs/ACPClientON` and a variant condition before requesting the logging
   script. The subsequent `NO_INSIGHT` condition guards additional startup
   commands, not every possible logging launch.
2. **Separate media path.** `misc.sh` also starts the `insightDetect` Lua
   service. That service registers for the `ACPClient_ON` MCD rule. Both
   extracted MCD configurations contain that rule and look for the
   `ACPClientON` marker on media. Its matched notification calls
   `runacpclient.sh` without a Lua-side check for the internal boot flag.
   This is a traced candidate in the later corpus, not an on-car test or a
   recommendation to create that marker.
3. **Conditional reachability.** The stock USB decision graph reaches this
   rule only after earlier application/audio/picture branches fail to take
   their matching exits. Consequently its behavior cannot be inferred from
   marker presence alone. The new model supplies synthetic callout results;
   it does not emulate native filesystem matching, mount events or timing.
4. **Side effects.** The called shell script uses a session lock, starts
   `acpmonitor`, a DBus ring buffer, and `fdumper`. The Insight configuration
   provides storage and upload settings. Actual upload availability or
   transmission is untested, but enabling this stack cannot be described as
   merely reading chip identity. Do not activate it as this investigation's
   collection method.

QNX documents MCD as a branching content classifier: clients are notified for
matched rules, and filename tests operate against the media filesystem. That
supports interpreting this configuration graph; it does not establish the
owner's installed daemon behavior or active configuration.
[QNX MCD reference](https://www.qnx.com/developers/docs/6.4.1/neutrino/utilities/m/mcd.html).

The Insight script's long header discusses software updating, but its actual
executable body only registers the logging callback. The source comments were
not treated as evidence of an updater or arbitrary-code loader in this path.
With the shell call mocked, the callback requests launch for both success and
failure return values and can request it again on another notification. The
external shell script's lock is not emulated by those tests.

The separate `AppleAppIns.lua` consumer provides a useful cross-check of the
information path. Its stock bytecode:

- Reads a session record, takes element 3 as the mountpoint, and opens
  `<mountpoint>/.FS_info./info.xml` for reading, with up to five attempts.
- Converts the XML and selects `info/device/transport/usb` product and
  manufacturer fields, optionally appending a media name to the product label.
- Sends only `dev.product_str` and `dev.vendor_str` through connection-manager
  `setProperties`, then emits an insertion proxy event. The tested synthetic
  `authcoproc` subtree is not forwarded.

This is positive evidence that the file has a stock reader, but negative
evidence for using **this particular consumer** to obtain chip details remotely.
It does not prove that every other media API or HMI route lacks such a feature.
The native `MediaService` also contains the information-file path; its complete
XML/API handling has not been audited in this step.

## Step 21 - Preserve the diagnostic checks and choose the next software task

Status: 10 modeled MCD cases, seven mocked stock Lua cases and five additional
safety/regression tests pass on 2026-09-09.

New reproduction files:

- `scripts/probe_diagnostic_routes.py`: verifies 11 extracted input hashes,
  follows both MCD graphs with synthetic callout outcomes, runs the bounded
  Lua harness, and reads the snapshot member into memory from the pinned ISO.
  The JSON record includes input hashes and explicit scope limits.
- `tests/diagnostic_routes_probe.lua`: executes the original Insight plaintext
  and Apple consumer bytecode in restricted guest environments. All file I/O,
  commands, services, XML/JSON conversion and delays are mocked. Each run or
  callback has an instruction budget below 200,000; the host subprocess also
  has a 20-second timeout. No vendor shell script is executed.
- `tests/test_diagnostic_routes.py`: verifies the complete probe, changed-input
  and changed-ISO refusal, existing-output protection, and failure on cyclic
  graphs or missing mock results.

The MCD model checks marker match/no match and application/audio/picture
preemption in both configurations. The Lua checks cover Insight launch requests
with two mocked return statuses, and Apple metadata forwarding, delayed file
availability, missing information file, failed XML conversion and missing
session file. These test control flow, not actual XML parsing, phone data,
native MCD events, network services or access permissions.

```powershell
python -B scripts/probe_diagnostic_routes.py
python -B -m unittest discover -s tests -p test_diagnostic_routes.py -v
```

The first saved evidence is `extracted/diagnostic-routes-probe.json`, ignored
by Git. `--output NEW_PATH` refuses existing files. The existing Win32 Lua
5.1.5 host and Windows tar are required; Unicorn is not used by this probe.
The earlier 17 authentication and 19 media-information native checks, eight
auth/media tool-safety tests and five CTest suites were rerun successfully.

**Outcome:** no read-only chip-information collection route to the PC has been
established among the inspected candidates. No USB marker was created, no
logging setting changed, no screenshot/crash dump requested and no remote
service contacted. The actual chip identity and CarPlay acceptance remain
unknown. The installed 6.9.0WL and exact Go hardware are still not available
for comparison.

The next productive implementation task is hardware-independent: add a bounded
iAP2 reliable-link state machine around the portable framing code, with host
tests for negotiation, sequence/ACK handling, retransmission and disconnects.
Use deterministic caller-supplied time and simulated transport; do not bind it
to the car yet. This can progress while identity/access/recovery remain open,
but cannot validate Apple authentication or make an installable receiver by
itself. The remaining native `MediaService` XML/API trace is another local
read-only investigation option; neither path authorizes enabling diagnostics.

## Step 22 - Implement a bounded iAP2 reliable-link profile

Status: implemented and tested on the PC; no native transport or iPhone test.

New `src/carplay/iap2_link.h` and `iap2_link.c` wrap the existing frame/stream
codec with an explicit state machine. They are part of the GPL-3.0-or-later
`carplay_protocol` library. The pinned LIVI source supplies public protocol
format/behavior reference, not a claim of Apple conformance.
[Pinned link reference](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-link/src/lib.rs),
[pinned upstream tests](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-link/tests/engine.rs).

The implemented progression is:

```text
IDLE -> DETECT (marker exchange) -> SYNCHRONIZE -> NORMAL
                                      |             |
                         timeout/reset/restart/EOF -> DEAD
```

1. **Detection and negotiation.** The marker can arrive in fragments. Marker
   and SYN retries are scheduled at 1000 ms and 500 ms respectively, within
   a total configurable handshake deadline (default 10 seconds). Reaching
   `NORMAL` requires a valid peer SYN, acknowledgement of the local SYN's
   exact sequence number, and handing the peer-SYN ACK to the transport caller.
   ACK-only traffic cannot open the link. An identical repeated peer SYN is
   re-ACKed; a changed accepted SYN terminates the old link as a restart.
2. **Strict synchronization payloads.** The version-1 codec checks complete
   session triplets, unique nonzero IDs, positive window/timer/retry values
   and compatible ACK timing. The engine accepts peer-selected window/packet
   limits only within its offer, retains the offered control session, and
   rejects unoffered session IDs/types/versions. There is no counterproposal
   algorithm or broader compatibility fallback yet.
3. **Bounded sending.** Eight fixed queue slots store copies of accepted
   payloads. The default in-flight window is four packets; filling that window
   does not send an extra packet. Sequence numbers are assigned when output
   is handed to the caller, not when data is queued. A full queue returns
   `BUSY` without accepting another message. Future ACKs cannot free unsent
   data; stale ACKs leave retained packets unchanged.
4. **Reliable receiving.** In-order delivery is separate from receipt/ACK
   tracking. Eight receive slots retain accepted payloads, including bounded
   out-of-order data, until the application reads them. Duplicates are not
   delivered twice. If storage fills, a new packet is dropped without
   advancing its cumulative ACK and `BUSY` is returned; recovery depends on
   the peer retransmitting after the application drains the queue.
5. **Timers and teardown.** Delayed ACKs can become cumulative or piggyback
   ACKs. Pure ACKs do not cause ACK traffic. Each sent packet keeps its own
   timer, so newer sends cannot postpone an older packet's timeout. The
   configured retry count means retransmissions **after** the initial send.
   Retry exhaustion, reset, changed accepted SYN, invalid marker, oversized
   receive frame or caller close ends the link and discards queue occupancy.
   Reconnection requires explicit reinitialization and resetting upper-layer
   authentication/session state. This is not secure erasure of buffer bytes.

Default profile and storage:

| Setting | Implemented default / bound |
| --- | --- |
| In-flight window | 4 by default; configured at most 8, sequence space kept below 128. |
| Frame size | At most 1024 bytes, including the header and optional body checksum. A default payload is at most 1014 bytes. |
| Queues | 8 TX and 8 RX slots, fixed memory; 17,688 bytes for the complete state on the tested Windows host ABI. Target ABI size is not asserted. |
| Data retransmission | 1000 ms; 3 retries after the initial transmission by default. |
| ACK policy | 100 ms or 2 accepted contiguous payloads by default; an outgoing data frame can acknowledge sooner. |
| Sessions | Control ID 10, type 0/version 1 by default. Up to 3 explicit offers; additional application protocols are not implemented by merely offering their IDs. |

Time is supplied as monotonically nondecreasing 64-bit milliseconds. Timer
arithmetic uses elapsed intervals, avoiding overflowing absolute deadlines near
the clock's upper limit. No engine operation allocates memory, sleeps, opens a
file, performs a USB/network write or invokes an application callback.

This is a deliberately limited profile. EAK controls, zero-ACK operation and
forced negotiation without marker exchange are unsupported. Gaps recover by
ordinary cumulative ACKs and packet timeouts, not EAK. The bounded queue/window,
ACK validation and retry semantics are local implementation choices, not a
byte-for-byte port of every behavior in the reference engine. No Apple-private
protocol documentation or certification has been used to establish conformance.

## Step 23 - Validate the link engine, memory behavior and ARM build

Status: six CTest suites pass; 16 link test groups, both sanitized protocol
suites and the expanded ARM portability check pass on 2026-09-09.

`tests/iap2_link_tests.cpp` is a new CTest executable. Coverage includes:

- Exact pinned synchronization-payload bytes and strict malformed-LSP rejection.
- Fragmented marker/frame input, garbage resynchronization, bad body checksums,
  coalesced-input consumption and oversized-header termination.
- Detection/negotiation deadlines, combined SYN/ACK, rejected ACK-only or wrong-
  sequence opening, duplicate SYN handling and peer restart/reset termination.
- Exact window limits, queue-full backpressure, cumulative prefix removal,
  all 256 ACK distances across sequence wrap, and 300 send/receive iterations.
- Retry timing/exhaustion, timers starting at output, oldest-packet deadlines,
  delayed/cumulative/piggyback ACKs and suppression of ACK-only response loops.
- Out-of-order receive, duplicate suppression, full RX queue with later retry,
  maximum/empty payloads, negotiated session/packet limits and session routing.
- Short marker/SYN/final-ACK/data/retry output buffers without consuming pending
  state, short application receive buffers, backward time, near-`UINT64_MAX`
  time arithmetic, disconnect and explicit reinitialization.
- Two independent engine instances connected by a synthetic byte transport.
  One data frame and one cumulative ACK are deliberately lost. All eight
  queued payloads eventually arrive exactly once and in order, and the sender
  releases every acknowledged packet. This is a self-interoperability test,
  not an iPhone or upstream-runtime comparison.

An early receive-capacity test used the wrong next sequence number; correcting
the fixture made it exercise actual queue saturation. The first ARM build also
exposed compiler-generated `__aeabi_memcpy` calls for struct assignment. The
new implementation uses explicit byte-copy loops; the final ARM object has no
unresolved runtime imports. These were PC test/build findings, not car failures.

`scripts/Check-CarPlaySanitizers.ps1` compiles the C sources and both C++
protocol test executables with the installed LLVM/Visual Studio toolchain,
AddressSanitizer and UndefinedBehaviorSanitizer, with sanitizer failures fatal.
It builds under ignored `build/carplay-sanitized` and makes the existing ASan
runtime available only within the script's process environment.

Reproduce:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
```

The ARM check now covers `iap2_wire.c`, `iap2_auth.c` and `iap2_link.c`. It
still produces a relocatable Cortex-A8 object, **not** a linked QNX program,
firmware update or executable validated on the unit. Sanitizer success covers
the exercised host cases, not every possible input or target timing behavior.

## Step 24 - Define the next integration boundary

Status: link/profile groundwork complete for this step; receiver integration
remains open.

The public API separates four responsibilities:

1. `feed`: consume incoming transport bytes and honor its consumed count even
   on an error; keep any unconsumed tail outside the engine.
2. `receive` / `send`: drain in-order session payloads and queue bounded outgoing
   payloads. Respect `MORE`, `BUSY` and `NO_SPACE`; do not silently drop data.
3. `output`: drain encoded output while the transport can retain the entire
   returned frame. Preserve partial physical-write tails externally, or close
   on failure. Handing a frame to this function's caller is not proof that a
   USB device accepted it.
4. `next_delay` plus caller time: service timers without blocking the engine.
   On closure/reinitialization, reset the separate authentication and session
   layers. The link object must not be copied after initialization, because
   its embedded stream refers to its own receive buffer.

The next implementation task is a bounded control-session adapter: reassemble
CSMs split across link payloads, split larger outgoing CSMs according to the
negotiated packet size, and connect the existing authentication sequencer
through explicit provider callbacks. Test it using synthetic providers and
transport before adding any QNX device access. There is currently no automatic
wiring between `iap2_link` and `iap2_auth`, and no real signing provider.

Physical chip identity, complete certificate retrieval, bus ownership, iPhone
acceptance, QNX USB transport, CarPlay session/media protocols, display/input,
audio focus and recovery still require separate work. Nothing in this step
establishes an installable CarPlay receiver or changes the car. Earlier
uncommitted diagnostic findings were preserved; no commit was requested or
created for this continuation.

Follow-up: checkpointed in `be252e5` at the owner's next request. Steps 25-27
below implement the bounded adapter described here, so the missing automatic
link/auth connection above is a historical status, not the current result.

## Step 25 - Connect control messages to the authentication sequencer

Status: implemented locally on 2026-09-09; synthetic transport/providers only.

The requested initial checkpoint is commit `be252e5`,
`Add bounded iAP2 reliable link and document diagnostic route limits`.
The working tree was clean immediately after that commit. This continuation
adds `src/carplay/iap2_control.h` and `.c`, its test executable, and build/check
integration. These new changes have not been committed automatically.

The adapter uses the six-byte, length-delimited CSM format and authentication
message fields from the same pinned LIVI revision. The references do not
establish that this new adapter interoperates with an iPhone. Its stream
reassembly, reply-ACK barrier and deadlines are explicit local policies, not
private Apple requirements. References checked again on 2026-09-09:
[pinned CSM codec](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/lib.rs)
and [authentication fields](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/messages/authentication.rs).

Implementation sequence:

1. Own the link and authentication objects in one noncopyable endpoint. Only
   the control API operates that link; callers must not separately reinitialize
   its embedded fields. Closing/reinitializing discards partial CSMs, pending
   replies and accepted authentication state together.
2. Offer exactly one control session, kind 0/version 1. Defaults retain session
   ID 10 and the previous link profile. Additional session types are rejected
   at initialization rather than silently drained without a handler.
3. Reassemble the CSM header first, check declared size against the caller's
   receive capacity, and then collect the exact body. A retained link-payload
   fragment preserves the tail when several CSMs share one payload. Malformed
   markers, lengths or parameter tails close the endpoint; there is no search
   for a new CSM marker inside damaged message data.
4. Call the existing authentication sequencer only from `poll`, using explicitly
   supplied synchronous certificate/signing callbacks. The library supplies no
   default signer, device path, key, chip access or certificate contents.
5. Retain each generated reply and queue fragments no larger than negotiated
   frame size minus ten bytes. Queue saturation pauses at the exact unsent
   offset; retries do not repeat the provider call. Later CSMs remain buffered
   until the complete reply is cumulatively acknowledged. This serializes local
   processing; it does not prove when a peer created a buffered message.
6. Hold a valid non-authentication CSM for explicit application inspection and
   release. Such a message is not treated as authentication success, nor is it
   silently executed as an identification or CarPlay command.
7. Enforce configurable local budgets: default 5 seconds from the first CSM
   byte consumed by the adapter through assembly/application release, and
   30 seconds from link NORMAL through authentication acceptance. Byte drips
   do not renew a message budget. Authentication backpressure counts against
   its total budget. Only an in-sequence success notification cancels that
   budget; an ACK alone cannot authenticate the accessory.

The three caller-owned buffers must be distinct: receive capacity 6..65535,
reply capacity 11..65535, and provider scratch capacity 1..reply capacity minus
10. A complete certificate is not assumed to fit a link packet. Tests cover a
2048-byte synthetic certificate and the maximum 65525-byte provider result
inside a 65535-byte CSM; these are capacity tests, not observed chip sizes.
Host endpoint state occupies 18,888 bytes plus caller buffers; the example
8192/8192/8182 buffer sizes bring this to 43,454 bytes, excluding caller/stack
overhead. ARM layout may differ. There is no heap or OS dependency.

## Step 26 - Verify streaming, pressure and connection teardown

Status: all seven CTest suites, all three sanitized protocol suites, the ARM
portability check and all 13 existing Python tool-safety tests pass.

`tests/iap2_control_tests.cpp` adds 14 test groups:

1. Configuration preflight, unchanged state on invalid initialization, argument
   handling, buffer canaries, and a nondefault negotiated control session ID.
2. Every split position in the certificate-request CSM header, with link frames
   themselves delivered one transport byte at a time.
3. Large inbound messages across 1/5/17/1014-byte payloads and an exact
   65535-byte message; unknown message bytes remain intact for the application.
4. Multiple coalesced messages and an application hold before authentication.
5. Malformed markers/lengths/parameters, over-capacity declarations, exact
   receive capacity and stable terminal error reporting.
6. A smaller negotiated 29-byte frame size (19 payload bytes), queue saturation,
   bounded poll yields, short physical-output buffers, exact reply resumption,
   and acknowledgement waits without a perpetual immediate-work timer.
7. Pipelined certificate request/challenge/success input: signing waits for
   certificate acknowledgement, and acceptance waits for signature
   acknowledgement and the explicit success notification.
8. Missing/failing certificate callback, zero/overreported provider result and
   a failing signing callback; no fallback authentication path.
9. Out-of-sequence/rejected authentication and duplicate certificate requests.
10. Disconnect with partial input, pending output, accepted authentication or
    a held application message; reinitialization cannot retain old acceptance.
11. Remote reset/restart, link retry exhaustion and handshake timeout; immediate
    upper-layer reset even without a later poll. A recoverable bad body checksum
    leaves the live endpoint able to accept a valid retransmission.
12. Partial-message/application-hold/authentication deadlines, byte-drip and TX
    stalls, accepted-session timer cancellation, backward time and arithmetic
    near `UINT64_MAX`.
13. Empty payloads, full receive queues followed by peer retransmission, and a
    maximum-length reply across thousands of small negotiated payloads.
14. Two actual library link endpoints exchanging synthetic authentication CSMs
    through fragmented transport. One certificate frame is deliberately lost.
    The peer checks complete certificate/signature bytes before sending the
    next request; both provider callbacks run exactly once despite retransmission.

The initial loss-test fixture inspected header byte 8 (checksum) instead of
byte 7 (session), so it had not actually dropped the intended packet. Its loss
assertion failed. Correcting the fixture made the final test exercise real
retransmission through the local engine. No car or iPhone was involved.

Reproduce from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

The ARM check now includes all four C99 units and reports no unresolved runtime
imports. Its result is still a relocatable Cortex-A8 object, not a QNX program,
installable update or verified target ABI. Sanitizers cover the exercised host
cases, not full protocol conformance. The Python tests require the pinned local
corpus/tools as previously documented; the CTest protocol cases do not.

## Step 27 - Keep the next receiver boundary explicit

Status: adapter integration complete for this local profile; a usable CarPlay
receiver is still not established.

A future transport loop must initialize/start the control endpoint, feed bytes
while honoring consumed counts, poll bounded application work, and drain output
only while it can retain entire returned frames. `MORE` waits for input;
`BUSY` needs transport/ACK progress; `MESSAGE` needs explicit application
handling/release; `OK` from poll requests another bounded poll. The minimum
link/adapter `next_delay` governs timer service. `feed`/`output` never invoke
providers. EOF/transport failure calls `close`, and externally retained write
tails must be discarded before opening a new connection.

Provider calls are synchronous and must themselves be bounded: caller-supplied
time cannot interrupt a hung hardware callback. Buffer clearing on closure is
not a secure-erasure guarantee. General application replies and accessory
identification handling remain absent, even though unknown CSMs can now be
held for inspection. Authentication ACCEPTED denotes only the sequencer's
receipt of an in-order notification, not CarPlay, a validated certificate or
a cryptographic check of the synthetic peer.

The next safe PC-side task is a bounded application-message reply path and
accessory-identification sequencer using the pinned public vectors and explicit
caller-supplied metadata. Do not invent physical device identity or advertise
unimplemented CarPlay capabilities. Keep its tests on the simulated transport
until the real provider, QNX execution/USB access and a recovery route are
established. Chip identity, complete real certificate retrieval, bus ownership
and iPhone acceptance remain unresolved independently of this adapter.

Follow-up: this adapter checkpoint was committed as `f4b8321` at the owner's
next request. Steps 28-30 implement the application-reply/identification work
outlined above; statements about those features being absent are historical.

## Step 28 - Add an atomic application-reply path

Status: implemented and PC-tested on 2026-09-09.

The requested initial checkpoint is commit `f4b8321`,
`Connect bounded control sessions to iAP2 authentication`. The working tree was
clean immediately after the commit. The continuation described below remains
uncommitted, ready for the owner's next checkpoint.

`iap2_control_reply` now connects an explicit application handler to the existing
bounded outgoing path:

1. Require a started, established link, accepted accessory authentication and,
   when enabled, accepted identification. A message being held for inspection
   does not itself permit an unauthenticated response.
2. Require one held application request; there is no unsolicited-send API or
   implicit application handler. Reject outgoing authentication/identification
   IDs so manual replies cannot bypass either sequencer.
3. Validate one complete CSM and available capacity before copying it. A malformed,
   reserved or oversized reply preserves the held request and existing queue.
4. On success, copy the reply into endpoint-owned reply storage and release the
   held request together. The caller can then change/free its source bytes.
5. Use the existing fragmentation, send-window and cumulative-ACK handling.
   A full queue retains the exact unsent offset and coalesced inbound tails.
6. Bound the queued application's reply-to-ACK duration using `message_ms`
   (default 5 seconds), separately from the preceding request's assembly/hold
   budget. A stalled physical transport therefore cannot hold a reply forever.
   The final valid ACK cancels this timer immediately, without needing a later
   poll to clear the completed reply buffer.

This API supplies message plumbing, not a CarPlay application protocol. The
test handler's `0x1234`/`0x1235` messages and pattern bytes are synthetic and are
not advertised as implemented phone services. Caller time, physical-write tails,
provider deadlines and disconnect rules remain as in Step 27.

## Step 29 - Add opt-in minimal accessory identification

Status: encoder, sequencer and endpoint integration implemented locally;
physical metadata and phone acceptance remain unverified.

The pinned reference defines StartIdentification `0x1D00`, Information `0x1D01`,
Accepted `0x1D02` and Rejected `0x1D03`, with identity, power, language and optional
component fields. Its rich test fixture advertises features this project does
not yet implement. Those optional capabilities are not copied into our generated
profile. References checked on 2026-09-09:
[pinned identification fields](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/messages/identification.rs)
and [pinned fixture assertions](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/tests/oracle.rs).

Implementation sequence:

1. Add allocation-free C99 `iap2_identification.h`/`.c`. The metadata requires
   explicit name, model, manufacturer, serial, firmware, hardware, current and
   supported languages, power capability and maximum current. There are no
   default vehicle identifiers and no hardware reads. The caller is responsible
   for supplying truthful values; the library cannot verify them.
2. Encode only fields 0..9, 12 and 13. Identity spans are 1..127 printable ASCII
   bytes, language spans 1..16, with one to four unique supported languages
   including the current one. These are bounded local restrictions, not a full
   Unicode or language-tag implementation. Strings are NUL-terminated on wire;
   integers use the observed field widths/byte order.
3. Advertise only the currently implemented auth/identification message IDs in
   the fixed sent/received lists. Emit no transport components, external-accessory
   protocols, USB interface number, Bluetooth MAC, vehicle data or CarPlay flags.
   Existing Bluetooth/wired Apple audio support does not establish these values
   for a custom QNX endpoint. The resulting subset may be rejected by a phone.
4. Pre-encode and copy metadata into 1024 bytes of owned storage. The maximum
   permitted profile at this checkpoint occupied 942 wire bytes (the packed-list
   correction in Step 41 reduces it to 930). Invalid metadata or insufficient
   endpoint reply capacity leaves the previous configuration unchanged. Source
   metadata spans need not remain alive after successful enablement.
5. Keep identification disabled by default. `iap2_control_enable_identification`
   is permitted only before starting the link. Every endpoint reinitialization
   disables identification and requires a fresh explicit opt-in.
6. Under the enabled local policy, require authentication acceptance before
   StartIdentification; send the prepared Information only once; await its full
   cumulative ACK before processing Accepted/Rejected. Reject duplicate starts,
   premature results, inbound Information and unexpected parameters. These are
   experimental sequencing choices, not a statement of Apple-required ordering.
7. Record unique empty rejection flags in a bounded 32-bit mask. A rejection
   closes the endpoint; its diagnostic mask survives closure until reinitialization.
   There is no automatic retry that changes identity or claims more capabilities.
8. Apply a default 30-second identification budget from authentication acceptance,
   including waiting for Start, transport pressure and the result notification.
   Accepted cancels this timer. Disconnect resets both accepted states and
   partial/reply data. Closure retains the prepared metadata in memory but cannot
   restart the closed link; a new init clears it. Clearing is not secure erasure.

This is accessory identification **to the phone**, not identification of the
Apple authentication chip. No chip version, real certificate, usable QNX USB
endpoint, actual module serial/hardware revision or iPhone acceptance has been
obtained through this work. The unit's display/audio identifiers must not be
substituted for the separate Go module's unknown identity.

## Step 30 - Verify the integrated exchange and define the transport task

Status: all eight CTest suites, four sanitized protocol suites, five-unit ARM
portability check and 13 existing Python tool-safety tests pass.

The new `iap2_identification_tests` executable has seven test groups covering
common pinned field bytes, explicit metadata validation, exact/maximum capacity,
owned metadata and sequencing, malformed/out-of-order messages, rejection-mask
bounds and disabled/null handling. The existing rich Information vector is
compared only for common identity/power/language fields; this is not a claim that
our intentionally smaller profile exactly reproduces the full upstream vector.
Accepted and Rejected use the committed pinned messages directly.

The control suite grows from 14 to 20 groups. Its six additions cover atomic
application replies, application deadlines, enabled identification under queue
pressure, rejection/configuration failures, lifecycle/deadlines and a combined
two-endpoint authentication/identification/application exchange. The combined
test fragments transport bytes, deliberately loses a certificate packet and an
identification packet, verifies complete replies before each next stage and
finishes with a synthetic application roundtrip. No real credential or device
identity is used.

The first small-MTU integration run correctly rejected the test peer's oversized
challenge packet. The fixture helper was updated to split the challenge by the
negotiated payload size. Review also added a regression ensuring a final ACK
received just before the application deadline cancels that deadline immediately,
even if the next poll occurs later. These were host fixture/implementation checks,
not observations from a car or iPhone.

Reproduce:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

Host endpoint state now occupies 19,952 bytes plus caller buffers. The five C99
units still produce a relocatable Cortex-A8 object with no unresolved runtime
imports, not a QNX executable or installation package. Sanitizers validate the
exercised host paths, not target timing or Apple protocol conformance.

Next, investigate the stock QNX USB transport and device ownership in the pinned
corpus: which computer owns the exposed Apple USB path, what role/endpoints the
stock iPod stack uses, and which services must coordinate access. Separate static
evidence from assumptions about the owner's installed 6.9.0WL version. Use those
findings to define a bounded transport adapter and host tests for partial writes,
stalls and disconnects. Do not guess a USB device path or open/reconfigure a
physical device. An actual native provider/transport, execution access and a
recovery route remain prerequisites for any car-side work.

## Step 31 - Pin and trace stock USB ownership

Status: preceding identification/reply work committed as `78cebe7`.
Continued with read-only inspection of the later 6.17.0WL navigation corpus.
Full step-by-step evidence is in [usb-transport.md](usb-transport.md).

The primary boot image carries `io-usb` / `dm816x-mg` launch arguments. Its host
driver describes its implementation as host-only. Apple configuration selection
feeds a HID rule for `io-fs-media`'s USB iPod transport and a separate rule for
`io-audio` capture. Pre-media startup explicitly orders the base sound service
before USB enumeration to avoid selecting the wrong sound card.

The existing external-accessory protocol is configured for Aha, while early
tunnel services and connection-manager rules refer to Entune. A legacy Bluetooth
iPhone rule is commented out, not active. These findings do not demonstrate
CarPlay transport. Static accessory defaults are not the owner's real serial
or hardware revision. Physical wiring/multiplexer ownership remains unresolved.

## Step 32 - Replay bounded stock USB transfers

Status: 12 inputs SHA256-verified; 17 synthetic USB scenarios pass. The ELF
inspector now supports the pinned `iofs-usb-ipod.so`, and the new
`scripts/probe_usb_transport.py` exercises only its read/write routines with
mocked URBs, status, timing, locks and logging. No device attachment, initializer,
real USB call or stock-service change occurs.

Outgoing data uses HID output SET_REPORT control transfers; incoming data uses
interrupt requests and cached report payloads. Tests cover padding, fragmentation,
partial returns, inactive handles, submission errors, stalls, busy status,
input caching/continuation and read timeout. A perpetual busy response is stopped
by the harness budget, not a demonstrated stock retry limit. Injecting a success
with short actual length shows a write-path assumption; it is not proof that
the real stack produces that combination. A read stall can be hidden by a
successful requeue, so raw return counts alone are not a complete lifecycle API.

All 19 Python tool tests and all eight CTest suites pass. Six Python tests are
new and cover pins, changed-input rejection, execution/import/interrupt limits,
memory/event bounds, all 17 scenarios and refusing an existing output file.
See the new report for reproduction commands and primary USB/QNX references.

## Step 33 - Specify the portable transport pump

Status: design contract documented in
[USB transport, Step 6](usb-transport.md#step-6---define-the-next-bounded-adapter);
implementation follows in Steps 34-36.

The pump must retain a complete pending frame, track partial progress without
interleaving, bound polling/deadlines, respect receive consumed counts, and clear
all connection state on failure. A future native backend needs explicit
ownership, validated descriptors, correct DMA-buffer lifetimes and completion
validation. HID framing is a separate profile, not automatically the required
iAP2 transport. Stock-service resets or shutdowns are not an access strategy.

The plan at this checkpoint was to implement the portable pump against a fake nonblocking byte-stream backend
and test partial/zero transfers, backpressure, stalls, disconnects and deadlines.
Keep it independent of any guessed QNX device path or unverified role switch.
Actual transport/profile selection, installed-version matching, authentication
compatibility and execution/recovery access remain separate gates.

## Step 34 - Implement the bounded byte-stream pump

Status: previous USB investigation committed as `cec54b6`.
Added allocation-free C99 `iap2_transport.h`/`.c` without changing the existing
protocol APIs. Full step-by-step implementation notes are in the new
[transport-adapter.md](transport-adapter.md).

The pump owns one 1024-byte TX buffer and one 1024-byte RX buffer, performs at
most one backend read/write each per poll, retains partial tails and honors
receive consumed counts. It services input while output is blocked and exposes
application messages through the existing control endpoint. Backends supply
nonblocking synchronous callbacks; there is no USB implementation or HID profile.

Results carry counts and connection generations. Out-of-range counts, invalid
status combinations and stale results close the connection. Close cancels once,
clears transport tails and resets endpoint state. Reconnect requires a fresh
endpoint initialization and higher generation; identification is disabled again
unless explicitly enabled. Backend buffer lifetimes, truthful completion
reporting and synchronous quiescence remain caller responsibilities.

## Step 35 - Bound stalled output and verify lifecycle behavior

Status: 15 new transport test groups pass, including a complete synthetic
authentication exchange and application roundtrip through three-byte reads
and five-byte writes.

Default no-progress backoff is 5 ms; the pending-output budget is 250 ms total,
not renewed by partial progress. A pending tail closes earlier if it would
block an existing link retransmission deadline. Control/handshake deadlines are
checked before I/O. These conservative local rules prevent indefinite retention
and frame interleaving; they are not measured head-unit or Apple-required timing.

Tests cover invalid configuration/counts, zero progress, partial output,
disconnect/fatal stalls, stale generations, exact timeout boundaries, coalesced
and fragmented input, bad/unsupported frames with retained tails, RX-full
consumed-count handling, receive under blocked output, remote reset, negotiated
retry timing and retry exhaustion. No old tail is transmitted after reconnect.
The backend is a fake byte stream, not an actual QNX async USB completion layer.

## Step 36 - Verify portability and define the next session task

Status: all nine CTest suites, five host-sanitized protocol suites, six-unit ARM
portability check and 19 Python tool tests pass. The pump occupies 2,184 bytes
on the host, in addition to the 19,952-byte endpoint and caller buffers. ARM
output is still a relocatable object without runtime imports, not a QNX program.

Next trace CarPlay session establishment and transport handoff in the pinned
reference. Map required application/control messages and capabilities against
the existing endpoint before implementing the next verified subset. The stock
HID transport is not automatically a valid iAP2/CarPlay profile. Native USB
ownership, real authentication compatibility and execution/recovery access are
still unresolved. Do not advertise guessed transport components or CarPlay
capabilities, or launch an installer to substitute for those missing facts.

## Step 37 - Publish the checkpoint and trace wired session startup

Status: transport work committed as `cecd732` and pushed to the requested
[GitHub repository](https://github.com/bound2/gt86-headunit-research).
`origin` is configured and `master` tracks `origin/master`; a remote-ref check
confirmed the full checkpoint hash. The continuation below remains local work
after that published checkpoint. No raw firmware or generated builds were added.

The new [carplay-session-start.md](carplay-session-start.md) records the pinned
LIVI trace step by step. Although the checkout is sparse, runtime sources are
available in its Git tree and were read with `git show`. The wired reference
selects a phone USB configuration, uses USBmux and trust pairing to open the
carkit service, and establishes a separate USB network path. This differs from
the traced stock iPod HID path; it is not an available QNX backend here.

The reference performs identification before authentication, then handles
CarPlayAvailability (`0x4300`) by building StartSession (`0x4301`) from actual
receiver network/interface and identity/key configuration. Our experimental
endpoint still requires authentication first. The reference also advertises
transport components and CarPlay message/capability metadata that our minimal
identification intentionally omits. Neither gap is silently treated as solved.

## Step 38 - Add bounded CarPlay startup codecs and a gated reply

Status: new C99 `iap2_carplay.h`/`.c` encodes/decodes transport identifiers
(`0x4e0e`), wireless availability (`0x4e0d`), CarPlay availability (`0x4300`)
and wired StartSession (`0x4301`). Wireless/mixed StartSession is unsupported.
Four existing pinned fixtures round-trip exactly. Wired addresses are separate
NUL-terminated strings packed into one parameter, not repeated parameters.

The subset bounds messages to 1024 bytes, addresses to four 63-byte strings and
other text to 127 printable ASCII bytes. It rejects malformed/duplicate/unknown
fields, preserves destination/output on failure, and returns borrowed decoder
views. The largest wired profile is 674 bytes. These are strict local policies,
not established Apple limits or a complete port of the upstream runtime.

`iap2_carplay_reply_wired_start` requires a held valid wired-available offer,
accepted authentication and enabled/accepted identification, actual caller-
provided receiver addresses, port 1..65535 and identity/key/source strings. It
delegates to the owned, atomic application-reply path. Invalid input or capacity
failure leaves the request held; terminal closure retains existing cleanup rules.
No automatic advertisement/dispatch, networking, key generation, USB change or
session-active state is added. Queued bytes do not prove phone acceptance.

## Step 39 - Verify the subset and identify the next compatibility task

Status: all ten CTest suites, six sanitized protocol executables, seven-unit
ARM portability check and 19 Python tests pass. Nine new codec groups cover
the pinned messages, packed strings, optional fields, full-width wire port,
malformed/truncated input, limits and transactional outputs. Three integration
groups bring the control suite to 23: explicit gating, fragmented owned replies,
invalid offers/profiles/clocks, reply capacity, timeout closure and reconnect
reset are tested with synthetic metadata and credentials.

The host endpoint remains 19,952 bytes and the pump 2,184 bytes plus caller
buffers; codecs use bounded local storage. ARM output remains a relocatable
Cortex-A8 object without runtime imports, not a QNX executable or installable
receiver. Reproduction commands and source pins are in the new report.

Next implement an explicit identification-first profile matching the reference,
without silently changing existing behavior. Test phase ordering, provider
gating, deadlines, backpressure and reset with a synthetic peer. Then address
truthful supported-message/transport declarations: the current identification
lists still do not advertise the new CarPlay messages. Real USB ownership,
authentication, pairing/network/media, installed-version matching and safe
execution/recovery access remain separate unresolved requirements.

## Step 40 - Support explicit identification-first startup

Status: preceding startup-message work committed and pushed as `ccd89dd`.
The new [startup-order.md](startup-order.md) records the configuration, phase
gates, timer ownership and source evidence step by step. The endpoint now
supports the pinned reference's identification-before-authentication order
without changing the existing default. Missing explicit identity blocks start;
premature authentication never invokes the provider. Reinitialization requires
identity opt-in again, and all terminal paths clear both phase states.

Seven new control groups bring that suite to 30; two new transport groups bring
it to 17. Both startup orders, ACK barriers, coalesced phase transitions,
independent deadlines, lost packets, provider failure and reset pass synthetic
tests. The wired reply helper also passes after identification-first startup.
All ten CTest suites, six sanitized suites, seven-unit ARM check and 19 Python
tests pass. Host endpoint size is now 19,960 bytes; pump size remains 2,184 bytes.

Review found that multi-language identification currently repeats parameter 13,
whereas the pinned encoder packs the language strings into one parameter. The
single-language fixture did not expose it. Correct that payload/test next, then
extend truthful supported-message/USB-host declarations. None of these host
checks establishes a real QNX transport, authentication acceptance or media.

## Step 41 - Correct multi-language identification encoding

Status: identification-first startup committed and pushed as `5fb094d`.
The [identification payload audit](identification-wire-audit.md) documents the
packed-language discrepancy, failing regression and fix. Field 13 now occurs
once with concatenated NUL-terminated language strings, matching the pinned
encoder rule. Single-language bytes are unchanged; the maximum minimal profile
is 930 rather than 942 bytes. No additional capability is advertised.

Eight identification groups now include independently specified one-to-four-
language payloads, every undersized output capacity, exact bounds and caller-
storage ownership. Control and pump integration fixtures now use two languages.
All ten CTest suites, six sanitized suites and the seven-unit ARM check pass
after the correction. Next extend explicit supported-message/USB-host metadata
and the referenced power-source message, before building the remaining real
pairing/network/media receiver path. Actual car compatibility remains unproven.

## Step 42 - Add unsolicited wired power-source notifications

Status: preceding language fix committed/pushed as `8dae42e`.
The new [power-notifications.md](power-notifications.md) traces the reference's
post-authentication `0xae03`, implements its typed fields and adds explicit
unsolicited application output. Notifications retain held/partial/coalesced
input without extending its deadline, use the same bounded TX/ACK queue as
replies, and cannot inject reserved startup messages. No provider is invoked.

The typed helper requires accepted identification/authentication and explicit
current/charge policy. Zero current is valid; no reference rating is assumed.
Three new codec and five control groups bring those suites to 12 and 35.
The fragmented pump simulation now includes unsolicited power before an
application exchange. All ten CTest suites, six sanitized suites, eight-unit
ARM check and 19 Python tests pass. Native charging/USB behavior is unchanged.

Next add explicit USB-host identification and implemented-message declarations;
the minimal default still declares neither CarPlay nor power-source messages.

## Step 43 - Declare explicit wired receiver capabilities

Status: power-notification work committed/pushed as `52f1ec1`.
The new [wired-identification.md](wired-identification.md) documents the pinned
USB-host fields, explicit metadata APIs, exact implemented-message lists and
profile lifetime. The minimal default is unchanged. The opt-in wired profile
matches the pinned USB-host component payload and requires caller-provided
component/name/interface and advanced-power metadata, not copied hardware defaults.

Three new identification and three control groups bring those suites to 11 and
38. Typed CarPlay/power helpers now reject accepted minimal identification as
unsupported without queueing bytes. Invalid/oversized profile activation is
transactional; reinitialization clears the wired declaration. The full pump
simulation now performs identification, authentication, unsolicited power,
CarPlay availability and the wired-start response over partial reads/writes.

All ten CTest suites, six sanitized suites and the eight-unit ARM check pass.
Endpoint storage is now 19,968 host bytes, pump 2,184 bytes plus caller buffers.
These tests use synthetic credentials/network values; no physical USB, phone
pairing or media connection occurs. Next trace and implement the USBmux framing
dependency below the iAP2 byte stream, then continue toward carkit pairing/TLS,
network/media and QNX integration. Hardware execution/recovery remains unresolved.

## Step 44 - Implement bounded USBmux packet framing

Status: wired-identity work committed/pushed as `65c6ad8`.
The new [usbmux-transport.md](usbmux-transport.md) records a pinned usbmuxd
cross-check alongside LIVI, including their different version/setup/sequence
handling. Independent C99 codecs preserve the raw header fields, bound frames
to 65,536 bytes and reject unsupported TCP options. Caller-owned streaming
assembly handles partial/coalesced input and latches malformed prefixes.

Seven independent synthetic vectors and 10 groups exercise exact bytes, all
fixture splits/truncations, transactional capacity failures, sequence/window
boundaries and maximum-size packets. All 11 CTest suites, seven sanitized
protocol suites, nine-unit ARM check and 19 Python tests pass. The new USBmux
files select GPL-3.0-only; iAP2 notices are unchanged. No reference daemon,
USB interface or phone-pairing code was executed.

Next add bounded version/setup and TCP connection state, then continue toward
Lockdown/TLS trust pairing and the carkit byte stream. The packet layer alone
does not connect to a phone or supply a physical transport. Real CarPlay,
hardware compatibility and execution/recovery remain unverified.

## Step 45 - Add a bounded USBmux version/setup host

Status: packet-layer checkpoint committed/pushed as `d754aca`.
The [USBmux report](usbmux-transport.md#step-5---implement-the-version-2-host-handshake)
now records the host state transitions, write-completion contract, explicit
sequence profiles and local failure/deadline policy. The host offers version
2.0, requires a major-2 reply and only becomes READY after setup is physically
written. It does not silently ignore failed negotiation or fall back to v1.

The host owns one pending TX packet and one partial/held RX packet in separate
caller buffers. Coalesced tails remain with the caller. TCP output is explicit
and copies its input; it neither consumes held RX nor performs TCP connection
handling. Generation guards close stale sessions without accepting stale time
or bytes. Total handshake/write/assembly-plus-hold budgets are not renewed by
partial progress. The caller must quiesce I/O before closing/restarting.

Fifteen new host groups pass, including independent first-SYN bytes under both
sequence conventions, every 16-bit sequence slot, exact deadlines, all version
split points and 65,536-byte packets. All 12 CTest suites, eight sanitized suites,
ten-unit ARM check and 19 Python tests pass. Host state is 200 bytes plus separate
RX/TX buffers; existing iAP2 endpoint/pump storage is unchanged.

Next implement bounded TCP connection, ACK/window and routing behavior on top
of these packet queues, before Lockdown/plist/TLS pairing and carkit integration.
READY means USBmux setup completed in the simulation, not an authenticated,
paired or CarPlay-capable phone connection. No device or vehicle was accessed.

## Step 46 - Add bounded TCP-style connections over USBmux

Status: version/setup host committed/pushed as `b933ebf`.
The new [usbmux-connection.md](usbmux-connection.md) records explicit port-pair
opening, physical-write versus peer-ACK accounting, eight bounded data flights,
scaled peer windows, owned RX rings and graceful/half-close behavior. It validates
SYN/ACK and ACK ranges, suppresses duplicate/overlapping receive data, rejects
over-credit input and retains previously granted receive credit despite window
rounding. All timed APIs reject stale generations and enforce local deadlines.

Fifteen groups pass, including initial sequence wrap through zero, both-port
routing, partial ACKs, ring/flight wrap, deadline boundaries and maximum-sized
packets. A layered simulation opens TCP through the actual packet-host code,
exchanges synthetic length-prefixed service bytes with three-byte reads and
five-byte writes, and only accounts TCP completion after physical mux completion.
The bodies are not Lockdown/TLS/carkit messages; no phone participates.

All 13 CTest suites, nine sanitized protocol suites, eleven-unit ARM check and
19 Python tests pass. Connection state is 360 host bytes plus caller RX/TX;
existing host/endpoint/pump storage is unchanged. The new files select GPL-3.0-only.
This profile relies on ordered reliable mux transport and has no TCP retransmit,
TIME-WAIT or production tuple dispatcher. Next connect the host/connection APIs
with a bounded dispatcher/byte-stream adapter, then add Lockdown/plist/TLS
pairing and carkit startup. Requested an already accessible read-only Go-module
identifier from the owner; no vehicle access, disassembly or setting change was
performed. Actual software-only CarPlay remains unverified and not installable.

## Step 47 - Connect the runtime dispatcher and byte-stream APIs

Status: TCP connection layer committed/pushed as `dcfdb7f`.
The new [usbmux-dispatcher.md](usbmux-dispatcher.md) documents the library bridge
between one packet host, up to four TCP streams and explicit raw backend
callbacks. Polling bounds read/feed/dispatch/submission/write work, retains
coalesced input and schedules complete packets round-robin. Connection output
is only credited after complete physical mux transmission, never on a host copy.

The dispatcher allocates non-reused local ports per physical generation and
tags application handles with both physical and connection generations. Graceful
closure plus RX drain permits slot reuse; old handles/retired tuples cannot
reach the new stream. CONTROL is held with an explicit release token while TX
continues. All shared hard deadlines precede I/O, and a terminal connection or
backend error cancels the whole physical generation exactly once.

Thirteen groups cover four concurrent streams, byte ownership, early replies,
three-byte reads/five-byte writes, coalesced control tails, stale callbacks,
token/slot reuse, cancellation, window backpressure, malformed results, exact
deadlines and maximum-size packets. All 14 CTest suites, ten sanitized protocol
suites, twelve-unit ARM check and 19 Python tests pass. Dispatcher storage is
1,240 host bytes including scratch; existing object sizes are unchanged. New
files select GPL-3.0-only. These are synthetic peer/callback tests, not physical
USB or phone-pairing evidence.

Next implement bounded Lockdown/service framing and plist exchanges on these
stream APIs, then TLS/trust pairing and carkit startup before attaching the
iAP2/control endpoint. The real QNX backend, authentication provider, media path,
hardware identity and execution/recovery remain unresolved; no installable
CarPlay image or vehicle change was produced.

## Step 48 - Add bounded Lockdown service framing

Status: runtime dispatcher committed/pushed as `1ed50a7`.
The new [lockdown-service.md](lockdown-service.md) pins LIVI's exact
`idevice 0.1.65` dependency, verifies the archive against Cargo.lock and traces
service framing, GetValue and carkit's pairing/session/TLS order. Only source
was inspected; no reference daemon, phone service or trust-record operation ran.

The independent C99 layer frames 1..65,536-byte opaque bodies with a four-byte
big-endian body length. Its explicit GetValue encoder escapes XML metadata and
checks output capacity before writing. The owned channel binds a plain,
TX-drained dispatcher stream and queues one request. Bounded polling reads
exactly one prefix/body, preserves following bytes, and publishes the response
only after the request is physically sent and TCP-acknowledged.

Release tokens, total exchange/hold budgets, stale-handle rejection and shared
transport cancellation bound lifetime and failure. Idle detach returns the
original stream without consuming possible handoff bytes or starting TLS.
The response remains opaque: even an Error plist is framed data, not an
accepted RPC result. There is no implicit pairing, retry or real GetValue call.

Seventeen groups cover independent XML fixtures, every response split position,
partial EOF, malformed lengths, capacity/metadata bounds, request ownership,
ACK gating, coalesced handoff tails, exact deadlines, token/generation checks,
other-stream/CONTROL progress and maximum-sized service bodies. All 15 CTest
suites, eleven sanitized protocol suites, fourteen-unit ARM check and 23 Python
tests pass. Channel state is 160 x64 host bytes plus caller buffers. The new
files/tests select GPL-3.0-only; the MIT-declared dependency is a source reference
only, and no implementation bodies were copied.

Next add bounded typed plist response validation, then explicit trust policy,
credential-provider/storage boundaries, TLS and carkit startup. A decrypted
stream adapter is still needed; detaching plain framing is not a TLS handshake.
Real QNX transport, authentication-chip access, network/media and verified
execution/recovery remain unresolved. No installable CarPlay image, update USB
or vehicle change was produced.

## Step 49 - Decode and validate Lockdown responses

Status: service framing checkpoint committed/pushed as `7fd17f7`.
The new [lockdown-responses.md](lockdown-responses.md) records a bounded C99
XML/binary plist decoder, strict typed GetValue/StartSession/StartService/Pair
response validation and an explicit bridge from held channel responses.
It uses the existing idevice pin plus checked CPython/Apple format references.
No upstream function bodies, real credentials or trust records were copied.

The decoder bounds input/arena size, nodes and depth; it handles strings, data,
integers, booleans and containers, rejects duplicate keys/reference cycles and
copies decoded values into caller storage. Unsupported types remain explicit.
The validator correlates Request, distinguishes remote Error, checks ports
before narrowing and rejects malformed SSL flags or a plaintext StartSession
downgrade. Validated fields do not mean pairing or TLS has succeeded.

Thirteen new groups cover parsing/security/ownership boundaries and 24,000
deterministic XML/binary mutations. Seven Python-serialized synthetic binary
fixtures receive independent semantic checks. The channel suite now has 18
groups, including typed XML/binary replies through the real dispatcher and fake
backend. All 16 CTest suites, twelve sanitized suites, sixteen-unit ARM check
and 24 Python tests pass. Nodes are 32 x64 bytes plus decoded byte storage.
The first ARM test found an unwanted division import; a bounded-product check
removed it without weakening validation.

Next add explicit session/service request builders and application state
transitions, with separate credential, user-authorized pairing/storage and TLS
boundaries. Real carkit startup, QNX transport, network/media and hardware
execution/recovery remain unresolved. No installable image or vehicle change
was produced; software-only CarPlay is not yet demonstrated.

## Step 50 - Add explicit Lockdown startup and TLS handoff

Status: response parser/validator committed/pushed as `f4587a1`.
The new [lockdown-bootstrap.md](lockdown-bootstrap.md) records explicit
StartSession/StartService XML encoders and an owning pre-TLS client. It binds a
fresh Lockdown stream, copies caller metadata, sends only explicit GetValue or
StartSession, validates replies and holds typed values/errors/TLS-required
events. There is no automatic pairing, UUID generation, record access or retry.

An accepted SSL-required reply cannot be released back to plaintext IDLE.
Exact-token handoff copies SessionID and returns the original stream with
trailing bytes preserved. The bootstrap becomes terminal; no mark-secure/resume
bypass or StartService dispatch path exists before a real TLS adapter. EOF,
malformed replies, stale generations and expired handoffs cannot expose a
usable TLS stream.

The shared timer-only dispatcher check strengthens timed channel operations:
release/detach now enforce other streams' deadlines without backend reads/writes,
after rejecting stale handles. A deadline test initially retained a pending ACK
write; it now drains physical output before testing the intended peer-ACK timer.
No production timeout was weakened.

Eleven groups cover independent request bytes, metadata/capacity bounds,
fresh-stream ownership, XML/binary reply splits, query-to-session sequencing,
explicit errors, handoff tails, parser limits, EOF, CONTROL and shared deadlines.
All 17 CTest suites, thirteen sanitized suites, seventeen-unit ARM check and 25
Python tests pass. Bootstrap storage is 248 x64 host bytes plus caller buffers.
New code/tests select GPL-3.0-only with no new upstream bodies or credentials.

Next implement a real bounded TLS stream adapter with credential/peer-validation
boundaries and cryptographic tests, then protected StartService and carkit
startup. The service encoder alone is not a live service request. Pairing/storage,
native QNX transport, network/media and hardware execution/recovery remain
unresolved; no installable CarPlay receiver or vehicle change was produced.

## Step 51 - Implement and cryptographically test the TLS stream upgrade

Status: bootstrap/handoff committed/pushed as `5683773`.
The new [lockdown-tls.md](lockdown-tls.md) records the pinned Mbed TLS 3.6.7
dependency, explicit credential/peer policy, stream ownership and test procedure.
The separate optional target performs actual TLS handshakes, not a callback
that claims encryption succeeded. It requires client certificate/key, normal CA
verification and an exact device DER pin. No verification flags are cleared,
legacy downgrade or plaintext fallback is provided. Reference idevice's disabled
verification is deliberately not reproduced; actual pairing-certificate
compatibility remains unverified.

Init consumes the validated handoff only on success and retains SessionID.
The last plaintext receive ACK can drain normally, but pending plaintext data
cannot cross the upgrade boundary. Polls limit backend and ciphertext BIO work;
owned pending plaintext preserves the crypto library's write-retry contract.
Explicit handshake/write/hold deadlines and generation checks remain connected
to shared transport timers. Errors free crypto, zero local app buffers and
cancel the current shared generation once, without touching a replacement.

Seven groups test real EC/RSA mutual authentication, encrypted StartService
fixture bytes and binary replies, wrong CA/device/client credentials, expired
certificates, entropy failure, incompatible suites, corrupted records, EOF,
close_notify, partial I/O, minimum RX rings, maximum app buffers, other streams,
CONTROL, deadlines and stale owners. Synthetic certificates/keys are generated
only in RAM; no real trust record or device is accessed. A test initially
assumed AES-128 preference; it now accepts either AES-GCM suite in the declared
profile, including the server's valid AES-256 selection.

Verification passes: 18 TLS-enabled CTest suites (17 in the ordinary build),
thirteen existing sanitizer suites plus the new fully instrumented TLS suite,
the unchanged seventeen-unit freestanding ARM check, and 25 Python tests.
The hosted TLS object is 7,976 bytes plus crypto heap and transport storage.
Its allocator, time, random provider and target crypto side-channel requirements
are explicitly separate from the freestanding portability result.

Next connect a protected framed RPC owner to this real TLS stream and existing
plist validation, then explicit StartService/port/SSL policy and carkit stream
startup. Encrypted fixture transport alone is not a completed service client.
QNX USB/network, pairing provision, media, exact hardware identity and verified
execution/recovery remain unresolved. No installable update or vehicle change
was produced; software-only CarPlay on the owner's head unit is not demonstrated.

## Step 52 - Own protected Lockdown requests and open carkit

Status: verified TLS upgrade committed/pushed as `aa418e1`.
The new [carkit-startup.md](carkit-startup.md) records the protected RPC owner,
port/TLS-policy gates, second stream and integration tests. A fresh authenticated
Lockdown session now owns explicit GetValue/StartService requests, bounded
framing/decoding, correlated typed replies and exact-token release. A complete
encrypted reply is not exposed until the request has physically drained and
been TCP-acknowledged. Coalesced following bytes are preserved and known
unsolicited data cannot be reassigned to a new request. Valid remote errors
remain explicit held events, not automatic pairing/retry instructions.

Carkit startup requests only com.apple.carkit.service, validates the integer
port and SSL policy, and opens a separate stream. TLS is required by default;
plain service mode needs explicit caller permission and a false/absent SSL flag.
A true flag always performs real TLS, with no downgrade after failure. The
service uses the same parsed host/device identity as the retained control
session and does not invent a SessionID or replay StartSession on its port.
READY exposes raw iAP2 bytes without a plist envelope. Either stream's failure
terminates both owners, while stale owners cannot cancel a new generation.

Seven groups cover actual encrypted RPCs/dual TLS and raw frame round trips,
one-byte TLS records, request-ACK gating, tokens/coalesced tails, invalid frame
lengths/plists/ports/SSL types, parser limits, remote errors, explicit plain
policy, certificate/identity rejection, startup/exchange/hold budgets, reused
TLS-session rejection and closure of either connection. The ephemeral TLS peer
and credentials moved into a shared test header; no real records/devices or
additional dependencies were introduced.

All 19 TLS-enabled CTest suites (17 ordinary), both fully instrumented TLS/carkit
suites, thirteen original sanitized suites, the unchanged seventeen-unit ARM
check and 25 Python tests pass. Hosted C99 warning checks and document links
also pass. Measured x64 structs are 312 bytes for the protected client, 176 for
carkit and 7,984 per TLS context, plus caller buffers and crypto heap; these are
not total QNX runtime measurements or an ARM executable.

Next attach the existing iAP2 transport/link/control engine to carkit with
correct completion/cancellation accounting. Copied TLS plaintext must not be
reported as physically written. Then integrate broader CarPlay session/network
and media paths. Native transport, pairing provision, authentication-chip
access, actual Go identity and verified execution/recovery remain unresolved.
No installable software-only CarPlay receiver or vehicle change was produced.

## Step 53 - Connect the iAP2 session engine to carkit

Status: protected RPC/carkit startup committed/pushed as `7539981`.
The new [carkit-iap2.md](carkit-iap2.md) records an owning bridge to the existing
iAP2 pump/link/control engine. Its pending frame is copied into independent
storage, submitted through carkit and not credited to the pump until service
TLS/USBmux output is drained and TCP-acknowledged. This does not manufacture an
iAP2 ACK or renew the retained-output/retransmission budgets.

Timer-only preflight now checks upper iAP2 deadlines before lower physical I/O.
One bridge poll drives at most two physical reads/writes. Explicit saved handles,
pump generation and one-shot ownership reject stale/rebound lifetimes; closure
resets endpoint authentication and clears pending data without cancelling a
replacement mux. Early decrypted but unread input is preserved, while prior
external application use prevents a false fresh-service rebind.

Six groups drive actual dual TLS (or explicitly allowed plain carkit) through
the existing detection/link negotiation, wired identification, synthetic
certificate/challenge/result sequence, explicit zero-intent power notification
and wired-start request/reply. Other groups verify unacknowledged writes staying
pending, three-byte plain prefixes, early encrypted markers, deadlines before
physical I/O, invalid binds/clocks/generations, provider/connection failure and
CONTROL handling. The accessory provider, phone peer and advertised projection
address/key are synthetic; no real authentication chip or media server is proven.

All 20 TLS-enabled suites (17 ordinary), three fully instrumented hosted suites,
thirteen original sanitizer suites, the seventeen-unit freestanding ARM check
and 25 Python tests pass. An initial sanitizer stack overflow came from combined
large test fixtures; test-owned heap allocation fixes it without changing
production limits/timeouts or disabling checks. Changed C99 warning checks and
document links pass. The bridge is 3,312 x64 bytes including its pump/pending
frame; carkit is now 184 bytes, with endpoint/buffers/crypto heap additional.

Next implement the separate projection-session request path and real receiver
identity/address/key provision, then network/media delivery. The pinned wired
runtime maintains a separate USB-network path for AV, so an iAP2 wired-start
fixture is not a working projection server. Native transport, actual pairing
and authentication-chip access, exact Go identity and verified execution/recovery
remain unresolved. No installable software-only CarPlay update was produced.

## Step 54 - Frame and own projection-control requests

Status: carkit/iAP2 integration committed/pushed as `27db539`.
The new [projection-control.md](projection-control.md) records a separate
RTSP/HTTP wire codec and serial plaintext request/response channel. They do not
put projection AV into the carkit stream or pretend a request frame is an
authenticated session. The pinned reference's connection/handler code shows a
separate control connection and a plaintext-to-cipher transition after its
pair-verify response; receiver identity is separate from Lockdown TLS identity.

The new codec parses one bounded message, supports opaque binary bodies and
builds explicit responses with request protocol/CSeq and generated length.
Strict CRLF/ASCII, decimal lengths/CSeq, duplicate framing-header rejection and
8,192-byte header/65,536-byte body/32-header caps prevent ambiguous framing.
The caller-buffer stream stops exactly at the message boundary and never reads
ahead into a following request or possible ciphertext. Unknown headers remain
ordered; ambiguous lookups reject. Unsupported framing errors are terminal.

The owning channel exposes a held request and generation/token key. Only an
explicit application response or close handles it; no unknown command receives
an automatic success. Stale keys/generations and invalid response/count/capacity
arguments cannot advance the clock or consume future work. Absolute idle,
receive, reply and output/release budgets do not renew on partial progress.
Closing/EOF/error clears retained bytes and invalidates tokens without I/O.

Output retirement means only that the caller's downstream owner accepted those
plaintext bytes, not physical completion or peer acceptance. The channel stays
SENT until explicit release, allowing the future owner to drain output and
perform a cryptographically verified layer handoff first. This step has no
socket, cipher, pairing store, identity generator or route/media handler.

Nine groups exercise exact bytes, fragmentation, coalesced tails, length/count
limits, malformed/injected/ambiguous headers, transactional capacity failures,
serial responses, stale tokens, token exhaustion, monotonic clocks, all absolute
budgets, output clearing and EOF. A deterministic 6,000-input campaign compares
fragmented and stateless results. No phone capture or actual key is a fixture.

All 18 ordinary/21 TLS-enabled CTest suites, fourteen protocol sanitizer suites,
three fully instrumented hosted suites and 25 Python tests pass. An unused test
helper initially failed the strict warning build; it was removed without
relaxing checks. Both new C99 units join the nineteen-unit freestanding ARM
check and import-free relocatable link. Measured x64 message/stream/channel
sizes are 1,112/48/152 bytes, with caller buffers and transient views additional.
This is not a QNX executable, measured target process or iPhone acceptance test.

Next add bounded TLV8 and real receiver identity/pairing cryptography, then an
authenticated control-frame handoff and typed session handlers. Verify required
crypto primitives and trust/provisioning before advertising any receiver key.
USB-network/listener/media integration, real pairing/authentication-chip access,
actual Go identity and verified execution/recovery remain unresolved. No
installable software-only CarPlay update or vehicle change was produced.

## Step 55 - Add receiver identity and real known-controller pair verification

Status: projection-control framing committed/pushed as `68f7c83`.
The new [pair-verification.md](pair-verification.md) records bounded TLV8,
explicit Ed25519 identity, real crypto primitives and a one-shot known-controller
pair-verify responder. This is not first-time enrollment, persistent trust or
Apple-chip authentication, and no real phone/CarPlay session was established.

The selected Mbed TLS source lacked usable Ed25519 signing/verification, so the
new optional target uses pinned Monocypher 4.0.3, whose release fixes a signing
timing leak in earlier versions. The archive, all used files and configure-time
source/header hashes are checked. Release files match the official pinned tag
apart from the version marker. Preparation extracts an exact source/licence
allowlist after documentation symlinks failed in a trial full extraction.
No dependency source/binary is committed and the existing TLS target is retained.

TLV8 validates before writing, preserves distinct repeated fields and rejects
ambiguous lookups. The handshake further rejects duplicate logical fields and
separators. Explicit identity import derives a complete signing key from a raw
seed and can validate the expected public key. Generation requires a caller
CSPRNG; there is no default key/identifier, file store or automatic replacement.
Primitive wrappers bound data/KDF sizes, reject all-zero X25519 shared secrets,
add canonical/low-order checks to Ed25519 verification and authenticate AEAD
before exposing plaintext. Secret material is cleared at failure/teardown.

M1 produces a fresh ephemeral key and signed/encrypted accessory proof. M3 must
authenticate its inner data, identify a controller in the read-only trusted-key
provider and pass real Ed25519 proof verification before directional keys are
derived. Output stays held through explicit M2/M4 release. Only a token-bound
one-time handoff after M4 release exports keys; it then clears/detaches state.
Absolute exchange/hold budgets, generations and stale-token guards prevent
restarts, reused output or unbounded holds. Release is an explicit downstream-
drain assertion by the integration owner, not a physical-I/O claim.

Three TLV8 groups include 6,000 mutations. Seven crypto groups cover RFC Ed25519,
X25519 and AEAD vectors, independent HKDF/transcript results, every-byte forgery
checks, malformed/duplicate fields, unknown/wrong controller keys, provider
failure, deadlines/clock edges, secret clearing and a fragmented RTSP handoff
simulation. All 21 public fixture values independently reproduce with PyCA
cryptography 50.0.1 in an ignored venv. They are never production credentials.
Initial missing-include/vector-count/hex-literal test issues were fixed without
relaxing validation, sanitizers or expected cryptographic results.

All 23 combined, 22 TLS-only and 19 standard CTest suites pass, as do fifteen
protocol sanitizer executables, both fully instrumented pairing suites, three
hosted TLS suites and 25 Python regressions. TLV8 joins the twenty-unit import-
free ARM core. The separate seven-unit crypto object compiles/relocatable-links
but reports `__aeabi_memclr8`, `__aeabi_uidiv`, `__aeabi_uidivmod` and
`__aeabi_uldivmod`; a target runtime is required. x64 identity/responder/exported-
key sizes are 176/1,400/168 bytes plus stack temporaries. No target CSPRNG, stack,
side-channel behavior, QNX process or recovery procedure is proven.

Next implement authenticated control-frame counters/streaming and connect this
handoff to the RTSP owner, then first-time pair-setup with explicit trust/store
policy. Typed session/media, MFi auth-setup, network listeners and real endpoint
advertising remain necessary. Actual module identity, native USB-network access,
authentication-chip interface and execution/recovery remain unresolved. No
installable CarPlay update or head-unit/phone/firmware/USB change was made.

## Step 56 - Own authenticated control records and the pairing handoff

Added [encrypted-control.md](encrypted-control.md), a step-by-step record of the
wire evidence, implementation, lifetime contract, independent tests and target
limits. The new optional `control_cipher` implements bounded IETF
ChaCha20-Poly1305 records with LE16 authenticated length, separate directional
LE64 counters and one retained record per direction. Empty records, fragmented
headers/tags, partial plaintext/ciphertext retirement and the 16 KiB maximum
payload are handled explicitly. Counters never wrap; bad tags, replay,
oversize, exhaustion, EOF and absolute phase deadlines fail closed and wipe.

The new `projection_control` owns fresh pair-verification, RTSP and cipher
children in one generation. Only exact plaintext POST /pair-verify with a
unique expected content type reaches the known-controller handshake. It
constructs correlated M2/M4 replies, leaves M4 plaintext, and requires complete
output retirement plus explicit downstream-drain release before taking verified
keys once. There is no unrelated-session attachment, raw-key bind or automatic
success for an unknown controller/route. Physical drain remains a future
transport owner's responsibility; copying output is not proof of it.

After the handoff, authenticated RTSP requests are held for explicit application
responses. A request can span records and a record can contain several requests;
authenticated tails survive response/drain holds and external wire tails remain
unconsumed. Responses split into bounded encrypted records without reencrypting
partial writes or renewing the enclosing absolute output budget. Shared-secret
and controller-ID state is retained only for this lifetime and cleared at close.
No listener, capability/auth-setup route, first-time enrollment, trust write or
media handler is introduced.

Five record and five owner integration groups cover independent vectors, every
split point and every-bit mutation of a sample record, one-byte retirement,
empty/max-size frames, directional counters/byte order, replay, truncation,
generation/token/clock/capacity failures, overflow, malformed/unexpected routes,
real pairing proofs, final-plaintext drain gating, multi-message tails,
multi-record binary replies and all phase budgets. Twelve public fixture values
reproduce independently with the existing PyCA environment; no real keys or
phone captures were used.

All 25 combined crypto/TLS, 22 TLS-only and 19 standard CTest suites pass.
Four fully instrumented pairing/control suites, fifteen protocol suites and
three hosted TLS/carkit suites pass ASan/UBSan. All 25 Python regressions and
both independent vector checkers pass. A fixture transcription error was fixed
before validation. The first ARM build exposed an extra `__aeabi_memcpy8` from
the large initializer copy; explicit byte copying removed it without widening
the allowlist. Explicit key initialization removes an MSVC warning. The final
build has no new compiler warnings; the dependency's pre-existing CMake
compatibility warning remains.

The twenty-unit core remains import-free on ARM. All nine optional pairing/
control/crypto units compile and relocatable-link with the same four required
runtime symbols as Step 55; they are not a QNX process. x64 cipher/owner objects
are 240/1,952 bytes plus caller buffers and stack temporaries. Target runtime,
stack, CSPRNG and side-channel suitability remain unverified.

Next implement first-time pair-setup with explicit enrollment authorization and
trust-commit ownership, then pre-session capability/auth routes and typed
session/network/media integration. Native USB network access, actual Go-module
identity, installed-version execution/recovery and the Apple-chip interface
remain unresolved. No installable update, head-unit/phone operation, actual
trust-record access or firmware/update-USB change occurred.

## Step 57 - Implement real first-time pairing and owned enrollment

Added [pair-setup.md](pair-setup.md), with exact reference blobs, selected byte
profile, authorization/storage boundaries, test commands and target limits.
New `pair_srp`, `pair_setup` and `pair_setup_channel` modules implement SRP-6a
3072/SHA512, the signed/encrypted M1-M6 identity exchange and an owning plaintext
RTSP enrollment route. They join a separate optional `carplay_enrollment` target
using the already-pinned Monocypher and hosted Mbed TLS MPI dependencies.

The code uses the pinned CarPlay reference's fixed username/code and explicit
integer serialization. A cross-check found minimal-versus-padded A/B proof
differences in another AirPlay implementation; these are documented rather than
hidden behind automatic fallback. Independent leading-zero A/B/S vectors test
the selected behavior. Real iPhone compatibility remains unverified. The
public-exponent unsafe MPI API is not used; target side-channel/allocator/stack
suitability remains unproven. Four prepared MPI source/header files matched the
pinned tag after UTF-8/line-ending normalization; an initial comparison mismatch
was a host text-decoding issue, not a source modification.

Enrollment starts disabled. A fresh local authorization ID enables one attempt,
but successful SRP with a public code is not permission to trust an identity.
M5 must authenticate and carry a valid session-bound Ed25519 proof, then its
candidate ID/key is held for explicit approval. Only approval invokes the
trusted commit provider. Success requires an atomic durable insert or exact
existing match; conflicting-key replacement/failure cannot produce M6 success.
Tests use a synthetic map implementing that contract, not a real durable store.
Actual approval UI and authorization provenance are frontend responsibilities.

The RTSP owner accepts only the explicit enrollment route and retains following
wire through every request/approval/reply/drain boundary. After committed M6
drains, a token-bound transfer initializes fresh pair verification under a new
generation, optionally reusing cleared RX/TX buffers. Source close/check cannot
wipe the receiving owner's data. Setup completion does not activate encryption;
pair verification is still required. A successful stored mapping is not rolled
back just because the final reply is lost; committed metadata survives close.

Nine groups cover independent normal/edge SRP/setup transcripts, invalid group
values, every-byte SRP proof mutation, bad AEAD/Ed25519/fields, RNG failure,
explicit denial, commit errors/collisions/idempotence, stale generation/token/
clock, response/deadline clearing, fragmented owned RTSP, retained wire, transfer
failure and same-buffer handoff through pair verification to encrypted requests.
A separate integration test also exchanges an encrypted explicit response using
the newly enrolled controller. All 51 fixture values reproduce with independent
Python client/server integer arithmetic and PyCA; all keys are public fixtures.

All 26 combined CTest, 22 TLS-only and 19 standard suites pass, along with all
25 Python regressions and all three independent vector checkers. The enrollment
and three TLS/carkit suites pass ASan/UBSan with both crypto dependencies and
composed modules instrumented. Four existing pairing/control sanitizer suites
also pass. New C99 modules pass strict Clang warnings. The unchanged twenty-unit
core and nine-unit optional crypto ARM checks pass their existing import policies;
the new hosted enrollment code is not part of those objects. x64 SRP/setup/
candidate/channel sizes are 824/2,144/104/2,392 bytes, plus buffers/MPI heap/stack.

Next implement the actual explicit durable identity/controller store and its
atomic-write/corruption tests, then enrollment UI/mode selection, capability/
auth routes and typed network/media session integration. Actual Go-module
identity, native USB-network access, installed-version execution/recovery and
the Apple authentication-chip interface remain unresolved. No real trust
record, phone, head unit, firmware image or update USB was read or modified.

## Step 58 - Persist receiver identity and approved controller trust

Added [pair-store.md](pair-store.md) with the exact binary format, filesystem
authority/lifetime contract, failure outcomes, tests and target limits. New
`pair_store` implements an explicit portable C99 identity/trust snapshot;
`pair_store_file` implements actual Windows files using private explicit paths,
current-process-user protected ACLs, exclusive ownership and append/flush before
acknowledged commit. It never reads a default credential path or regenerates a
missing identity. Tests use only public fixture keys in new ignored build paths.

The journal holds at most seventeen 1,888-byte full snapshots: initial receiver
identity, then up to sixteen approved controller insertions. Open validates every
checksum, canonical field and history transition. Existing mappings cannot be
replaced; identical mappings are idempotent, even at capacity. Corrupt/partial
tails, reordered images, changed prefixes and inconsistent seed/public keys
fail closed without automatic truncation, deletion, retry or repair.

This step corrects Step 57's overly strong requirement that every storage failure
leave storage unchanged. Physical write/flush failure can be indeterminate.
`PAIR_STORE_UNCERTAIN` suppresses M6, leaves the new cached entry unpublished and
poisons the store against further trust use. Explicit close/reopen can reconcile
only a fully valid journal followed by a successful flush. A partial tail remains
rejected; a complete authorized but unacknowledged record can be recovered.
The setup `committed` flag records acknowledgement, not proof of absent disk
writes when false or proof of peer receipt when true. Failed initial creation
may leave a new empty/partial/complete file but never overwrites an existing one.

Generation-bound views and one-attempt enrollment bindings reject stale lifetimes,
authorization mismatches and key conflicts. Receiver identity stays immutable
while borrowed. Frontends must quiesce borrowers before closing/wiping storage,
and isolate synchronous OS I/O from real-time work. No approval UI, thread worker
or actual listener was added. The store is not an MFi authentication provider.

Portable tests cover every-byte corruption and every shorter image length,
recomputed-hash noncanonical fields, explicit RNG/identity failures, duplicates,
conflicts, capacity and prefix preservation. Real Windows tests cover private
ACLs, missing/existing-file refusal, unsafe paths, hard links, ancestor/file rename
locks, process-wide exclusion and process restart. An actual directory junction
exercises reparse refusal; the separate symlink case is explicitly skipped because
this host lacks its creation privilege, with no privilege change attempted.

Separate test-only hooks interrupt real creation/append I/O before writing, after
23 bytes, before flush and after successful flush but before acknowledgement.
Owned RTSP enrollment tests prove denial/no write and uncertain/no M6, then verify
complete recovered or committed enrollment via real pair verification and a
bidirectional encrypted RTSP exchange after reopening. The ordinary/security/
enrollment paths also run against the production library with no fault-hook API.

All 29 combined CTest, 19 ordinary, 22 TLS-only and 25 Python regressions pass.
Five pairing/control/store suites and the real-file/setup/three TLS-carkit suites
pass ASan/UBSan with their actual dependencies instrumented. New C99 code passes
strict Clang warnings; production symbol inspection finds no test-hook exports.
A sanitizer assertion issue was fixed in the test oracle: unspecified aggregate
padding is now initialized before byte-transactionality comparisons. No storage
or crypto sanitizer check was disabled. Successful suites cleaned their exact
new synthetic test paths. Four failed-run directories remain ignored beneath
`build/enrollment-sanitized/` after the environment rejected their cleanup;
they contain only public test records, not user credentials.

The optional ARM relocatable check now includes ten portable translation units
with the same four allowed runtime helpers; the twenty-unit import-free core is
unchanged. The Windows backend and hosted SRP/MPI/TLS are not QNX ports. Plaintext
seeds rely on file permissions, not encryption; exact-boundary rollback cannot
be detected without an external trusted counter. Revocation, rotation, migration,
backup/recovery policy and actual power-loss durability remain unimplemented or
untested and are explicitly documented, not silently approximated.

Next connect enrollment policy/first-request mode selection to pre-session
capability/auth routes and then typed network/media session handling. Target
storage/provisioning/revocation work remains necessary. Actual Go-module identity,
native USB-network ownership, authentication-chip access and installed-version
execution/recovery remain unresolved. No real trust record, phone, head unit,
firmware image or update USB was read or modified; no installable CarPlay update
has been produced.

## Step 59 - Own encrypted MFi authentication after verification

Date: 2026-09-10. Added [mfi-sap.md](mfi-sap.md) with pinned primary sources,
the exact response calculation, provider contract, ownership rules, independent
vectors and remaining integration limits. The selected reference places this
exchange inside encrypted control after pair verification; it is not an
unauthenticated plaintext authentication route.

New hosted `mfi_sap` performs fresh X25519, the protocol's SHA1 AES key/IV
derivations, SHA1 or SHA256 transcript hashing for explicit protocol majors 2/3,
and AES128-CTR signature encryption. It requires a supplied certificate/signing
provider with a stable identity and bounded operations. Unknown chip protocol
majors, malformed requests, invalid ECDH and failed/empty/overreported provider
outputs fail closed. There is no default credential, emulated MFi private key,
actual chip driver or claim that opaque certificate length checks validate an
Apple certificate chain. Ephemeral secrets and crypto temporaries are wiped.

New `projection_auth` owns fresh verification/control and MFi children. Only
exact encrypted `POST /auth-setup` with a unique octet-stream content type can
invoke the provider. Plaintext requests, failed controller verification and
cipher tampering never reach it. The bounded reply uses the existing correlated
encrypted output, fragmentation and retained-tail handling. Partial writes do
not re-sign. Only complete matching downstream drain releases the MFi reply;
`MFI_SAP_DRAINED` means local output drained, not phone acceptance or active media.
Generation/token, monotonic-time and independent absolute reply budgets remain
enforced. Synchronous provider I/O must itself be bounded.

`pair_setup_channel_take_auth` extends the committed-M6 transfer into this fresh
owner with a new generation. It supports reuse of the same cleared RX/TX buffers,
preserves following external wire, and leaves the destination/source unchanged
on argument rejection. Old-source teardown or repeated transfer cannot erase
the receiving owner. The old control-only handoff remains available. The new
integration test uses a memory-only trust-provider simulation; actual Windows
file persistence remains independently tested by Step 58.

Seven test groups cover both protocol majors, independent crypto/transcript
bytes, AES partial blocks, maximum response, malformed/short requests, provider
failures, zero/low-order ECDH, deadlines, stale ownership, clearing and no retry.
Integrated tests cover real verification, byte-fragmented encrypted requests,
multi-record/partial replies, same-record next-request tails, explicit application
501 responses, replayed auth, premature/lost drain and EOF. Approved SRP setup,
commit/M6 gating, same-connection transfer, verification and encrypted MFi reply
also run end to end with public synthetic credentials. The independent PyCA/
hashlib checker reproduces 39 public values, not real MFi licensing signatures.

All 30 combined CTest, 19 ordinary, 22 TLS-only and 25 Python regressions pass.
The new suite, enrollment, actual-file and three TLS/carkit suites pass ASan/UBSan
with both crypto dependencies instrumented, as do the five existing pairing/
control/store suites. Latest MFi test additions were rebuilt and rerun against
the instrumented objects. New/changed C99 modules and tests pass strict Clang
warnings; static analysis reports no finding in the changed C99 modules. Nine
prepared AES/SHA source/header files match the pinned Mbed TLS tag after newline
normalization; this is not a revalidation of its entire extracted source tree.

The new hosted target is excluded from both ARM claims. The unchanged optional
ten-unit ARM check still passes its four-helper policy. MFiSAP occupies 4,744
bytes and the owning wrapper 6,728 bytes on x64, plus caller buffers and stack
temporaries. Target runtime, side-channel and performance suitability remain
unverified. No actual phone, authentication chip, head unit, real trust record,
firmware image or update USB was accessed or modified.

Next implement initial route/mode selection and explicit capability encoding
tied to available display/audio/input resources, followed by typed session
handling and actual endpoints. Unknown application requests remain held for
explicit policy, not automatically acknowledged; no unsupported capabilities
are advertised. A compatible factory-chip provider, target execution/recovery,
USB-network ownership and actual media integration remain unresolved. Software-
only CarPlay on the factory unit is still unproven and not installable.

## Step 60 - Route the initial request and own the continuous receiver

Date: 2026-09-10. Added [receiver-routing.md](receiver-routing.md), documenting
the implementation, pinned reference, caller contract, public/internal lifetime
mapping, actual tests and remaining target limits. New hosted
`projection_receiver` selects enrollment or known-controller verification from
one complete initial plaintext request and owns the selected children through
encrypted MFi authentication. Initial input is staged separately, copied exactly
into the selected child and cleared without consuming following wire.

Enrollment is disabled by default. Enabling it permits an explicit local
authorization decision, not automatic pairing. Permission can precede the first
request or follow a bounded `PROJECTION_RECEIVER_AUTHORIZE` event. No RNG,
lookup, commit or MFi provider runs while that request awaits local permission.
Verified M5 still requires a separate token-bound candidate approval before
commit/M6. Denial, unknown-controller lookup, provider failure and malformed
traffic close without switching modes, retrying or authorizing by wire.

The public connection generation stays stable while the internal verification
child uses a second reserved generation. Public response tokens increase across
the transfer; a delayed enrollment callback cannot alias verification token 1.
After acknowledged commit and complete M6 downstream drain, the router invokes
the existing owned transfer automatically using the same emptied active buffers.
It returns setup completion, not encrypted readiness. Pair-verify M4 drain alone
activates encrypted control; MFi reply drain still does not prove phone acceptance.

The initial idle/receive/local-permission budgets default to 30/10/30 seconds,
absolute per phase. Selected child budgets start at selection or transfer.
Fragmentation, repeated authorization, bad callbacks and partial output do not
renew their applicable deadlines. Unknown initial routes, including discovery
outside the two exact pairing paths, fail closed. Broader initial sequencing
and target forms remain a real interoperability gap, not an implemented feature.

Seven groups exercise every two-piece initial-verify split, byte-fragmented
traffic, both preauthorized/deferred enrollment, real SRP/verified approval,
automatic transfer, real verification and encrypted MFi on one simulated
connection. They check correlated replies, same-record authenticated tails,
external ciphertext after M4, explicit application 501 replies, stale generation/
token/count/decision handling, deliberate token exhaustion, deadline boundaries,
EOF, clearing, failed commit and lost M6/MFi drain. Invalid initialization is
checked against nonzero buffer sentinels. Public fixture keys and a memory-only
trust provider are used; existing actual Windows persistence tests remain separate.

All 31 combined CTest, 19 ordinary, 22 TLS-only and 25 Python regressions pass.
The new router, MFi, setup, actual-file and three TLS/carkit suites pass ASan/UBSan
with both crypto dependencies instrumented. Strict Clang C99/C++ warnings pass;
static analysis reports no finding in the new C99 module. Existing independent
39-value MFi/pairing and 51-value setup vectors reproduce successfully. No new
dependency version, production credential, permissive fallback or installation
artifact was added.

The five existing pairing/control/store sanitizer suites and ten-unit optional
ARM relocatable check also pass, with the same four allowed runtime helpers.

The hosted receiver occupies 9,632 bytes on x64, plus caller buffers, stack
temporaries and dependency allocations. It is not part of either existing ARM
claim and is not a linked/executed QNX receiver. No actual phone, authentication
chip, head unit, real trust record, firmware image or update USB was accessed
or modified. Software-only CarPlay on the factory unit remains unproven.

Next implement explicit capability responses and required discovery routing,
then typed session/resource negotiation and real endpoints. Actual display/
audio/input resources must back advertised capabilities. Local approval/rate
limiting, target persistence/revocation, provider scheduling, native USB-network
ownership and installed-version execution/recovery remain necessary.

## Step 61 - Encode explicit capabilities and own bounded discovery

Date: 2026-09-10. Added [projection-capabilities.md](projection-capabilities.md)
with pinned source blobs, typed profile rules, binary-format checks, route and
runtime-provider contracts, tests and remaining target limits. The new pure
`projection_info` encoder accepts only explicit identity, feature, display,
audio, HID, resource and optional extension/OEM data. It supplies no production
feature mask or guessed factory hardware properties. Structural consistency
does not validate opaque HID/icon formats or actual backend availability.

Encoding is bounded to 640 internal objects and 32,768 bytes, with measurement
and failure-before-output guarantees. Positive `UINT64_MAX` retains its sign;
speech mode -1 retains the pinned writer's real-number wire type. The full
synthetic profile exposed the previous decoder's 256-object/no-real limit.
A separate projection-only binary decoder now permits 640 objects/expanded
nodes and finite 32/64-bit real values, stored as distinct raw-bit nodes without
floating-point execution. The original Lockdown decoder remains unchanged in
its accepted types and 256-node limit; NaN/infinity and unsupported extensions
remain rejected.

The existing receiver can enable exact `/info` once before initial input,
requiring immutable profile data, separate scratch and an explicit bounded
synchronous runtime availability callback. A valid GET or binary-dictionary
POST produces the full profile, not selector-filtered data, through the normal
owned response queue. Invalid requests, bad cipher records and failed providers
close without a false success. Scratch clears, callbacks do not repeat under
backpressure, and an application cannot replace an internally pending reply.
No real runtime availability provider is implemented by the synthetic tests.

Encrypted info is available after verification, before or after MFi, without
implying media authorization. Initial plaintext discovery requires extra opt-in;
default settings allow four replies within 60 seconds from receiver initialization
when enabled. Discovery cannot renew that total lifetime or interleave in the
middle of setup/verification. Replies must drain before the next initial request;
following wire stays with the caller. Configuration and public tokens survive
both pairing routes and automatic post-enrollment transfer.

Four codec groups cover deterministic output, 42 invalid profiles, capacity/
integer boundaries, isolated decoder semantics, real bit patterns, 640/641-node
limits and 600 deterministic mutations/truncations. The receiver's three new
groups bring it to ten, including full 310-object POSTs over fragmented cipher
records, a 25,777-byte plaintext request and encrypted replies spanning more
than 100 records, real enrollment/verification, retained tails, provider failures,
clearing, stale callbacks and exact nonrenewable deadlines. Independent Python
`plistlib` checks reproduce exact types/keys/values/order for three synthetic
profiles of 580, 4,056 and 25,777 bytes (50, 310 and 415 objects).

All 32 combined, 20 ordinary and 23 TLS-only CTest suites and 25 Python
regressions pass. Sixteen protocol/capability sanitizer suites and seven hosted
TLS/carkit/enrollment/file/MFi/router suites pass ASan/UBSan, with both crypto
dependencies instrumented in the latter. Strict Clang C99/C++ warnings pass;
static analysis finds no issue in the three changed C99 modules. The twenty-unit
import-free ARM core check passes after the decoder change. Dependency CMake/
MSVC warnings and the existing privileged-symlink test skip are recorded in the
new report; actual Windows directory-junction rejection passes.

The profile occupies 1,224 bytes and the hosted receiver 9,696 on x64, before
caller buffers, stack and dependency allocations. Individual Clang-O2 frames
include 28,392 bytes for encoding and 20,712 for info reply handling; these are
not a whole-call-stack or QNX suitability proof. The new encoder/hosted receiver
remain outside both existing ARM claims. No dependency version, actual phone,
authentication chip, head unit, real trust record, firmware or update USB changed.

Next implement typed SETUP/session/resource negotiation with explicit allocation,
endpoint results and teardown, constrained by actually available capabilities.
Real network/media/input backends, approval/rate limiting, target persistence/
revocation, native USB-network ownership and installed-version execution/recovery
remain necessary. Software-only CarPlay on the factory unit is not installable.

## Step 62 - Own typed sessions, derived keys and resource leases

Date: 2026-09-10. Added [projection-session.md](projection-session.md) with
source pins, request schemas, exact key domains, provider contracts, tests and
remaining backend limits. The existing receiver can now enable a typed session
child after info configuration and before any initial input/discovery. Only
verified encrypted requests after local MFi reply drain reach resource allocation;
this does not establish real MFi or handset acceptance.

Initial SETUP binds its opaque target and validates the peer NTP timing port and
optional low-power request. Stream SETUP preflights all entries against the same
advertised profile: main/alternate screen, three audio types with single-bit
format selection and optional main-audio microphone, plus an explicitly enabled
iAP tunnel. Integer/bool/real/string types are distinct; malformed dictionaries,
unknown stream types, inconsistent capabilities and reused IDs fail closed.
The target is never a network destination or controller trust identity.

Event and stream keys use the real owned pairing shared secret with separate
HKDF-SHA512 salts/info; media/tunnel receive and microphone send directions are
explicit. Unsigned decimal IDs retain zero, 2^63 and UINT64_MAX. A 128-entry
lifetime ledger includes retired stream IDs/seeds, preventing setup from
recreating a prior key/counter domain. Full teardown ends the connection rather
than restarting events with the same keys.

The explicit bounded provider transfers unique leases and validated port results.
There are no default ports or real backend implementation in these tests. Any
failed allocation/result closes all owned resources, including earlier streams.
RECORD starts prepared resources only after its exact reply drains; added streams
start after their own setup reply drains. Failed start, response construction,
deadline, EOF and explicit close also clean up. Valid partial teardown closes only
the selected streams; invalid bodies never become successful full teardown.
Runtime loss cannot prevent cancellation. Resource providers must bind the actual
control peer and preserve counter/transport ownership themselves.

Four session groups cover lifecycle, schemas/capacities/state/ID limits, 600
mutations/truncations, failures at every allocation position, invalid/duplicate
leases, availability/start failure and capability/configuration gates. The
receiver now has twelve groups, including both real enrollment/verification
routes through encrypted full session lifecycles, output/drain ownership, stale
callbacks, retained authenticated tails, pre-MFi/plaintext denial and cleanup.
An enablement guard was tightened to reject enabling after a discovery reply
even though its staging buffer has already been cleared.

All 33 combined, 20 ordinary and 23 TLS-only CTest suites and 25 Python regressions
pass. Eight hosted TLS/carkit/enrollment/file/MFi/session/router suites pass
ASan/UBSan with both crypto dependencies instrumented. Strict Clang C99/C++
warnings pass and static analysis finds no issue in the changed C99 modules.
Independent standard-library checks reproduce 42 public fixtures, 16 directional
key/zero values and three reply dictionaries of 178, 450 and 158 bytes; the last
preserves UINT64_MAX correlation. Existing independent capability profiles pass.

The child occupies 3,840 bytes and the receiver 13,536 on x64, before scratch,
stack and dependency allocations. Session parse alone has a 20,680-byte individual
Clang-O2 frame; no whole-stack or target-suitability claim follows. The new target
is outside both prior ARM claims. No new dependency version, real phone/chip,
head unit, trust record, firmware or update USB changed.

Next implement actual peer-bound endpoint services and cancellation, timing/event
protocols and stream packet/record owners, then media/input backends. The synthetic
resource provider is not a production fallback. Factory execution/recovery,
USB-network ownership, compatible existing authentication-chip access, target
persistence and real-phone validation remain necessary; CarPlay is not installable.

## Step 63 - Implement real timing and encrypted event sockets

Date: 2026-09-10. Added [projection-services.md](projection-services.md), with
exact source pins, timing/socket contracts, validation commands and remaining
limitations. `carplay_timing` is a pure bounded C99 RTCP-style timing/steered-clock
engine. The optional Windows `carplay_services` provider creates actual
nonblocking, exclusive, non-inheritable UDP timing, TCP event and optional UDP
keepalive endpoints. All network tests use PC loopback only.

Timing pins the control peer IP and SETUP port, matches a single pending probe,
validates RTT and filters observations. Unsigned fixed-point arithmetic handles
negative phase and NTP rollover without signed overflow or changing the OS clock.
Malformed/stale traffic does not renew synchronization deadlines. Actual UDP
send acceptance commits a probe; would-block probes are freshly timestamped.

Events accept one matching peer, then close the listener. The existing cipher
authenticates records with independent event keys/counters; bounded network tails
and held plaintext preserve backpressure. Tag/replay/EOF/deadline failures wipe
and close, never reconnect under reused keys. Unsolicited output waits for the
outer RECORD reply drain. There is no automatic event-command success or complete
RTSP event-message owner yet. Media requires an explicit delegate; no synthetic
port allocation becomes a production fallback.

Provider leases are remapped uniquely and cleanup retains Winsock while delegated
resources need it. The receiver now supports paired optional poll/next-delay
callbacks, enforcing outer control generation/deadlines before backend I/O and
closing all leases on polling failure. Full-teardown reply drain still works
after all service leases have closed.

Four timing groups cover wire validation, filter/window eviction, modular clocks,
transactional/deadline boundaries and 10,000 malformed packets. Eight real-socket
groups cover IPv4/IPv6, peer pinning, actual binding/cleanup, encrypted fragments/
tails/empty records, replay/tag/EOF and lifetime failures. Integration uses actual
pair verification/encrypted MFi/session routing and event key derivation; the
public credentials, MFi provider and media driver remain explicitly synthetic.

All 35 combined, 21 ordinary, 24 TLS-only and 25 Python regressions pass.
Seventeen ordinary and nine hosted suites pass ASan/UBSan, with both crypto
dependencies instrumented. Strict C99/C++ Clang warnings and static analysis of
the four changed/new C99 modules pass. An independent Python Fraction checker
matches 12 clock/filter values; existing session/capability checkers also pass.
The service context measures 920 bytes, session 3,856 and receiver 13,552 on
x64, excluding caller buffers, stack and dependency/kernel allocations.
No new dependency or ARM/QNX portability claim is introduced. The existing
dependency warning and privileged-symlink skip remain; junction rejection passes.

Next implement the authenticated event message owner and explicit feedback/input
commands, then actual stream receivers and display/audio/microphone drivers.
Factory identification, execution/recovery, USB-network ownership, existing Apple
authentication-chip access and phone interoperability remain unresolved. No
installable CarPlay update, modified ISO or vehicle operation is produced.

## Step 64 - Own bidirectional event messages and explicit commands

Date: 2026-09-10. Added [projection-events.md](projection-events.md) with pinned
references, schemas, ownership contracts and verification commands. Reinspection
confirms `/feedback` belongs to the control connection, not the event channel;
the earlier combined next-step description is corrected.

The new pure C99 event owner supports up to four outstanding commands and atomic
multi-command enqueueing, so explicit press/release pairs do not partially enter
a full queue. Non-reused CSeqs and lifetime tokens correlate final replies,
including out-of-order and non-200 replies. Incoming phone requests have their
own namespace and require explicit handler responses; no generic 200 is supplied.
Replies take priority over new commands without interrupting active output.
Plaintext copying and final ciphertext drain are separate; only the latter starts
the response deadline. Held messages, receive, output/drain and pending replies
have absolute budgets. Unknown/duplicate/premature responses and malformed input
close the owner, never reset counters or retry commands automatically.

Typed binary-plist encoders implement HID reports, Siri down/up, night mode,
iAP messages and keyframe requests with exact advertised-ID and feature gates.
They supply no physical input driver or default identity. The socket provider
can enable the owner before allocating sockets, disabling raw record access.
RECORD reply drain enables commands; pre-start incoming requests may still get
explicit replies. Polling joins message/cipher/socket deadlines and cleanup.

Six pure groups include request encoding, schema/capacity rejection, all four
slots, bidirectional correlation, atomic queueing, output priority, stale tokens,
exact deadlines/exhaustion and 5,000 malformed/truncated messages. Eight generated
command plists decode independently with exact types/data. Full synthetic
pairing/MFi/session integration now tests actual IPv4/IPv6 command exchanges,
64-byte outgoing and 31-byte incoming records, pre-RECORD gates, out-of-order
responses and cleanup on invalid/missing replies or held-request expiry.

The first sanitizer pass caught undefined intermediate pointer arithmetic when
selecting slot four. Computing the final index before adding it to the array
base fixes the problem, and the all-four-slot test remains in the sanitizer suite.
Final validation passes 36 combined, 22 ordinary, 25 TLS-only CTest suites and
25 Python regressions, with 18 ordinary and nine hosted ASan/UBSan suites. Strict
Clang warnings and static analysis pass. The refreshed twenty-unit ARM core
remains import-free; new event/command and Windows service targets are excluded.
The event owner is 392 bytes and the service context 1,320 on x64, before caller
queues/stack/kernel storage. No dependency version or real credential changed.

Next implement typed control `/feedback` from actual media observations and
explicit control mode/resource command handling, then actual media decoders and
input/output drivers. Target execution/recovery, USB-network ownership, factory
authentication-chip access and phone validation remain unresolved. No installable
CarPlay update or vehicle modification is produced.

## Step 65 - Report control feedback from observed playback

Date: 2026-09-10. Added [projection-feedback.md](projection-feedback.md) with
pinned schema references, configuration, timestamp arithmetic, provider
contracts, validation and remaining work. The owned session now optionally
handles exact POST `/feedback` on verified encrypted control after local MFi
and initial session SETUP reply drain. Feedback is disabled unless explicitly
configured with a freshness limit and playback/clock observers.

The handler enumerates only current audio leases, reports their actual counter
rates, and includes timestamp anchors only after RECORD with fresh playback
observations and a synchronized clock. Missing/stale positions omit anchors;
receipt, decode, queueing and successful sends never become played samples.
Integer nanosecond-to-NTP conversion preserves full uint64 IDs/times and modular
wrap. Invalid output or callback failure closes every lease before any partial
reply. Normal encrypted output/token/drain ownership protects the response and
retained coalesced requests. Feedback never starts media or renews timing sync.

The actual Windows provider remaps live audio leases to its explicit delegate
and exports its own timing snapshot, without an OS wall-clock fallback. Review
added a per-lease open-time guard so replacement streams cannot report positions
from before their creation. The regression includes an otherwise fresh old
timestamp, not only a retired lease lookup. Clock/observation callbacks perform
no socket I/O; real peer-bound timing exchange remains in endpoint polling.

Six session, thirteen receiver and nine service groups pass. Expanded tests
cover mixed/absent observations, exact freshness bounds, invalid third-stream
output, wrap, authentication and lifecycle gates, lease replacement, deadlines
and actual IPv4/IPv6 timing sockets through synthetic pairing/MFi/control.
Seven C outputs pass independent Python plist decoding; previous session keys
and fixture outputs are unchanged. Validation passes 36 combined, 22 ordinary,
25 TLS-only suites and 25 Python regressions, plus nine hosted ASan/UBSan suites
with both crypto dependencies instrumented. Strict C99/C++20 warnings and static
analysis pass. Context sizes on x64 are session 3,872, receiver 13,568 and service
1,384 bytes, excluding buffers/stack/heap/kernel storage. No dependency is added;
these components remain outside the existing import-free ARM claim.

Next implement bounded audio reception/sequence handling and a real decoder/
output backend that supplies actual playback observations, then remaining
media, input and control mode/resource semantics. Factory execution/recovery,
USB-network ownership, actual authentication-chip access and phone acceptance
remain unresolved. This is not an installable CarPlay update or a vehicle change.

## Step 66 - Receive encrypted audio through real UDP services

Date: 2026-09-10. Added [projection-audio.md](projection-audio.md), tracing the
pinned native receiver/player beyond control SETUP. The envelope authenticates
the timestamp, SSRC and payload, but not RTP sequence/flags/type. The new pure
owner therefore uses verified nonce counters for ordering and a 64-packet replay
window. Fixed-header/dynamic-payload and increasing-counter requirements are
explicit local profile bounds still requiring actual-phone validation.

Seventeen exact format mappings cover PCM16, AAC-LC and Opus without unknown-bit
fallbacks. Opus downlink has a 48 kHz clock even when negotiated microphone input
is 16 or 24 kHz. PCM frame alignment and big-to-little-endian conversion are
implemented; compressed bytes remain raw units awaiting a real decoder.
Caller-owned bounded queues handle reordering, gaps, pre-start reception and
atomic held-output consumption with generation/token/deadline protections.
Late packets cannot move delivery backwards after a packet is borrowed. No
received, converted or accepted sample is misreported as played audio.

The Windows audio delegate binds actual nonblocking, exclusive, non-inheritable
data/control UDP ports per audio stream. Peer IP must match; source port pins
only after authentication. A required sink prepares and validates actual format/
device support, starts after RECORD drain, handles packets and supplies observed
playback. Callback/backpressure failures and partial start close all audio
resources. Root receiver cleanup still owns other services. This delegate is
audio-only: no screen/iAP/mic fallback. Control UDP is currently bounded drain,
not implemented retransmission/flush/synchronization semantics.

Six core and five service groups pass, including actual IPv4/IPv6 reception,
5,000 malformed inputs, independent decryption, all 64 slots, counter/timestamp
wrap, PCM conversion, source-port pinning, backpressure, exact expiry, partial
start failure and synthetic pairing/MFi/session/timing/feedback integration.
Replacement-stream tests reject old-key data before accepting the new key.
The independent PyCA checker reproduces 13 public fixture values and checks all
17 formats/four decrypted outputs. It found a fixture transcription error; the
capability validator also caught an omitted audio resource declaration. Both
fixtures were corrected without weakening validation.

Validation passes 38 combined, 22 ordinary, 25 TLS-only suites, 25 Python
regressions, the independent checker, strict warnings and static analysis.
Eleven hosted ASan/UBSan suites pass with both crypto dependencies instrumented.
The x64 audio owner is 4,288 bytes and three-stream service context 13,288,
before caller storage, stack and device/kernel allocations. No receiver
dependency version changes; audio remains outside existing ARM portability
claims. All sinks/observations in these tests are explicitly synthetic, and
compressed fixture transport does not prove decoding or physical playback.

Next implement real PCM device output and played-position reporting, then
compressed decoders, timestamp pacing, remaining media/input and control focus/
mode semantics. Factory execution/recovery, native USB, existing authentication
chip access and real-phone acceptance remain unresolved. No installable update
or vehicle/audio-device change has been made.

## Step 67 - Implement explicit Windows PCM device output

Date: 2026-09-10. Added [projection-pcm-output.md](projection-pcm-output.md) and
an actual WASAPI implementation of the audio sink contract. Its explicit active
render endpoint, shared-mode PCM initialization, device buffer/clock queries and
private nonpersistent audio session have no default-device, microphone or volume
fallback. COM ownership and all callbacks remain on the creating STA thread.
Windows performs requested PCM channel/rate conversion; AAC/Opus are unsupported.

Three per-type output resources each own a 65,536-byte ring. Whole PCM16BE
packets copy/convert atomically, with bounded backpressure and immediate wiping
of consumed bytes. RECORD start arms output; actual device start follows media
prefill. Contiguous sample timestamps, modulo 2^32, are required within a run.
Low headroom stops appending until the observed tail drains, then resets the
device epoch. This can introduce gaps; adaptive loss handling, negotiated latency,
flush and synchronized pacing are not implemented by this basic renderer.

Playback maps an accurate IAudioClock position/frequency pair into the media
epoch and preserves the device's correlated QPC time. Zero, delayed and beyond-
media readings report no position. Reversal/future times, overflow and device
errors fail closed. All enclosing services must use the supplied absolute QPC
ns clock. Submission, padding and elapsed wall time never become played-sample
anchors. Lease replacement, error propagation and final cleanup are explicit.

Seven output groups test twelve PCM formats, ring/timestamp wrap, full queues,
startup/drain/restart, partial allocation, device failures and clock bounds. A
sixth real-UDP service group now crosses encryption, ordering and the actual PCM
engine into a synthetic device, then validates observed feedback and fatal port/
key cleanup. Windows tests check argument rejection, nonexistent explicit
endpoints without fallback, COM balancing and thread/clock rules without starting
a speaker. The large integration fixture uses heap ownership, checks both runtime
and final buffer wiping, and explicitly exercises exception cleanup.

Forty combined, twenty-two ordinary and twenty-five TLS-only CTest suites pass,
alongside twenty-five Python regressions and the existing independent audio
checker. Strict warnings/static analysis and thirteen hosted ASan/UBSan suites
pass, with the documented Clang 19 named-catch limitation avoided in the explicit
unwind test without disabling instrumentation. The x64 output engine is 197,016
bytes including its three queues; device/OS allocations are additional.
Only read-only physical endpoint enumeration has been performed. The explicit
prepare/silent-smoke commands are available but no endpoint is selected or
started automatically. This is Windows host implementation, not validated QNX
audio or a working factory CarPlay installation.

Next validate the selected physical output, add compressed decoders and complete
timestamp-aware playout, then remaining media/input/control focus semantics.
Factory execution/recovery, native USB, existing authentication-chip access and
real-phone acceptance remain unresolved. No vehicle or audio preference changed.

## Step 68 - Decode AAC-LC/Opus and own PCM delivery

Date: 2026-09-10. Added [projection-decode.md](projection-decode.md), real optional
Opus 1.6.1/FAAD2 2.11.3 decoders and an owning adapter into the PCM sink. Both
source checkouts require exact pinned commits and clean trees. Default builds
remain unchanged; the new media script opts in without installing codecs.

Seventeen negotiated descriptors map to native PCM16, including raw AAC-LC
stereo at 44.1/48 kHz and mono Opus at a 48 kHz clock, bounded to 120 ms. FAAD's
first raw AAC AU primes without fabricated PCM. Subsequent output uses the
packet's own timestamp; no guessed encoder delay or container pre-skip is used.
Inputs must already be authenticated/ordered. Gaps, overlaps, codec changes or
invalid media fail closed; loss concealment and seek/flush are not implemented.

Each type 100..102 owns its decoder and downstream PCM lease. Submitted payloads
are copied; pending decoded output prevents accepting another packet. Poll
delivers at most one 8,192-byte chunk and preserves exact frame offsets. Absolute
hold deadlines cannot be renewed by partial consumption. Failures retire every
owned resource and propagate to the enclosing UDP/session owner. Playback still
comes only from the downstream device clock, never from decoded/submitted frames.

Five decoder/adapter groups cover all formats, priming, 120 ms chunking,
backpressure, timestamp wrap, stale callbacks, failure ownership and 1,000 fresh/
primed mutation cases. Three integration groups cross actual IPv4/IPv6 encrypted
UDP, reverse arrival, RECORD gates, decoding and the PCM engine into a synthetic
device, checking observed feedback and three-stream key/socket cleanup.

The pinned test-only PyAV environment reproduces 33 synthetic packets and
compares 59,648 PCM samples. Deterministic AAC/no-PNS and Opus CELT controls match
native FFmpeg within one PCM16 unit. Original AAC noise-substitution fixtures
use explicit residual/SNR checks. Original hybrid Opus differs from native FFmpeg
by up to 1,836 units but matches PyAV/libopus exactly; its underlying cause is
unresolved and the same-algorithm comparison is not called independent validation.
The report preserves the initial failed comparison and added controls.

Forty-two media, forty existing combined, twenty-two ordinary and twenty-five
TLS-only CTest suites pass, plus twenty-five Python regressions and both audio
reference checkers. Both new suites and their linked codecs pass ASan/UBSan;
thirteen existing hosted suites also pass. The sample comparison agrees for
MSVC release and instrumented Clang builds. Strict production C99 warnings and
static analysis pass. Upstream notices, warning/toolchain limits and reproducible
commands are recorded in the report and third-party inventory.

No physical playback or car/phone access occurred. Next implement explicit
timestamp-aware playout, latency/loss/flush/pacing and continue codec timing/
interoperability checks. Factory execution/recovery, native USB/network,
compatible existing authentication-chip access, remaining media/input/focus
semantics and real iPhone acceptance are still necessary.

## Step 69 - Own authenticated audio FLUSH without resetting replay state

Date: 2026-09-10. Added [projection-flush.md](projection-flush.md) and an optional
two-phase flush contract across session/root/audio providers, the codec bridge
and PCM output. The pinned LIVI CarPlay stack does not define a FLUSH handler;
Shairport Sync and OpenAirPlay supply primary references for the narrower classic
AirPlay form. Real-iPhone acceptance of this form remains unverified.

Exact bodyless FLUSH requires verified encrypted control after local MFi and
RECORD drain, the already-bound target, one owned audio stream and one bounded
RTP-Info header containing seq/rtptime. The named timestamp is the first allowed
packet, not the last discarded packet; this was corrected after source review.
Malformed or ambiguous requests fail closed before invoking flush. A new failing
regression exposed and fixed a routing interaction with the POST-only /feedback
endpoint; FLUSH cannot bypass that method check.

Begin stops/resets output, wipes pending PCM/packet queues, recreates the codec
and arms a timestamp fence. Keys, nonce window/floor, SSRC, source pinning,
sockets, leases and lifetime tokens persist. Already-received nonces cannot be
replayed, including unseen lower counters behind the retained delivery floor.
New authenticated packets can queue while suspended, but submission/decoding and
device start wait for actual encrypted-response drain and ordinary media prefill.
Errors or close/deadline expiry retire all owned resources without resuming.

This clears all already-owned media, including packets beyond the timestamp;
it may introduce extra gaps and is not selective buffered flushing or partial-
packet trimming. Sequence metadata never becomes UDP authentication authority.
Actual device-clock observations remain the only source of playback feedback.
No real endpoint or phone test establishes acoustic behavior or A/V timing.

Expanded suites now contain seven session, seven audio, seven audio-service,
eight PCM-output, five decoder and four decoder-service groups. They cover
held/running media, replay/timestamp wrap/equality/half-range, stale tokens,
queued compressed chunks, AAC re-priming, exact fresh-decoder PCM, new observed
origins, reply-drain gating and reset/resume/timeout cleanup. Real loopback
pairing/control/timing/events/audio cryptography uses public synthetic credentials
and a synthetic final output device.

Forty-two media, forty combined, twenty-two ordinary and twenty-five TLS-only
CTest suites pass, plus twenty-five Python regressions and both audio reference
checkers. Thirteen hosted and two codec-enabled sanitizer suites pass; strict
C99/C++20 warnings and static analysis pass for the changed production units.
The prior codec-reference and toolchain limitations remain documented.

Next implement timestamp-aware latency/pacing and loss policy, then remaining
media/input/control semantics. Factory identification, execution/recovery, native
USB/network, existing authentication-chip access and real-phone acceptance remain
unresolved. No vehicle, USB, physical playback or firmware operation occurred.

## Step 70 - Pace decoded audio and recover bounded packet loss

Date: 2026-09-10. Added [projection-playout.md](projection-playout.md), explicit
relative scheduling and bounded loss recovery through the owned decoder/PCM
pipeline. The pinned LIVI/GStreamer pipeline and Opus public API supply primary
references. No new dependency or real-phone/physical-playback claim is added.

The opt-in recovery policy requires an authenticated nonce gap plus a bounded
forward timestamp gap with valid codec geometry. It owns a copied future AU
while bounded polls produce actual Opus PLC or marked PCM/AAC silence. AAC also
recreates decoder history and marks its recovery priming interval. Counter/replay
state is not reset; malformed, excessive or unsignaled discontinuities fail closed.

An explicit paced mode anchors exact accumulated frame counts to local receipt/
start time plus SETUP latency. Checked arithmetic avoids per-AU rounding drift.
Lookahead bounds early PCM delivery; a prefilled device waits until the first
presentation time to start. Bounded provenance maps follow replacement frames
through software/device rings and suppress source feedback during concealment.
Only actual device-clock observations of genuine media can yield an anchor.

FLUSH retires future AUs, recovery state, presentation offsets and prefilled/
playing media without changing keys, leases or replay protection. Per-AU absolute
deadlines include scheduled waiting when pacing is enabled and cannot be renewed
by partial chunks or busy responses. New features/config fields require explicit
sink support; zero initialization preserves the prior strict/unpaced behavior.

Seven decoder, nine PCM-output and five integration groups pass. Four sustained
160-slot AAC/Opus timelines use actual IPv4/IPv6 encrypted UDP with bursts, two
losses and a late replay each. A synthetic 1 ms advancing device clock verifies
one Start per stream, exact frame counts, timestamp wrap and concealment-aware
feedback. Unit tests also cover 500 ms multi-chunk gaps, exact scheduling bounds,
44.1 kHz arithmetic, timed/recovery flush, overflow and a 60-second scheduled wait.

Forty-two media, forty combined, twenty-two ordinary and twenty-five TLS-only
CTest suites pass, plus twenty-five Python regressions and existing audio/codec
reference checks. Two codec-enabled and thirteen hosted sanitizer checks pass;
strict production C99/C++20 warnings and static analysis pass. Existing codec
comparison, AAC quality and toolchain limitations remain documented.

This is local relative pacing, not acoustic-latency verification or peer-NTP/A-V
sync. Next implement late-media/drop-resynchronization and clock-drift policy.
Trailing loss, DTX/FEC/retransmission, adaptive jitter and selective flushing need
more work. Factory execution/recovery, native USB/network, existing Apple-chip
access, remaining media/input/focus and handset acceptance remain unresolved.
No car, physical output, default device, firmware or USB operation occurred.

## Next checks

1. Obtain read-only identification of the actual Go module and establish a
   recovery route before preparing anything intended to execute on the car.
   The missing facts are its model/part number and hardware revision; the
   installed navigation version is already confirmed by the existing photos.
   An already accessible module label or ordinary read-only identification is
   suitable evidence; do not change service-menu flags to obtain it.
2. Match the installed 6.9.0WL loader against the later corpus. The checks above
   cannot establish that both versions contain the same defects.
3. Validate the explicit PCM device backend, implement late-media/drop-resync and
   adaptive clock-drift policy, sender/A-V synchronization, selective buffered
   flush, remaining media/input backends and control mode/resource semantics.
   Step 70 adds opt-in relative timed PCM delivery and bounded packet-loss recovery
   with concealment-aware feedback; sustained tests still use a synthetic device.
   Step 69 adds authenticated two-phase classic
   FLUSH and media-state retirement without resetting replay protection; its
   single-stream form and all-queue discard policy need actual phone validation.
   Step 68 adds source-pinned AAC-LC/Opus decoding and owned PCM delivery,
   with codec/reference limitations documented separately. Step 67 adds Windows WASAPI PCM output and device-clock queries;
   automated playback tests still use a synthetic final device. Step 66 adds real
   encrypted audio UDP reception and PCM byte conversion through an explicit
   output-sink boundary; its full receiver tests use synthetic sinks.
   Step 65 adds explicit control feedback
   from typed observed playback and the actual timing service, including lease
   replacement and freshness gates. Real playback observations still require
   an actual audio backend; current media-provider tests are synthetic.
   Step 64 adds event message ownership and explicit command encoders, with
   real-socket integration; `/feedback` is a separate control route now handled
   in Step 65. Physical input capture, control mode/resource
   semantics and media drivers are still missing. Step 63 adds actual
   peer-bound Windows timing/event/keepalive sockets and receiver polling, tested
   over loopback. Audio packet processing is added in Step 66; video/iAP stream
   processing and a QNX socket backend remain missing.
   Step 62 adds
   typed session/resource ownership and key derivation, with strict capability/
   state gates, lease cleanup and reply-drain/start handling. Media allocation
   in the current integration tests remains explicitly synthetic.
   Step 61 adds explicit capability encoding and optional bounded `/info` routing,
   including plaintext discovery opt-in and encrypted responses. Its runtime
   availability contract still needs actual display/audio/input backend support;
   request selectors and broader discovery variants are not implemented.
   Step 60 connects
   initial pairing-mode selection, explicit local authorization and separate
   verified-candidate approval through one owning receiver, with automatic
   post-M6 transfer and stable public lifetime tokens. A real approval/rate-limit
   frontend, broader initial discovery and actual phone interoperability
   remain missing; no generic initial command success is supplied.
   Step 59 implements the post-verification encrypted MFiSAP route and same-
   transport enrollment handoff using real crypto and explicit synthetic test
   providers. The actual factory authentication-chip provider remains absent;
   local reply drain does not establish phone acceptance or usable media.
   Step 58 implements a portable identity/controller snapshot and actual private
   Windows store with strict journal/flush/uncertainty handling. Target QNX storage,
   real provisioning/approval and explicit revocation/recovery remain necessary.
   First-time SRP/setup and owned enrollment-to-pair-verify transfer are now
   implemented in Step 57; no actual phone is enrolled by the synthetic tests.
   Authenticated control-frame
   streaming/counters and the owned pairing-to-RTSP handoff are implemented in
   Step 56, with explicit plaintext-M4 downstream-drain gating.
   TLV8, explicit receiver identity and real known-controller pair verification
   are implemented in Step 55, but no actual phone is enrolled or connected.
   Bounded RTSP/HTTP framing and explicit request/response ownership are now
   implemented in Step 54; they do not authenticate or handle session commands.
   The iAP2 transport/link/control engine is connected
   to carkit with completion/cancellation/ownership accounting in Step 53.
   Protected framed RPC ownership, StartService/port/SSL policy and carkit stream
   startup are implemented in Step 52. The real TLS
   adapter with explicit credentials, peer validation and deadlines is now
   implemented in Step 51; it is not yet a verified QNX crypto port.
   Explicit request encoders and pre-TLS startup/handoff are implemented in Step 50.
   Bounded XML/binary
   response decoding/validation is implemented in Step 49.
   Service framing, GetValue encoding and a bounded
   opaque response channel are implemented in Step 48.
   USBmux dispatch/byte-stream integration is now
   implemented in Step 47. TCP-style connection, routing and
   flow control are implemented in Step 46; version/setup and packet queues in
   Step 45, packet codecs and streaming in Step 44.
   Explicit supported-message/USB-host declarations are implemented
   in Step 43; typed PowerSourceUpdate and unsolicited output in Step 42. The packed SupportedLanguage defect is fixed
   in Step 41. Identification-first startup is implemented and tested; Steps 37-39
   trace session startup and implement a bounded message subset. Real native
   transport and broader runtime interoperability remain missing. The bounded host
   transport pump passes simulated transfers and authentication (Steps 34-35).
   The pinned corpus's stock USB/HID path and service coordination are traced
   (Steps 31-32), but physical ownership and a usable iAP2 profile are unknown.
   Application replies and minimal opt-in identification pass simulated
   exchanges (Steps 28-30); actual QNX USB transport remains separate. Establish the
   existing Apple authentication chip's identity
   and usable interface. The register operations and cached `authcoproc`
   relative export path are now traced. The first diagnostic-route inspection
   found no established read-only collection method (Steps 19-21); do not
   enable logging to substitute for one. Link and control/authentication
   integration now pass simulated transport tests while physical access remains unresolved.
   `acp_ver` is not a hardware query. Any new provider must
   validate complete certificates and coordinate bus ownership. iPhone
   acceptance remains a separate test. This is a condition on the software-only
   approach, not a requirement for an added receiver module.
4. Resolve whether the AIR decoder can be used outside AIR, or whether a
   separate decoder is needed. Port the remaining CarPlay session/media
   protocols and trace display ownership and audio focus.
5. Once execution and recovery are established, prove display/input/audio with
   a minimal native diagnostic, then integrate a receiver and test video/audio.

Do not use the research corpus or local test results as a USB installation
procedure. No modified ISO, update USB, or vehicle change has been produced.
