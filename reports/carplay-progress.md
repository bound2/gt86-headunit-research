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
sequencing, validated against 33 upstream vectors. All five CTest suites pass.
The components also compile to 32-bit ARM objects. All 13 earlier host-side
manifest/dispatch/authentication checks pass. They confirm additional weaknesses
in resident update control flow, with explicit mock assumptions. Adobe AIR also
contains H.264 decoder class references worth investigating. Neither result
establishes a working CarPlay receiver or a demonstrated recovery method. All
work below is on the local PC.

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

`acp_ver` is a useful candidate for a runtime metadata query through the
existing media stack. It is not a recovered chip-version value, and the query
path and field semantics are not yet established. The module's own
`VERSION=20.26.53` is a software build identifier, not the Apple chip generation.
Its exported `iofs_module` object is a plugin interface, not an established
standalone certificate/signing API. These clues do not yet justify a new
program taking ownership of `/dev/i2c0` alongside the stock iPod service.

Reproduce the string inspection without executing the vendor library:

```powershell
./build/Release/fwinspect.exe strings extracted/qnx-system-v3/image-380000/lib/dll/iofs-i2c-ipod.so
```

## Next checks

1. Obtain read-only identification of the actual Go module and establish a
   recovery route before preparing anything intended to execute on the car.
   The missing facts are its model/part number and hardware revision; the
   installed navigation version is already confirmed by the existing photos.
   An already accessible module label or ordinary read-only identification is
   suitable evidence; do not change service-menu flags to obtain it.
2. Match the installed 6.9.0WL loader against the later corpus. The checks above
   cannot establish that both versions contain the same defects.
3. Connect the portable iAP2 components to a reliable link engine and actual
   QNX USB transport. Establish the existing Apple authentication chip's identity
   and usable interface, first tracing the stock driver's `acp_ver` metadata
   route. Neither Bluetooth music nor iPod USB playback proves its suitability
   for CarPlay. This remains a condition on the software-only approach, not a
   requirement for an added receiver module.
4. Resolve whether the AIR decoder can be used outside AIR, or whether a
   separate decoder is needed. Port the remaining CarPlay session/media
   protocols and trace display ownership and audio focus.
5. Once execution and recovery are established, prove display/input/audio with
   a minimal native diagnostic, then integrate a receiver and test video/audio.

Do not use the research corpus or local test results as a USB installation
procedure. No modified ISO, update USB, or vehicle change has been produced.
