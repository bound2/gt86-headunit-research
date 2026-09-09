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

The Apple-authentication path is now traced through both stock ARM modules:
17 synthetic-bus checks pass, including cached identity reporting, certificate
paging and challenge/signature transfers. `acp_ver` proved to be a fixed plugin
entry, not a chip-version reading; see Steps 13-15. The cached-description path
is now connected to `<actual iPod mountpoint>/.FS_info./info.xml` in the later
corpus, with 19 additional native media-information checks and eight tool-safety
tests passing. This is a filesystem export, not an established means of reaching
the unit. The actual mountpoint, real chip identity, installed-version behavior
and iPhone acceptance remain unknown; see Steps 16-18.

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
   and usable interface. The register operations and cached `authcoproc`
   relative export path are now traced; next investigate an existing read-only
   diagnostic/export route for the actual unit (Step 18). `acp_ver` is not a
   hardware query. Any new provider must
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
