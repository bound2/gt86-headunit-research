# GT86 head unit research

Local, read-only firmware research for a European 2017 facelift Toyota GT86.

Observed from the owner's photos:

| Component | Identifier |
| --- | --- |
| Display/audio device | `13TFDAEU-DA05` |
| Display/audio software | `0101B0` |
| Navigation software | `6.9.0WL` |
| Map release | `2017 v1` |

The seven originals in `Pictures/headunit` have been inspected; photo-by-photo
evidence and the remaining hardware-identification gaps are recorded in
[CarPlay progress, Step 11](reports/carplay-progress.md#step-11---inspect-the-owners-existing-head-unit-photographs).

The display/audio unit and Go navigation module are separate research targets.
Firmware from the same product family is not proof that it can be installed on
this particular unit. This project does not flash hardware or prepare an update
USB. Selected pinned ARM/Lua inputs are exercised only in bounded host-side
emulation or mocked Lua environments; vendor programs are not run on the car.

**Result:** an official Toyota-hosted **6.17.0WL / WEU-Low** navigation firmware
corpus is available locally, with matching ZIP CRC32 and supplied MD5 checksums.
Analysis identifies QNX 6.5 SP1 components, ARM little-endian executables, Lua 5.1
bytecode and an image-authentication step. This is a later version from the same
navigation family, not a verified flash image for the owner's specific unit.

The second pass decompresses all five embedded QNX image files, validates their
imagefs checksums and traces two updater authentication layers. The embedded
SHA256 digest matches both official ISO payloads. Custom-code execution on the
physical unit and CarPlay support have not been demonstrated.

Read [the initial findings](reports/findings.md) and
[the QNX extraction and authentication analysis](reports/qnx-analysis.md).
Continue with the [step-by-step CarPlay progress record](reports/carplay-progress.md)
for the current findings, mock test outcomes and remaining requirements.

## Build and verify (Windows)

Uses the installed VS2022 C++ tools and CMake. miniLZO 2.10 is vendored for QNX
decompression; see [dependency provenance and license](third_party/README.md).

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Verify-Firmware.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Verify-IsoPayload.ps1
```

`Build.ps1` normalizes an inherited duplicate `Path`/`PATH` environment entry
that otherwise causes MSBuild to fail in this workspace. It affects only the
script process environment.

## Mocked Lua update-path checks

The CarPlay investigation adds 13 host-only checks covering complete stock
manifests, resident dispatch and update-mode authentication. First extract the
corpus as documented below and unpack `extracted/qnx-system-v3`. The harness
requires Python 3 and a **Win32 Lua 5.1.5** host, matching the vendor chunk's
32-bit `size_t` layout. No Python packages are needed for this harness.

The local source archive `downloads/lua-5.1.5.tar.gz` comes from the
[official Lua download area](https://www.lua.org/ftp/), whose published SHA256 is
`2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333`.
For a fresh checkout, obtain that archive, verify its SHA256 with `Get-FileHash`,
and extract it into a fresh `build/lua-source` directory. The existing local
source is `build/lua-source/lua-5.1.5/src`. Build from the project root:

```powershell
$headunitLuaBuildPath = $env:Path
Remove-Item Env:PATH
$env:Path = $headunitLuaBuildPath
cmake -S scripts/lua-host -B build/lua-host -G 'Visual Studio 17 2022' -A Win32 "-DLUA_SOURCE_DIR=$PWD/build/lua-source/lua-5.1.5/src"
cmake --build build/lua-host --config Release
python scripts/probe_update_path.py
```

The driver verifies five vendor input hashes before loading them. Guest file,
shell and service operations are intercepted; native installers and hardware
are not executed. The result is not full-system emulation or flash readiness.
Use `--output extracted/carplay-update-path.json` to save a new evidence file;
existing files are refused. These corpus-dependent checks are run separately
from the synthetic CTest suites.

For bytecode listings use `luac.exe -l -p FILE`: `-p` prevents the compiler from
creating its default `luac.out` output file.

## Native CarPlay protocol components (in development)

The selected approach is software only on the factory head unit. The new
`carplay_protocol` C99 library implements iAP2 link framing/checksums, streaming
frame reassembly, control-message encoding/decoding, a bounded CarPlay startup
message subset, and accessory authentication sequencing through a caller-supplied
certificate/challenge provider. The new
transport pump invokes explicit backend callbacks; no built-in device I/O,
authentication keys or fallback signer is supplied.

`scripts/Build.ps1` builds this library and runs `iap2_tests`, `iap2_link_tests`,
`iap2_control_tests`, `iap2_identification_tests`, `iap2_transport_tests` and
`iap2_carplay_tests`, `usbmux_tests`, `usbmux_host_tests` and
`usbmux_connection_tests` and `usbmux_dispatcher_tests` alongside the four
existing suites. The tests use 33 committed
LIVI message vectors and golden
link frames; they also cover fragmentation, corrupt packets, length bounds and
authentication failures. Provenance and GPL-3.0-or-later licensing are recorded
in [third_party/README.md](third_party/README.md).

An optional portability check uses the installed LLVM compiler:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
```

It produces `build/carplay-arm/carplay_protocol.o`, a 32-bit ARM relocatable
object with no unresolved symbols. This checks portable code generation, not
QNX executable linking or compatibility with the car. The receiver still needs
USB/Bluetooth transport, broader link-profile interoperability, the actual Apple
authentication provider, CarPlay session/media protocols, and QNX display/audio
integration. There is no installable CarPlay package yet.

### Experimental reliable-link layer

`src/carplay/iap2_link.h` documents the new C99, allocation-free engine. It
handles marker detection, bounded SYN/ACK negotiation, send windows, cumulative
ACKs, delayed/piggyback ACKs, retransmission, duplicate suppression, reordered
input and teardown. Time and transport remain caller supplied. The API exposes
explicit queue/output backpressure; it does not execute callbacks or perform I/O.

Defaults are a four-packet window, 1024-byte frames, eight fixed TX/RX slots
each, and control session 10/version 1. Peer parameters must fit the offer;
EAK, zero-ACK profiles and forced negotiation without marker exchange are not
implemented. Other session IDs require explicit offers and application handlers.
The control-session adapter below now connects this engine to authentication;
actual device transport and a real provider remain separate work. See
[CarPlay progress, Steps 22-24](reports/carplay-progress.md#step-22---implement-a-bounded-iap2-reliable-link-profile).

Fourteen CTest suites pass, including 16 link test groups and a simulated two-endpoint
exchange with deliberate packet/ACK loss. Optional host memory/undefined-behavior
checks use the installed LLVM and Visual Studio toolchain:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
```

This builds/runs the ten protocol test executables with AddressSanitizer and
UndefinedBehaviorSanitizer under `build/carplay-sanitized`. No research firmware
or car access is required. The ARM portability check now covers all twelve C99
translation units; it still produces no QNX executable.

### Bounded control-session/authentication adapter

`src/carplay/iap2_control.h` documents the endpoint that owns both link and
authentication state. It reassembles split control messages, preserves coalesced
messages and fragments authentication replies to the negotiated frame size.
Caller-owned receive/reply/provider buffers have explicit limits; there is no
heap allocation. Only `poll` invokes the caller's synchronous provider. Pending
replies survive queue pressure without repeating certificate/signature requests.

The experimental profile offers one control session, serializes subsequent
messages behind a fully acknowledged reply, and closes on malformed messages,
authentication failures or local deadlines. Disconnect/reinitialization resets
authentication, identification results and partial messages together. Messages
not handled by enabled sequencers are held for explicit application handling;
`iap2_control_reply` now copies a bounded response and releases the request
atomically. Reserved authentication/identification replies cannot be injected
through this API. See
[CarPlay progress, Steps 25-27](reports/carplay-progress.md#step-25---connect-control-messages-to-the-authentication-sequencer).

Thirty-eight control test groups cover buffer limits, backpressure, teardown, deadlines
and exchanges between two library endpoints with byte-fragmented transport
and deliberate packet loss. Provider results are synthetic patterns, not real
credentials. These are local stream/serialization choices, not an Apple
conformance result, an iPhone test or proof of CarPlay compatibility.

### Opt-in accessory identification

`iap2_identification.h` defines a minimal identity encoder and a strict
Start/Information/Accepted-or-Rejected sequencer. Enable it through
`iap2_control_enable_identification` before starting the endpoint, using explicit
caller-supplied identity, language and power metadata. Identification is disabled
after every new endpoint initialization; no real identity is guessed. The
default profile requires authentication first. Set `config.startup_order` to
`IAP2_CONTROL_IDENTIFICATION_FIRST` to use the pinned runtime's order instead;
this mode requires enabled metadata before start and defers authentication
callbacks until identification acceptance. Both phases have independent total
budgets, ACK barriers and reset behavior. See the new
[startup-order report](reports/startup-order.md) for integration checks and limits.

The minimal encoder deliberately omits USB/Bluetooth/vehicle components, application
protocols and CarPlay flags. Its fixed message lists contain only implemented
authentication/identification IDs. This incomplete profile is for PC integration
tests, not a claim of phone acceptance. Identifying the accessory to a phone
does **not** read the existing Apple authentication chip's identity.

Eleven dedicated test groups compare common fields and accepted/rejected messages
with the pinned vectors, enforce metadata/size limits, and check sequencing.
The extended endpoint simulation verifies a fragmented identification response
despite packet loss, followed by a synthetic application roundtrip. See
[CarPlay progress, Steps 28-30](reports/carplay-progress.md#step-28---add-an-atomic-application-reply-path).
The subsequent [payload audit](reports/identification-wire-audit.md) corrects
multi-language encoding to one packed field, adds independent byte regressions
and reduces the minimal encoder's maximum message size to 930 bytes.

`iap2_control_enable_wired_identification` explicitly opts into a separate wired
subset: caller-supplied USB-host component ID/name/interface, advanced-power
capability and implemented CarPlay/power message IDs. Its USB-host field matches
the pinned fixture exactly. Large combinations are rejected within the same
1024-byte storage limit. Typed wired-start/power helpers now require this accepted
profile; minimal identification cannot authorize them. See
[the wired-identification report](reports/wired-identification.md).

### Bounded byte-stream transport pump

`iap2_transport.h` connects a caller-supplied nonblocking backend to the control
endpoint. It retains one complete pending frame, accounts for partial writes
and receive tails, and bounds work/backpressure/deadlines. Connection generations
reject stale results after reconnect; cancellation clears transport and endpoint
state. It has no USB descriptors, HID framing, device paths or built-in OS calls.

Seventeen test groups exercise a fake backend, including complete synthetic
exchanges in both startup orders over fragmented reads/writes. All fourteen CTest suites and
ten sanitized protocol suites pass. Details and callback lifetime requirements
are in the
[step-by-step transport adapter report](reports/transport-adapter.md) and
[CarPlay progress, Steps 34-36](reports/carplay-progress.md#step-34---implement-the-bounded-byte-stream-pump).
Actual QNX USB transport, installed-version compatibility and real credentials
remain unresolved; this is not a usable car-side receiver yet.

### CarPlay startup message subset

`iap2_carplay.h` adds strict, allocation-free codecs for transport identifiers,
wireless availability, CarPlay availability and wired StartSession. Four pinned
fixtures round-trip exactly; a wireless StartSession is explicitly unsupported.
Nine codec test groups cover nested fields, packed address lists, malformed
input, borrowed views and transactional output bounds.

Three additional power-codec groups bring that suite to 12, with an exact pinned
PowerSourceUpdate roundtrip. `iap2_control_notify` adds explicit unsolicited
output without consuming held input. The typed power helper requires accepted
explicit wired identification/authentication and caller-supplied power policy; it supplies no
current-rating default and changes no hardware charging state. See
[the power-notification report](reports/power-notifications.md).

An explicit application helper can queue a wired-start reply only after both
authentication and explicit wired-identification acceptance and a valid wired-available offer.
It requires caller-supplied receiver addresses, port and identity/key metadata.
Three integration groups verify gating, fragmentation, ownership and lifecycle.
Nothing automatically advertises CarPlay, opens a socket, pairs a phone or starts
media. The minimal identification message lists still omit these new messages
and transport capabilities; the separate wired profile declares them only when
explicitly enabled. The fragmented transport test now completes power and wired
StartSession after reference-order startup, but a real phone exchange is not established.

The pinned wired reference uses USBmux, trust pairing, the carkit service and a
separate USB network path, not the traced stock iPod HID path. Its startup order
is now supported as an explicit opt-in endpoint profile. See the
[step-by-step session-start report](reports/carplay-session-start.md) and
[CarPlay progress, Steps 37-39](reports/carplay-progress.md#step-37---publish-the-checkpoint-and-trace-wired-session-startup).

### Bounded USBmux packet layer

`usbmux_wire.h` adds allocation-free raw USBmux version/setup/control/TCP packet
codecs and one-frame streaming assembly with caller-owned storage. It preserves
both sequence slots and peer magic, bounds frames to 65,536 bytes, rejects TCP
options and latches malformed stream prefixes until reset. Ten new test groups
cover seven independent synthetic vectors, every fixture split, coalesced input,
short-output canaries and maximum-size frames.

`usbmux_host.h` now negotiates version 2/setup with physical-write completion
barriers, separate caller-owned RX/TX storage and one held received packet.
Explicit sequence profiles reproduce either reference convention. Fifteen host
test groups cover partial/coalesced transfers, backpressure, hard deadlines,
stale generations, every sequence slot and maximum-size packets. Host state is
200 bytes plus the two caller buffers; no backend is invoked.

The host API is packet-only, not a USB backend or phone-pairing implementation.
The separate connection engine below adds bounded TCP-style streams. The
USBmux files select GPL-3.0-only after cross-checking LIVI against pinned
usbmuxd source; existing iAP2 files retain GPL-3.0-or-later. See the
[step-by-step USBmux report](reports/usbmux-transport.md) and
[reference provenance](third_party/README.md).

### Bounded TCP-style connections over USBmux

`usbmux_connection.h` opens an explicitly routed port pair, validates SYN/ACK
and cumulative acknowledgement ranges, bounds peer-window use and tracks eight
unacknowledged data flights. A caller-owned receive ring handles duplicate and
overlapping input, advertises bounded credit and retains unread bytes through
peer half-close. Graceful FIN/ACK closure, stale-event rejection and independent
opening/write/ACK/read/close budgets are implemented without I/O or allocation.

Fifteen test groups include a complete synthetic request/response through the
packet host using three-byte reads and five-byte writes. Connection state is
360 host bytes plus separate RX/TX storage. This is not a general IP TCP stack:
no retransmission/congestion control or TIME-WAIT is supplied. The dispatcher
below now allocates fresh ports and coordinates multiple streams. A real USBmux backend, phone
pairing/TLS, carkit service and media path still need integration. See the
[step-by-step connection report](reports/usbmux-connection.md).

### Runtime USBmux dispatcher and stream API

`usbmux_dispatcher.h` connects one packet host and up to four TCP connections
to explicit nonblocking raw read/write/cancel callbacks. It routes both ports,
retains coalesced input and schedules complete packets round-robin. TCP completion
is credited only after the containing physical mux packet completes. Fresh local
ports and generation-tagged stream handles prevent stale requests from reaching
reused slots. Read/write/finish APIs expose bounded byte streams.

Thirteen dispatcher groups cover four concurrent streams, three-byte reads and
five-byte writes, held control events, stale callbacks/handles, exact shared
deadlines, cancellation and maximum-sized packets. Dispatcher storage is 1,240
host bytes, including a 1,024-byte scratch buffer; host/connection objects and
their buffers are additional. No native USB implementation, phone trust/TLS,
carkit service or media receiver is provided. See the
[step-by-step dispatcher report](reports/usbmux-dispatcher.md).

## Read-only firmware analysis

### Apple authentication-driver analysis

The two pinned Apple-authentication modules can now be inspected and exercised
with synthetic I2C responses on the PC. The native ARM checks cover identity,
certificate paging and signature transfers; they do not access the car or
authenticate an iPhone. Findings and limits are recorded in
[CarPlay progress, Steps 13-15](reports/carplay-progress.md#step-13---separate-plugin-metadata-from-the-actual-chip-identity).

```powershell
python -B scripts/inspect_ipod_auth.py
python -B scripts/inspect_ipod_auth.py --module ipod --disassemble
python -B scripts/probe_ipod_auth.py
python -B -m unittest discover -s tests -p test_ipod_auth_tools.py -v
```

These corpus-dependent tools require the extracted research inputs. The probe
uses the existing Unicorn 2.1.4 installation in `build/python-libs`; disassembly
uses LLVM, whose location can be supplied with `--llvm`. Optional `--output`
paths must be new files. No vendor binaries or device identities are bundled
in the tools. The fixed `acp_ver` plugin entry is **not** a chip-version reading.

### Cached media-information export

The later corpus connects the iPod driver's cached `authcoproc` description to
`<actual iPod mountpoint>/.FS_info./info.xml`. This is a derived filesystem path,
not a confirmed route into the owner's installed firmware. The mountpoint,
physical chip identity and an accessible read/export mechanism remain unknown.
See [CarPlay progress, Steps 16-18](reports/carplay-progress.md#step-16---connect-cached-chip-details-to-the-media-information-file).

```powershell
python -B scripts/inspect_ipod_auth.py --module media --disassemble
python -B scripts/probe_media_info.py
python -B -m unittest discover -s tests -p test_ipod_auth_tools.py -v
```

The new probe runs 19 bounded ARM checks with synthetic state, including a
mount-description **slice**, a separate actual iPod description callback,
directory/node handling and cached reads. It does not start QNX's resource
manager, mount a device, serialize a full real XML document, or contact the car.
Eight tool-safety tests now cover all three pinned binaries and the new probe.
The same Unicorn dependency and create-new-only `--output` rules apply.

### Diagnostic/export route investigation

The inspected snapshot, crash-dump, Insight logging and Apple connection-script
paths do not establish a read-only export of the chip information to the PC.
The logging configuration includes uploads, so enabling it is not an identity-
only operation. Findings and the correction about the separate USB logging
trigger are in [CarPlay progress, Steps 19-21](reports/carplay-progress.md#step-19---inspect-existing-diagnostics-without-activating-them).

```powershell
python -B scripts/probe_diagnostic_routes.py
python -B -m unittest discover -s tests -p test_diagnostic_routes.py -v
```

The probe verifies 11 extracted inputs plus the installation ISO. It models
10 MCD decision paths and replays seven stock Lua scenarios with all guest I/O,
services, parsers and timing mocked. Five regression/safety tests pass. It uses
the existing Win32 Lua host and `C:/Windows/System32/tar.exe` to read one pinned
ISO member into memory; no vendor shell script runs and no trigger file is
created. Optional `--output` must name a new file.

### Stock USB transport investigation

The later corpus configures QNX USB host ownership, an iPod HID data path and
separate audio capture. Seventeen bounded native scenarios now reproduce stock
report framing, partial transfers, stalls and disconnect behavior using mocked
USB only. Six new tool tests bring the Python suite to 19 passing tests.

```powershell
python -B scripts/inspect_ipod_auth.py --module usb
python -B scripts/probe_usb_transport.py
python -B -m unittest discover -s tests -p test_usb_transport_tools.py -v
```

The probe verifies 12 inputs and refuses modified files or existing output
targets. It neither opens USB nor runs attachment/initialization code. Findings,
source references and the next portable-adapter contract are in the new
[step-by-step USB transport report](reports/usb-transport.md) and
[CarPlay progress, Steps 31-33](reports/carplay-progress.md#step-31---pin-and-trace-stock-usb-ownership).
This does not establish an iAP2 USB backend, installed-version compatibility or
physical port ownership on the car. No installable CarPlay update exists yet.

### C++ binary analyzer

```powershell
./build/Release/fwinspect.exe info extracted/swdl/usr/bin/usbSquelch
./build/Release/fwinspect.exe strings extracted/swdl/usr/bin/usbSquelch QNX ldqnx
./build/Release/fwinspect.exe info extracted/swdl/usr/share/scripts/update/authISO.lua
./build/Release/fwinspect.exe strings extracted/swdl/usr/share/scripts/update/authISO.lua
./build/Release/fwinspect.exe crc downloads/6.17.0L/swdl.iso 542f3f5e
```

`fwinspect` identifies ELF/Lua/ISO headers, calculates CRC32, and emits printable
ASCII strings with hexadecimal file offsets. It never executes input files. Input
files are limited to 1 GiB. Strings are clues, not a substitute for disassembly.

Tests cover a standard CRC32 vector, empty input, ARM endianness, invalid/truncated
ELF headers, Lua version recognition and strings ending at EOF. ZIP tests cover a
roundtrip through an independent ZIP encoder, offsets above 4 GiB and rejection
of incomplete directory data.

## QNX unpacker

After extracting the ISOs below, use fresh output directories:

```powershell
./build/Release/qnxinspect.exe unpack extracted/swdl/usr/share/swdl.bin extracted/qnx-updater-v3
./build/Release/qnxinspect.exe unpack extracted/install/usr/share/IFS/ifs-extbox.bin extracted/qnx-system-v3
```

`qnxinspect` handles the observed little-endian ARM startup/LZO container and
Toyota's HBCIFS v2 block-compressed variant. It checks decompressed lengths,
32-bit imagefs checksums, directory bounds and regular-file paths. It emits raw
imagefs files, regular files and an inventory with CRC32 and extraction paths.
It records symlinks and devices without creating them. Conflicting duplicate
filenames are retained under `duplicates/`; this does not emulate QNX lookup
precedence. Empty file records ending in `/` remain inventory-only markers.
Existing output roots are rejected. A filesystem/write error can leave partial
output; only a zero exit status indicates a complete extraction.

QNX tests cover synthetic containers, multi-block LZO roundtrips, corrupt and
truncated data, metadata overlap, path traversal, symlink bounds, duplicate-file
preservation and refusing an existing destination. The payload hash script
reproduces the observed SHA256 comparison; it does **not** validate signatures.

## Download and extraction

Original firmware remains outside Git in `downloads/`. To fetch the pinned
corpus into a fresh project copy after building:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Fetch-Corpus.ps1
```

This fetches only ZIP ranges containing the directory, firmware and package log
(about 189.4 MB instead of the 5.2 GB full map archive). An existing complete
corpus is verified without downloading it again. The extraction script uses an
explicit filename allowlist, bounded decompression and create-new output files.

To extract the relevant ISO directories for static inspection:

```powershell
New-Item -ItemType Directory -Path extracted/swdl,extracted/install -Force
tar.exe -xf downloads/6.17.0L/swdl.iso -C extracted/swdl etc usr/share/scripts usr/share/swdl.bin usr/bin usr/lib lib armle
tar.exe -xf downloads/6.17.0L/swdlInstall.iso -C extracted/install etc usr/share/scripts usr/share/IFS usr/share/MMC_PROG_DATA/bin usr/share/MMC_PROG_DATA/usr/lib
```

Only operate on the pinned, checksum-verified corpus when using these extraction
commands. The scripts and analyzer are research tooling, not a general archive
security audit or a firmware flasher. Raw firmware, extracted vendor files and
build outputs are ignored by Git. `origin` points to
[bound2/gt86-headunit-research](https://github.com/bound2/gt86-headunit-research),
and `master` tracks `origin/master`.
