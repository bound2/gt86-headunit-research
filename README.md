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
frame reassembly, control-message encoding/decoding, and accessory authentication
sequencing through a caller-supplied certificate/challenge provider. It performs
no I/O and contains no authentication keys or fallback signer.

`scripts/Build.ps1` builds this library and runs `iap2_tests` and
`iap2_link_tests` alongside the four existing suites. The tests use 33 committed
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
Session-message fragmentation/reassembly and real authentication integration
are still separate work. See [CarPlay progress, Steps 22-24](reports/carplay-progress.md#step-22---implement-a-bounded-iap2-reliable-link-profile).

Six CTest suites pass, including 16 link test groups and a simulated two-endpoint
exchange with deliberate packet/ACK loss. Optional host memory/undefined-behavior
checks use the installed LLVM and Visual Studio toolchain:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
```

This builds/runs the two protocol test executables with AddressSanitizer and
UndefinedBehaviorSanitizer under `build/carplay-sanitized`. No research firmware
or car access is required. The ARM portability check now covers all three C99
translation units; it still produces no QNX executable.

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
security audit or a firmware flasher. Raw firmware and extracted vendor files
are ignored by Git; no remote is configured.
