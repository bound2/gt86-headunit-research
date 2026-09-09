# GT86 head unit research

Local, read-only firmware research for a European 2017 facelift Toyota GT86.

Observed from the owner's photos:

| Component | Identifier |
| --- | --- |
| Display/audio device | `13TFDAEU-DA05` |
| Display/audio software | `0101B0` |
| Navigation software | `6.9.0WL` |
| Map release | `2017 v1` |

The display/audio unit and Go navigation module are separate research targets.
Firmware from the same product family is not proof that it can be installed on
this particular unit. This project does not flash hardware or prepare an update
USB. Downloaded firmware is treated as data and is not executed.

**Result:** an official Toyota-hosted **6.17.0WL / WEU-Low** navigation firmware
corpus is available locally, with matching ZIP CRC32 and supplied MD5 checksums.
Analysis identifies QNX 6.5 SP1 components, ARM little-endian executables, Lua 5.1
bytecode and an image-authentication step. This is a later version from the same
navigation family, not a verified flash image for the owner's specific unit.

Read [the findings and remaining unknowns](reports/findings.md).

## Build and verify (Windows)

Uses the installed VS2022 C++ tools and CMake; no third-party build dependencies.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Verify-Firmware.ps1
```

`Build.ps1` normalizes an inherited duplicate `Path`/`PATH` environment entry
that otherwise causes MSBuild to fail in this workspace. It affects only the
script process environment.

## Read-only C++ analyzer

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
