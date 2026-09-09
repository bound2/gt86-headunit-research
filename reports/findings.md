# Initial firmware analysis — 2026-09-09

A meaningful navigation-module firmware corpus has been downloaded and inspected.
It is **6.17.0WL / WEU-Low**, not a dump of the owner's installed **6.9.0WL**.
No installable CarPlay modification has been produced.

## Source and relevance

Source ZIP: [Toyota's 6.17.0L EU package](https://mapupdatecontent.toyota-europe.com/Updates/Toyota/6.17.0L_EU/6.17.0L_EU.zip).
Retrieved over HTTPS from Toyota's Amazon S3/CloudFront download service on
2026-09-09. Total ZIP size: **5,224,629,268 bytes**. Last-Modified:
2021-03-01 16:14:08 GMT. ETag: `64b586543c14628c33e6c3892f9e07f9-499`.
This multipart ETag is not treated as a whole-file MD5.

Toyota's [Touch 2 with Go dealer guide](https://mapupdatecontent.toyota-europe.com/Documents/Dealer%20Guide/MapUpdate_16MM_DealerGuide_English.pdf)
documents `swdl.iso` and `swdlInstall.iso` as the firmware images accompanying
navigation updates for this family. The ZIP was found through a public reference
to that Toyota-hosted URL; compatibility conclusions below rely on Toyota's guide
and the package's own metadata, not forum installation advice.

The owner's photographs identify Touch 2 with Go, navigation **6.9.0WL**, audio
**0101B0**, audio device **13TFDAEU-DA05**, maps **2017 v1**. This makes the
WEU-Low navigation firmware a relevant research sample. The audio device ID is
not the navigation module's hardware part number. **Compatibility for flashing
this particular car has not been established.** No matching DA05 audio `.kwi`
package or exact original 6.9.0WL archive was verified in this pass.

## Retrieved files and integrity

Only approximately **189.4 MB** of ZIP ranges were needed; map data was omitted.
The complete ZIP64 central directory contains **967 records**. Its 64-bit offsets,
entry count, and boundaries were checked. Each extracted file passed ZIP CRC32
and size verification. Both ISOs match their supplied MD5 sidecars. SHA256 hashes
recorded locally identify the exact corpus; these are not vendor signatures.

| File | Bytes | CRC32 |
| --- | ---: | --- |
| `swdl.iso` | 40,312,832 | `542f3f5e` |
| `swdlInstall.iso` | 231,057,408 | `25fe3a96` |
| `swdl.iso.md5` | 124 | `d24c7ee9` |
| `swdlInstall.iso.md5` | 131 | `e9827142` |
| `KaliSWDL.log` | 234,393 | `d278d3d0` |

See [integrity results](firmware-integrity.json), [SHA256 inventory](6.17.0L-sha256.json)
and [ZIP directory](6.17.0L-zip-directory.json). HTTP response headers and original
images are preserved under `downloads/`, excluded from Git.

## Direct observations

The C++ analyzer's concrete output is saved in
[platform-evidence.txt](platform-evidence.txt).

| Finding | Evidence in the extracted corpus | Interpretation / limit |
| --- | --- | --- |
| `6.17.0WL`, `WEU-Low`, built 2021-01-27 | `extracted/install/etc/version.txt`, first seven lines; install manifest constants | This is the actual firmware version, not just the ZIP filename. |
| QNX 6.5 SP1 components | `version.txt` entries `QNX650`, `QNX650SP1`, `QNX MME`; QNX dynamic loader in an executable | Confirms the OS family of this corpus. It does not independently prove the exact installed kernel build in the car. |
| 32-bit, little-endian ARM | `usbSquelch` and `libkalman.so.1` ELF headers: class 1, data 1, machine 40 | Host MSVC binaries cannot run directly on this target. |
| QNX executable loader | `usbSquelch` string `/usr/lib/ldqnx.so.2` at offset `0xf4` | ELF OSABI 0 must not be misidentified as Linux. |
| DM814x / Jacinto5 platform clues | `usr/share/IFS/nand-ipl-dm814x-teb.bin`, `startup-dm814x-teb` string in IFS, `usr/lib/graphics/jacinto5` | Strong evidence of the firmware's intended TI platform; exact silicon/RAM in the owner's module remains unverified. |
| Lua 5.1 bytecode | `authISO.lua` header `1b 4c 75 61 51 00 01 04 04 04 08 00` | Many `.lua` files are compiled bytecode, not plaintext scripts. No bytecode was executed. |
| Firmware update authentication | `authISO.lua` contains `verifyISO sha256 ` at `0x695`, authentication status/error strings | There is an authentication step. String inspection does **not** establish its cryptographic implementation or a bypass. |
| System and persistent payloads | Install manifest refers to IFS, IPL, MMC program data and ETFS; actual payloads are present | This is substantial system firmware, not merely navigation maps. |

The installer manifest is bytecode. Its string constants are recorded in
[install-manifest-strings.txt](install-manifest-strings.txt); they are not a
decompilation or proof of control flow. The same caveat applies to
[authISO-strings.txt](authISO-strings.txt).

A filename/package-inventory search for `carplay`, `iap2`, `airplay`, `mfi` and
`h264` found no matches. This limited negative result does not prove that no
related code or hardware capability exists inside compressed images or binaries.

## Implications for native CarPlay

We now have a concrete target for further analysis: a Harman-associated QNX/ARM
navigation software stack with an updater, system images and compiled scripts.
This is enough to investigate the boot process and loading rules locally.

It does not yet provide a way to run custom code on the owner's unit. A future
native program would need a compatible QNX ARM toolchain/ABI, access to the
display/audio/input interfaces, and a working CarPlay receiver implementation.
The installed Windows C++ tools successfully build our **host-side analyzer**;
that is separate from compiling programs for the head unit.

## Next useful work

1. Parse/decompress the QNX IFS images and locate the actual `verifyISO` executable,
   runtime services and startup configuration. Its implementation has not yet been
   extracted or analyzed; raw strings in compressed images are unreliable evidence.
2. Statically inspect the updater's authentication and file-loading flow. Merely
   recalculating the public MD5 sidecars is not a demonstrated installation route.
3. Obtain the navigation module's hardware identity and, ideally, the exact 6.9.0WL
   corpus before claiming applicability to the car. Diagnostic identification can
   help; a device dump would need a separately planned recovery-aware procedure.

No head-unit connection, firmware flash, map activation, or vehicle setting change
was performed. No public repository or external message was created.

## Tool validation

VS2022/MSVC 19.44 built the C++20 analyzer successfully. Both CTest suites passed:
binary-reader checks and ZIP extraction/ZIP64 regression checks. All five corpus
files passed the separate integrity script. The corpus fetcher's existing-file
verification path was exercised; the live download/extraction steps were carried
out individually during research. A one-byte-short initial firmware range was
repaired by fetching the final checksum entry separately. The reusable fetcher
contains the corrected inclusive range end (`5224501483`).
