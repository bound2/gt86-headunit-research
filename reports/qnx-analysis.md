# QNX extraction and updater authentication

Research date: 2026-09-09. Target corpus: official Toyota-hosted 6.17.0WL /
WEU-Low navigation firmware, build 2021-01-27. The owner's observed version is
6.9.0WL and the display/audio identifier is 13TFDAEU-DA05. Findings below concern
the downloaded navigation corpus; compatibility with that exact car remains
unconfirmed. See [initial provenance and hashes](findings.md).

## Result

The new host-side C++ tool decompresses all five embedded QNX imagefs files and
extracts their regular files. All five imagefs additive checksums pass. We can
now read the startup scripts, inspect native graphics/audio/input components,
and disassemble the actual ISO verifier.

The normal update-mode boot script has two authentication layers before it
mounts and loads the updater. The second passes embedded metadata to Harman's
security API and separately compares a SHA256 payload hash. We reproduced that
hash comparison on both official ISO files. These results do not establish a
way to execute custom code, install modified firmware, or run CarPlay.

## Reproducible extraction

Run the README build and ISO extraction commands, then:

```powershell
./build/Release/qnxinspect.exe unpack extracted/swdl/usr/share/swdl.bin extracted/qnx-updater-v3
./build/Release/qnxinspect.exe unpack extracted/install/usr/share/IFS/ifs-extbox.bin extracted/qnx-system-v3
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Verify-IsoPayload.ps1
```

Output directories must be new. The inventories describe every nonzero-inode
directory record, including files, symlinks and devices; counts are not counts
of unique executables. The [updater inventory](qnx-updater-inventory.tsv) and
[system inventory](qnx-system-inventory.tsv) retain those results. Raw firmware,
images and disassemblies remain ignored by Git.

| Input | Container offset | Format | Stored container bytes | Imagefs bytes | Directory entries |
| --- | --- | --- | ---: | ---: | ---: |
| swdl.bin | 0x0 | HBCIFS v2 / LZO blocks | 23,580,544 | 50,285,096 | 378 |
| ifs-extbox.bin | 0x8 | QNX startup / LZO blocks | 1,074,136 | 2,256,808 | 47 |
| ifs-extbox.bin | 0x120000 | HBCIFS v2 / LZO blocks | 2,473,969 | 5,452,288 | 79 |
| ifs-extbox.bin | 0x380000 | HBCIFS v2 / LZO blocks | 20,278,177 | 41,753,664 | 587 |
| ifs-extbox.bin | 0x16e0000 | HBCIFS v2 / LZO blocks | 2,495,857 | 5,388,888 | 65 |

The startup header identifies little-endian ARM and LZO compression. Its
compressed stream starts after the declared startup section; the final four
container bytes are excluded. HBCIFS has a 64-byte header with observed version
and compression bytes `02 02 88 00` at offsets 24-27. This Toyota variant uses
two-byte big-endian compressed-block lengths followed by LZO1X data, ending in
a zero-length block. Each block expands to at most 64 KiB.

After decompression, `imagefs` headers and directory records are parsed with
bounds checks. The modulo-2^32 sum of all little-endian words, including the
last checksum word, is zero for each image. This validates the decoded imagefs
content; it does not authenticate the container or prove flash compatibility.

Symlink target offsets are relative to the path field. Symlinks and devices
are recorded without being created. The updater has two conflicting duplicate
paths: `usr/lib/libmmlink.so.1` and `usr/lib/libGLESv1_CM.so.1`. Both versions are
preserved, with alternate output paths in the inventory. We have not determined
which duplicate QNX selects at runtime. Zero-length file records ending in `/`
are retained as inventory markers.

## Update-mode trust checks

The extracted `image-8/bin/bootmode.sh` first examines a FRAM update-mode field.
In the update branch, it locates `swdl.iso` and performs these operations before
mounting the ISO and loading its `usr/share/swdl.bin` through `memifs_j5`:

1. Run `isodigest` for ISO images in the USB root. Extract the first 64 bytes of
   each ISO as a signature and call `openssl dgst -sha256 -verify` against public
   keys under `/etc/keys`. The script expects the success text `Verified OK`.
2. If that check has left authentication successful, run `verifyISO sha256` on
   the selected updater ISO. Failure routes into the script's error/retry path.
3. After authentication, mount the updater ISO and load its embedded IFS, then
   invoke its installation script.

This describes observed script control flow, not an audit of every branch,
recovery path, image-selection edge case or caller. The first check's 64-byte
signature and digest-generation algorithm have not been independently verified.
No cryptographic algorithm is inferred solely from signature size.

### Native verifier trace

`verifyISO` is a sectionless ELF32 little-endian ARM executable with interpreter
`/usr/lib/ldqnx.so.2`. Its executable load segment has virtual address 0x100000
at file offset zero, so subtract 0x100000 to translate the following code
addresses to file offsets. LLVM can disassemble its program segments despite
the absence of section headers. Warnings about absent sections are expected.

| Code address / object | Observed operation |
| --- | --- |
| verifyISO 0x1020fc | Main validates arguments and calls helper at 0x100f18 |
| verifyISO 0x100f9c-0x100fcc | Seek to byte 64, read exactly 288 bytes of ISO metadata |
| verifyISO 0x101f84 | Call `CreateSecurityComponentAPI` with selector 1 |
| verifyISO 0x100fe8-0x101014 | Call virtual method at vtable +0x0c with metadata pointer and length 288; reject false |
| verifyISO 0x101e54 | Call `system` for the constructed `hashFile` command |
| verifyISO 0x101e84-0x101f04 | Read 32 bytes of generated digest and compare against the first 32 metadata bytes |
| verifyISO 0x1020e8 | Initial byte comparison before the remaining-byte loop |
| verifyISO 0x102130-0x102148 | Main returns failure or prints verification success |

Dynamic symbols and relocations resolve the virtual method to
`LibCurlSecurityAPI::verifySoftwareUpdateSignature`. Its vtable starts at
0x92c10, with the object address point eight bytes later; the relevant relocation
is at 0x92c24. The factory at library-relative address 0x10e30 selects the
non-simulator object for selector 1. The method at 0x112d4 calls
`SecurityChip::verifySoftwareUpdateSignature` at 0x16fd0 via PLT 0xec30 and GOT
relocation 0x93114. That method calls `SAM_SecureAuthDec_M2M` via PLT 0xed2c and
GOT relocation 0x93168, then turns the SAM result into success/failure.

The class name and SAM interface are evidence of the verification boundary.
They do not by themselves prove which physical chip is fitted to the owner's
module, the complete signature algorithm, or that every possible code-loading
path is protected. No private signing keys were sought or extracted.

### Embedded payload hash confirmed

Static inspection of `hashFile` shows an OpenSSL EVP digest operation over file
bytes beginning at the supplied offset. Independently hashing both ISO files
from offset 0x8000 to EOF reproduces the 32 bytes stored at offsets 0x40-0x5f:

| ISO | SHA256 of bytes from 0x8000 to EOF |
| --- | --- |
| swdl.iso | `aeb79c7e6ed864516521d3b655aebe6731fe6367728addf1d3ddd8751984da64` |
| swdlInstall.iso | `cd224ed32a2d2f915a0da797f68e9c4154ed28ed46d0f16a5ca6a498e21283b2` |

The 288-byte metadata block therefore starts with the digest and has 256 further
bytes passed to the signature API. Their exact cryptographic encoding remains
unresolved. The local verification script deliberately reports vendor
signatures as `NOT_VERIFIED`; matching an embedded hash is not signature
authentication. Original ZIP CRC32 and MD5 sidecars serve a separate transport
integrity role.

## Interfaces relevant to a native application

These are observations from the downloaded system configuration, not runtime
measurements on the owner's car:

| Area | Evidence | Practical implication |
| --- | --- | --- |
| Graphics | `start_screen.sh` starts QNX `screen`; Jacinto5 `graphics.conf` selects 800x480 at 60 Hz and SGX530rev125 | A native display service and accelerated graphics libraries exist |
| Graphics libraries | `libscreen.so.1`, EGL, GLES and PowerVR libraries | Candidate APIs for a future display proof of concept |
| Touch | `graphics.conf` selects `driver = toyota`, width 800, height 480; `libmtouch-toyota.so.1` is present | Input is integrated through a Toyota-specific driver |
| Audio | `pre-media.sh` launches Jacinto5/DM814x McASP audio drivers and Toyota audio control service | Playback and microphone routing need application/service integration |
| Phone connectivity | `connectivity.sh` references `mirrorLinkSvc` with variant conditions | MirrorLink is present in startup logic; that does not establish CarPlay support |
| Apple accessory hardware | `secondary-boot.sh` labels I2C0 as an iPod authentication-chip connection | Legacy iPod integration exists in the design; CarPlay compatibility is unproven |
| Diagnostic access | `misc.sh` gates inetd on internal `/fs/etfs/ENABLE_TELNET`; inetd configuration contains telnetd | The image contains a conditional diagnostic service, not evidence of an accessible shell |
| Service gateway | `pre-hmi.sh` defaults DBusGateway to `--localonly`; an internal flag changes it | Runtime state and access still need to be established |

A service-menu screen is insufficient to establish any of those internal flags
or an ability to write them. Nothing was connected to or changed on the car.
The installed MSVC compiler builds these Windows analysis tools; a head-unit
application would require a compatible QNX ARM toolchain and ABI. An operational
CarPlay receiver, transport/authentication support and adequate video decoding
have not been demonstrated.

## Evidence identity and validation

SHA256 identifiers for the exact native objects analyzed:

| Object | SHA256 |
| --- | --- |
| verifyISO | `23c5d0f8c64bdd1a31cf0a1a8b8a9ebd922971969d62783c374003be732049bc` |
| hashFile | `42029c5a6caf5b32b5afa1a3ad17af0991cc6ec54e15d5100519532fb2afaf43` |
| libSecurityComponentAPI.so.1 | `3bd817b8c0caa4cce4506c34dd533827acf11fbb6d8893e5208f6b2660b6c91c` |

MSVC Release builds and four CTest suites pass: binary reader, QNX parser,
QNX extraction integration and ZIP reader/extractor. Synthetic tests exercise
LZO roundtrips and failures, malformed directories, checksums, metadata overlap,
traversal, symlink offsets, conflicting duplicates, destination reuse and startup
size overflow. All five real imagefs checksums pass. Both official ISO payload
digests match. An independent Python byte/CRC comparison checked all 938
extracted regular-file records (289 updater, 649 system), including duplicates,
against their raw imagefs slices. The payload verification script accepted a
synthetic valid image and rejected a one-byte payload mutation. No vendor
executable was executed.

## Next bounded investigations

1. Trace the diagnostic/service Lua entry points and their validation rules,
   including whether any supported diagnostic operation exposes runtime state.
   File presence alone is not a code-execution route.
2. Resolve the first `isodigest` authentication layer and the remaining metadata
   fields; examine installation/recovery callers before drawing conclusions
   about the full update trust model.
3. Identify the exact Go module hardware and obtain matching 6.9.0WL firmware or
   a separately planned read-only device capture. This determines whether the
   later corpus's entry points and interfaces apply to this vehicle.
4. Once a legitimate execution route and QNX toolchain are established, start
   with an isolated graphics/input/audio proof of concept before attempting
   phone projection.

## Format references

- [QNX mkifs documentation](https://qnx.com/developers/docs/6.4.0/neutrino/utilities/m/mkifs.html)
  documents image generation and compression options.
- [QNX dumpifs documentation](https://qnx.com/developers/docs/7.1/com.qnx.doc.neutrino.utilities/topic/d/dumpifs.html)
  describes inspecting startup and image filesystem content.
- [Published imagefs field declarations](https://github.com/vocho/openqnx/blob/master/trunk/services/system/public/sys/image.h)
  were used as a field-layout reference. No QNX header source is vendored.
- [HBCIFS research implementation](https://github.com/ReverseEngDotDev/dump_hbcifs)
  helped identify the container family. The observed Toyota block framing
  differs from that implementation's single-block variant.
- [Official LZO source](https://www.oberhumer.com/opensource/lzo/)
  supplies the actual safe LZO1X decoder; see [dependency provenance](../third_party/README.md).

The parser's field interpretation is supported by complete directory traversal,
decompressed-size agreement and checksums across all five images, rather than
assuming the reference format matches Toyota unchanged.
