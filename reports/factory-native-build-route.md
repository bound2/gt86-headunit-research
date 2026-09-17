# Factory runtime packages and native build route

Date: 2026-09-17. Step 100, following [network identity](factory-network-identity.md).
Starting checkpoint: `2c615696ab166f208ae8a80110ee25a805ae7483`.

The seven previously uninspected ZIPs do not reveal a native IPv6 stack or SDK.
A newly located public ARMv7 toolchain repository does contain an IPv6 stack,
but its 2010 binary is missing **two exports required by the factory NCM driver**.
It is not an established drop-in replacement for the later factory stack.

This step supplies reproducible archive and ELF comparison tools, not a native
CarPlay executable. The factory inputs are still the later **6.17.0WL** corpus,
not the owner's installed **6.9.0WL**. No vendor executable, installer, container,
USB operation, network reconfiguration or vehicle update was run.

## 1. Finish the named nested-archive audit

`scripts/inspect_packaged_runtime.py` first checks the existing installation ISO:

- Path: `downloads/6.17.0L/swdlInstall.iso`.
- SHA-256: `06bdc5c05b889ae68bd372dd060502226ea911fc0715a646072c59b1832bf30d`.
- Outer directory: 842 entries, with the same seven named ZIPs as Step 97.

It reads each ZIP into memory using host `tar`, checks its exact size and SHA-256,
then reads every member to EOF with ZIP CRC validation. Nothing is extracted.
Each ZIP's digest and deterministic full-member inventory digest are in the
script/output; vendor asset bytes are not committed.

Paths below are relative to the ISO; abbreviated paths share
`usr/share/MMC_PROG_DATA/`:

| ZIP | Entries / files | Expanded bytes |
| --- | --- | --- |
| `usr/bin/nav/NNG_SyncTool/content/global_cfg/global_cfg.zip` | 3,131 / 3,101 | 14,997,056 |
| `.../bin/nav/content/global_cfg/global_cfg.zip` | 3,131 / 3,101 | 14,997,056 |
| `.../nav/NNG/data.zip` | 2,117 / 2,076 | 32,802,824 |
| `.../nav/NNG/skin/skin_opennav_toyota_cy13_eu_blue_high.zip` | 69 / 60 | 2,986,338 |
| `.../nav/NNG/skin/skin_opennav_toyota_cy13_eu_blue.zip` | 69 / 60 | 3,110,978 |
| `.../nav/NNG/ux/junctionview.zip` | 56 / 39 | 86,489 |
| `.../nav/NNG/ux/opennav_toyota.zip` | 140 / 114 | 790,584 |

Total: **8,713 entries, 8,551 files, 69,771,325 expanded bytes**. The two
`global_cfg.zip` copies are byte-identical; totals count both locations.
Contents are predominantly navigation imagery, configuration, scripts and shaders.

No member contains ELF magic, and the selected network/SDK name and runtime-marker
searches have no hits. No further common archive signature/suffix is found.
The one executable-signature hit is `data.zip!shaders/building/converter.exe`:
892,928 bytes, PE machine `0x14c` (x86), SHA-256
`14197db035cb96f70be5504f2bea729b0a7ee7e8f2dbe9dadc97ecf92f9b4237`.
It is not an ARM/QNX executable and was not run.

Limits are explicit: this is a complete ZIP-member read plus selected signature/
marker inspection, not decoding every custom navigation format. Opaque `.blz`,
`.xpd`, `.nng`, `.bin` and other assets are not recursively interpreted. Absence
of signatures is not a proof of global unavailability or installed-unit contents.
The earlier outer-file audit is not silently upgraded into a whole-package audit.

Before decompression, the inspector rejects duplicate/noncanonical paths,
encrypted entries, nonregular types, unsupported compression and excessive sizes.
Limits are 64 MiB compressed per ZIP, 10,000 entries, 8 MiB per expanded member,
and 128 MiB expanded per ZIP. Further archive candidates are reported, not
silently treated as covered. This is scoped research tooling, not a general
hostile-archive security certification.

## 2. Establish the native ABI family from the files

`scripts/inspect_qnx_runtime_candidate.py` checks four factory hashes before
parsing bounded ELF program headers, dynamic metadata and SysV symbol tables.
All four are ELF32 little-endian ARM, with flags `0x05000002`. The stack's
interpreter is `/usr/lib/ldqnx.so.2`.

| Factory component | Embedded date | Version / tag |
| --- | --- | --- |
| `image-8/lib/libc.so.3` | 2015-12-01 | 182 / `PSP_kernel-libc_br650_be650SP1` |
| `image-120000/lib/libsocket.so.3` | 2015-10-13 | 1306 / `PSP_networking_br650_be650SP1` |
| `image-380000/sbin/io-pkt-v4-hc` | 2016-04-22 | 1445 / `PSP_networking_br650_be650SP1` |
| `image-380000/lib/dll/devnp-ncm.so` | 2017-10-25 | 1758 / `PSP_networking_br650_be650SP1` |

The pinned kernel was also inspected separately: `image-8/proc/boot/procnto-instr`,
585,728 bytes, SHA-256
`f987e14c0fa76748d0cf9b45c3e3f435f78bab117c5970bb94ab91f856d75fac`.
Its ELF type/machine/flags are 2/40/`0x05000002`.

The appropriate starting SDK family is therefore **QNX 6.5 SP1 ARMle-v7/EABI**,
not generic ARMle, x86-only SDP, or merely any compiler that emits ARM code.
This is an inference from the corpus, not identification of every installed ABI.
QNX documents that ARMle-v7 uses EABI and is not binary-compatible with the older
ARMle runtime; its compiler target is `gcc_ntoarmv7le`. Floating-point calling
conventions and runtime libraries must also agree.
[QNX ARMv7 technote](https://www.qnx.com/developers/docs/6.5.0SP1/neutrino/technotes/QNX_for_ARMv7_Cortex_Processors.html).

The existing `Check-CarPlayArm.ps1` still produces only `armv7-none-eabi`
relocatable objects. It provides neither a QNX entry point nor an executable
linked against the factory OS. This audit does not relabel that output.

## 3. Check the host without changing its SDK configuration

Read-only checks found no `qcc`, `QCC`, `qconfig`, `ntoarmv7-gcc` or `ntoarm-gcc`
on PATH and no configured `QNX*`/`QCONF*`/`QDE*` environment variables.
No QNX/Momentics directory was found directly under either Program Files folder.
These explicitly checked locations do not exist:

```text
C:/QNX650
C:/QNX660
C:/qnx700
C:/qnx710
C:/qnx800
C:/Users/donjulio/qnx650
C:/Users/donjulio/qnx660
C:/Users/donjulio/.qnx
```

A filename search of the workspace's `downloads`/`extracted` trees found no SDK
headers, CRT object files, compiler or `io-pkt-v6-hc`. A QNX-related filename
search of the user's Downloads folder found no package. This is not a search
of every disk, registry entry or arbitrary installation directory. An initial
search included the nonexistent workspace `tools` directory; the scoped search
was repeated against the existing directories.

Docker is installed through Rancher Desktop; its server reports `29.5.3`.
WSL lists the Rancher Desktop distributions. Those are potential build hosts,
not QNX SDKs. No container was started, image pulled or daemon setting changed.

QNX distinguishes host tools (`QNX_HOST`) from target headers/libraries
(`QNX_TARGET`); copied runtime `.so` files alone are not the development kit.
[QNX development layout](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.momentics_welcome/start.html).
The official x86-only 6.5 SP1 download explicitly excludes other target support,
so it is not the required ARM package.
[QNX x86-only package](https://www.qnx.com/download/feature.html?programid=23651).

## 4. Inspect a newly located public toolchain candidate

The maintainer's `luka-dev/qnx65-armv7-toolchain` repository is pinned at
`baa45224f18ae6b13c2e9c77c6663bb8181eb6a1`. Its complete GitHub tree response
contains 16,749 entries; `sdp/` has 3,432 blobs totaling 158,716,689 bytes.
The tree includes ARMv7 CRT objects, headers and an `io-pkt-v6-hc` binary.
The Docker recipe builds a compiler around that supplied sysroot; this does not
make the sysroot a matching factory SDK.
[Pinned candidate](https://github.com/luka-dev/qnx65-armv7-toolchain/tree/baa45224f18ae6b13c2e9c77c6663bb8181eb6a1),
[build recipe](https://github.com/luka-dev/qnx65-armv7-toolchain/blob/baa45224f18ae6b13c2e9c77c6663bb8181eb6a1/Dockerfile).

The optional `--fetch-candidate` reads only three pinned binary references into
memory. It validates their exact lengths, Git blob IDs and SHA-256 before parsing.
It neither clones the SDK nor executes the downloaded code.

| Candidate | SHA-256 |
| --- | --- |
| `armle-v7/lib/libc.so.3` | `3ea952170deb54ee7916ff8a6d35d0cd056af3b27c13f92f319f069562d40e00` |
| `armle-v7/lib/libsocket.so.3` | `965e36a0977935b315a697df269aaa7d6a22ec951ec3992d2097afccfb8aac74` |
| `armle-v7/sbin/io-pkt-v6-hc` | `a51a2c4fd4aba6ddcaf8559dd734d1326d8bd102ef4388a307035375f5fca0f9` |

All three identify **2010-07-09, version 6.5.0, tag 89**, not the factory SP1
build tags. The stack exports `inet6domain` and has the same ARM ELF flags and
interpreter as the factory executable. That is a candidate runtime, not a
working or compatible factory installation.

The factory NCM driver requires these names supplied by its factory stack, but
the candidate stack does **not** export them:

```text
stk_context_callback_2
stk_context_callback_2_clean
```

These are the actual scheduling/cleanup boundaries traced in Step 97. Do not
satisfy them with no-op stubs or assume similarly named older helpers have the
same contract. The unmodified pair lacks those providers at the compared stack
boundary. Additional provider modules, data layouts, symbol versions, kernel
interfaces and real loader behavior have not been verified. Even a zero missing-
name count would not prove ABI compatibility.

The candidate `net/route.h` defines old information messages as `0xe` and current
`RTM_IFINFO` as `0xf`, explaining the Step 99 documentation/binary discrepancy
without patching constants. Its blob ID is
`e64f73195f9f7c8597f6f64fae57f27f2cd273db`.
[Pinned route header](https://github.com/luka-dev/qnx65-armv7-toolchain/blob/baa45224f18ae6b13c2e9c77c6663bb8181eb6a1/sdp/target/qnx6/usr/include/net/route.h).

The supplied QNX headers retain a QNX licensing notice. Public repository
visibility is not evidence of permission to redistribute an SDK or build image.
No SDK/header/runtime content is imported into this repository. A usable build
route still needs appropriate SDK access and compatibility checks.
[Candidate header notice](https://github.com/luka-dev/qnx65-armv7-toolchain/blob/baa45224f18ae6b13c2e9c77c6663bb8181eb6a1/sdp/target/qnx6/usr/include/sys/neutrino.h).

## 5. Verify the tools and preserve the scope of the results

```powershell
python -B scripts/inspect_packaged_runtime.py
python -B scripts/inspect_qnx_runtime_candidate.py
python -B scripts/inspect_qnx_runtime_candidate.py --fetch-candidate
python -B -m unittest discover -s tests -p test_packaged_runtime.py -v
python -B -m unittest discover -s tests -p test_qnx_runtime_candidate.py -v
python -B -m unittest discover -s tests -p 'test_*.py'
ctest --test-dir build/video -C Release --output-on-failure
git diff --check
```

Observed: **19 new tests; 169/169 Python tests and 50/50 existing Release CTest
suites passed**. The explicit online comparison also completed with all pins
matching and the two missing stack exports above. The normal Python suite makes
no candidate network request; its remote-pin tests use synthetic data.

Tests cover complete pinned ZIP reads, renamed ELF/marker detection, nested
archive reporting, CRC rejection, bounds/path/type refusals, factory ELF metadata,
changed-input rejection before parsing/network use, candidate pin checks and the
distinction between symbol-name matches and ABI verification. Receiver C/C++ is
unchanged. No new native build, sanitizer result or real phone test is claimed.

## 6. Next implementation decision

The nested-ZIP search is no longer the next dependency. Do not retry it as if
the SDK or IPv6 stack might appear through another filename-only search.

1. Establish usable QNX 6.5 SP1 ARMv7 development inputs. A local SDK path was
   requested while this audit ran; no path has been supplied at this checkpoint.
   The community compiler recipe is a concrete lead for further inspection,
   not a verified replacement SDK. Inspect its compiler/CRT/library requirements
   and the minimal native diagnostic's C API boundary before building it.
2. Keep native **application compilation** separate from **network-stack
   deployment**. An older sysroot may be useful for a carefully checked C
   application, but that does not make its old networking manager compatible
   with the 2017 NCM module. Prefer matching SP1 stack/driver inputs; another
   stack/USB bridge requires its own full implementation and ownership evidence.
3. Once a target executable can be built, establish installed-version execution
   and recovery before running it on the unit. A minimal read-only diagnostic
   should precede the native CarPlay service, factory rendering/input/audio and
   real-phone acceptance checks.

The [factory integration gates](factory-integration-gates.md) remain open.
Software-only CarPlay on the actual unit is still unachieved.
