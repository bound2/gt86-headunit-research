# Native QNX network diagnostic source and build gate

Date: 2026-09-17. Step 101, following [the native build audit](factory-native-build-route.md).
Starting checkpoint: `764d96edde6f07e4529ecfc8cfd381d99587a2ef`.

Implemented a QNX-specific network diagnostic source and an SDK-based build entry
point. Its query/reporting logic passes synthetic host tests and sanitizers.
**No QNX executable has been built:** the real SDK preflight stops because no
QNX host/target SDK paths are configured or supplied. That is the immediate
dependency, not an invitation to replace the factory network stack.

This is preparation for verifying the actual native network APIs before a
CarPlay backend. It is not the receiver, an installer, or a demonstrated route
onto the owner's installed 6.9.0WL unit. No car, firmware, USB device, factory
service or network configuration changed.

## 1. Check the compiler recipe's dependency boundary

The pinned community compiler recipe from Step 100 requires `QNX_HOST` and
`QNX_TARGET`, builds GCC against the supplied sysroot and reuses its binutils.
The CMake cross file selects target-side headers/libraries and does not run target
programs during configuration. Neither file creates a matching factory SDK from
compiler source. Their C++ runtime work is not needed by this small C diagnostic.
[Pinned compiler recipe](https://github.com/luka-dev/qnx65-armv7-toolchain/blob/baa45224f18ae6b13c2e9c77c6663bb8181eb6a1/gcc/build.sh),
[cross configuration](https://github.com/luka-dev/qnx65-armv7-toolchain/blob/baa45224f18ae6b13c2e9c77c6663bb8181eb6a1/cross/qnx-armv7.cmake).

The web renderer could not retrieve those raw files; the exact pinned raw URLs
were subsequently read successfully with the host HTTP client. No recipe was
executed and no SDK, compiler container or license activation was installed.

## 2. Confirm the diagnostic's C API providers

The existing pinned factory ELF comparison verifies that these names are exported:

| Library | Selected diagnostic APIs |
| --- | --- |
| `libc.so.3` | `printf`, `puts`, `fflush`, `ferror`, `strcmp`, `getenv`, `close`, `__get_errno_ptr` |
| `libsocket.so.3` | `socket`, `getifaddrs`, `freeifaddrs`, `if_nametoindex` |

QNX documents socket creation separately from connecting/sending; the default
socket namespace can be overridden by `SOCK`. The diagnostic reports only whether
that variable is present, does not change it, and does not print its contents.
[QNX socket API](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/s/socket.html).

The interface list is allocated by `getifaddrs` and released with `freeifaddrs`.
Addresses may be null. A subsequent name-to-index lookup can fail and is not
atomic with that earlier snapshot; it does not authenticate a phone.
[QNX enumeration](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/g/getifaddrs.html),
[interface fields](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/i/ifaddrs.html),
[index lookup](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/i/if_nametoindex.html).

A selected static check of factory `io-pkt-v4-hc` startup at `0x115ee0` also
shows why a normal CRT is required: it calls `_init_libc`, preinit/fini/init-array
helpers and `atexit` before `main`/`exit`. Those library providers are present.
This step does not create a guessed `_start`, replay OS initialization or prove
that any supplied CRT matches the installed runtime.

## 3. Implement the native diagnostic

Source: `src/carplay/qnx_network_diagnostic.c`.

- No argument prints usage only. The explicit `--inspect-network` argument is
  required before any socket, environment or interface query.
- Opens one unbound datagram socket per IPv4/IPv6 family, records success or
  errno, then closes each successful descriptor once. Descriptor zero is valid.
  An ambiguous close failure is reported, not retried.
- Obtains one address snapshot and reports at most 128 entries. Releases an
  obtained nonempty list once, including after reporting errors/truncation.
- Bounds interface names using the SDK's `IFNAMSIZ`, prints names as hex to
  avoid control-character output, and reports index-lookup failures explicitly.
- Handles absent addresses, short sockaddr headers, unexpected family-specific
  lengths and uninterpreted families without reading an IPv6 payload as IPv4.
- Reports address bytes and scope **as observed**, not as normalized CarPlay
  wire addresses. It does not alter an embedded-scope IPv6 representation.
- Never calls bind/listen/connect/send, interface-setting ioctls, process launch,
  mount or USB APIs. It prints no hardware serial number or phone credentials.

Successful collection still ends with `phone_association_verified=0` and
`listener_ready=0`. Exit 0 means the selected collection completed, not CarPlay
readiness. Exit 1 indicates an unavailable/failed query, invalid/truncated result
or output failure; an IPv6 socket failure on the stock stack is an expected
possible observation. Unsupported arguments return 2.

The real source branch includes the SDK's networking headers and rejects a
non-QNX/non-little-endian-ARM compiler. Compile-time checks require 32-bit pointers
and the corpus's 16-byte IPv4 / 28-byte IPv6 sockaddr layout with scope offset 24.
These checks detect some wrong SDK choices; they cannot verify the installed OS.
The 128-entry cap bounds our traversal/output, not the duration of OS API calls
or the allocation performed inside `getifaddrs`.

## 4. Add an SDK-only build path without a host fallback

`scripts/build_qnx_network_diagnostic.py` accepts `--qnx-host`/`--qnx-target` or
the corresponding QNX environment variables. It checks `qcc`, configuration,
selected headers and ARMle-v7 CRT/C/socket libraries before creating output or
invoking a compiler. `--check-sdk` performs those file checks only.

With development inputs supplied, the build path is designed to:

1. Hash the selected SDK files and diagnostic source; verify factory reference
   library hashes before using their export sets.
2. Compile through `qcc -Vgcc_ntoarmv7le` with C99 and `-lsocket`, in a fresh
   ignored `build/qnx-network-diagnostic-*` directory. Set SDK paths only in the
   child process environment; do not change global SDK configuration.
3. Check the output is the selected ARM EABI executable form with the QNX
   interpreter, a file-backed executable entry and only C/socket dependencies.
   Require the diagnostic query imports, reject selected mutating/device imports
   (including weak ones), and require nonweak imports to exist in the pinned
   factory libraries. Recheck selected input hashes after compilation.
4. Write a build record only after those checks pass. Never execute the target
   output, package it into an ISO, copy it to a USB drive or install it.

Those are **selected ELF/import checks**, not a complete loader, relocation,
symbol-version, data-layout or ABI proof. The forbidden-name list is not a
security sandbox. Weak imports remain explicitly listed for later review.
A successful future build record would still mark target execution and installed-
version compatibility unverified.

Observed preflight, run on this PC:

```powershell
python -B scripts/build_qnx_network_diagnostic.py --check-sdk
```

Result: exit 2, requesting QNX host/target paths. No compiler was invoked and no
native output directory was created. No usable SDK path has been supplied since
the earlier request. **The real QNX include/compile/link branch remains untested.**
Do not treat the host test executable below as an output of this native build.

## 5. Test the implementation without claiming target execution

The host CTest target compiles the same query/reporting source against the
explicit model in `tests/qnx_network_diagnostic_test_api.h`. Its family numbers
are deliberately different from QNX; its types are not SDK headers. It never
opens a real socket or enumerates the host's interfaces.

Five test groups cover opt-in behavior, socket/list/close failures, descriptor
zero and exact close ownership, IPv4/IPv6 raw observations, missing/invalid names
and lengths, index errors, 128-entry boundaries, output failures and cleanup.
Nine Python tests cover missing SDK refusal, check-only behavior, factory export
pins, selected executable/import gates and refusal to promote ELF checks into
target verification. Gate fixtures are synthetic, not native executables.

```powershell
cmake --build build/video --config Release --target qnx_network_diagnostic_tests -- /verbosity:quiet
ctest --test-dir build/video -C Release --output-on-failure
python -B -m unittest discover -s tests -p 'test_*.py'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-QnxDiagnosticHost.ps1
git diff --check
```

Observed: **51/51 CTest suites and 178/178 Python tests passed**. The five new
host groups also passed Clang AddressSanitizer/UndefinedBehaviorSanitizer.
An initial manual sanitizer command failed PowerShell parsing because its comma-
containing flag was unquoted; no compiler ran in that attempt. Quoting it fixed
the command, and the checked-in helper uses a flag array to preserve it.
The final sanitizer run includes the descriptor-zero and exact-boundary cases.

## 6. Immediate dependency and next action

To validate this native build, supply usable QNX 6.5/SP1 ARMle-v7 development
inputs: the SDK's host-tools and target-tree paths. The current SDK-based route
cannot build with the files configured here. The community recipe's public
availability does not establish its licensing or factory compatibility; neither
the older IPv6 manager nor replacement factory libraries were adopted.

After a real build, inspect the CRT/imports/relocations against the factory
runtime, then establish installed-version execution and recovery before running
the diagnostic. Only then can its observations support the phone-associated
IPv6 owner and native CarPlay network backend. MFi, display/input/audio and real
phone acceptance remain required in [the integration gates](factory-integration-gates.md).
Software-only CarPlay on the actual unit is still unachieved.
