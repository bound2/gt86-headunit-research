# Factory wired network: NCM is present, native IPv6 is not established

Date: 2026-09-17. Step 96, following [the iAP stream-profile work](iap-stream-profile.md).
Starting checkpoint: `3ff139b6820ef04ec4d49cf13b347e54ccc735f6`.

The later **6.17.0WL** research corpus already contains a native USB NCM network
driver and scripts that load it. A second userspace NCM implementation should
therefore not be the default next step. However, the bundled, selected network
stack has no built-in IPv6 domain. Driver presence does not establish a usable
wired CarPlay interface, and neither finding identifies what is actually
available on the owner's **6.9.0WL** unit.

No firmware, startup script, network interface, USB device or vehicle was changed.
The added code is an offline inspector and its regression tests, not a target
driver or an installable receiver.

## 1. Keep the two wired transports separate

Step 95 traces iAP2 control over the carkit service. The reference's wired audio/
video connection uses a **separate USB network function**. The existing stream
profile cannot turn the carkit TLS byte stream into an Ethernet interface.

The reviewed LIVI source is still commit
`a76553fc941dcf378dd55c04da56aaf3d6911e08`. Its
`native/livi-helperd/crates/iap2-usbmux/src/ncm.rs` blob is
`48bcc3b9d2cba96053c1d407ee3bc4fb8627c621`.

That implementation first looks for a Linux `cdc_ncm` interface associated with
the selected phone. Otherwise it claims the USB control/data interfaces and
bridges NCM blocks to a Linux TAP interface. It selects data alternate setting 1
and configures the link through Linux-specific facilities. Its header comment
about kernel rejection is not a captured phone descriptor or evidence of why
this QNX driver would reject a phone. This step does not run the helper or copy
its bridge into the receiver. [Pinned LIVI NCM source](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-usbmux/src/ncm.rs).

## 2. Pin the actual factory inputs

All paths below are relative to `extracted/qnx-system-v3/`. The inspector checks
all six hashes before interpreting the inputs. Firmware remains ignored by Git.

| Input | SHA-256 |
| --- | --- |
| `image-380000/lib/dll/devnp-ncm.so` | `bdabe7a1b29cd4070c03e0cb5c98403c632a0147c8d5da1686d2b41b834ff996` |
| `image-380000/sbin/io-pkt-v4-hc` | `f0f0624759c6d06e77dcd459dcd2d95bb3577d0f94730a9c031382bdab27b13b` |
| `image-380000/boot/scripts/secondary-boot.sh` | `581665a0ef5f18b80d2e8cc0203bfd8a476fc5b9130a75c9efbfac4cc39505f8` |
| `image-16e0000/boot/scripts/connectivity.sh` | `fc3c55dd500aa60c790e07e667a0b568d795d932cff1af504d38deba3499c3ef` |
| `image-16e0000/boot/scripts/dbservice_recovery.sh` | `d44e5f3eff33d55b00964f37beb36366b76434889425ee65e2ac0c56568c6243` |
| `inventory.tsv` | `9296d45028a16d62ae0a77e8b9eff35e3719b874eb7bd565efd2003b24a52cbf` |

The NCM ELF is ARM32 little-endian, 61,418 bytes. Embedded metadata identifies
version 1758, dated 2017-10-25, marked experimental, with a QNX 6.5 SP1 networking
tag. This is provenance, not a compatibility guarantee.

At line 21, `connectivity.sh` contains a `mount -T io-pkt -o pnp` invocation for
`/lib/dll/devnp-ncm.so`; the recovery script repeats it at line 107. Both commands
are outside the nearby variant-dependent Wi-Fi/MirrorLink blocks. These are
script contents, not proof that either script reaches that command on a running
unit. In particular, the unusual spaced `VARIANT = ...` line in the connectivity
script is preserved, not silently repaired or treated as evidence of its runtime
value. The recovery script is not executed.

QNX describes this as an `io-pkt` network driver, with Ethernet interfaces named
`ncmX`. Its additional `/dev/serncmX` endpoint is for AT commands, **not the
Ethernet/CarPlay byte stream**. The documented `pnp` behavior distinguishes
physical device removal from explicitly destroying the last interface; teardown
must not conflate those operations. [QNX 6.5 SP1 NCM driver](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_utilities/d/devnp-ncm.so.html).

## 3. Trace the actual interface and request boundaries

Addresses here are unrelocated ELF virtual addresses. The inspector resolves
selected ARM calls through the actual PLT/GOT relocations, checks instruction
words and follows direct local calls. It does not execute the driver.

| Boundary | Observed factory code |
| --- | --- |
| Small support predicate, `0x5424` | Checks two 32-bit fields against class `2` and subclass `13`; returns 0 or 19. This leaf alone is not the complete attach path. |
| Candidate routine, `0x3fe0` | Called from detection at `0x4b64` and `0x4d80`; reads control-interface class/subclass, then CDC Union fields. |
| Association, `0x4048` onward | Copies Union master and first subordinate interface numbers; rejects when either retained field is `-1`. Looks up the associated data interface and checks class `10`. No VID/PID comparison occurs in this selected routine. |
| MAC/capabilities, `0x5ed4` | Reads Ethernet functional descriptor subtype `0x0f`, its MAC string and maximum segment size, plus NCM subtype `0x1a` capabilities. |
| Pipe setup, `0x6b34` | Requests control + interrupt-IN pipes at control alt 0, selects data alt 0, configures parameters, then selects alt 1 and requests bulk-IN + bulk-OUT pipes. |
| Vendor-request wrapper, `0x61d8` | Calls `usbd_setup_vendor` at `0x623c` with request type `0x21`, passing the selected control-interface index. |

The Union-field check does not prove that every missing-Union configuration is
rejected: the entire detection loop's field-reset behavior has not been audited.
No real phone descriptor set has been supplied or captured. Do not replace that
missing evidence with the looser interface pairing in the Linux reference.

Selected class requests in the factory parameter path are:

| Callsite | Request | Observed parameter/condition |
| --- | --- | --- |
| `0x640c` | `0x80` GET_NTB_PARAMETERS | 28-byte buffer |
| `0x66dc` | `0x86` SET_NTB_INPUT_SIZE | Four-byte selected size, when it differs |
| `0x6824` | `0x84` SET_NTB_FORMAT | Value 0, when reported format bit 1 is set |
| `0x6858` | `0x8a` SET_CRC_MODE | Value 0, when capability bit 4 is set |
| `0x6958` | `0x87` GET_MAX_DATAGRAM_SIZE | Two-byte buffer, capability bit 3 |
| `0x63c0` | `0x88` SET_MAX_DATAGRAM_SIZE | Two-byte selected size; reached when it differs |

The descriptor and request names above are mapped against the primary
[Linux v6.12 CDC definitions](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/usb/cdc.h).
The QNX API's distinct flags, request, request-type, value, index and buffer
arguments prevent confusing its direction flags with USB request-type bits.
[QNX `usbd_setup_vendor`](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.ddk_en_usb/usbd_setup_vendor.html).

One concrete caution: immediately after GET_NTB_PARAMETERS, instruction `0x6410`
reads the response buffer without checking the wrapper's return value. The
descriptor setup also does not gate progress on the parameter helper's return.
These are static observations, not an injected-failure replay or a complete
driver-safety assessment. Reuse requires checking initialization failures,
descriptor bounds, transfer limits and detach ownership, not merely finding
the right class number.

## 4. Verify the IPv6 gap beyond the filename

`secondary-boot.sh:35` starts `io-pkt-v4-hc` with `-S` and
`-ptcpip stacksize=8192,enmap=0`. Its pinned executable is 1,077,454 bytes and
identifies itself as version 1445, dated 2016-04-22.

More decisively, `domaininit` at `0x1c70fc` walks the linker-set interval
`[0x1ffd18, 0x1ffd30)` and calls `domain_attach`. Reading those pointers and their
actual domain objects yields:

| Symbol | Family | Stored name |
| --- | --- | --- |
| `arpdomain` | 28 | `arp` |
| `inetdomain` | 2 | `internet` |
| `keydomain` | 29 | `key` |
| `linkdomain` | 18 | `link` |
| `routedomain` | 17 | `route` |
| `unixdomain` | 1 | `unix` |

There is no built-in IPv6 domain in that set. The binary also has no raw `inet6`,
`ip6_input` or `IPv6` markers, although absence of strings alone would be weaker
evidence. The complete IFS inventory, including symlink targets, lists this
stack and the NCM driver, but no `io-pkt-v6-hc` path/alias. This inventory is **not**
a search of all MMC contents or a dump of the installed car; dynamically attached
modules are outside the built-in domain table's scope.

QNX documents `io-pkt-v4-hc` as IPv4 and `io-pkt-v6-hc` as IPv6 plus IPv4.
The IP stack is integral to the executable; `-ptcpip` supplies parameters, not a
replacement IPv6 stack. Changing an address string, finding IPv6-aware client
utilities, or writing an NCM packet codec therefore does not resolve this gap.
[QNX networking architecture](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.io-pkt_en_user_guide/overview.html).

## 5. Reproduce and check the evidence

```powershell
python -B scripts/inspect_factory_network.py
python -B scripts/inspect_factory_network.py --disassemble ncm --start 0x3fe0 --stop 0x417c
python -B scripts/inspect_factory_network.py --disassemble ncm --start 0x63d4 --stop 0x6c84
python -B scripts/inspect_factory_network.py --disassemble stack --start 0x1c70fc --stop 0x1c71a4
python -B -m unittest discover -s tests -p test_factory_network_trace.py -v
python -B -m unittest discover -s tests -p 'test_*.py'
ctest --test-dir build/video -C Release --output-on-failure
git diff --check
```

The nine new tests cover pinned startup/inventory evidence, actual imported and
local call targets, descriptor association, six selected requests, the actual
domain objects and their consumer, changed-input refusal, bounded symbol/table
handling and repeatability without subprocesses or input changes. The optional
disassembly runs host LLVM on an in-memory adapted header; it neither patches
the original file nor loads a QNX program.

Observed results: **9/9 new tests, 101/101 Python tests and 50/50 existing Release
CTest suites passed**. The existing host receiver code is unchanged; earlier crypto/media/sanitizer
results are not reclassified as native NCM or IPv6 verification.

## 6. Next implementation decision

Follow-up: [Step 97](factory-ncm-lifecycle.md) now traces separate connections,
replays insertion/removal selection, identifies `pnp` retention and abort timeout
counter resets, and audits the outer installation-ISO directory. It does not
establish live claim/cancellation guarantees or a compatible IPv6 runtime.
The original decision sequence below remains historical context for that work.

1. Trace the NCM insertion/removal and interface-attachment ownership, including
   initialization-failure cleanup and how stock MirrorLink/network management
   identifies the interface. Establish what would have to cooperate with the
   existing driver before introducing another USB owner.
2. Determine whether the available corpus contains an additional compatible
   IPv6 runtime outside these IFS files, and whether an isolated stack can be
   supported with a matching QNX toolchain/runtime. Neither replacing the active
   factory stack nor obtaining a compatible IPv6 stack is established here.
3. Only after those boundaries are understood, choose native NCM reuse or a
   separately justified userspace network implementation. Require a real
   phone-associated interface, scoped IPv6 address and owned listener before
   sending the wired-start address; a Windows loopback fixture is not that proof.

This changes the next action from assuming NCM is missing to auditing the native
driver and the separate IPv6 runtime gap. The [factory integration gates](factory-integration-gates.md)
remain open: installed-version execution/recovery, matching build environment,
USB/MFi ownership, factory media/input integration and real phone/unit acceptance.
