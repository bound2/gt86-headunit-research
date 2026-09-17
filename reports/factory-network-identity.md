# Factory network interface identity and readiness

Date: 2026-09-17. Step 99, following [USB ownership](factory-usb-ownership.md).
Starting checkpoint: `71cb4dfbd32c4a79b1d8de7a622b6c2f9d8d6ac5`.

The factory networking service configures `ncm0` by **name**, stores interface
objects in a name-keyed cache, and matches interface-information events by numeric
network index. These paths do not join the interface to an authenticated phone or
USB generation. Link state, addresses, and listener readiness are separate facts.

The client really has IPv6-aware address handling, not just IPv6 diagnostic
strings. That does **not** supply the missing IPv6 stack identified in Step 96.
No native CarPlay backend or working factory CarPlay session is produced here.
All binary findings concern the later **6.17.0WL** corpus, not verified behavior
of the owner's installed **6.9.0WL**. No device, service, route or firmware changed.

## 1. Recover the specific omitted client library

Step 97 read this library into memory from the installation ISO. This step
extracts just that member into the fresh ignored directory
`extracted/factory-network-617-step99/`, preserving earlier extractions.

| Input | SHA-256 |
| --- | --- |
| `downloads/6.17.0L/swdlInstall.iso` | `06bdc5c05b889ae68bd372dd060502226ea911fc0715a646072c59b1832bf30d` |
| ISO member `usr/share/MMC_PROG_DATA/wicome/libnetworkingservice.so` | `30ac5eb41a56be89e252c52af4e52c16791742977966d3d8e418822cd6d5d55c` |
| `extracted/qnx-system-v3/image-16e0000/etc/wicome/wicome.cfg` | `b56af8f9393fd8ebe97b118c221b34b1a6a047369012ca564884476b23123fb3` |

The library is 1,976,933 bytes and retains its static symbol table. The inspector
checks both library/configuration hashes before interpreting them, selected exact
function names/addresses/sizes, ARM words, direct/imported calls and PIC literals.
All addresses below are unrelocated ELF virtual addresses.

For a fresh checkout with the already verified ISO:

```powershell
$headunitNetworkIso = Join-Path (Get-Location).Path 'downloads/6.17.0L/swdlInstall.iso'
if ((Get-FileHash -LiteralPath $headunitNetworkIso -Algorithm SHA256).Hash.ToLowerInvariant() -ne '06bdc5c05b889ae68bd372dd060502226ea911fc0715a646072c59b1832bf30d') { throw 'Not the pinned ISO' }
$headunitNetworkOutput = Join-Path (Get-Location).Path 'extracted/factory-network-617-step99'
if (Test-Path -LiteralPath $headunitNetworkOutput) { throw 'Inspect existing output; will not overwrite' }
New-Item -ItemType Directory -Path $headunitNetworkOutput | Out-Null
& C:/Windows/System32/tar.exe -xkf $headunitNetworkIso -C $headunitNetworkOutput usr/share/MMC_PROG_DATA/wicome/libnetworkingservice.so
if ($LASTEXITCODE -ne 0) { throw 'Inspect partial extraction; will not overwrite' }
if ((Get-FileHash -LiteralPath (Join-Path $headunitNetworkOutput 'usr/share/MMC_PROG_DATA/wicome/libnetworkingservice.so') -Algorithm SHA256).Hash.ToLowerInvariant() -ne '30ac5eb41a56be89e252c52af4e52c16791742977966d3d8e418822cd6d5d55c') { throw 'Not the pinned library' }
```

This step used that extraction path once and verified the resulting hash. Raw
vendor files remain ignored by Git. The commands do not start a QNX process.

## 2. Separate configured names from physical device identity

The pinned configuration contains:

| Line | Configuration |
| --- | --- |
| 210 | `NetworkingService_5.type = pan` |
| 211 | `NetworkingService_5.ifname = ncm0` |
| 212 | `NetworkingService_ncm0.ipmode = dhcp` |
| 213 | `NetworkingService_ncm0.additionaldhcpcparams = -m -R` |
| 370 | `UPnPService.InterfaceName = uap0,sta0,ncm0,ncm1,ncm2` |

These are distributed settings, not the owner's observed runtime configuration.
The `pan` label here does not change the actual NCM driver's USB transport.
The UPnP list is not evidence that all listed interfaces exist or belong to one
phone. `NetworkingService_5` is a configuration instance number; it must not be
confused with a USB interface number or the OS's network interface index.

`CIP::readServiceConfig` at `0x83080` constructs a per-name configuration key.
Its resolved literals include `NetworkingService`, `ipmode`, `dhcp` and `dhcp6`.
Configuration dispatch therefore distinguishes IPv4/IPv6 client modes, but a
configuration keyword alone cannot make the selected factory stack support IPv6.

The service's interface map is at `CIP +0x64`. Creation (`0x83a60`) looks up the
incoming interface name at `0x83ae4`, allocates an interface object, queries it,
stores the supplied OS index (`0x83bfc`), inserts by name (`0x83c48`), and reads
that name's configuration (`0x83ccc`). It explicitly sets cached link state false
at `0x83c08`, even after the initial query; later information events update it.
The removal branch removes the named map entry and destroys its interface object
before notifying its subscriber. These branches are statically traced, not
executed as a complete concurrent service.

## 3. Check what an interface query actually establishes

`CIP::createNewIfInstance` at `0x7a07c` opens an IPv4 query socket, clears a
144-byte request, copies the interface name and issues ioctl `0xc0906980` at
`0x7a120`. It consumes returned type, link state and MTU. The exact numeric ioctl
is evidence from this binary, **not a constant to copy into a new backend in
place of matching SDK headers**. QNX documents platform-dependent ioctl commands
and their direction/size encoding.
[QNX 6.5 ioctl reference](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/i/ioctl.html).

Bounded native replay with a synthetic ioctl response establishes:

- Types 6, 23 and 71 are retained; type 24 is mapped to internal type 1.
  Tested unsupported types 0, 1 and 255 return false without changing the output.
- Link state becomes true only for returned value 2. Unknown/down/other tested
  values become false. The accepted query also stores MTU and name.
- Socket failure and ioctl failure leave the output unchanged. An opened socket
  is closed, including on ioctl failure or rejected type.
- Query success does not populate the object with a phone identity, interface
  index, address list or administrative-up state. Those require other paths.

This is a mocked socket/ioctl boundary, not an observation of a running interface.
In particular, the test fixture's `ncm0`, index and addresses are not car data.

## 4. Follow the separate snapshot and event paths

Initial enumeration at `CIP::initialize` uses `getifaddrs` (`0x7c25c`), groups
entries by name and records link-level interface index from the `AF_LINK` entry
(`0x7c4e0/0x7c4e4`). It distinguishes address families 2 and 24 when adding IP
addresses. Administrative state comes from interface flags, separately from the
link-state query. QNX's API returns an allocated interface list; address/netmask
pointers can be null, and enumeration can fail while the list changes. A new
collector must handle those documented cases rather than copy unchecked private
offsets. [QNX `getifaddrs`](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/g/getifaddrs.html),
[QNX `ifaddrs`](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/i/ifaddrs.html).

The event monitor opens a routing socket at `0xc98fc` and registers an I/O-watch
callback at `0xc996c`. The information-event branch reads administrative flag
bit 0, compares the link-state field with 2, and passes the message's 16-bit
interface index to its subscriber (`0xca984/0xca990`). The selected address-event
branch accepts families 2 and 24 and dispatches address changes separately.

Do not infer the private event ABI solely from a generic documentation example:
the actual jump table routes type 15 to the information branch at `0xca8bc`,
whereas the linked QNX ROUTE page lists `RTM_IFINFO` as 14. This discrepancy is
another reason to require headers/runtime matching the target. No numeric route
parser is implemented from the documentation or vendor offsets in this step.
[QNX 6.5 ROUTE reference](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/r/route_proto.html).

`CIP::handleInfoEventMsg` calls `findInterfaceByIfNumber` at `0x840d4`. Bounded
execution of that helper (`0x8061c`) verifies that it scans cached objects, skips
null objects, and returns the **first matching numeric index** at object `+0x5c`.
It does not query the OS, compare a USB generation, or validate a phone/session.
Synthetic duplicate indices select the first regardless of stored name/MAC.
This does not prove that duplicate indices or stale events occur on the real unit.

`getIfConfig` (`0x82178`) copies cached objects through `convertIfConfig`
(`0x866b4`), including index, addresses, administrative state and link state.
It is not a fresh hardware query at that boundary. Consequently, a cached
configuration reply is not sufficient authority for starting a CarPlay listener.

## 5. Verify the IPv6 client boundary without claiming a stack

`CIpAddr::setSockAddr` at `0xcc9d0` copies 16 bytes for family 2, or 28 bytes for
family 24, and sets its internal valid flag. Replay verifies that all 28 IPv6
bytes, including the scope field at offset 24, survive unchanged.

That helper neither validates the supplied length/scope nor normalizes the
address. An unsupported family leaves the old destination and valid flag intact.
Its flag therefore means supported-family copying in this path, not validated
readiness or freshness. Callers must filter/validate their input and lifetime.

QNX's IPv6 documentation distinguishes normal scoped socket addresses from the
KAME internal form, where a link-local interface index can be embedded in address
bytes exposed by route/sysctl interfaces. That internal form must not be sent
as the phone's advertised wire address. Preserve explicit scope and establish
the source representation before conversion; a blind 28-byte copy does not do
that normalization. [QNX 6.5 INET6 reference](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.neutrino_lib_ref/i/inet6_proto.html).

These findings strengthen the evidence for an IPv6-capable **client**. They do
not change the selected `io-pkt-v4-hc` domain table, find a missing IPv6 runtime,
or establish an IPv6 address/listener on the owner's unit.

The static table also contains CarPlay-named base `CEthernet` methods. The two
selected enable/disable functions at `0x70348/0x70350` each return constant 4
immediately. Their names are not a firmware CarPlay-enable switch. Derived Wi-Fi
implementations and complete CarPlay service availability are outside this check;
no general claim that every CarPlay-named method is a stub is made.

## 6. Reproduce and verify

```powershell
python -B scripts/inspect_network_identity.py
python -B scripts/probe_network_identity.py
python -B scripts/inspect_network_identity.py --disassemble --start 0x7a07c --stop 0x7a340
python -B scripts/inspect_network_identity.py --disassemble --start 0x8061c --stop 0x80674
python -B scripts/inspect_network_identity.py --disassemble --start 0xcc9d0 --stop 0xcca14
python -B -m unittest discover -s tests -p test_network_identity.py -v
python -B -m unittest discover -s tests -p 'test_*.py'
ctest --test-dir build/video -C Release --output-on-failure
git diff --check
```

Observed: **13 new tests, 150/150 Python tests and 50/50 existing Release CTest
suites passed**. The new tests check the pinned configuration/code, query failures
and type/link distinctions, index matching, address copying and its validation
limits, changed-input/instruction/symbol rejection, guard failures, repeatability
and unchanged inputs. An exploratory annotation command initially passed string
values to a resolver expecting symbol records; that host-only display helper was
corrected before interpreting its output. No vendor execution resulted.

Replay is limited to the query, index lookup and address-copy helpers plus their
selected callees/PLT ranges. Socket, ioctl, logging, PAL string assignment and
vector validation are mocks. It uses the existing Unicorn dependency, checks the
library hash before creating the emulator, permits at most 10,000 instructions/
one second per entry, bounds allocations/events and checks output canaries.
Unexpected imports, entries and interrupts fail. Full event dispatch, threads,
configuration side effects and race behavior are not replayed.

Receiver C/C++ code is unchanged. No new sanitizer run, QNX executable, physical
network observation or phone acceptance is claimed.

## 7. Native implementation decision

Use stock networking observations as supporting evidence, not as the authority
binding CarPlay to a phone. The native owner must join its current USB/phone
session to the selected network interface, retain a separate connection epoch,
collect current addresses with explicit scope, and own a successfully bound
listener before replying with a wired-start address. Removal/index reuse must
invalidate that binding; a name like `ncm0` is not a durable identity.

The immediate next dependency is the **matching native build/IPv6 runtime route**:
finish the remaining packaged-runtime audit and check available target SDK
artifacts before choosing a QNX backend or a justified alternative stack. Do not
change `dhcp` to `dhcp6`, patch route constants, unload the stock stack, or send
configuration commands as a substitute for that missing capability.

Installed-version execution/recovery, MFi, factory media/input and actual
phone/unit verification remain open in [factory integration gates](factory-integration-gates.md).
The requested software-only CarPlay outcome is still unachieved.
