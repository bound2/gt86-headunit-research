# Factory NCM ownership, removal and the remaining IPv6 runtime gap

Date: 2026-09-17. Step 97, following [the factory network trace](factory-usb-network.md).
Starting checkpoint: `a2c9d486546debc98c5314f2080de7f5e95a0e33`.

The shipped NCM driver has separate inspection and I/O USB connections, queues
insertion work, and hands removal to the network framework. Its removal selector
uses only bus/address; its abort timeout paths can force pending counters to zero.
Neither behavior establishes a safe handoff to a second USB owner. The installation
ISO adds no **named** IPv6 stack to the earlier IFS evidence.

This step implements reproducible offline inspection and native callback replay,
not a native CarPlay backend. All observations concern the later **6.17.0WL**
corpus, not the owner's installed **6.9.0WL** firmware. No firmware, USB device,
network interface, stock service or car was changed.

## 1. Pin inputs and distinguish static evidence from replay

The driver remains `extracted/qnx-system-v3/image-380000/lib/dll/devnp-ncm.so`,
61,418 bytes, SHA-256
`bdabe7a1b29cd4070c03e0cb5c98403c632a0147c8d5da1686d2b41b834ff996`.
All addresses below are unrelocated ELF virtual addresses.

`scripts/inspect_ncm_lifecycle.py` verifies the driver hash, selected instruction
words, imported/direct call targets, and actual relative relocations for callback
and ownership slots. It follows PIC literals rather than treating an unrelocated
word as a callable pointer. This is selected-code evidence, not a whole-driver audit.

`scripts/probe_ncm_lifecycle.py` executes only the insertion/removal callbacks and
their small class predicate using the existing Unicorn dependency. USB instance
data, allocations, list nodes, locks and counters are synthetic. Imports are
intercepted; queued work and `dev_remove` are recorded, **not executed**. Unexpected
imports, interrupts or execution outside the allowed callback/PLT ranges fail.
Each entry is limited to 10,000 instructions and one second. No host USB/QNX library
is loaded. Replay does not exercise attach, detach, worker scheduling or races.

## 2. Follow the two USB connections

The control object is at `0xe608`; its connection fields are separate:

| Native boundary | Observed ownership |
| --- | --- |
| `usbd_connect` at `0x48d8` | Callback-enabled connection stored at control `+0x14` |
| `0x4948` / `0x494c` | Clears the callback-table parameter before the next connection |
| `usbd_connect` at `0x4964` | Inspection connection stored at control `+0x18` |
| Worker `usbd_attach` at `0x53b0` | Uses inspection connection; requests zero extra bytes |
| Attach calls at `0x37b8`, `0x3910` | Use callback connection for control/data interfaces; each requests four extra bytes |

QNX documents callback-enabled attachment as exclusive I/O access, and attachment
without callbacks as shared configuration access. The third `usbd_attach` argument
is **additional allocation size**, not claim flags. Its instance structure includes
separate path, device number, generation, identity, configuration, interface and
alternate fields. [QNX 6.5 `usbd_attach`](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.ddk_en_usb/usbd_attach.html).

With null callbacks, QNX does not provide asynchronous I/O or its event thread.
With callbacks, the library creates a monitoring thread and requires shared-state
protection. [QNX 6.5 `usbd_connect`](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.ddk_en_usb/usbd_connect.html).

Inference: another receiver cannot assume it can claim a stock-owned phone merely
because it uses a different IP stack. Exact device/interface claim granularity
and coexistence with the Apple media/usbmux path still require the actual USB
library/server trace. The public API description alone does not establish that
two different applications can concurrently own the required interfaces.

## 3. Replay insertion selection and queueing

The insertion entry `0x515c` first skips while control flags contain mask `0x2`, then
uses `0x5424` to require class 2/subclass 13. It allocates 52 bytes and copies the
complete 36-byte instance to allocation `+8`. It increments the insertion counter
at `0xe5fc` and calls `stk_context_callback_2` with callback `0x5310`, the allocation,
and the control object. It does not itself create the interface.

Replay verifies exact copying, including generation, VID/PID, configuration,
interface and alternate fields, with canaries around the copied field. Wrong
class/subclass, the scanning bit and allocation failure do not queue or increment.
The separate `pnp` flag (value 4) does not by itself suppress insertion.

Static continuation: callback `0x5310` acquires process privileges and calls
`kthread_create1` with worker `0x5384`. The worker attaches through the inspection
connection, calls candidate `0x3fe0`, increments the device count on candidate
success, detaches the inspection handle, decrements the insertion counter, frees
the allocation and exits. No thread is created by the replay. Privilege/thread
failure ownership is not proven by checking these selected calls.

## 4. Replay removal selection, not full teardown

Entry `0x4f50` applies the same class/subclass predicate and locks control `+0x348`.
The list at `0xe604` contains 12-byte nodes with next/context pointers and the
path/device bytes at node `+8/+9`.

At `0x4fd0`, it reads only the first 16 bits of the incoming instance. It compares
that value with node `+8`, selects the **first** match, releases the lock, increments
the removal counter at `0xe600`, and calls `dev_remove(context)` at `0x50f0`.

Replay checks empty/no-match lists, differing bus/address, non-head selection,
class rejection, balanced locking and unlock-before-handoff. Changing generation,
interface, configuration, VID/PID, alternate or protocol does not change the
bus/address selection. Two synthetic nodes sharing that address select the first.
The mocked handoff leaves nodes intact because actual detach is not executed.

This establishes what the callback compares. It does **not** prove that a stale
event can reach it on the real system: USB-server ordering, library serialization
and framework lifetime rules remain outside the replay. A new receiver should
not use bus/address alone as durable phone or session identity.

## 5. Trace attachment, names and teardown caveats

Actual `ncm_ca` relative slots `0xe4a0/0xe4a4` point to attach `0x358c` and detach
`0x3050`. The device context is `0xc40` bytes. Successful attachment obtains
control/data handles at context `+0xb20/+0xb1c`, initializes memory and NCM
descriptors, then calls `if_attach` and `ether_ifattach` at `0x3b4c/0x3b58`.

The normal interface name is copied from the framework's device name. The optional
extended-name branch uses a supplied name or format `ncm_%d_%d` with bus/address.
A name alone is therefore not a verified phone association or stable reconnect
identity. The stock network-manager consumer of that name is not yet traced.

The later initialization-failure path at `0x3c28` calls memory cleanup, detaches
data then control, and frees the list node. Earlier failures take different exits;
this selected path is not proof that all failures release every resource.

Detach unlinks the context's list node, stops the interface, surrounds Ethernet/
interface removal with `quiesce_all`/`unquiesce_all`, removes its shutdown hook,
calls abort helper `0x71d8`, detaches both USB handles, destroys the serial-device
resource, drains selected queues and frees memory.

The abort helper contains three `usbd_abort_pipe` calls. With waiting requested,
it polls interrupt/RX/TX pending counters, but timeout branches explicitly store
zero at context `+0xc14`, `+0xbe0`, and `+0xb90`. It then attempts data alternate 0
and returns zero, including after logging a selection failure. These are static
branches, not fault-injected transfer tests. A zero counter or helper return is
not independent proof that all real callbacks have completed. Determining whether
library cancellation guarantees make this safe requires further evidence.

The option parser maps `pnp` to control flag 4. During detach, that flag clears the
context's module handle, bypassing the last-device connection-disconnect path.
Pending insertion/removal work and remaining devices also affect retention.
The non-retained last-device path disconnects **both** connections and cleans
queued stack callbacks. Thus interface removal is not equivalent to unloading
the stock USB owner. No unload, remount or replacement-stack command is proposed.

## 6. Extend the IPv6 search to the installation ISO

The optional `--iso` audit hashes
`downloads/6.17.0L/swdlInstall.iso` before invoking Windows host `tar`:
SHA-256 `06bdc5c05b889ae68bd372dd060502226ea911fc0715a646072c59b1832bf30d`.
Its complete outer verbose directory listing has **842 entries**. The documented
network-name filter matches only `wicome/devnp-pan.so` and
`wicome/libnetworkingservice.so`, under `usr/share/MMC_PROG_DATA/`.
It finds no named `io-pkt`/IPv6 stack or `lsm-*` module there.

The networking client library is read into memory, not extracted or loaded:
1,976,933 bytes, SHA-256
`30ac5eb41a56be89e252c52af4e52c16791742977966d3d8e418822cd6d5d55c`.
It contains `AF_INET6` once, `inet6` once and `IPv6` five times. These strings are
not evidence of an executable IPv6 stack. Seven ZIP entries remain nested;
their contents and arbitrarily renamed binaries are not searched by this audit.
Nothing here inventories the installed unit or proves global unavailability.

QNX supports separate stack instances and a socket-path prefix, with clients
selecting a stack using `SOCK`. Those mechanisms isolate socket namespaces;
they do not establish access to the same physical USB interface (inference).
The matching IPv6 binary/runtime/toolchain is still absent from the established
inputs. [QNX 6.5 `io-pkt`](https://www.qnx.com/developers/docs/6.5.0SP1/neutrino/utilities/i/io-pkt.html).

## 7. Reproduce and verify

```powershell
python -B scripts/inspect_ncm_lifecycle.py --iso
python -B scripts/probe_ncm_lifecycle.py
python -B scripts/inspect_factory_network.py --disassemble ncm --start 0x4f50 --stop 0x5448
python -B scripts/inspect_factory_network.py --disassemble ncm --start 0x3050 --stop 0x3550
python -B scripts/inspect_factory_network.py --disassemble ncm --start 0x71d8 --stop 0x74c0
python -B -m unittest discover -s tests -p test_ncm_lifecycle.py -v
python -B -m unittest discover -s tests -p 'test_*.py'
ctest --test-dir build/video -C Release --output-on-failure
git diff --check
```

Observed: **17 new tests, 118/118 Python tests, 50/50 existing Release CTest
suites passed**. Tests include changed-input rejection before emulation, changed
relocation rejection, unexpected import/interrupt/entry refusal, a cyclic synthetic
list stopped by the instruction budget, repeatability without subprocesses, and
the pinned read-only ISO audit. Receiver C/C++ and vendor inputs are unchanged.
No new sanitizer, ARM/QNX executable or real phone result is claimed.

## 8. Next implementation decision

1. Trace the actual USB library/server's claim and cancellation guarantees:
   can control/usbmux and NCM cooperate on this phone without replacing the
   factory media owner, and what proves transfers are drained before releasing
   buffers? Treat the timeout counter reset as a question, not a safety guarantee.
2. Trace how the stock networking client associates interface names with devices.
   Keep interface discovery, full phone/session identity, IPv6 readiness and owned
   listener lifetime distinct. Do not announce a wired-start address from a stale
   name or a Windows-only loopback result.
3. Establish a matching IPv6 runtime/target build route. A separate socket prefix,
   an NCM block codec or the optional wireless iAP tunnel does not supply it.

Installed-version execution/recovery, native build, MFi, factory display/input/
audio integration and actual phone acceptance remain open in the
[factory integration gates](factory-integration-gates.md). This is not an
installable software-only CarPlay update yet.

## Step 98 follow-up - Library/server ownership and retirement

[The subsequent USB trace](factory-usb-ownership.md) verifies interface-granular
conflict checks in both library and server after instance resolution. It also
finds library-level removal deferral and transfer-callback-before-counter-retirement
ordering. Those library counts are distinct from the NCM-private timeout stores
above; the stores alone do not demonstrate a failed normal-removal path. Abort
return still does not establish callback drain, and detach command errors can
consume local handles. Actual hardware cancellation, configuration coexistence
and phone-associated interface readiness remain unverified.
