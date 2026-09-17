# Factory USB claims and callback lifetime

Date: 2026-09-17. Step 98, following [the NCM lifecycle trace](factory-ncm-lifecycle.md).
Starting checkpoint: `1f399684af5c2c000cf5a4521c4c41a247da3aee`.

The selected factory USB server checks exclusive claims **per resolved interface**,
not simply per whole device. The client library defers a removal callback while
its device has pending I/O. Its asynchronous completion path invokes the transfer
callback before retiring the pipe/device counters. An abort command's return is
not a substitute for that retirement.

These findings make coordinated interface sharing worth pursuing, but do not
establish working coexistence with the factory Apple services or a real phone.
This remains analysis of the later **6.17.0WL** corpus, not verification of the
owner's installed **6.9.0WL**. No native receiver, update USB, firmware change,
stock-service change or on-car operation is produced by this step.

## 1. Pin the actual library and server

The first three inputs are below
`extracted/qnx-system-v3/image-120000/`; the NCM driver is below
`extracted/qnx-system-v3/image-380000/`.

| Input | SHA-256 |
| --- | --- |
| `lib/libusbdi.so.2` | `bb57492945edf721bfc1677e7827b56018a81cea9a740790ffba63030f7775c0` |
| `lib/libusbdi.so` | `cca264fa0088e55c66e9ccca0377b75292ea3e53c462719d5c3936d1a60f2c6b` |
| `sbin/io-usb` | `9128ef23a002c4523fdaad4e1941c97397535524d13c54c28e1b62c353b3b7ec` |
| `lib/dll/devnp-ncm.so` | `bdabe7a1b29cd4070c03e0cb5c98403c632a0147c8d5da1686d2b41b834ff996` |

The library/server metadata identifies version 1493 and tag
`PSP_USB_br650_be650SP1`, with July 2016 build dates. The NCM driver's actual
`DT_NEEDED` entries are `libusbdi.so.2` and `libc.so.3`.

The two library copies differ only at file offsets `0x41`, `0x42`, `0x61`,
`0x62`, within the first two ELF load headers' physical-address fields. All
remaining bytes match, including code. They are not assumed identical solely
because of their filenames or metadata.

`scripts/inspect_usb_ownership.py` hashes each input before parsing it, checks
selected instruction words and direct/imported call targets, and compares the
copies. Addresses below are unrelocated ELF virtual addresses, not file offsets
or an API for calling private vendor functions.

## 2. Follow the server's actual claim path

QNX describes callback-enabled attachment as exclusive I/O access and attachment
without callbacks as shared configuration access. Its instance structure includes
path, device number, generation, identity, configuration, interface and alternate.
That general description does not establish the implementation's conflict key.
[QNX 6.5 `usbd_attach`](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.ddk_en_usb/usbd_attach.html).

The library's `usbd_connect` sets the selected connection flags to 7 when callbacks
are supplied, versus zero when absent (`0x8700/0x8704`), before command 1.
The server command-1 branch passes flags to client creation at `0x117b80`, and
the latter stores them at client `+0x10` (`0x116f60`). Additional caller flags
also participate in connection setup; this is not a complete flags specification.

The attach command follows three distinct stages:

1. Dispatcher command 3 selects `0x117c34` through table entry `0x117b14`.
2. Call `0x117c6c -> 0x105f88` resolves/validates the requested device instance.
   Selected instructions check a requested generation, write the resolved
   generation at instance `+2`, and write the resolved interface at `+0x1c`.
3. On success, `0x117c80 -> 0x11682c` allocates a 44-byte claim node, copies the
   36-byte instance to node `+8`, then calls the conflict checker at
   `0x116880 -> 0x11661c`.

The library has the corresponding conflict routine at `0x371c`. Both versions
walk the clients and their claim lists. A conflict requires flag mask 2 on both
the requesting and existing client, equal first 32 bits of the instance
(`path:u8`, `devno:u8`, `generation:u16`), and equal interface at instance `+0x1c`.
The selected collision branch returns 16 (`EBUSY`). The current client is not
excluded from this search, so duplicate claims within one client also conflict.

Bounded execution of **both** native conflict routines establishes:

| Synthetic resolved claims | Selected checker result |
| --- | --- |
| Same path/device/generation/interface, both exclusive | Second claim returns 16, existing claim preserved |
| Same device tuple, different interface | Both inserted |
| Different path, device number or generation | Both inserted |
| Same key, changed VID/PID/class/configuration/alternate | Still conflicts |
| Shared inspection and exclusive I/O, either order | Both inserted |
| Same-client duplicate, or a matching non-head node | Conflict found |

The last fields are not in this particular key. **Changing them in a request is
not a way to bypass server validation.** These fixtures directly supply resolved
nodes to the checker; they do not replay descriptor resolution, configuration
selection, or the whole server dispatcher. Real requests must first pass stage 2.
Different-interface acceptance here is not proof of safe configuration changes,
physical USB routing or cooperation with every stock service.

## 3. Distinguish removal notification from transfer completion

Library device lookup at `0x5700` compares the complete 36-byte instance using
`memcmp` at `0x573c`. It is separate from the NCM callback's bus/address-only
selector described in Step 97.

The library helper `usbdi_synchronise` at `0x5a0c` manages device flags at `+0x14`
and the library's pending-I/O count at `+0x18`:

1. Removal marking sets flag 1. If the count is nonzero, it returns 16 without
   invoking removal. At zero it returns zero; the event-thread caller invokes
   removal in that branch, not this initial helper call.
2. New positive-count operations are rejected after removal with 19, or while
   suspended (flag 2) with 11, without increasing the count.
3. A negative-count update that reaches zero while removed can invoke the
   registered removal callback. It releases the global mutex at `0x5af4` before
   calling the function pointer at `0x5b08`.

The static event-thread trace connects that helper to actual event handling:

| Event-thread boundary | Selected order |
| --- | --- |
| Removal event | Lookup at `0x7f50`; mark/test at `0x7f64`; nonzero skips callback at `0x7f6c` |
| No matching handle or zero pending count | Call removal handler at `0x7f84`, if present |
| Asynchronous transfer completion | Invoke transfer callback at `0x7ff4` |
| After that callback returns | Decrement pipe `+0xc` at `0x8004` |
| Then | Decrement device count through `usbdi_synchronise` at `0x8014`; this can deliver deferred removal |

The helper replay checks marking, rejection of new I/O, two successive explicit
retirements, and an unlocked removal callback at zero. The **event thread itself
is statically traced, not replayed**; its scheduling and races are not simulated.
The no-matching-handle branch also means this evidence does not prove that stale
notifications can never reach NCM's weaker selector.

Implementation consequence: do not block inside a transfer callback waiting for
that callback's library count to retire. It retires only after the callback
returns. Publish completion to an owning coordinator and preserve the necessary
pipe/device lifetime until retirement is established.

## 4. Test abort, close and detach separately

QNX documents `usbd_abort_pipe` as aborting requests on a pipe, but that page does
not specify a client-callback-drain barrier. The selected binary supplies the
more precise wrapper behavior below.
[QNX 6.5 `usbd_abort_pipe`](https://qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.ddk_en_usb/usbd_abort_pipe.html).

At `0x5e5c`, abort checks the device pending count. At zero it returns zero without
sending a command. Otherwise it builds a request containing device identity,
configuration, interface, alternate and endpoint, temporarily increments pipe
`+0xc` (`0x5ec4`), sends command 6 (`0x5edc`), decrements that temporary reference
(`0x5eec`), and returns the command status. It does not itself retire the device
I/O count. The server dispatches command 6 to `0x109c24` at `0x117d84`;
controller/hardware completion is not replayed here.

Injected command statuses 0, 5 and 19 propagate while the original pending counts
remain unchanged. A mocked zero is **not** evidence of actual successful hardware
cancellation. The end-to-end fixture explicitly clears the synthetic pipe count
and calls the native helper with delta -1 before allowing detach; that retirement
is a test action, not an effect attributed to abort.

`usbd_close_pipe` at `0x58b0` returns 16 before unlinking/freeing when pipe `+0xc`
is nonzero. `usbd_detach` at `0x5f38` similarly checks device `+0x18` first. These
early busy paths preserve the local objects. This agrees with QNX's pending-I/O
caveat and automatic pipe closure description.
[QNX 6.5 `usbd_detach`](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.ddk_en_usb/usbd_detach.html).

There is an important **error/lifetime distinction** after the early check:

1. Detach unlinks the device locally, then sends command 4 at `0x5fd0`.
2. It saves the command result and proceeds with pipe cleanup even when it is
   nonzero. Pending pipes cause a delay/retry loop; the replay does not pretend
   that a delay drains real work.
3. It frees the device at `0x6030`, then returns the saved command result.

Tests inject 0, 5, 19 and 16 after a zero-pending check; all dispose of the local
pipe/device. A separate fixture produces **the same return value 16** through
the early pending check, preserving both objects. This does not prove that the
real server returns 16 for command 4; it proves that the wrapper's integer result
alone cannot distinguish those paths if it does. Do not implement unconditional
retry-on-error using a possibly freed handle. A native adapter needs coordinated
submission shutdown, retirement and an explicit consumed-handle/error contract.

## 5. Refine the earlier NCM finding without inventing a live failure

Step 97's timeout stores affect **NCM-private counters**, not the library device
and pipe counters examined here. Normal removal delivery has the additional
library deferral described above. Thus the timeout stores alone are not proof of
a use-after-free or a failed normal-removal path. Conversely, forcing private
counters to zero is still not a general cancellation guarantee for a new backend.

Selected interface-level conflict checking makes separate control/usbmux and
NCM ownership a candidate architecture. Shared device configuration, alternate
selection, stock media coordination, actual descriptors and reconnect identity
still require evidence. Do not replace or unload factory services based on this
offline result.

## 6. Reproduce and verify

```powershell
python -B scripts/inspect_usb_ownership.py
python -B scripts/probe_usb_ownership.py
python -B scripts/inspect_usb_ownership.py --disassemble usb --start 0x7f30 --stop 0x8028
python -B scripts/inspect_usb_ownership.py --disassemble usb --start 0x5f38 --stop 0x6040
python -B scripts/inspect_usb_ownership.py --disassemble server --start 0x11661c --stop 0x116758
python -B -m unittest discover -s tests -p test_usb_ownership.py -v
python -B -m unittest discover -s tests -p 'test_*.py'
ctest --test-dir build/video -C Release --output-on-failure
git diff --check
```

The probe uses the existing Unicorn dependency, pinned ARM code, synthetic
objects and mocked imports. Only the conflict, counter, abort, close and detach
routines plus selected PLT ranges can execute. The server replay is conflict-only.
Entry execution is limited to 10,000 instructions and one second, with bounded
heap/read/event sizes. Unexpected imports, entries and interrupts fail. Mutexes
and atomics are test models, not concurrent native primitives; mock `free` records
ownership disposal without implementing an allocator or proving absence of
use-after-free. No kernel call, real wait, USB transfer or vendor process runs.

Observed: **19 new tests, 137/137 Python tests and 50/50 existing Release CTest
suites passed**. Tests include changed-input rejection before emulator creation,
code-difference rejection between library copies, conflict/list cases, explicit
retirement, abort/error propagation, cleanup/lifetime distinctions, repeatability
without subprocesses or input changes, and a cyclic claim list stopped by the
instruction budget. Receiver C/C++ code is unchanged. No new sanitizer, target
executable or phone result is claimed.

## 7. Next implementation boundary

1. Trace the factory networking client's interface-to-device association and
   readiness observations. Separate a reusable name from the phone/session,
   scoped IPv6 address and owned listener lifetime.
2. Establish the compatible IPv6 runtime and target SDK/build route; the stock
   NCM driver and a socket namespace prefix do not supply the missing stack.
3. Use these claim/lifetime constraints when implementing the native USB adapter,
   with actual submission/cancellation retirement rather than synthetic counts.
   Validate device-wide configuration coordination before attempting coexistence.

The [factory integration gates](factory-integration-gates.md) still require
installed-version execution/recovery, a real target build, usable MFi hardware,
factory media/input and acceptance by an actual phone. This is not yet an
installable software-only CarPlay update.

Follow-up: [Step 99](factory-network-identity.md) now traces the stock name/index
cache and separate link/address events. It verifies an IPv6-aware client, not a
missing runtime or USB/phone association. Matching SDK/runtime and scoped-address
normalization remain prerequisites for a real native network owner.
