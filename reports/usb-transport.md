# Stock USB transport investigation

Updated: 2026-09-09. Continues [CarPlay progress, Step 30](carplay-progress.md#step-30---verify-the-integrated-exchange-and-define-the-transport-task).

## Result and scope

The later navigation firmware configures a native QNX USB host stack with an
iPod HID transport and a separate USB audio path. Its stock transport wraps
outgoing bytes in HID output reports and strips report framing from incoming
interrupt data. It is not an established raw iAP2 transport for our receiver.

This narrows the software-only integration task; it does **not** establish that
CarPlay can run on the owner's hardware. The corpus is 6.17.0WL, while the owner's
installed navigation software is 6.9.0WL. The display/audio unit and Go module
are separate computers. Configuration in a Go firmware image does not establish
the physical connector/multiplexer wiring or current ownership in the car.

No device was opened, USB request sent, stock service stopped, configuration
changed, firmware installed, or real credential/identity collected. All native
replays below use synthetic memory and mocked USB calls on the PC.

## Step 1 - Preserve the checkpoint and pin the evidence

Committed the preceding control/identification work as `78cebe7`,
`Add opt-in iAP2 identification and bounded application replies`.

The new [USB probe](../scripts/probe_usb_transport.py) SHA256-checks 12 inputs
before running its scenarios: the primary uncompressed imagefs, host-controller
DLL, nine configuration/boot files and the USB iPod DLL. Its JSON includes every
path and full digest. All paths below are relative to
`extracted/qnx-system-v3/`; raw vendor files remain outside Git.

The principal native input is `image-380000/lib/dll/iofs-usb-ipod.so`, SHA256
`45c140270c8e168ecfbca426fb86e0bf5780bc40010b2ee313117a00e4b2a1f8`.
The existing [ELF inspector](../scripts/inspect_ipod_auth.py) now accepts
`--module usb`, displays its descriptor and disassembles bounded ranges.
The loader does not execute its initializer, attachment logic or callbacks.

## Step 2 - Trace startup and service ownership

1. The primary `image-8.imagefs` contains the adjacent boot argument strings at
   file offsets `0x90a18..0x90a68`: executable/argv name `io-usb`, then `-vvv`,
   `-c`, `-d`, `dm816x-mg`, and
   `ioport=0x47401400,irq=18,ctrl_noping,in_rndis`.
   These are checked bytes from the image, not a command to run on the car.
   The probe does not implement a general QNX boot-script record parser.
2. `image-120000/lib/dll/devu-dm816x-mg.so` describes itself as a DM816x USB OTG
   controller driver with a **host-only** implementation. This characterizes
   this software package, not every capability of the silicon. Device-role
   support, role switching and the actual physical port topology remain unknown.
3. `image-120000/etc/enum-usb.conf` matches Apple VID `05AC`, PID pattern `12*`,
   prefers audio configuration class `01`, tags it `AppleIpod`, and supplies the
   incremental mount prefix `/fs/ipod`. Mass-storage class `08` is the fallback.
   This is not an observed mountpoint, bus number, device number or endpoint.
4. `image-120000/etc/system/enum/common` enables USB enumeration. Its
   `devices/usb/ipod` rule loads `io-fs-media` with the `ipod` driver and
   `transport=usb:busno=...:devno=...` for the tagged HID interface. It supplies
   an `acp=i2c:speed=40000` authentication provider, audio control/URL and
   mount arguments. A separate audio-control-interface rule loads the `ipod`
   driver into `io-audio` for capture.
5. `image-380000/boot/scripts/secondary-boot.sh` starts the I2C0 driver labeled
   for iPod authentication, runs early/pre-media services, and only later starts
   `enum-devices`. Its charging-offset setting is 500 mA above a documented
   default in the script; this is neither a current measurement nor proof of
   the owner's power hardware.
6. `pre-media.sh` starts the base audio service and waits for `/dev/snd` before
   the Toyota audio-control service. Its comment explicitly explains that USB
   enumeration must come later to avoid attaching to the wrong sound card when
   an iPod is connected. USB ownership and audio focus cannot be treated as
   independent, uncoordinated resources.

Configuration-level relationship in this corpus:

```text
QNX io-usb + dm816x-mg host driver
  -> Apple USB configuration / enum-devices rules
       -> HID: io-fs-media / iofs-ipod / iofs-usb-ipod
            -> existing I2C Apple-authentication provider
            -> media mount and connection-manager notifications
       -> Audio: io-audio ipod capture / Toyota audio control
```

This does not grant another process ownership of these interfaces. No second
USB stack, device reset, configuration switch or stock-service shutdown is an
approved collection method or an implemented handoff mechanism.

## Step 3 - Separate existing phone applications from CarPlay

`image-380000/etc/ipod.cfg` advertises the external-accessory protocol
`com.ahamobile.link.v1`, with configured send size 494 and receive buffer 32768.
Its accessory defaults include Toyota/Harman, model `TEB`, serial `0001` and
firmware/hardware strings `010101`. These are configuration values, not reads
of the owner's unique identifiers, and must not be copied into our opt-in
identification profile as verified hardware facts.

`early_services.sh` loads a network tunnel module early; its explanation is an
Entune app startup deadline. `connmgr_r0.json` routes media insertion/removal
events to `ITunCtrl.lua` and tracks tunnel-session files. This is evidence of
existing phone-app integration, not a demonstrated CarPlay network path.
This pass inspects the configuration, not an execution of `ITunCtrl.lua`.

The old Bluetooth iPhone rule invoking `StartIoFsMedia.lua` in
`connmgr_r1.json` is **commented out**. Its comment cites conflicts with the
cabled iPhone feature. The files contain comments and must not be interpreted
as plain JSON, or every text match as an active rule. No Bluetooth CarPlay path
has been established.

## Step 4 - Identify native transport operations

Addresses below are unrelocated ELF virtual addresses in the pinned USB DLL.
The exported `iofs_module` at `0x4920` points through `0x4944` to the
`ipod_transport` descriptor at `0x4bf0`. Slots `0x4c1c` and `0x4c20` point to
the write (`0x1674`) and read (`0x11cc`) routines respectively; operation labels
come from their disassembled behavior.

The descriptor-selection code at `0x1d48..0x1f44` checks a HID interface
class/subclass/protocol of `3/0/0`, one declared endpoint, HID/report descriptor
types `0x21/0x22`, and control/interrupt endpoint transfer attributes in its QNX descriptor
walk. It obtains concrete values at runtime. This inspection does not recover
the actual phone's endpoint numbers or descriptors.

| Direction | Observed stock operation | Boundary to preserve |
| --- | --- | --- |
| Outgoing | `usbd_setup_vendor`, then synchronous `usbd_io` on the control pipe | HID report ID, fragmentation flags, payload and padding |
| Incoming | `usbd_setup_interrupt`, then callback-based `usbd_io` | Interrupt completion lengths, report lookup and cached payload tails |
| Lifecycle | Context contains active handle, pipes, URBs, cache and completion flags | Disconnect invalidates more than a file descriptor |

For an outgoing report, the native call uses flags `2`, request `9`, request
type `0x21`, value `0x200 | report_id`, runtime interface index and a length
including the report ID. These fields identify a HID output `SET_REPORT`
class/interface request. The QNX function name `usbd_setup_vendor` does not
mean this request's USB type is vendor-specific. This interpretation follows
[USB-IF HID 1.11, section 7.2](https://www.usb.org/sites/default/files/hid1_11.pdf)
and the [QNX setup API](https://www.qnx.com/developers/docs/6.5.0SP1/ddk_en/usb/usbd_setup_vendor.html).

The output `usbd_io` callback argument is NULL, with timeout argument zero;
the input request carries callback `0x1630` and timeout `0xffffffff`.
QNX documents synchronous-only vendor-request submission and distinguishes
preparing a URB from transferring it. No numeric meaning is assumed for the
output timeout beyond the observed zero.
[QNX usbd_io](https://www.qnx.com/developers/docs/6.5.0SP1/ddk_en/usb/usbd_io.html).

Input setup uses flags `5` and a runtime transfer length. QNX documents
direction and short-transfer flags for interrupt URBs, plus its USB-buffer
allocation requirements. A future native backend must use that allocation
contract, not arbitrary C heap buffers passed directly to USB.
[QNX usbd_setup_interrupt](https://www.qnx.com/developers/docs/6.5.0SP1/ddk_en/usb/usbd_setup_interrupt.html).

No `usbd_setup_bulk` import exists in this DLL. Together with these traced
functions, that establishes the selected stock HID path, **not** the absence
of all iAP2/CarPlay support from the entire firmware or possible future software.

## Step 5 - Replay transfers with synthetic USB only

The probe runs only the audited read/write code and PLT stubs in Unicorn.
Unexpected imports, execution outside the allowed routines and guest
syscalls/interrupts fail closed. All URBs, pipes, interface/report numbers,
completion results and bytes are invented fixtures. It does not replay device
attachment, parse a real phone's reports or perform full-system emulation.

Limits: 1024-byte payloads/buffers, 64-byte injected interrupt completions,
256 import events per probe, 100,000 guest instructions and a five-second
execution ceiling per call. Delays and waits are recorded, not slept. Input
destinations have checked canaries. Optional output uses create-new semantics.

All **17 scenarios** pass:

1. Three bytes become a ten-byte output report for synthetic ID 7, with
   report ID/flags followed by `abc` and zero padding.
2. Seventeen bytes split into payload chunks of 8/8/1, with flags 2/3/1.
3. Empty writes submit no transfer.
4. An inactive handle rejects a write with return -1 / native errno 9.
5. An injected first-submission removal error returns -1 / errno 19.
6. Failure on the second submission returns the eight bytes already completed;
   errno is not a replacement for inspecting a positive partial result.
7. A write completion with stall status invokes the mocked control-pipe reset
   and returns -1 / errno 5. No real pipe was reset.
8. An intentionally injected successful status with actual length 2 still makes
   the write routine report all three payload bytes completed. Disassembly
   confirms it does not consult actual length on this success branch. This
   fault-injection result does not prove the real QNX stack/device can produce
   that combination; it identifies an assumption not to inherit unchecked.
9. A busy write status followed by success records a 100-ms delay and completes.
10. Perpetual busy status is stopped by the harness event budget. The selected
    stock polling loop has no visible retry count; this is not a measured hang.
11. A ten-byte input report loses its two-byte header and supports sequential
    reads of three then five payload bytes, preserving the cached tail.
12. A report split across synthetic completions preserves its remaining-length
    state and does not strip a second header from the continuation.
13. An unknown input report ID exposes no payload.
14. A header-only completion exposes no payload.
15. An inactive handle rejects a read.
16. A seven-millisecond read wait becomes 7,000,000 nanoseconds in the mocked
    wait call; the injected native timeout value returns an empty read.
17. A read stall invokes the mocked interrupt-pipe reset, then requeues input;
    successful requeue returns zero rather than the earlier completion error.

QNX distinguishes the status-query return, USB completion status and actual
transfer length. A new backend must validate the combination before claiming
progress. [QNX usbd_urb_status](https://www.qnx.com/developers/docs/6.5.0SP1/ddk_en/usb/usbd_urb_status.html).

## Step 6 - Define the next bounded adapter

This was the design contract for the next implementation. The portable portion
is now implemented and tested in [transport-adapter.md](transport-adapter.md);
it still does not open the stock driver. The existing C99
`iap2_control`/`iap2_link` APIs remain unchanged. An independently verified transport profile remains a
prerequisite; HID framing must not simply be assumed suitable for iAP2.

1. Separate the portable byte-stream pump from a native backend. The pump owns
   one bounded pending frame and its offset, plus a bounded receive buffer.
   The backend reports `progress(count)`, `would_block`, `disconnected` or
   `fatal`; it must not disguise a reset, timeout or removal as progress.
2. Call link output only when a complete frame can be retained. Once retained,
   send only the unsent tail until complete. Do not interleave a retransmitted
   frame into that tail. A successful write/USB completion is not an iAP2 ACK.
3. Check counts against the requested extent. Zero progress is backpressure,
   never completion or a reason to busy-spin. A positive count followed by
   failure advances only that count, then closes/discards the old connection
   if safe resumption cannot be established. Never replay its tail on a new
   device that happens to reuse the same address.
4. Bound work per poll and time for pending output. Continue servicing control
   and link deadlines under backpressure. Link retransmit clocks start when
   output is produced, not when physical transmission completes: the adapter
   needs an explicit compatible deadline/closure policy, not an infinite queue.
5. Feed only validated incoming payload bytes, respecting the engine's consumed
   count. Retain any unconsumed tail within fixed capacity. USB boundaries and
   iAP2 frame/message boundaries must remain separate.
6. On disconnect, cancel pending native operations, invalidate completion
   generations and clear transport plus link/authentication/identification
   state. A fresh attach requires fresh endpoint initialization and explicit
   identification enablement. No callback may access freed/reused old buffers.
7. In the future QNX backend, obtain validated descriptors and coordinated
   interface ownership, satisfy USB buffer lifetime/allocation requirements,
   and handle completion status plus actual length. Any HID envelope belongs
   in an explicitly selected, proven profile below the byte-stream pump.
   No default bus, device, interface, endpoint, role switch or reset is allowed.

The planned host-only tests exercise the pump with partial/zero writes,
backpressure, invalid completion counts, stalls, deadlines, split/coalesced
reads, unplug/replug and stale completions. These are additional to the stock
behavior probes above. Their implemented coverage and limits are recorded in
the [adapter verification](transport-adapter.md#step-6---verify-the-implementation).

## Step 7 - Reproduce and keep the limits visible

```powershell
python -B scripts/inspect_ipod_auth.py --module usb
python -B scripts/inspect_ipod_auth.py --module usb --disassemble --start 0x1674 --stop 0x1920
python -B scripts/probe_usb_transport.py
python -B -m unittest discover -s tests -p test_*.py -v
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
```

Optional evidence capture: add `--output extracted/usb-transport-probe.json`
only if that path does not already exist. All 19 Python tests (six new USB
tool tests) and all eight CTest suites pass. The native probe's 17 scenarios
also run as one of the six new test groups. No production protocol C source
changed in this continuation.

Still missing before car-side execution: actual Go part number/hardware
revision, installed-version matching, physical port ownership/role evidence,
real authentication-provider compatibility, execution access and recovery.
CarPlay session/media protocols, video decoding, display/input routing and
audio focus also remain unfinished. This report is not a USB installation
procedure and does not require added receiver hardware.
