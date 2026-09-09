# Explicit wired CarPlay identification profile

Updated: 2026-09-09. Continues [power-notifications.md](power-notifications.md).

## Step 1 - Publish power notifications and verify the wired schema

Committed/pushed `52f1ec1`, `Add bounded power-source notifications without
consuming input`. The next change addresses the missing capability declarations.

At pinned LIVI commit `a76553fc941dcf378dd55c04da56aaf3d6911e08`, the wired
identity uses USBHostTransportComponent in field 16. Its nested fields are:

| Field | Encoding |
| --- | --- |
| 0 | Big-endian u16 component ID |
| 1 | NUL-terminated component name |
| 2 | Empty iAP2 support flag |
| 3 | One-byte CarPlay interface number |
| 4 | Empty CarPlay support flag |
| 5 | Empty repeated iAP2 flag emitted by the pinned transport macro |

The existing IdentificationInformation fixture contains component ID 2, name
`usbhost`, interface 0 and those three flags. The new encoder matches its entire
USB-host payload exactly; it does not infer that these values describe the car.
[Pinned schema and transport macro](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/messages/identification.rs).

The reference runtime additionally declares numerous subscription/vehicle
features. Only the implemented subset is included here, not that whole profile.
[Pinned runtime identity builder](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/livi-runtime/src/ident.rs).

## Step 2 - Add an explicit profile without changing the minimal default

`iap2_identification_encode_wired` and `iap2_identification_init_wired` take the
existing base metadata plus an explicit `iap2_identification_wired` component
ID, name and interface number. They require the base advanced-power capability
value 2, matching the selected wired reference profile; they do not invent an
available current rating. Component IDs 0..65535 and interfaces 0..255 remain
explicit values, including zero. Names use the existing 1..127 ASCII policy.

The profile adds outgoing IDs `0x4301` and `0xae03`, and incoming IDs `0x4300`,
`0x4e0d`, `0x4e0e`, to the implemented authentication/identification IDs. It does
not declare power-update subscriptions, Bluetooth/wireless transport, vehicle
information, navigation subscriptions or other unimplemented application IDs.
Applications must handle declared incoming messages explicitly; codecs alone
do not provide automatic application dispatch.

The original minimal API and its encoded bytes remain unchanged. Neither API
selects an OS device, inspects descriptors or validates the caller's claims.
Selecting the wired API is a caller assertion that the stated transport/power
and receiver capabilities exist; synthetic tests are not such hardware evidence.

## Step 3 - Bound activation, storage and helper behavior

`iap2_control_enable_wired_identification` is allowed only before start and
copies encoded metadata into owned storage. It rejects invalid metadata,
oversized aggregate profiles and insufficient reply capacity without replacing
the prior profile. Either explicit startup order remains configurable;
identification-first is the tested reference-order path.

The minimal profile still tops out at 930 encoded bytes. The wired profile adds
42 bytes plus its component-name length and remains bounded to 1024 bytes.
For example, the maximum base identity plus a 52-byte USB name fits exactly;
53 bytes is rejected even if the caller supplies a larger output buffer.

Read-only `identification.wired_carplay` records which profile was encoded.
Reset retains metadata but clears acceptance; full endpoint reinitialization
disables identification and clears that declaration. Re-enabling a minimal
profile before start removes the previous wired declaration.

The typed wired-start and power-source helpers now require accepted explicit
wired identification. Accepted minimal identification returns `UNSUPPORTED`
without consuming the held request or queueing output. This tightens those
helpers' previous contract; generic reply/notification APIs still leave truthful
message declaration to the application. No advertisement creates a real USB,
network, authentication or media implementation.

## Step 4 - Verify fields and the complete simulated startup subset

Three additional identification groups bring that suite to 11. They check the
exact pinned USB-host field, independent supported-message lists, absence of
unimplemented components, full-width ID/interface values, flags, every output
capacity through 1024, aggregate overflow, invalid metadata, owned snapshots
and replacement with the minimal profile.

Three additional control groups bring that suite to 38: transactional profile
activation/replacement, null/live-call refusal, exact reply capacity with a
29-byte MTU, reset behavior and refusing wired helpers after minimal acceptance.
Existing wired helper tests now enable explicit wired metadata.

The 17-group transport suite's reference-order simulation now completes:

```text
Explicit wired identification -> authentication -> unsolicited power update
    -> CarPlayAvailability received -> wired StartSession queued and ACKed
```

It uses a synthetic peer over three-byte reads/five-byte writes, synthetic
credentials, a zero-current power policy and a non-listening test address/key.
The peer checks complete control-message bytes. The generic authentication-only
exchange remains covered separately. This proves the implemented startup subset
connects through the pump, not that an iPhone accepts it or media starts.

All ten CTest suites, six host-sanitized protocol executables and the eight-unit
ARM portability check pass. Host endpoint size is now 19,968 bytes; the pump
remains 2,184 bytes plus caller buffers. The 19 Python tests passed earlier in
this turn; this step changes no Python tooling or firmware inputs.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
```

## Step 5 - Continue below the iAP2 byte-stream boundary

The next concrete dependency is USBmux framing/stream handling for the wired
carkit route. Read-only inspection shows the reference mux emits an initial
version packet, setup, and framed minimal TCP traffic; lockdown pairing/service
startup then supplies the channel carrying raw iAP2 bytes. This is separate from
the already implemented iAP2 link and from the stock iPod HID path.
[Pinned mux implementation](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-usbmux/src/mux.rs),
[carkit service channel](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-wired/src/carkit.rs).

Next trace that framing completely and implement a bounded portable transport
subset with independent byte fixtures, fragmentation and failure tests. Do not
copy the reference's fixed USB configuration/endpoints as GT86 hardware facts or
execute its device-selection/pairing routines. Actual backend ownership,
pairing/TLS, receiver networking/media, authentication compatibility, QNX
display/audio/input and verified execution/recovery remain unfinished. No
installable update or vehicle-side change was produced.
