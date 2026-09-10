# Factory display control: request, notification and restoration

Date: 2026-09-10. Starting checkpoint: `b8832eb`.
Continues [CarPlay progress, Step 80](carplay-progress.md#step-80---trace-factory-display-control-and-distinguish-local-status-from-hardware-evidence).
Scope: static inspection of the existing later `6.17.0WL` corpus, not execution
on the owner's installed `6.9.0WL` system.

## Step 1 - Close the public stock-update check without assuming eligibility

Toyota's current UK customer guidance directs Touch 2 with Go owners without
smartphone integration to MyToyota's e-Store and a USB update. It does not expose
this owner's offered package or entitlement. The reviewed public TechDoc frontend
also did not yield a verified account-specific offer. No account was accessed,
purchase made or latest eligible version established.
[Toyota customer map-update guidance](https://www.toyota.co.uk/owners/connectivity/map-updates).

Toyota Estonia's retrofit page names RAV4/Corolla and identifies eligible
multimedia generations as 17/17MM/CY17/17CY. A 2017 vehicle year and the shared
Touch 2 branding do not establish membership in that hardware generation.
The known Panasonic TAS400 / `13TFDAEU-DA05` and Harman NAVI BOX observations
are unchanged; the page supplies no confirmed CarPlay retrofit for this GT86.
[Toyota Estonia retrofit scope](https://www.toyota.ee/owners/connected-services/multimedia-updates).

The stock-update route remains separate from custom CarPlay implementation.
Continue the already planned offline display work without asking again for
unavailable hardware labels or purchasing a map update as a CarPlay experiment.

## Step 2 - Pin and validate the selected firmware inputs

All paths below are under
`extracted/qnx-system-v3/image-380000/usr/share/lua/service/toyotamanager/`.
Sizes and CRC32 values match [the extraction inventory](qnx-system-inventory.tsv).
Complete SHA256 checks are enforced by
[inspect_display_control.py](../scripts/inspect_display_control.py).

| Input | Bytes | CRC32 |
| --- | ---: | --- |
| `toyotamanager.lua` | 30,380 | `1504764f` |
| `modemanager.lua` | 85,132 | `afbc7b6c` |
| `avclan.lua` | 67,589 | `03d5a627` |
| `properties.lua` | 2,131 | `23c4038b` |

Newly pinned `modemanager.lua` SHA256:
`dc8f8437a02153f5e36ab2bb3a8a39a291b6b1e23a537f116d6e69d4a62c1ed5`.
The other three hashes match the prior navigation-identification inspection.
Source line numbers below are debug metadata in bytecode, not line numbers of
plaintext source files. Only the host compiler's parse/list operation ran.

## Step 3 - Follow the request and release paths

| Boundary | Selected static evidence |
| --- | --- |
| Public service wrappers | `toyotamanager.lua:303-307` and `312-316` call the mode manager, discard its results, then return a literal `allowed=true` table |
| Request control | `modemanager.lua:2085-2090`: if the stored display state is 0, mark a pending request and call `avclan.requestDisplay(1, 1)` |
| Release control | `modemanager.lua:2095-2103`: if stored state is 1 and current HMI mode is `DA`, mark pending and request `(0, 1)`; otherwise an outstanding request sets a cancellation flag |
| Outgoing request | `avclan.lua:648-656` compares cached state/mode flag and writes a `REQUEST_DISPLAY` message when different; an explicit simulator branch can call the callback directly |
| Incoming callback | `avclan.lua:663-667` stores message fields 2 and 3 and passes them to the registered display callback |
| Mode-manager callback | `modemanager.lua:469-539` calls `confirmDisplay`, updates the stored property and emits `displayState`, then handles pending/cancelled requests and mode restoration |

Manual inspection of the enclosing chunks links the incoming handler to the
`REQUEST_DISPLAY` dispatch entry (`avclan.lua:667`) and the callback to the mode
manager (`modemanager.lua:541`). These registration/linkage observations are
separate from the automated selected-function instruction checks.

`avclan.lua:659-661` sends a `CONFIRM_DISPLAY` message. The shared writer
(`186-196`) calls `dev.write`; startup (`2060-2081`) opens `/dev/avclan/tm` in
read/write mode and sets up notifications and other service subscriptions.
This is an internal active-control path, not a passive query available from a
PC. The tool does not invoke any of these functions or open that device.

## Step 4 - Do not mistake a local status event for physical ownership

The immediate wrapper reply is not a hardware grant. There is a second, less
obvious limitation: `restoreDisplay` (`modemanager.lua:1436-1464`) itself assigns
display state 1 and emits the same `displayState` property before its remaining
audio/HMI restoration work. `properties.lua:36` also initializes state to 0.
The service signal forwarder (`toyotamanager.lua:82-85`) forwards the supplied
signal and parameters; it does not add a hardware-origin marker.

Consequently, simply subscribing to `displayState` and treating state 1 as a
fresh device acknowledgement is not justified. The selected path also does not
provide a per-client ownership token. State changes can be software-generated,
and the explicit simulator callback is not evidence of a physical transition.

`updateExtRGBStatus` (`modemanager.lua:317-359`) incorporates the stored state
and mode flag into a status bitmask along with other HMI/audio conditions. It
sends changed status through `sendExtRGBStatus`; the routine is not a pixel
renderer or a video decoder. Neither the name nor its message demonstrates
that CarPlay frames can be displayed.

## Step 5 - Constrain the eventual native adapter

These are design requirements inferred from the inspected code, not implemented
target behavior:

1. Keep request acceptance, device-origin state observations and renderer
   readiness distinct. Do not enable projection from `allowed=true` or an
   unqualified property snapshot alone.
2. Establish how observations are sourced and correlated with the current
   request before assigning ownership. The stock shared property is insufficient
   by itself; do not invent an acknowledgement token that the API does not show.
3. Coordinate with existing HMI/audio modes, cancellation and service lifetime.
   No existing navigation/phone process may be displaced on an assumption that
   a request succeeded. Screen control does not automatically grant audio focus.
4. Trace the native consumer and rendering surface next, including how loss of
   screen access stops projection and restores the factory UI. Touch routing,
   video decoding and deployment/recovery remain separate work.

This step defines evidence boundaries for the adapter; it does not add a QNX
receiver or alter the host receiver's advertised capabilities.

## Step 6 - Make the inspection repeatable and test its limits

```powershell
python -B scripts/inspect_display_control.py
python -B scripts/inspect_display_control.py --instructions
python -B -m unittest discover -s tests -p 'test_*.py'
```

The tool validates all four inputs before launching the existing Win32 Lua 5.1
compiler with `-l -p`, then checks each input again. It selects 14 complete
function listings, verifies their instruction numbering/counts and produces
normalized listing hashes. It has no file-output option. These are reproducible
instruction listings, not an automatic dataflow proof or a Lua execution model.

A binary-stdin trial failed because this host's Lua file loader keeps stdin in
text mode on Windows. The implemented route uses verified file paths, which the
loader reopens in binary mode. No firmware or compiler source was patched.

All **40 Python regression tests pass**, including **11 new display-trace tests**.
They cover selected instruction anchors, local versus callback-generated status,
the simulator branch, parser failures, changed-input refusal, timeouts, repeatable
output and parse-only invocation. They do not simulate screen switching or test
a phone. The firmware bytes remain unchanged; no update USB, service command,
activation request or vehicle operation was produced.
