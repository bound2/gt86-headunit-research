# Factory graphics: named windows and native Screen properties

Date: 2026-09-10. Starting checkpoint: `c6054de`.
Continues [CarPlay progress, Step 81](carplay-progress.md#step-81---trace-factory-window-management-and-the-native-screen-boundary)
and the [display-control trace](factory-display-control.md).
Scope: static inspection of the later `6.17.0WL` corpus, not the installed
`6.9.0WL` unit. No QNX executable, service method or display command was run.

Follow-up: [Step 82](mirrorlink-graphics-producer.md) corrects the original
selective extraction's omission of WiCoME libraries and traces CPU pixel upload
and EGL presentation. Searches in this report cover the earlier extracted set,
not all files inside the installation ISO.

## Step 1 - Separate the renderer lead from a misleading string match

The previous step established that ToyotaMGR's shared `displayState` signal can
originate from local restoration, not just the AVCLAN callback. Searching the
extracted system for that literal also finds Adobe AIR's `libCore.so`, but this
is not sufficient to identify the Toyota signal's native consumer.

The pinned AIR library contains 43 exact `displayState` matches, five
`flash.display:StageDisplayState` matches and 25 `NativeWindowDisplayState`
matches. These include generic Flash window/stage concepts. No contiguous
`com.harman.service.ToyotaMGR` string is present. This does not exclude generic
forwarding or a separate HMI application; the Toyota subscription-to-renderer
link remains unestablished. Screen API names in AIR likewise do not establish
an externally usable video-decoder API.

A separate, concrete lead is `hmiClient.lua`: the HMI's current screen selection
controls named windows through the native `DisplayManager`.

## Step 2 - Pin the evidence before inspecting it

Paths below are relative to `extracted/qnx-system-v3/image-380000/`.
All six sizes and CRC32 values were independently matched against the
[extraction inventory](qnx-system-inventory.tsv). Complete SHA256 values are
enforced by [the graphics inspector](../scripts/inspect_factory_graphics.py)
and [the Lua listing inspector](../scripts/inspect_display_control.py).

| Input | Bytes | CRC32 |
| --- | ---: | --- |
| `usr/bin/DisplayManager` | 214,966 | `623d79c8` |
| `usr/share/lua/service/toyotamanager/hmiClient.lua` | 5,267 | `0c728e02` |
| `usr/lib/graphics/jacinto5/graphics.conf` | 1,869 | `0b2e7594` |
| `usr/bin/start_screen.sh` | 163 | `1941db6f` |
| `boot/scripts/secondary-boot.sh` | 9,932 | `9d913c0d` |
| `lib/air/runtimeSDK/Adobe AIR/Versions/1.0/libCore.so` | 10,992,051 | `ec5a4437` |

The manager is ELF32 ARM. Addresses below are unrelocated virtual addresses,
mapped through its load segments, not a universal file-offset subtraction.
Lua line references are embedded source metadata from parse-only listings.

## Step 3 - Follow HMI selection into window visibility

The Lua module identifies `com.harman.service.HMIService`. Its availability
handler (`97-117`) subscribes `currentScreen` to `hmiCurrentScreenHandler`.
The selected handler (`53-90`) contains these command payloads, shown as static
data only; they were not sent to `/dev/DisplayManager:0`:

| HMI selection/transition | Named-window payloads in the handler |
| --- | --- |
| Enter `com.harman.screen.apps.extApps.AppTemplate` | `FlashWindow:AMS,v,1;`, `:map,v,0;` |
| Leave that selection, if the cached AMS flag is set | `FlashWindow:AMS,v,0;`, `:map,v,1;` |
| Enter `com.harman.screen.apps.mirrorlinkApps.MirrorLinkApps` | `mlc,o,1;`, `mlc,v,1;` |
| Leave that selection, if the cached MirrorLink flag is set | `mlc,v,0;` |

Each command is passed to `os.execute`; its result is discarded. Local
`AMS_visible` and `ML_visible` flags are then updated. Those flags are neither
native command acknowledgements nor proof that pixels reached the audio unit.
This is window coordination, separate from Step 80's physical display request.

Availability handling also creates `/tmp/flashHMILoaded` and sends an HMI-ready
event. The `firstMapReady` callback (`93-95`) creates `/tmp/firstMapReady`.
Initialization (`119-124`) establishes service-owner tracking. These routines
have side effects; none is a passive identification query or CarPlay-readiness
test. No marker was created and no vendor routine was invoked.

## Step 4 - Establish the stock graphics configuration

`secondary-boot.sh:38-43` starts the Screen script, waits for `/dev/screen`,
starts `DisplayManager` and waits for its resource-manager endpoint. The startup
script launches `screen`; both scripts were read, not executed.

The Jacinto5 configuration names `SGX530rev125` and sets display 1 to
800 x 480 at 60 Hz. The `mlc` class starts invisible with RGBA8888 source,
surface and window sizes of 800 x 480. Its pipeline-2 assignment is commented
out. `FlashWindow` starts invisible with order 4; framebuffer1 uses pipeline 3
and `pvr2d`. Later boot code (`230`) raises the named HMI window to order 5.
The touch configuration names a Toyota driver and 800 x 480 dimensions.

These are configuration facts, not measured runtime ownership, supported
CarPlay resolution, accessible input events or decoder throughput. Commented
video-layer settings do not prove those hardware paths are enabled.

## Step 5 - Resolve visibility and order to native property calls

Two 32-byte manager descriptors link command characters, labels, setters,
one-parameter counts and property IDs:

| Command | Descriptor VA | Label / property ID | Setter VA | Selected setter call VA |
| --- | --- | --- | --- | --- |
| `v` | `0x1285d8` | Visibility / 51 | `0x109694` | `0x109760` |
| `o` | `0x128778` | z-Order / 54 | `0x1097a8` | `0x109864` |

Both selected ARM calls resolve through the dynamic symbol table to
`screen_set_window_property_iv`. The examined setter code loads the descriptor's
property ID and supplies the window handle and integer-value pointer. Readback
calls at `0x108dc4` and `0x108f20` resolve to
`screen_get_window_property_iv`. QNX's reference published under its
6.5.0SP1.update documentation path identifies 51 as `SCREEN_PROPERTY_VISIBLE`
and 54 as `SCREEN_PROPERTY_ZORDER`, consistent with the binary labels.
[QNX Screen property types](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.screen/topic/screen_8h_1Screen_Property_Types.html).

A separate helper contains `screen_flush_context` at `0x1098e4`, with its
second argument set to zero at `0x1098dc`. This does not establish that every
setter automatically calls that helper or waits for a physical display change.
The selected routines change/read properties; they do not submit decoded frames.
`screen_post_window` is absent from the manager's listed imports, but import
absence alone is not an exhaustive proof about every possible rendering path.

The embedded usage text, read from the binary without executing a help command,
describes a visibility cache for destroyed/recreated windows. Boot starts the
manager without `-disable_cache`. Inference: a future adapter must account for
visibility restoration under this configuration. Actual cache behavior and its
complete parser/event paths have not been exercised.

## Step 6 - Constrain the eventual renderer and identify the next trace

QNX documents a first `screen_post_window` call as necessary before a window can
become visible, and notes that posting can change which rendering buffers are
available. This is an API requirement, not evidence that the GT86 displayed a
frame. That reference's argument and description sections disagree about zero
dirty-rectangle count; do not turn that edge case into an implementation
assumption without checking the target implementation.
[QNX screen_post_window](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.screen/topic/screen_post_window.html).

QNX also describes the window-manager context as privileged, controlling other
windows and their layout/input events. The candidate renderer should cooperate
with the existing manager, not assume it needs to become another global manager.
[QNX window management](https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.screen/topic/manual/cscreen_windowing-management.html).

Design requirements inferred from these findings, not implemented capabilities:

1. Own a dedicated window and its buffers. Do not reuse `mlc`, `:map`, `:hmi`
   or `FlashWindow:AMS`, or issue manager-wide visibility/close operations.
2. Keep the new window hidden until initialized content and coordinated display
   access are established; account for cached visibility during recreation.
3. Keep first-frame submission, native property/readback results, input focus
   and fresh physical display ownership distinct. A Lua flag or Screen return
   code alone does not satisfy all of them.
4. On cancellation, service loss or teardown, stop owned projection and restore
   the factory state through an established coordination path. Audio focus and
   microphone access remain separate.
5. Next, trace the existing MirrorLink window producer and its buffer creation,
   posting and teardown calls offline. This can clarify the factory Screen
   interface; MirrorLink is not CarPlay and does not prove H.264-decoder reuse.

Matching SDK/ABI, actual window permissions, usable decoding, Toyota signal
provenance, native execution/recovery and phone validation remain unresolved.
No receiver capability flag is enabled by this static investigation.

## Step 7 - Make the findings repeatable and verify the tooling

```powershell
python -B scripts/inspect_factory_graphics.py
python -B scripts/inspect_factory_graphics.py --disassemble
python -B scripts/inspect_display_control.py --instructions
python -B -m unittest discover -s tests -p 'test_*.py'
```

The new graphics tool checks five full hashes, reads selected descriptors,
resolves five callsites and parses three flat configuration classes. Default
inspection launches no subprocess. Optional disassembly uses the existing
bounded LLVM helper on an in-memory ELF-header adaptation; the selected range
is `0x109694..0x109914`. Original input bytes remain unchanged.

The Lua tool now covers five inputs and 18 complete routines, adding four HMI
routines to Step 80's historical 14. It continues to use parse-only host Lua
listing, never vendor execution. The ELF helper accepts explicit pins/base
directory without changing existing callers' defaults.

All **49 Python tests pass**, including eight new graphics tests and one new
HMI trace test. Checks include selected descriptors/calls, configuration and
comment parsing, changed-input refusal, in-memory mutation rejection and
unchanged inputs with no default subprocess. The optional bounded LLVM listing
also passed its selected-callsite and unchanged-input checks. Tests do not
emulate a manager, render video, exercise a device or demonstrate CarPlay.

No firmware bytes, USB media, service flags or vehicle state changed. Only
research tools, their tests and Markdown documentation are part of this step.
