# Step 90 - Owned video colour conversion and native rendering

Date: 2026-09-17. Continues [session-bound video TCP](projection-video-services.md).

Follow-up: [Step 91](projection-video-source.md) implements per-picture SPS/VUI
metadata and opt-in strict source colour/SAR rendering. This report retains the
Step 90 policy and test counts as historical evidence.

## Result and boundary

Decoded video now has a real Windows GDI sink, with independently owned BGRA
pixels, explicit colour selection, aspect-preserving resize, repaint and
epoch/teardown invalidation. A separate C99 converter is independent of Windows
and the codec implementation. Real encrypted IPv4/IPv6 TCP input reaches actual
GDI bitmap surfaces through the Step 89 service and H.264 decoder.

Forty rendered frames match an independent FFmpeg decode plus floating-point
colour calculation, with zero observed RGB component difference on that fixture.
This is **host rendering, not CarPlay working on the car**. The native bitmap
drawing path is exercised; the HWND branch has hidden-window lifecycle tests,
not a visible-window scan-out or physical display test. No visible window was
opened. No actual phone, MFi chip, factory display, firmware or vehicle state was
used or changed. The factory software-only requirement remains unchanged.

## 1. Define colour conversion without guessing sender metadata

Public [pixel API](../src/carplay/projection_video_pixels.h) and
[C99 implementation](../src/carplay/projection_video_pixels.c) accept the existing
decoder's contiguous, tight, even-sized I420 view. The caller must explicitly
choose one of four modes:

| Mode | Matrix | Luma range | Neutral chroma |
| --- | --- | --- | --- |
| `BT601_LIMITED` | Kr=.299, Kb=.114 | 16..235 | 128 |
| `BT601_FULL` | Kr=.299, Kb=.114 | 0..255 | 128 |
| `BT709_LIMITED` | Kr=.2126, Kb=.0722 | 16..235 | 128 |
| `BT709_FULL` | Kr=.2126, Kb=.0722 | 0..255 | 128 |

The limited-range conversion scales luma by 255/219 and chroma differences by
255/224. Full-range uses unit scale. Q16 integer coefficients implement the
matrix, round to the nearest output value and clip each component to 0..255.
Chroma samples are replicated over 2x2 luma blocks. The output is top-down BGRA8,
with alpha 255; the GDI BI_RGB destination's fourth byte is not an alpha contract.
The matrix/range basis is cross-checked against Microsoft's
[YUV conversion reference](https://learn.microsoft.com/en-us/windows/win32/medfound/recommended-8-bit-yuv-formats-for-video-rendering).

This is a local conversion implementation, not copied reference code. It
validates dimensions, tight plane offsets/strides, exact input size, destination
stride/capacity, arithmetic bounds and pixel-storage overlap before writing.
Caller storage must be live and disjoint from the descriptor too. It does no
allocation, authentication, platform I/O or automatic capability declaration.

Colour metadata is not yet carried from SPS/VUI to this output interface. The
matrix/range must not be inferred from resolution or advertised as discovered
from a phone. Transfer functions, primary/gamut conversion, HDR, ICC management,
phase-aware chroma filtering and non-square sample aspect ratios are not handled.
These are outstanding compatibility requirements, not silently assumed defaults.

## 2. Bind the native sink explicitly

The [GDI API](../src/carplay/projection_video_gdi.h) and
[implementation](../src/carplay/projection_video_gdi_win.cpp) expose the existing
`projection_video_sink` callbacks. They create no window, message loop, worker,
default target or receiver capabilities.

1. Bind one or two explicit screen types (110/111), unique targets, colour modes
   and source/target bounds. A target is either a caller-owned HWND or an exclusive
   caller-owned memory DC containing a 32-bit BI_RGB DIB section. The latter is
   explicitly offscreen rendering, not physical display availability.
2. HWNDs must belong to this process and creating thread. Both the window and
   calling thread must be per-monitor DPI aware. This implementation uses Windows
   10 1607+ DPI queries and rejects other awareness states; it never changes the
   application's DPI policy. Microsoft's separate
   [thread](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getthreaddpiawarenesscontext)
   and [window](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowdpiawarenesscontext)
   queries establish why both are checked.
3. Assign `projection_video_gdi_sink(renderer)` to Step 89's `config.sink` before
   constructing that service. Continue composing the video service under the
   root receiver provider; do not bypass pair-verify, MFi or reply-drain gates.
4. Keep all callbacks, polling, WM_PAINT and teardown on the creating thread,
   serial and non-reentrant. Bindings remain valid/exclusive through destruction.
   Route the target's WM_PAINT to `projection_video_gdi_paint`, which pairs
   [BeginPaint](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-beginpaint)
   and EndPaint. Stop that routing before destroying the opaque owner.
5. A real application's `/info` availability callback still needs to verify its
   complete usable output/input/audio configuration. No such readiness is
   inferred from a memory DC or successful library construction.

Common window DCs are acquired/released on that same thread. Private/class DCs
remain window-owned; they must not be treated as failed common-DC releases.
This follows the [ReleaseDC contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-releasedc).
The caller retains ownership of every HWND, DC and selected DIB.

## 3. Retain copies, not decoder pointers

`open` prepares a monotonic child lease without drawing a frame. Configuration
retires old pixel copies and clears/invalidates the target; it can precede
RECORD. `start` enables submission only after the owning service's control reply
has drained. Frames must match generation and configuration epoch and retain
strictly increasing record counters across reconfiguration. Metadata must keep
the frame-authenticated/configuration-unauthenticated distinction. This is a
consistency check on a trusted service contract, not a new authentication boundary.

Submission converts into an independently owned work buffer. Only successful
drawing swaps it into the retained current frame. The decoder's view is never
retained. There is no playback queue: at most two BGRA buffers per screen,
including during growth. The bound is `2 * max_width * max_height * 4` bytes
(16,711,680 bytes at 1920x1088), plus small owner state. Decoder/input queues and
OS/caller display allocations are separate and may be substantial.

Hidden, minimized, zero-sized or fully clipped targets return backpressure
without accepting the frame. Step 89 continues owning that frame and enforcing
its absolute hold deadline; this sink grants no new timeout. An accepted current
frame is retained for repaint until replaced, reconfigured or closed, not treated
as a queued future presentation. Owned CPU buffers are wiped before release;
this does not establish erasure of copies held by the OS/display driver.

Native drawing uses a top-down DIB and
[StretchDIBits](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-stretchdibits),
with nearest/COLORONCOLOR scaling into a centred square-pixel fit and black
letterboxing. The fit floors the secondary extent, with a one-pixel minimum;
an odd spare pixel remains on the right/bottom. A saved DC state is restored
after normalizing transforms, origin, layout, clipping and colour-management mode.
The service polls for size changes and redraws its retained copy; WM_PAINT also
redraws that copy without accessing the retired decoder frame.

Draw/repaint counts, dimensions, generation-bound leases, epochs and counters
are observable. Counts saturate rather than wrapping. Successful drawing and
[GdiFlush](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-gdiflush)
do **not** establish physical scan-out time, vsync, phone timestamp mapping or
A/V synchronization. There is no fabricated presentation clock.

## 4. Invalidate old output through teardown and failure

Partial close retires only the named screen, wipes/releases both copies and
clears/invalidates that target. Other screens remain usable. Reconfiguration
discards the previous frame before acknowledging the new epoch; a subsequent
resize cannot resurrect it. A fresh child may restart its local counter check
only under the enclosing session's fresh stream/key lifetime.

Invalid input metadata, OS target loss, unsupported target layout, allocation
failure or drawing error terminates this renderer's active children. The owning
service/receiver must immediately consume that failure and close its other
resources. Stale API generations, wrong-thread calls and nonexistent leases do not
mutate live output. Close/destroy must run on the creating thread.

Blanking a lost or unavailable OS target is best effort. While the renderer owner
still exists, closed/failed HWND bindings retain black-only WM_PAINT handling;
they never replay released source pixels. Before deleting the owner, remove its
message route and take over repainting or close the window after releasing the
owner. Do not leave a window procedure holding a freed context.

## 5. Reproduce the verification

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayVideo.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayVideoSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayPixelsArm.ps1
./build/media-reference/Scripts/python.exe -B scripts/check_projection_video_render.py build/video/Release/projection_video_gdi_tests.exe build/openh264-2.6.0/res
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_video.py build/video/Release/projection_video_tests.exe build/openh264-2.6.0/res
./build/media-reference/Scripts/python.exe -B scripts/check_projection_h264.py build/video/Release/projection_h264_tests.exe build/openh264-2.6.0/res
python -B -m unittest discover -s tests -p 'test_*.py'
git diff --check
```

The pixel implementation has no Windows/OpenH264 dependency. A clean host build
with all three optional codec/crypto source paths empty also passes its test;
the ARM object check is separate below. The optional GDI target requires the
existing Windows video-service configuration. No new downloaded
library is introduced. Windows `gdi32`/`user32` supply native calls; the source and
Python dependency pins/limits remain those recorded in Steps 87-89.

Verification for this step:

- **46/46 optional-video CTest suites pass**, including pixel and GDI suites.
  The complete GDI suite also passes five consecutive normal reruns.
- **6/6 media sanitizer suites pass**, with local C/C++, OpenH264 and crypto
  dependencies instrumented. Windows DLL internals are not instrumented; their
  returned status and actual bitmap pixels are tested. No disabled checks or
  Windows leak-sanitizer claim.
- The portable test checks **230,400 colour triples / 921,600 output pixels**
  against separately derived double-precision equations, allowing at most one
  level of fixed-point rounding error. It also covers chroma layout, padding,
  rejected aliases/bounds, maximum dimensions and fit geometry.
- GDI tests cover retained-copy repaint, upscaling/letterboxing, DC-state
  restoration, multiple targets, counter/epoch rejection, partial/full cleanup,
  DPI/wrong-thread guards, hidden HWND backpressure and target loss. Hidden
  windows exercise message lifetime, not visible-window pixel presentation.
- Four colour modes each render ten public `Static.264` pictures over IPv4 and
  IPv6. Tests additionally verify epoch clearing, retained counters and tag-failure
  blanking. The shared synthetic wire helper is factored out of Step 89's test;
  its original full receiver tests still pass.
- The independent [render checker](../scripts/check_projection_video_render.py)
  verifies the fixture SHA256, uses pinned PyAV 18.1.0 / native FFmpeg h264, computes
  RGB independently, and compares 40 real GDI readbacks and frame order. Maximum
  observed B/G/R difference is **0** for every mode. Destination alpha is excluded
  deliberately. This is not a real-phone capture or an independent reference for
  every GDI scaling ratio.
- Previous **740 encrypted/decrypted/decoded** and **395 independent decoder**
  frame checks pass again; all **83 Python regression tests pass**.
- The separate ARM check compiles the C99 pixel implementation to a 32-bit
  Cortex-A8-targeted object. Its sole unresolved helper is `__aeabi_uidiv`.
  This is not part of the earlier import-free core claim and is **not a QNX
  executable, verified unit CPU match, on-device performance test or GDI port**.

## 6. Next work toward the actual unit

Carry verified source colour/range and sample-aspect-ratio metadata through the
decoder/configuration path before selecting output automatically. Establish
sender presentation timestamps and continuous A/V mapping from evidence; record
counters and GDI completion are not substitutes. Visible HWND/device behavior,
physical input and actual-phone interoperability still require validation.

The portable converter and explicit ownership contract can support a future
native target renderer, but this Windows backend cannot be installed on QNX.
The factory path still needs a matching ARM/QNX compiler/runtime, safe
installed-version execution/recovery, USB/authentication-chip ownership,
display/input routing, audio focus/microphone access and measured memory/CPU
budget. Do not call private AIR offsets or replace these gates with host success.
The owner's module revision remains unknown; no additional identification data
is assumed. The later 6.17.0WL corpus remains offline research, not an update to
flash over the installed 6.9.0WL unit.
