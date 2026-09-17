/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_VIDEO_GDI_H
#define GT86_PROJECTION_VIDEO_GDI_H
#include "projection_video_services.h"
#include "projection_video_pixels.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_VIDEO_GDI_CLOSED (-7)
typedef struct projection_video_gdi projection_video_gdi;
typedef struct projection_video_gdi_target {
    uint32_t type; /* 110 or 111, unique; no default target. */
    enum projection_video_color color;
    uintptr_t window; /* Caller-owned HWND from this process/current thread. */
    uintptr_t memory_dc; /* OR caller-owned exclusive memory HDC with 32-bit DIB. Test/offscreen only. */
} projection_video_gdi_target;
typedef struct projection_video_gdi_config {
    projection_video_gdi_target targets[2]; size_t count;
    uint32_t max_width,max_height,max_target_width,max_target_height;
} projection_video_gdi_config;
typedef struct projection_video_gdi_status {
    uint64_t lease,epoch,counter,draws,repaints;
    uint32_t width,height,target_width,target_height;
    uint8_t active,started,has_frame;
} projection_video_gdi_status;
/* Optional Windows sink, not a QNX backend or default /info capability.
 * Windows 10 1607+ APIs. Window AND calling thread must be per-monitor DPI
 * aware; caller owns that choice, no process/thread DPI mode is changed here.
 * All calls on creating thread; serial/non-reentrant. Borrowed windows/DCs
 * must remain exclusively bound and valid through destroy. Memory targets are
 * real offscreen GDI rendering, NOT physical display availability. Do not bind
 * arbitrary desktop/other-process windows or select/delete a live target DC.
 * Caller may replace its selected DIB for resizing between calls.
 *
 * The sink owns converted copies, never decoder pointers. At most two bounded
 * BGRA buffers per configured screen, reused across frames; no playback queue.
 * submit returns MORE without accepting on a hidden/minimized/zero-size window.
 * Successful GDI drawing+GdiFlush increments draws, NOT a scan-out/presentation
 * clock. No invented PTS, vsync or A/V synchronization. Explicit square-pixel
 * fit/nearest scaling, opaque BGRA, no automatic source colour interpretation.
 * configure retires old frame storage and clears the target before returning.
 * poll repaints a resized target; caller routes WM_PAINT to paint below.
 * close invalidates all owned copies; blanking an unavailable/lost OS target is
 * best effort. Closed/failing windows continue black-only WM_PAINT handling
 * while this owner exists. Before destroy, remove its message route and take
 * over repainting (or close the window after releasing this owner).
 * Terminal failures require owning video service/receiver closure immediately.
 * No window creation/showing, worker thread, message loop or hardware discovery.
 */
int projection_video_gdi_create(const projection_video_gdi_config *,uint64_t,projection_video_gdi **);
projection_video_sink projection_video_gdi_sink(projection_video_gdi *);
/* Call only for this target's WM_PAINT, instead of caller BeginPaint/EndPaint.
 * Handles black repaint for closed/failing leases, including after close.
 * Owner outlives routing. Counter statistics saturate at UINT64_MAX. */
int projection_video_gdi_paint(projection_video_gdi *,uint64_t,uint32_t type);
int projection_video_gdi_get_status(const projection_video_gdi *,uint64_t,uint32_t type,projection_video_gdi_status *);
int projection_video_gdi_error(const projection_video_gdi *);
void projection_video_gdi_close(projection_video_gdi *);
void projection_video_gdi_destroy(projection_video_gdi *);
#ifdef __cplusplus
}
#endif
#endif
