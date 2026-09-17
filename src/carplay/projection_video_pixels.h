/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_VIDEO_PIXELS_H
#define GT86_PROJECTION_VIDEO_PIXELS_H
#include "projection_h264.h"
#ifdef __cplusplus
extern "C" {
#endif
enum projection_video_color {
    PROJECTION_VIDEO_BT601_LIMITED=1, PROJECTION_VIDEO_BT601_FULL=2,
    PROJECTION_VIDEO_BT709_LIMITED=3, PROJECTION_VIDEO_BT709_FULL=4,
    PROJECTION_VIDEO_SOURCE=5 /* GDI policy only; never a raw conversion mode. */
};
typedef struct projection_video_rect { uint32_t x,y,width,height; } projection_video_rect;
/* CPU conversion of the decoder's contiguous tight even-sized I420 view to
 * top-down BGRA8 (A=255). Caller supplies disjoint live storage; bad arguments
 * write nothing. No allocation or platform I/O. Chroma uses nearest 2x2 samples,
 * not phase-aware interpolation. Explicit matrix/range, no size-based guess,
 * VUI parsing, transfer/primary conversion, HDR, ICC or presentation timing.
 * Returns 0 or -1. Dimensions are bounded by the existing decoder maxima.
 */
int projection_video_bgra(const projection_h264_view *,enum projection_video_color,
                          uint8_t *out,size_t capacity,size_t stride);
/* Centred fit, no cropping/stretch. Floor the fitted extent, minimum one pixel;
 * odd spare pixels remain on right/bottom. Destination each 1..4096. */
int projection_video_fit(uint32_t width,uint32_t height,uint32_t target_width,
                         uint32_t target_height,projection_video_rect *);
/* Explicit sample aspect ratio, each 1..65535. Same fit/rounding contract. */
int projection_video_fit_sar(uint32_t width,uint32_t height,uint32_t sar_width,
                             uint32_t sar_height,uint32_t target_width,
                             uint32_t target_height,projection_video_rect *);
/* Resolve explicitly signalled SDR matrix/range, with known SDR transfer and
 * primaries only. Missing/unknown/HDR values reject; no resolution-based guess.
 * This selects Y'CbCr -> source R'G'B', NOT display gamut/transfer management.
 * Does not resolve SAR. Returns 0 or -1 without modifying output on failure. */
int projection_video_source_color(const projection_h264_source *,enum projection_video_color *);
#ifdef __cplusplus
}
#endif
#endif
