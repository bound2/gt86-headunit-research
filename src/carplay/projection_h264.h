/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_H264_H
#define GT86_PROJECTION_H264_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_H264_MAX_NAL (1024u * 1024u)
#define PROJECTION_H264_MAX_WIDTH 1920u
#define PROJECTION_H264_MAX_HEIGHT 1088u
typedef struct projection_h264 projection_h264;
typedef struct projection_h264_frame projection_h264_frame;
typedef enum projection_h264_result {
    PROJECTION_H264_FRAME = 0,
    PROJECTION_H264_MORE = 1,
    PROJECTION_H264_END = 2,
    PROJECTION_H264_ARGUMENT = -1,
    PROJECTION_H264_STALE = -2,
    PROJECTION_H264_STATE = -3,
    PROJECTION_H264_BITSTREAM = -4,
    PROJECTION_H264_LIMIT = -5,
    PROJECTION_H264_MEMORY = -6,
    PROJECTION_H264_BACKEND = -7
} projection_h264_result;
typedef struct projection_h264_source {
    uint32_t sar_width, sar_height; /* 0:0 = unspecified, NOT implicitly square. */
    uint32_t num_units_in_tick, time_scale; /* Nominal VUI syntax, NOT sender PTS. */
    uint8_t vui_present, aspect_present, aspect_idc, signal_present;
    uint8_t video_format, full_range, colour_present;
    uint8_t primaries, transfer, matrix; /* H.264 code points; 2 = unspecified. */
    uint8_t chroma_present, chroma_top, chroma_bottom;
    uint8_t timing_present, fixed_frame_rate;
} projection_h264_source;
typedef struct projection_h264_view {
    const uint8_t *plane[3]; /* Tight I420 Y, U, V; no codec padding. */
    uint32_t width, height, stride[3];
    uint64_t generation, timestamp; /* Opaque input timestamp, NOT a played clock. */
    size_t bytes;
    projection_h264_source source; /* Immutable per-picture SPS/VUI snapshot. */
} projection_h264_view;
/* Optional source-built OpenH264, serial/non-reentrant, one owner per stream.
 * No network, authentication, file, renderer, conversion or capability changes.
 * Compressed slices must already be authenticated, ordered and split into NALs.
 * Out-of-band SPS/PPS may follow an explicit caller clear-configuration policy;
 * do not label that configuration authenticated merely because slices are.
 * Each push accepts EXACTLY ONE Annex-B NAL (3/4-byte start code, <=1 MiB).
 * SPS preflight admits only progressive 8-bit 4:2:0 profile 66/77/100, bounded
 * coded dimensions and <=16 references; it is NOT a full H.264 validator or a
 * hard cap on all third-party heap allocations. Decoder concealment is disabled.
 * Only I/P slices are admitted. B/SP/SI slices and extension NALs are rejected;
 * B-frame pixel differences against an independent decoder remain unresolved.
 * Parameters must be resent after destroy/create. Detected malformed/unsupported
 * input, budget exhaustion and reported codec failures close this owner. Bad
 * arguments and stale generations do not mutate it. Supply a fresh, nonzero,
 * never-reused generation for each new stream; create cannot enforce global reuse.
 *
 * FRAME means exactly one independently allocated output, transferred to the
 * caller. MORE means no picture yet, never fabricated pixels. All result slots
 * must be provided and are cleared on entry (release existing frames first).
 * Output survives further decode/drain/destroy until frame_destroy exactly once.
 * Caller must bound its retained frame queue; this adapter does not own that queue.
 * Timestamp follows the codec's VCL timestamp, not a transport clock
 * conversion or scheduling guarantee. Supply the same timestamp to every slice
 * of a picture. No C++ exception crosses this C API.
 * SPS/PPS IDs select each picture's source metadata; internal codec tokens keep
 * delayed output associated even when caller timestamps repeat. At most 32
 * pending picture snapshots; exhaustion/missing associations fail closed.
 * Absent VUI keeps unspecified SAR/colour and normative limited-range default,
 * not a resolution-derived guess. This metadata is not separately authenticated.
 * create returns MORE on success; no frame is produced by initialization.
 */
int projection_h264_create(uint64_t generation, uint32_t max_width,
                           uint32_t max_height, projection_h264 **out);
int projection_h264_push(projection_h264 *, uint64_t generation, const uint8_t *,
                         size_t size, uint64_t timestamp, projection_h264_frame **out);
/* REQUIRED after every complete access unit (all slices of one picture), before
 * starting the next. <=1 MiB / 256 NALs per AU, otherwise fail closed. The first
 * slice must start at macroblock zero; later slices have nonzero starts and the
 * same timestamp. No arbitrary slice order/redundant first slices. Parameter
 * sets/AUD/SEI must precede slices. The caller, not this adapter, identifies the
 * complete AU; a transport packet boundary is not sufficient. This explicit
 * boundary also avoids a delayed-output ordering issue observed in OpenH264.
 * Does not end the stream or drain the codec's remaining output history.
 */
int projection_h264_end_access_unit(projection_h264 *, uint64_t generation,
                                    projection_h264_frame **out);
/* Terminal drain: call repeatedly until END. First finishes the pending AU,
 * then drains delayed pictures. MORE can occur on the first call. Push and
 * end_access_unit are invalid after drain starts. Destroy/create to restart. */
int projection_h264_drain(projection_h264 *, uint64_t generation,
                          projection_h264_frame **out);
int projection_h264_frame_view(const projection_h264_frame *, projection_h264_view *out);
void projection_h264_frame_destroy(projection_h264_frame *);
void projection_h264_destroy(projection_h264 *);
#ifdef __cplusplus
}
#endif
#endif
