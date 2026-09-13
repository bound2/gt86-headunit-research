/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_VIDEO_H
#define GT86_PROJECTION_VIDEO_H
#include "projection_h264.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_VIDEO_HEADER 128u
#define PROJECTION_VIDEO_CONFIG_LIMIT 65536u
typedef struct projection_video projection_video;
enum projection_video_result {
    PROJECTION_VIDEO_MORE = 1, PROJECTION_VIDEO_CONFIG = 2,
    PROJECTION_VIDEO_PACKET = 3, PROJECTION_VIDEO_IGNORED = 4,
    PROJECTION_VIDEO_FRAME = 5, PROJECTION_VIDEO_BUSY = 6, PROJECTION_VIDEO_END = 7,
    PROJECTION_VIDEO_ARGUMENT = -1, PROJECTION_VIDEO_STALE = -2,
    PROJECTION_VIDEO_STATE = -3, PROJECTION_VIDEO_WIRE = -4,
    PROJECTION_VIDEO_AUTH = -5, PROJECTION_VIDEO_FORMAT = -6,
    PROJECTION_VIDEO_LIMIT = -7, PROJECTION_VIDEO_MEMORY = -8,
    PROJECTION_VIDEO_DEADLINE = -9
};
typedef struct projection_video_config {
    uint32_t max_width, max_height; /* Coded limits, as in projection_h264_create. */
    uint32_t receive_ms, hold_ms; /* Absolute per-record / queued-frame; 1..60000. */
    uint8_t queue_frames; /* 2..8; two free slots reserved before accepting input. */
    uint8_t allow_clear_config; /* Must explicitly be 1 for this wire profile. */
} projection_video_config;
typedef struct projection_video_metadata {
    uint64_t generation, configuration_epoch, counter, received_ms;
    uint8_t header[PROJECTION_VIDEO_HEADER]; /* Original authenticated FRAME header. */
    uint8_t frame_authenticated, configuration_authenticated; /* 1 and 0 respectively. */
} projection_video_metadata;
typedef struct projection_video_configuration {
    uint64_t generation, epoch;
    uint8_t profile, length_size, authenticated; /* Configuration is NOT authenticated. */
} projection_video_configuration;
/* Serial heap-owning screen child. No sockets, keys generated here, display,
 * frame scheduling or receiver capability changes. Bind ONLY a fresh directional
 * key from the verified session's screen resource and pin its TCP peer outside
 * this layer. Exactly one transport for its lifetime; no reconnect/nonce reset.
 * The generation must be fresh and nonzero. Buffers/arguments are disjoint.
 *
 * LIVI-reference wire profile: 128-byte header, LE32 body size, opcode at byte4.
 * Config (1) is CLEARTEXT and advances no nonce; explicit acceptance policy is
 * required. Frames (0) require ciphertext + 16-byte Poly1305 tag, whole header
 * as AAD, nonce zero32 || LE64 counter, starting at zero. Short untagged frames
 * are rejected. Unknown opcodes are bounded ignored records, never commands.
 * Malformed/authentication/decoder/deadline failures close, release queued
 * frames, and wipe wire/plain/key buffers. Pixel allocations are not securely wiped.
 *
 * Config accepts a bare avcC, exact avcC box or correctly bounded avc1 sample entry
 * containing one avcC box. No arbitrary fourcc search, HEVC or SPS extensions.
 * Length prefixes are 1/2/4 bytes. Each frame message is one complete access unit;
 * this mapping remains to be verified with a real phone. Initial/reconfigured
 * video requires an IDR. In-band SPS/PPS must match the current configuration;
 * changed sets need a new configuration record. Reconfiguration replaces history and drops queued
 * old frames WITHOUT resetting the nonce; CONFIG announces the new epoch.
 * Frames transferred earlier remain allocated, but caller must invalidate old
 * epochs before presentation. Retain/check epoch alongside every owned frame.
 *
 * Decoder timestamp is the authenticated RECORD COUNTER, not a guessed wire PTS.
 * Raw authenticated headers remain in metadata for later timing investigation.
 * Counter UINT64_MAX is usable once. No successful receive/decode means played.
 * No C++ exceptions cross this interface. create returns MORE, not readiness.
 */
int projection_video_create(const projection_video_config *, const uint8_t key[32],
                            uint64_t generation, uint64_t now_ms, projection_video **out);
/* Feed consumes at most ONE record, leaves coalesced tail with caller, and keeps
 * partial input until complete. No pointer retention. BUSY consumes zero; no
 * timeout is refreshed by backpressure or partial input. Decoding/queueing can
 * precede RECORD, but take is gated by explicit start after control reply drain.
 */
int projection_video_feed(projection_video *, uint64_t, const uint8_t *, size_t,
                          size_t *consumed, uint64_t now_ms);
int projection_video_start(projection_video *, uint64_t, uint64_t now_ms);
int projection_video_check(projection_video *, uint64_t, uint64_t now_ms);
uint32_t projection_video_next_delay(const projection_video *);
int projection_video_get_configuration(const projection_video *, uint64_t,
                                       projection_video_configuration *out);
/* FRAME transfers one H.264 frame and metadata; destroy it exactly once using
 * projection_h264_frame_destroy. Caller bounds frames retained outside this
 * queue. Output slots are cleared on entry; release existing frames first. */
int projection_video_take(projection_video *, uint64_t, projection_h264_frame **out,
                          projection_video_metadata *, uint64_t now_ms);
/* Explicit clean source EOF. Partial wire record is an error. Stops input,
 * wipes key and drains codec output into the bounded queue. Retry BUSY after
 * taking frames; END means codec drain completed, queue may still contain frames.
 * Transport errors/TEARDOWN should destroy instead of presenting a drained tail. */
int projection_video_finish(projection_video *, uint64_t, uint64_t now_ms);
void projection_video_destroy(projection_video *);
#ifdef __cplusplus
}
#endif
#endif
