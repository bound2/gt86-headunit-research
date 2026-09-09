/* SPDX-License-Identifier: GPL-3.0-or-later
 * Protocol reference: LIVI, Copyright (C) 2025 Lasse Heitgres.
 * See third_party/README.md for the pinned source and license.
 */
#ifndef GT86_IAP2_WIRE_H
#define GT86_IAP2_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum iap2_result {
    IAP2_OK = 0, IAP2_MORE = 1, IAP2_END = 2,
    IAP2_INVALID = -1, IAP2_NO_SPACE = -2, IAP2_ARGUMENT = -3,
    IAP2_UNSUPPORTED = -4, IAP2_AUTH_FAILED = -5, IAP2_PROVIDER_FAILED = -6
};

#define IAP2_LINK_HEADER_SIZE 9u
#define IAP2_MAX_FRAME_SIZE 65535u

/* This marker is exchanged before link frames, not passed to the frame decoder. */
extern const uint8_t iap2_detect_marker[6];

typedef struct iap2_frame {
    uint8_t control, sequence, acknowledgement, session;
    int has_payload; /* Distinguishes no payload from an empty checksummed payload. */
    const uint8_t *payload;
    size_t payload_size;
} iap2_frame;

typedef struct iap2_message {
    uint16_t id;
    const uint8_t *params;
    size_t params_size;
} iap2_message;

typedef struct iap2_param {
    uint16_t id;
    const uint8_t *data;
    size_t size;
} iap2_param;

/* Input/output pointers must be non-null unless the corresponding size is zero.
 * Decoders return views into the input; the caller owns its lifetime.
 * Encoders validate sizes before writing; input and output must not overlap.
 * On failure *consumed and *written are zero. Decode consumes one frame/message,
 * allowing callers to handle coalesced transport data without discarding it.
 */
int iap2_frame_decode(const uint8_t *data, size_t size,
                      iap2_frame *frame, size_t *consumed);
int iap2_frame_encode(const iap2_frame *frame, uint8_t *out,
                      size_t capacity, size_t *written);
int iap2_message_decode(const uint8_t *data, size_t size,
                        iap2_message *message, size_t *consumed);
int iap2_message_encode(uint16_t id, const iap2_param *params, size_t count,
                        uint8_t *out, size_t capacity, size_t *written);
int iap2_params_validate(const uint8_t *data, size_t size);
/* Start with offset=0; IAP2_END means all parameters have been consumed.
 * Duplicate/unknown parameters are preserved; typed handlers apply semantics.
 */
int iap2_param_next(const iap2_message *message, size_t *offset, iap2_param *param);

typedef struct iap2_stream {
    uint8_t *buffer;
    size_t capacity, used, discarded;
} iap2_stream;

/* Caller supplies 9..65535 bytes of receive storage. No allocations or I/O.
 * push returns one complete frame at a time and the number of input bytes used.
 * A returned frame view lasts until the next push/init. Remaining input belongs
 * to the caller. Bad headers are scanned past; an oversized packet or bad body
 * checksum is reported and clears buffered state. A transport timeout/EOF must
 * discard partial data by reinitializing the stream. No timeout is hidden here.
 */
int iap2_stream_init(iap2_stream *stream, uint8_t *buffer, size_t capacity);
int iap2_stream_push(iap2_stream *stream, const uint8_t *data, size_t size,
                     size_t *consumed, iap2_frame *frame);

#ifdef __cplusplus
}
#endif
#endif
