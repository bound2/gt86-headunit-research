/* SPDX-License-Identifier: GPL-3.0-or-later
 * Protocol reference: LIVI, Copyright (C) 2025 Lasse Heitgres.
 * Bounded C99 implementation; no operating system or runtime dependencies.
 */
#include "iap2_wire.h"

const uint8_t iap2_detect_marker[6] = {0xff, 0x55, 0x02, 0x00, 0xee, 0x10};

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static void write16(uint8_t *p, size_t n) {
    p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n;
}
static uint8_t sum8(const uint8_t *p, size_t n) {
    uint8_t sum = 0;
    size_t i;
    for (i = 0; i < n; ++i) sum = (uint8_t)(sum + p[i]);
    return sum;
}
static void copy_bytes(uint8_t *out, const uint8_t *data, size_t size) {
    size_t i;
    for (i = 0; i < size; ++i) out[i] = data[i];
}

int iap2_frame_decode(const uint8_t *data, size_t size,
                      iap2_frame *frame, size_t *consumed) {
    size_t total;
    iap2_frame result;
    if (consumed) *consumed = 0;
    if (!consumed || !frame || (!data && size)) return IAP2_ARGUMENT;
    if (size < 2) return IAP2_MORE;
    if (data[0] != 0xff || data[1] != 0x5a) return IAP2_INVALID;
    if (size < IAP2_LINK_HEADER_SIZE) return IAP2_MORE;
    total = read16(data + 2);
    if (total < IAP2_LINK_HEADER_SIZE || sum8(data, 9) != 0) return IAP2_INVALID;
    if (size < total) return IAP2_MORE;
    result.control = data[4]; result.sequence = data[5];
    result.acknowledgement = data[6]; result.session = data[7];
    result.has_payload = total > IAP2_LINK_HEADER_SIZE;
    result.payload_size = result.has_payload ? total - 10 : 0;
    result.payload = result.has_payload ? data + 9 : NULL;
    if (result.has_payload && sum8(data + 9, total - 9) != 0) return IAP2_INVALID;
    *frame = result; *consumed = total;
    return IAP2_OK;
}

int iap2_frame_encode(const iap2_frame *frame, uint8_t *out,
                      size_t capacity, size_t *written) {
    size_t total;
    if (written) *written = 0;
    if (!frame || !out || !written ||
        (!frame->payload && frame->payload_size) ||
        (!frame->has_payload && frame->payload_size)) return IAP2_ARGUMENT;
    if (frame->payload_size > IAP2_MAX_FRAME_SIZE - 10u) return IAP2_NO_SPACE;
    total = frame->has_payload ? frame->payload_size + 10 : 9;
    if (capacity < total) return IAP2_NO_SPACE;
    out[0] = 0xff; out[1] = 0x5a; write16(out + 2, total);
    out[4] = frame->control; out[5] = frame->sequence;
    out[6] = frame->acknowledgement; out[7] = frame->session;
    out[8] = (uint8_t)(0u - sum8(out, 8));
    if (frame->has_payload) {
        copy_bytes(out + 9, frame->payload, frame->payload_size);
        out[total - 1] = (uint8_t)(0u - sum8(frame->payload, frame->payload_size));
    }
    *written = total;
    return IAP2_OK;
}

int iap2_params_validate(const uint8_t *data, size_t size) {
    size_t offset = 0;
    if (!data && size) return IAP2_ARGUMENT;
    while (offset < size) {
        size_t length;
        if (size - offset < 4) return IAP2_INVALID;
        length = read16(data + offset);
        if (length < 4 || length > size - offset) return IAP2_INVALID;
        offset += length;
    }
    return IAP2_OK;
}

int iap2_message_decode(const uint8_t *data, size_t size,
                        iap2_message *message, size_t *consumed) {
    size_t total;
    if (consumed) *consumed = 0;
    if (!message || !consumed || (!data && size)) return IAP2_ARGUMENT;
    if (size < 2) return IAP2_MORE;
    if (data[0] != 0x40 || data[1] != 0x40) return IAP2_INVALID;
    if (size < 6) return IAP2_MORE;
    total = read16(data + 2);
    if (total < 6) return IAP2_INVALID;
    if (size < total) return IAP2_MORE;
    if (iap2_params_validate(data + 6, total - 6) != IAP2_OK) return IAP2_INVALID;
    message->id = read16(data + 4);
    message->params = data + 6; message->params_size = total - 6;
    *consumed = total;
    return IAP2_OK;
}

int iap2_param_next(const iap2_message *message, size_t *offset, iap2_param *param) {
    size_t length;
    if (!message || !offset || !param || (!message->params && message->params_size))
        return IAP2_ARGUMENT;
    if (*offset > message->params_size) return IAP2_INVALID;
    if (*offset == message->params_size) return IAP2_END;
    if (message->params_size - *offset < 4) return IAP2_INVALID;
    length = read16(message->params + *offset);
    if (length < 4 || length > message->params_size - *offset) return IAP2_INVALID;
    param->id = read16(message->params + *offset + 2);
    param->data = message->params + *offset + 4; param->size = length - 4;
    *offset += length;
    return IAP2_OK;
}

int iap2_message_encode(uint16_t id, const iap2_param *params, size_t count,
                        uint8_t *out, size_t capacity, size_t *written) {
    size_t i, total = 6, offset = 6;
    if (written) *written = 0;
    if (!out || !written || (!params && count)) return IAP2_ARGUMENT;
    /* Each parameter consumes at least four bytes. Bound the preflight loop. */
    if (count > (IAP2_MAX_FRAME_SIZE - 6u) / 4u) return IAP2_NO_SPACE;
    for (i = 0; i < count; ++i) {
        if (!params[i].data && params[i].size) return IAP2_ARGUMENT;
        if (total > IAP2_MAX_FRAME_SIZE - 4u ||
            params[i].size > IAP2_MAX_FRAME_SIZE - total - 4u) return IAP2_NO_SPACE;
        total += 4 + params[i].size;
    }
    if (capacity < total) return IAP2_NO_SPACE;
    out[0] = 0x40; out[1] = 0x40; write16(out + 2, total); write16(out + 4, id);
    for (i = 0; i < count; ++i) {
        write16(out + offset, params[i].size + 4);
        write16(out + offset + 2, params[i].id);
        copy_bytes(out + offset + 4, params[i].data, params[i].size);
        offset += params[i].size + 4;
    }
    *written = total;
    return IAP2_OK;
}

int iap2_stream_init(iap2_stream *stream, uint8_t *buffer, size_t capacity) {
    if (!stream || !buffer || capacity < 9 || capacity > IAP2_MAX_FRAME_SIZE)
        return IAP2_ARGUMENT;
    stream->buffer = buffer; stream->capacity = capacity;
    stream->used = 0; stream->discarded = 0;
    return IAP2_OK;
}

static void discard_byte(iap2_stream *stream) {
    size_t i;
    for (i = 1; i < stream->used; ++i) stream->buffer[i-1] = stream->buffer[i];
    --stream->used; ++stream->discarded;
}

int iap2_stream_push(iap2_stream *stream, const uint8_t *data, size_t size,
                     size_t *consumed, iap2_frame *frame) {
    if (consumed) *consumed = 0;
    if (!stream || !consumed || !frame || (!data && size) || !stream->buffer ||
        stream->capacity < 9 || stream->capacity > IAP2_MAX_FRAME_SIZE ||
        stream->used >= stream->capacity) return IAP2_ARGUMENT;
    while (*consumed < size) {
        size_t total, parsed;
        int status;
        stream->buffer[stream->used++] = data[(*consumed)++];
        for (;;) {
            if (stream->used && stream->buffer[0] != 0xff) { discard_byte(stream); continue; }
            if (stream->used >= 2 && stream->buffer[1] != 0x5a) { discard_byte(stream); continue; }
            if (stream->used < 9) break;
            total = read16(stream->buffer + 2);
            if (total < 9 || sum8(stream->buffer, 9) != 0) { discard_byte(stream); continue; }
            if (total > stream->capacity) { stream->used = 0; return IAP2_NO_SPACE; }
            if (stream->used < total) break;
            status = iap2_frame_decode(stream->buffer, stream->used, frame, &parsed);
            stream->used = 0;
            return status;
        }
    }
    return IAP2_MORE;
}
