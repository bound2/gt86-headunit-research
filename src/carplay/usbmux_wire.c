/* SPDX-License-Identifier: GPL-3.0-only */
#include "usbmux_wire.h"
static uint16_t get16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] * 256u + p[1]); }
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void put16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }
static void put32(uint8_t *p, uint32_t n) {
    p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16); p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n;
}
static void copy(uint8_t *d, const uint8_t *s, size_t n) { size_t i; for (i = 0; i < n; ++i) d[i] = s[i]; }
static int shape(uint32_t protocol, size_t length, size_t *header) {
    if (protocol != USBMUX_VERSION && protocol != USBMUX_CONTROL && protocol != USBMUX_SETUP && protocol != USBMUX_TCP)
        return IAP2_UNSUPPORTED;
    *header = protocol == USBMUX_VERSION ? 8 : 16;
    if (length < *header || (protocol == USBMUX_VERSION && length != 20) ||
        (protocol == USBMUX_SETUP && length != 17) || (protocol == USBMUX_TCP && length < 36)) return IAP2_INVALID;
    return length > USBMUX_FRAME_LIMIT ? IAP2_NO_SPACE : IAP2_OK;
}
int usbmux_frame_decode(const uint8_t *data, size_t size, usbmux_frame *out, size_t *consumed) {
    usbmux_frame value = {0, 0, 0, 0, NULL, 0}; size_t length, header; int status;
    if (consumed) *consumed = 0;
    if ((!data && size) || !out || !consumed) return IAP2_ARGUMENT;
    if (size < 8) return IAP2_MORE;
    value.protocol = get32(data); length = get32(data + 4);
    status = shape(value.protocol, length, &header); if (status) return status;
    if (size < length) return IAP2_MORE;
    if (header == 16) {
        value.magic = get32(data + 8); value.tx_sequence = get16(data + 12); value.rx_sequence = get16(data + 14);
    }
    value.payload = data + header; value.payload_size = length - header;
    *out = value; *consumed = length; return IAP2_OK;
}
int usbmux_frame_encode(const usbmux_frame *value, uint8_t *out, size_t capacity, size_t *written) {
    size_t header, length; int status;
    if (written) *written = 0;
    if (!value || !out || !written || (!value->payload && value->payload_size)) return IAP2_ARGUMENT;
    header = value->protocol == USBMUX_VERSION ? 8 : 16;
    if (value->payload_size > USBMUX_FRAME_LIMIT - header) return IAP2_NO_SPACE;
    length = header + value->payload_size;
    status = shape(value->protocol, length, &header); if (status) return status;
    if (header == 8 && (value->magic || value->tx_sequence || value->rx_sequence)) return IAP2_ARGUMENT;
    if (capacity < length) return IAP2_NO_SPACE;
    put32(out, value->protocol); put32(out + 4, (uint32_t)length);
    if (header == 16) { put32(out + 8, value->magic); put16(out + 12, value->tx_sequence); put16(out + 14, value->rx_sequence); }
    copy(out + header, value->payload, value->payload_size); *written = length; return IAP2_OK;
}
int usbmux_version_decode(const uint8_t *data, size_t size, usbmux_version *out) {
    usbmux_version value;
    if (!data || !out) return IAP2_ARGUMENT;
    if (size != 12) return IAP2_INVALID;
    value.major = get32(data); value.minor = get32(data + 4); value.padding = get32(data + 8);
    *out = value; return IAP2_OK;
}
int usbmux_version_encode(const usbmux_version *value, uint8_t *out, size_t capacity, size_t *written) {
    if (written) *written = 0;
    if (!value || !out || !written) return IAP2_ARGUMENT;
    if (capacity < 12) return IAP2_NO_SPACE;
    put32(out, value->major); put32(out + 4, value->minor); put32(out + 8, value->padding); *written = 12; return IAP2_OK;
}
int usbmux_tcp_decode(const uint8_t *data, size_t size, usbmux_tcp *out) {
    usbmux_tcp value;
    if (!data || !out) return IAP2_ARGUMENT;
    if (size < USBMUX_TCP_HEADER) return IAP2_INVALID;
    if (size > USBMUX_FRAME_LIMIT - 16) return IAP2_NO_SPACE;
    if ((data[12] >> 4) < 5 || (data[12] & 15)) return IAP2_INVALID;
    if (data[12] != 0x50) return IAP2_UNSUPPORTED;
    value.source_port = get16(data); value.destination_port = get16(data + 2);
    value.sequence = get32(data + 4); value.acknowledgement = get32(data + 8); value.flags = data[13];
    value.window = get16(data + 14); value.checksum = get16(data + 16); value.urgent = get16(data + 18);
    value.payload = data + 20; value.payload_size = size - 20; *out = value; return IAP2_OK;
}
int usbmux_tcp_encode(const usbmux_tcp *value, uint8_t *out, size_t capacity, size_t *written) {
    size_t length;
    if (written) *written = 0;
    if (!value || !out || !written || (!value->payload && value->payload_size)) return IAP2_ARGUMENT;
    if (value->payload_size > USBMUX_TCP_PAYLOAD_LIMIT) return IAP2_NO_SPACE;
    length = 20 + value->payload_size;
    if (capacity < length) return IAP2_NO_SPACE;
    put16(out, value->source_port); put16(out + 2, value->destination_port);
    put32(out + 4, value->sequence); put32(out + 8, value->acknowledgement);
    out[12] = 0x50; out[13] = value->flags; put16(out + 14, value->window);
    put16(out + 16, value->checksum); put16(out + 18, value->urgent);
    copy(out + 20, value->payload, value->payload_size); *written = length; return IAP2_OK;
}
int usbmux_stream_init(usbmux_stream *stream, uint8_t *buffer, size_t capacity) {
    if (!stream || !buffer || capacity < 36 || capacity > USBMUX_FRAME_LIMIT) return IAP2_ARGUMENT;
    stream->buffer = buffer; stream->capacity = capacity; usbmux_stream_reset(stream); return IAP2_OK;
}
void usbmux_stream_reset(usbmux_stream *stream) {
    if (stream) { stream->used = stream->expected = 0; stream->ready = 0; stream->error = IAP2_OK; }
}
int usbmux_stream_push(usbmux_stream *stream, const uint8_t *data, size_t size, size_t *consumed, usbmux_frame *out) {
    size_t taken = 0, amount, header, decoded; int status;
    if (consumed) *consumed = 0;
    if (!stream || !stream->buffer || !out || !consumed || (!data && size)) return IAP2_ARGUMENT;
    if (stream->error) return stream->error;
    if (stream->ready) { stream->ready = 0; stream->used = stream->expected = 0; }
    if (stream->used < 8) {
        amount = 8 - stream->used; if (amount > size) amount = size;
        copy(stream->buffer + stream->used, data, amount); stream->used += amount; taken += amount;
        if (stream->used < 8) { *consumed = taken; return IAP2_MORE; }
    }
    if (!stream->expected) {
        stream->expected = get32(stream->buffer + 4);
        status = shape(get32(stream->buffer), stream->expected, &header);
        if (!status && stream->expected > stream->capacity) status = IAP2_NO_SPACE;
        if (status) { *consumed = taken; stream->error = status; return status; }
    }
    amount = stream->expected - stream->used; if (amount > size - taken) amount = size - taken;
    if (amount) copy(stream->buffer + stream->used, data + taken, amount);
    stream->used += amount; taken += amount; *consumed = taken;
    if (stream->used < stream->expected) return IAP2_MORE;
    status = usbmux_frame_decode(stream->buffer, stream->used, out, &decoded);
    if (status) { stream->error = status; return status; }
    stream->ready = 1; return IAP2_OK;
}
