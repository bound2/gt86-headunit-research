/* SPDX-License-Identifier: GPL-3.0-only */
#include "usbmux_host.h"

static void clear(void *p, size_t n) { size_t i; for (i = 0; i < n; ++i) ((uint8_t *)p)[i] = 0; }
static int initialized(const usbmux_host *p) { return p && p->rx.buffer && p->tx; }
static int active(const usbmux_host *p) { return p->state >= USBMUX_HOST_VERSION_TX && p->state <= USBMUX_HOST_READY; }
static uint32_t smaller(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t remaining(uint64_t now, uint64_t at, uint32_t budget) {
    uint64_t age = now - at; return age >= budget ? 0 : budget - (uint32_t)age;
}
static void discard(usbmux_host *p) {
    usbmux_stream_reset(&p->rx); clear(&p->packet, sizeof p->packet);
    p->tx_size = p->tx_offset = 0; p->held = p->rx_timer = 0;
    p->tx_at = p->rx_at = 0;
}
static int stop(usbmux_host *p, enum usbmux_host_reason reason, int error) {
    if (active(p)) {
        p->state = USBMUX_HOST_DEAD; p->reason = reason; p->last_error = error; discard(p);
    }
    return USBMUX_HOST_CLOSED;
}
uint32_t usbmux_host_next_delay(const usbmux_host *p) {
    uint32_t delay = UINT32_MAX;
    if (!initialized(p) || !active(p)) return delay;
    if (p->state != USBMUX_HOST_READY) delay = remaining(p->now, p->started_at, p->config.handshake_ms);
    if (p->tx_size) delay = smaller(delay, remaining(p->now, p->tx_at, p->config.write_ms));
    if (p->rx_timer) delay = smaller(delay, remaining(p->now, p->rx_at, p->config.receive_ms));
    return delay;
}
static int tick(usbmux_host *p, uint64_t generation, uint64_t now) {
    if (!initialized(p)) return IAP2_ARGUMENT;
    if (!active(p)) return USBMUX_HOST_CLOSED;
    if (generation != p->generation) return stop(p, USBMUX_HOST_REASON_STALE, IAP2_INVALID);
    if (now < p->now) return IAP2_ARGUMENT;
    p->now = now;
    if (!usbmux_host_next_delay(p)) return stop(p, USBMUX_HOST_REASON_DEADLINE, USBMUX_HOST_CLOSED);
    return IAP2_OK;
}
void usbmux_host_default_config(usbmux_host_config *config) {
    if (config) {
        config->sequence = USBMUX_HOST_USBMUXD;
        config->handshake_ms = 2000; config->write_ms = 250; config->receive_ms = 5000;
    }
}
int usbmux_host_init(usbmux_host *p, const usbmux_host_config *config,
                     uint8_t *rx, size_t rx_capacity, uint8_t *tx, size_t tx_capacity) {
    if (!p || !config || !rx || !tx || rx == tx || rx_capacity < 36 || tx_capacity < 36 ||
        rx_capacity > USBMUX_FRAME_LIMIT || tx_capacity > USBMUX_FRAME_LIMIT ||
        (config->sequence != USBMUX_HOST_USBMUXD && config->sequence != USBMUX_HOST_LIVI) ||
        !config->handshake_ms || config->handshake_ms > 60000 ||
        !config->write_ms || config->write_ms > 60000 || !config->receive_ms || config->receive_ms > 60000)
        return IAP2_ARGUMENT;
    clear(p, sizeof *p);
    p->config.sequence = config->sequence; p->config.handshake_ms = config->handshake_ms;
    p->config.write_ms = config->write_ms; p->config.receive_ms = config->receive_ms;
    (void)usbmux_stream_init(&p->rx, rx, rx_capacity); p->tx = tx; p->tx_capacity = tx_capacity;
    return IAP2_OK;
}
static int queue(usbmux_host *p, uint32_t protocol, const uint8_t *data, size_t size) {
    usbmux_frame frame = {0, 0, 0, 0, NULL, 0}; size_t written; int status;
    frame.protocol = protocol; frame.payload = data; frame.payload_size = size;
    if (protocol != USBMUX_VERSION) {
        frame.magic = USBMUX_HOST_MAGIC; frame.tx_sequence = p->tx_sequence; frame.rx_sequence = p->rx_sequence;
    }
    status = usbmux_frame_encode(&frame, p->tx, p->tx_capacity, &written);
    if (!status) { p->tx_size = written; p->tx_offset = 0; p->tx_at = p->now; }
    return status;
}
int usbmux_host_start(usbmux_host *p, uint64_t generation, uint64_t now) {
    static const uint8_t version[12] = {0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0};
    if (!initialized(p) || (p->state != USBMUX_HOST_IDLE && p->state != USBMUX_HOST_DEAD) ||
        !generation || generation <= p->generation || now < p->now) return IAP2_ARGUMENT;
    discard(p); clear(&p->peer_version, sizeof p->peer_version);
    p->generation = generation; p->now = p->started_at = now;
    p->tx_sequence = 0; p->rx_sequence = p->config.sequence == USBMUX_HOST_USBMUXD ? UINT16_MAX : 0;
    p->state = USBMUX_HOST_VERSION_TX; p->reason = USBMUX_HOST_REASON_NONE; p->last_error = IAP2_OK;
    /* init's minimum capacity guarantees this 20-byte packet fits. */
    return queue(p, USBMUX_VERSION, version, sizeof version);
}
void usbmux_host_close(usbmux_host *p) {
    if (initialized(p)) (void)stop(p, USBMUX_HOST_REASON_LOCAL, USBMUX_HOST_CLOSED);
}
int usbmux_host_poll(usbmux_host *p, uint64_t generation, uint64_t now) { return tick(p, generation, now); }
int usbmux_host_output(const usbmux_host *p, const uint8_t **data, size_t *size) {
    if (data) *data = NULL;
    if (size) *size = 0;
    if (!initialized(p) || !data || !size) return IAP2_ARGUMENT;
    if (!active(p)) return USBMUX_HOST_CLOSED;
    if (!p->tx_size) return IAP2_MORE;
    *data = p->tx + p->tx_offset; *size = p->tx_size - p->tx_offset; return IAP2_OK;
}
int usbmux_host_advance(usbmux_host *p, size_t completed, uint64_t generation, uint64_t now) {
    int status = tick(p, generation, now); if (status) return status;
    if (completed > p->tx_size - p->tx_offset) return stop(p, USBMUX_HOST_REASON_RESULT, IAP2_INVALID);
    if (!completed) return IAP2_MORE;
    p->tx_offset += completed;
    if (p->tx_offset != p->tx_size) return IAP2_MORE;
    p->tx_size = p->tx_offset = 0; p->tx_at = 0;
    if (p->state == USBMUX_HOST_VERSION_TX) p->state = USBMUX_HOST_VERSION_RX;
    else {
        p->tx_sequence = (uint16_t)(p->tx_sequence + 1u);
        if (p->state == USBMUX_HOST_SETUP_TX) p->state = USBMUX_HOST_READY;
    }
    return IAP2_OK;
}
int usbmux_host_feed(usbmux_host *p, const uint8_t *data, size_t size, size_t *consumed,
                     uint64_t generation, uint64_t now) {
    usbmux_frame frame; usbmux_tcp tcp; int status;
    if (consumed) *consumed = 0;
    if (!consumed || (!data && size)) return IAP2_ARGUMENT;
    status = tick(p, generation, now); if (status) return status;
    if (p->held || p->state == USBMUX_HOST_VERSION_TX || p->state == USBMUX_HOST_SETUP_TX) return USBMUX_HOST_BUSY;
    if (size && !p->rx_timer) { p->rx_timer = 1; p->rx_at = now; }
    status = usbmux_stream_push(&p->rx, data, size, consumed, &frame);
    if (status == IAP2_MORE) return status;
    if (status) return stop(p, USBMUX_HOST_REASON_PROTOCOL, status);
    if (p->state == USBMUX_HOST_VERSION_RX) {
        static const uint8_t setup = 7;
        if (frame.protocol != USBMUX_VERSION) return stop(p, USBMUX_HOST_REASON_PROTOCOL, IAP2_INVALID);
        status = usbmux_version_decode(frame.payload, frame.payload_size, &p->peer_version);
        if (status) return stop(p, USBMUX_HOST_REASON_PROTOCOL, status);
        if (p->peer_version.major != 2) return stop(p, USBMUX_HOST_REASON_VERSION, IAP2_UNSUPPORTED);
        usbmux_stream_reset(&p->rx); p->rx_timer = 0; p->rx_at = 0;
        p->state = USBMUX_HOST_SETUP_TX;
        /* The 17-byte setup packet fits the capacity validated by init. */
        return queue(p, USBMUX_SETUP, &setup, 1);
    }
    if (frame.protocol != USBMUX_CONTROL && frame.protocol != USBMUX_TCP)
        return stop(p, USBMUX_HOST_REASON_PROTOCOL, IAP2_INVALID);
    if (frame.protocol == USBMUX_TCP) {
        status = usbmux_tcp_decode(frame.payload, frame.payload_size, &tcp);
        if (status) return stop(p, USBMUX_HOST_REASON_PROTOCOL, status);
    }
    p->packet.protocol = frame.protocol; p->packet.magic = frame.magic;
    p->packet.tx_sequence = frame.tx_sequence; p->packet.rx_sequence = frame.rx_sequence;
    p->packet.payload = frame.payload; p->packet.payload_size = frame.payload_size;
    if (p->config.sequence == USBMUX_HOST_USBMUXD) p->rx_sequence = frame.rx_sequence;
    p->held = 1; return USBMUX_HOST_PACKET;
}
int usbmux_host_packet(const usbmux_host *p, const usbmux_frame **packet) {
    if (packet) *packet = NULL;
    if (!initialized(p) || !packet) return IAP2_ARGUMENT;
    if (!active(p)) return USBMUX_HOST_CLOSED;
    if (!p->held) return IAP2_MORE;
    *packet = &p->packet; return USBMUX_HOST_PACKET;
}
int usbmux_host_release(usbmux_host *p, uint64_t generation, uint64_t now) {
    int status = tick(p, generation, now); if (status) return status;
    if (!p->held) return IAP2_MORE;
    usbmux_stream_reset(&p->rx); clear(&p->packet, sizeof p->packet);
    p->held = p->rx_timer = 0; p->rx_at = 0; return IAP2_OK;
}
int usbmux_host_send_tcp(usbmux_host *p, const uint8_t *data, size_t size, uint64_t generation, uint64_t now) {
    usbmux_tcp tcp; int status;
    if (!data) return IAP2_ARGUMENT;
    status = tick(p, generation, now); if (status) return status;
    if (p->state != USBMUX_HOST_READY || p->tx_size) return USBMUX_HOST_BUSY;
    status = usbmux_tcp_decode(data, size, &tcp); if (status) return status;
    return queue(p, USBMUX_TCP, data, size);
}
