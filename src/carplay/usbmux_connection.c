/* SPDX-License-Identifier: GPL-3.0-only */
#include "usbmux_connection.h"
#define FIN 1u
#define SYN 2u
#define RST 4u
#define PSH 8u
#define ACK 16u
#define OUT_SYN 1u
#define OUT_OPEN 2u
#define OUT_DATA 3u
#define OUT_ACK 4u
#define OUT_FIN 5u
#define HALF UINT32_C(0x80000000)
static void clear(void *p, size_t n) { size_t i; for (i = 0; i < n; ++i) ((uint8_t *)p)[i] = 0; }
static int initialized(const usbmux_connection *c) { return c && c->rx && c->tx; }
static int active(const usbmux_connection *c) { return c->state >= USBMUX_CONNECTION_SYN_TX && c->state <= USBMUX_CONNECTION_DRAINED; }
static int newer(uint32_t a, uint32_t b) { uint32_t d = a - b; return d && d < HALF; }
static uint32_t smaller(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t remaining(uint64_t now, uint64_t at, uint32_t ms) { uint64_t d = now - at; return d >= ms ? 0 : ms - (uint32_t)d; }
static void discard(usbmux_connection *c) {
    c->rx_head = c->rx_used = c->tx_size = c->tx_offset = c->tx_payload = 0;
    c->flight_head = c->flight_count = 0; clear(c->flights, sizeof c->flights);
    c->output_kind = c->ack_pending = c->fin_requested = c->fin_sent = c->fin_acked = c->peer_fin = 0;
    c->tx_at = c->ack_at = c->read_at = c->close_at = 0;
}
static int stop(usbmux_connection *c, enum usbmux_connection_reason reason, int error) {
    if (active(c)) { c->state = USBMUX_CONNECTION_DEAD; c->reason = reason; c->last_error = error; discard(c); }
    return USBMUX_CONNECTION_CLOSED;
}
uint32_t usbmux_connection_next_delay(const usbmux_connection *c) {
    uint32_t d = UINT32_MAX;
    if (!initialized(c) || !active(c)) return d;
    if (c->state <= USBMUX_CONNECTION_OPEN_ACK) d = remaining(c->now, c->started_at, c->config.open_ms);
    if (c->tx_size) d = smaller(d, remaining(c->now, c->tx_at, c->config.write_ms));
    if (c->ack_pending) d = smaller(d, remaining(c->now, c->ack_at, c->config.ack_ms));
    if (c->flight_count) d = smaller(d, remaining(c->now, c->flights[c->flight_head].sent_at, c->config.ack_ms));
    if (c->rx_used) d = smaller(d, remaining(c->now, c->read_at, c->config.read_ms));
    if (c->fin_requested && c->state != USBMUX_CONNECTION_DRAINED) d = smaller(d, remaining(c->now, c->close_at, c->config.close_ms));
    return d;
}
static int tick(usbmux_connection *c, uint64_t generation, uint64_t now) {
    if (!initialized(c)) return IAP2_ARGUMENT;
    if (!active(c)) return USBMUX_CONNECTION_CLOSED;
    if (generation != c->generation) return stop(c, USBMUX_CONNECTION_REASON_STALE, IAP2_INVALID);
    if (now < c->now) return IAP2_ARGUMENT;
    c->now = now;
    if (!usbmux_connection_next_delay(c)) return stop(c, USBMUX_CONNECTION_REASON_DEADLINE, USBMUX_CONNECTION_CLOSED);
    return IAP2_OK;
}
void usbmux_connection_default_config(usbmux_connection_config *config) {
    if (config) {
        config->send_limit = 16384; config->open_ms = config->ack_ms = config->read_ms = config->close_ms = 5000;
        config->write_ms = 250;
    }
}
static int budget(uint32_t n) { return n && n <= 60000; }
int usbmux_connection_init(usbmux_connection *c, const usbmux_connection_config *config,
                           uint8_t *rx, size_t rx_capacity, uint8_t *tx, size_t tx_capacity) {
    if (!c || !config || !rx || !tx || rx == tx || rx_capacity < 256 || rx_capacity > 65536 ||
        tx_capacity < 21 || tx_capacity > USBMUX_FRAME_LIMIT - 16 || !config->send_limit ||
        config->send_limit > USBMUX_TCP_PAYLOAD_LIMIT || config->send_limit > tx_capacity - 20 ||
        !budget(config->open_ms) || !budget(config->write_ms) || !budget(config->ack_ms) ||
        !budget(config->read_ms) || !budget(config->close_ms)) return IAP2_ARGUMENT;
    clear(c, sizeof *c); c->rx = rx; c->rx_capacity = rx_capacity; c->tx = tx; c->tx_capacity = tx_capacity;
    c->config.send_limit = config->send_limit; c->config.open_ms = config->open_ms; c->config.write_ms = config->write_ms;
    c->config.ack_ms = config->ack_ms; c->config.read_ms = config->read_ms; c->config.close_ms = config->close_ms;
    return IAP2_OK;
}
static int make(usbmux_connection *c, uint8_t flags, const uint8_t *data, size_t size, uint8_t kind) {
    usbmux_tcp tcp; size_t n; int status;
    tcp.source_port = c->local_port; tcp.destination_port = c->remote_port; tcp.sequence = c->tx_next;
    tcp.acknowledgement = (flags & ACK) ? c->rx_next : 0; tcp.flags = flags;
    tcp.window = (uint16_t)((c->rx_capacity - c->rx_used) >> 8); tcp.checksum = tcp.urgent = 0;
    tcp.payload = data; tcp.payload_size = size;
    status = usbmux_tcp_encode(&tcp, c->tx, c->tx_capacity, &n); if (status) return status;
    c->tx_size = n; c->tx_offset = 0; c->tx_payload = size; c->tx_at = c->now; c->output_kind = kind;
    c->output_ack = tcp.acknowledgement; c->output_window = tcp.window;
    if (flags & ACK) { c->ack_pending = 0; c->ack_at = 0; }
    return IAP2_OK;
}
int usbmux_connection_start(usbmux_connection *c, uint16_t local_port, uint16_t remote_port,
                            uint32_t initial_sequence, uint64_t generation, uint64_t now) {
    if (!initialized(c) || (c->state != USBMUX_CONNECTION_IDLE && c->state != USBMUX_CONNECTION_DEAD &&
        c->state != USBMUX_CONNECTION_DRAINED) || c->rx_used || !local_port || !remote_port ||
        !generation || generation <= c->generation || now < c->now) return IAP2_ARGUMENT;
    discard(c); c->local_port = local_port; c->remote_port = remote_port; c->initial_sequence = initial_sequence;
    c->tx_una = c->tx_next = initial_sequence; c->peer_initial = c->rx_next = c->rx_limit = 0;
    c->peer_window = c->window_sequence = c->window_ack = 0; c->initial_window = 0;
    c->generation = generation; c->now = c->started_at = now; c->state = USBMUX_CONNECTION_SYN_TX;
    c->reason = USBMUX_CONNECTION_REASON_NONE; c->last_error = IAP2_OK;
    return make(c, SYN, NULL, 0, OUT_SYN);
}
void usbmux_connection_close(usbmux_connection *c) {
    if (initialized(c)) (void)stop(c, USBMUX_CONNECTION_REASON_LOCAL, USBMUX_CONNECTION_CLOSED);
}
static void need_ack(usbmux_connection *c) { if (!c->ack_pending) { c->ack_pending = 1; c->ack_at = c->now; } }
static void drained(usbmux_connection *c) {
    if (c->fin_acked && c->peer_fin && !c->ack_pending && !c->tx_size) c->state = USBMUX_CONNECTION_DRAINED;
}
int usbmux_connection_finish(usbmux_connection *c, uint64_t generation, uint64_t now) {
    int status = tick(c, generation, now); if (status) return status;
    if (c->state == USBMUX_CONNECTION_DRAINED) return IAP2_END;
    if (c->state < USBMUX_CONNECTION_OPEN) return USBMUX_CONNECTION_BUSY;
    if (!c->fin_requested) { c->fin_requested = 1; c->close_at = now; c->state = USBMUX_CONNECTION_CLOSING; }
    return IAP2_OK;
}
int usbmux_connection_poll(usbmux_connection *c, uint64_t generation, uint64_t now) {
    int status = tick(c, generation, now); if (status) return status;
    if (!c->tx_size && c->state >= USBMUX_CONNECTION_OPEN && c->state < USBMUX_CONNECTION_DRAINED) {
        if (c->ack_pending) (void)make(c, ACK, NULL, 0, OUT_ACK);
        else if (c->fin_requested && !c->fin_sent && !c->flight_count) (void)make(c, FIN | ACK, NULL, 0, OUT_FIN);
    }
    drained(c);
    return c->state == USBMUX_CONNECTION_DRAINED ? IAP2_END : (c->tx_size ? IAP2_OK : IAP2_MORE);
}
int usbmux_connection_output(const usbmux_connection *c, const uint8_t **data, size_t *size) {
    if (data) *data = NULL;
    if (size) *size = 0;
    if (!initialized(c) || !data || !size) return IAP2_ARGUMENT;
    if (!active(c)) return USBMUX_CONNECTION_CLOSED;
    if (!c->tx_size) return IAP2_MORE;
    *data = c->tx + c->tx_offset; *size = c->tx_size - c->tx_offset; return IAP2_OK;
}
int usbmux_connection_advance(usbmux_connection *c, size_t completed, uint64_t generation, uint64_t now) {
    int status = tick(c, generation, now); if (status) return status;
    if (completed > c->tx_size - c->tx_offset) return stop(c, USBMUX_CONNECTION_REASON_RESULT, IAP2_INVALID);
    if (!completed) return IAP2_MORE;
    c->tx_offset += completed; if (c->tx_offset < c->tx_size) return IAP2_MORE;
    if (c->output_kind == OUT_SYN) {
        c->initial_window = c->output_window; c->tx_next++; c->state = USBMUX_CONNECTION_SYN_WAIT;
    } else {
        uint32_t right = c->output_ack + ((uint32_t)c->output_window << 8);
        /* Rounded-down new windows never revoke already granted receive credit. */
        if (newer(right, c->rx_limit)) c->rx_limit = right;
        if (c->output_kind == OUT_OPEN) c->state = USBMUX_CONNECTION_OPEN;
        else if (c->output_kind == OUT_DATA) {
            unsigned index = (c->flight_head + c->flight_count) % USBMUX_CONNECTION_FLIGHTS;
            c->tx_next += (uint32_t)c->tx_payload;
            c->flights[index].end = c->tx_next; c->flights[index].sent_at = now; c->flight_count++;
        } else if (c->output_kind == OUT_FIN) { c->fin_sent = 1; c->tx_next++; }
    }
    c->tx_size = c->tx_offset = c->tx_payload = 0; c->output_kind = 0; c->tx_at = 0;
    drained(c); return IAP2_OK;
}
static int acknowledge(usbmux_connection *c, const usbmux_tcp *tcp) {
    uint32_t delta = tcp->acknowledgement - c->tx_una;
    if (delta == HALF) return stop(c, USBMUX_CONNECTION_REASON_ACK, IAP2_INVALID);
    if (delta > HALF) return IAP2_OK; /* Old ACK: no window/flight change. */
    if (delta > c->tx_next - c->tx_una) return stop(c, USBMUX_CONNECTION_REASON_ACK, IAP2_INVALID);
    c->tx_una = tcp->acknowledgement;
    while (c->flight_count && !newer(c->flights[c->flight_head].end, c->tx_una)) {
        c->flight_head = (c->flight_head + 1) % USBMUX_CONNECTION_FLIGHTS; c->flight_count--;
    }
    if (c->fin_sent && c->tx_una == c->tx_next) c->fin_acked = 1;
    if (newer(tcp->sequence, c->window_sequence) || (tcp->sequence == c->window_sequence &&
        (tcp->acknowledgement == c->window_ack || newer(tcp->acknowledgement, c->window_ack)))) {
        c->window_sequence = tcp->sequence; c->window_ack = tcp->acknowledgement;
        c->peer_window = (uint32_t)tcp->window << 8;
    }
    return IAP2_OK;
}
static void append(usbmux_connection *c, const uint8_t *data, size_t size) {
    size_t i, index = c->rx_head + c->rx_used;
    if (index >= c->rx_capacity) index -= c->rx_capacity;
    if (!c->rx_used && size) c->read_at = c->now;
    for (i = 0; i < size; ++i) { c->rx[index++] = data[i]; if (index == c->rx_capacity) index = 0; }
    c->rx_used += size; c->rx_next += (uint32_t)size;
}
int usbmux_connection_feed(usbmux_connection *c, const uint8_t *data, size_t size, uint64_t generation, uint64_t now) {
    usbmux_tcp tcp; size_t skip = 0, amount; uint32_t behind, credit; int status;
    if (!data) return IAP2_ARGUMENT;
    status = tick(c, generation, now); if (status) return status;
    status = usbmux_tcp_decode(data, size, &tcp); if (status) return stop(c, USBMUX_CONNECTION_REASON_PROTOCOL, status);
    if (tcp.source_port != c->remote_port || tcp.destination_port != c->local_port) return USBMUX_CONNECTION_UNROUTED;
    if (c->state == USBMUX_CONNECTION_DRAINED) return IAP2_END;
    if (c->state == USBMUX_CONNECTION_SYN_TX || c->state == USBMUX_CONNECTION_OPEN_ACK ||
        (c->tx_size && c->output_kind != OUT_ACK)) return USBMUX_CONNECTION_BUSY;
    if (tcp.flags & RST) {
        if (c->state == USBMUX_CONNECTION_SYN_WAIT || tcp.sequence == c->rx_next)
            return stop(c, USBMUX_CONNECTION_REASON_RESET, IAP2_END);
        need_ack(c); return IAP2_OK;
    }
    if (c->state == USBMUX_CONNECTION_SYN_WAIT) {
        if (tcp.flags != (SYN | ACK) || tcp.payload_size || tcp.urgent)
            return stop(c, USBMUX_CONNECTION_REASON_PROTOCOL, IAP2_INVALID);
        if (tcp.acknowledgement != c->tx_next) return stop(c, USBMUX_CONNECTION_REASON_ACK, IAP2_INVALID);
        c->peer_initial = tcp.sequence; c->rx_next = tcp.sequence + 1u;
        c->rx_limit = c->rx_next + ((uint32_t)c->initial_window << 8);
        c->tx_una = tcp.acknowledgement; c->peer_window = (uint32_t)tcp.window << 8;
        c->window_sequence = tcp.sequence; c->window_ack = tcp.acknowledgement;
        c->state = USBMUX_CONNECTION_OPEN_ACK; return make(c, ACK, NULL, 0, OUT_OPEN);
    }
    if (tcp.flags == (SYN | ACK) && !tcp.payload_size && !tcp.urgent && tcp.sequence == c->peer_initial &&
        tcp.acknowledgement == c->initial_sequence + 1u) { need_ack(c); return IAP2_OK; }
    if (!(tcp.flags & ACK) || (tcp.flags & ~(ACK | PSH | FIN)) || tcp.urgent)
        return stop(c, USBMUX_CONNECTION_REASON_PROTOCOL, IAP2_UNSUPPORTED);
    behind = c->rx_next - tcp.sequence;
    if (behind >= HALF) { need_ack(c); return IAP2_OK; } /* Gap/ambiguous serial distance. */
    if (behind) skip = behind < tcp.payload_size ? (size_t)behind : tcp.payload_size;
    amount = tcp.payload_size - skip;
    credit = c->rx_limit - c->rx_next; if (credit >= HALF) credit = 0;
    if ((c->peer_fin && amount) || amount > credit || amount > c->rx_capacity - c->rx_used)
        return stop(c, USBMUX_CONNECTION_REASON_WINDOW, IAP2_NO_SPACE);
    status = acknowledge(c, &tcp); if (status) return status;
    if (amount) append(c, tcp.payload + skip, amount);
    if (tcp.payload_size) need_ack(c);
    if (tcp.flags & FIN) {
        uint32_t fin_at = tcp.sequence + (uint32_t)tcp.payload_size;
        if (!c->peer_fin && fin_at == c->rx_next) { c->peer_fin = 1; c->rx_next++; }
        need_ack(c);
    }
    drained(c); return IAP2_OK;
}
int usbmux_connection_write(usbmux_connection *c, const uint8_t *data, size_t size, size_t *accepted,
                            uint64_t generation, uint64_t now) {
    uint32_t outstanding, available; size_t amount; int status;
    if (accepted) *accepted = 0;
    if (!accepted || (!data && size)) return IAP2_ARGUMENT;
    status = tick(c, generation, now); if (status) return status;
    if (!size) return IAP2_MORE;
    if (c->state != USBMUX_CONNECTION_OPEN || c->fin_requested || c->tx_size || c->flight_count == USBMUX_CONNECTION_FLIGHTS)
        return USBMUX_CONNECTION_BUSY;
    outstanding = c->tx_next - c->tx_una;
    available = c->peer_window > outstanding ? c->peer_window - outstanding : 0;
    amount = size; if (amount > c->config.send_limit) amount = c->config.send_limit;
    if (amount > available) amount = available;
    if (!amount) return USBMUX_CONNECTION_BUSY;
    status = make(c, ACK, data, amount, OUT_DATA); if (!status) *accepted = amount; return status;
}
int usbmux_connection_input(const usbmux_connection *c, const uint8_t **data, size_t *size) {
    if (data) *data = NULL;
    if (size) *size = 0;
    if (!initialized(c) || !data || !size) return IAP2_ARGUMENT;
    if (!active(c)) return USBMUX_CONNECTION_CLOSED;
    if (!c->rx_used) return c->peer_fin ? IAP2_END : IAP2_MORE;
    *size = c->rx_used; if (*size > c->rx_capacity - c->rx_head) *size = c->rx_capacity - c->rx_head;
    *data = c->rx + c->rx_head; return IAP2_OK;
}
int usbmux_connection_consume(usbmux_connection *c, size_t count, uint64_t generation, uint64_t now) {
    size_t available; uint32_t right; int status = tick(c, generation, now); if (status) return status;
    available = c->rx_used; if (available > c->rx_capacity - c->rx_head) available = c->rx_capacity - c->rx_head;
    if (count > available) return IAP2_ARGUMENT;
    if (!count) return IAP2_MORE;
    c->rx_used -= count; c->rx_head += count; if (c->rx_head == c->rx_capacity) c->rx_head = 0;
    c->read_at = c->rx_used ? now : 0;
    right = c->rx_next + (uint32_t)(((c->rx_capacity - c->rx_used) >> 8) << 8);
    if (!c->peer_fin && newer(right, c->rx_limit)) need_ack(c);
    return IAP2_OK;
}
