/* SPDX-License-Identifier: GPL-3.0-only */
#include "lockdown_channel.h"
static void clear(void *p, size_t n) { size_t i; for (i = 0; i < n; ++i) ((uint8_t *)p)[i] = 0; }
static int initialized(const lockdown_channel *c) { return c && c->dispatcher && c->rx && c->tx; }
static int active(const lockdown_channel *c) { return c->state <= LOCKDOWN_CHANNEL_HELD; }
static uint32_t smaller(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t remaining(uint64_t now, uint64_t at, uint32_t ms) { uint64_t d = now - at; return d >= ms ? 0 : ms - (uint32_t)d; }
static void discard(lockdown_channel *c) {
    c->rx_used = c->tx_size = c->tx_offset = 0; c->rx_expected = 4; c->complete = 0; c->token = 0;
}
static int stop(lockdown_channel *c, enum lockdown_channel_reason reason, int error, int cancel) {
    if (active(c)) {
        enum usbmux_connection_state state;
        c->state = LOCKDOWN_CHANNEL_DEAD; c->reason = reason; c->last_error = error;
        if (cancel && usbmux_dispatcher_state(c->dispatcher, &c->handle, &state) == IAP2_OK) usbmux_dispatcher_close(c->dispatcher);
        discard(c);
    }
    return LOCKDOWN_CHANNEL_CLOSED;
}
static int check_time(lockdown_channel *c, uint64_t now) {
    enum usbmux_connection_state state; int status;
    if (!initialized(c)) return IAP2_ARGUMENT;
    if (!active(c)) return LOCKDOWN_CHANNEL_CLOSED;
    status = usbmux_dispatcher_state(c->dispatcher, &c->handle, &state);
    if (status) return stop(c, status == USBMUX_DISPATCHER_STALE ? LOCKDOWN_CHANNEL_REASON_STALE : LOCKDOWN_CHANNEL_REASON_TRANSPORT, status, 0);
    if (now < c->now || now < c->dispatcher->now) return IAP2_ARGUMENT;
    c->now = now;
    if ((c->state == LOCKDOWN_CHANNEL_EXCHANGE && now - c->started_at >= c->config.exchange_ms) ||
        (c->state == LOCKDOWN_CHANNEL_HELD && now - c->held_at >= c->config.hold_ms))
        return stop(c, LOCKDOWN_CHANNEL_REASON_DEADLINE, LOCKDOWN_CHANNEL_CLOSED, 1);
    return IAP2_OK;
}
void lockdown_channel_default_config(lockdown_channel_config *config) { if (config) config->exchange_ms = config->hold_ms = 5000; }
int lockdown_channel_init(lockdown_channel *c, usbmux_dispatcher *d, const usbmux_handle *handle,
                          const lockdown_channel_config *config, uint8_t *rx, size_t rx_capacity,
                          uint8_t *tx, size_t tx_capacity, uint64_t now) {
    enum usbmux_connection_state state; const usbmux_connection *connection; int status;
    if (!c || !d || !handle || !config || !rx || !tx || rx == tx || rx_capacity < 5 || tx_capacity < 5 ||
        rx_capacity > LOCKDOWN_FRAME_LIMIT || tx_capacity > LOCKDOWN_FRAME_LIMIT ||
        !config->exchange_ms || config->exchange_ms > 60000 || !config->hold_ms || config->hold_ms > 60000) return IAP2_ARGUMENT;
    status = usbmux_dispatcher_state(d, handle, &state); if (status) return status;
    connection = d->connections[handle->slot];
    if (state != USBMUX_CONNECTION_OPEN || connection->tx_size || connection->flight_count) return LOCKDOWN_CHANNEL_BUSY;
    if (now < d->now || now < connection->now) return IAP2_ARGUMENT;
    clear(c, sizeof *c); c->dispatcher = d;
    c->handle.physical = handle->physical; c->handle.connection = handle->connection; c->handle.slot = handle->slot;
    c->config.exchange_ms = config->exchange_ms; c->config.hold_ms = config->hold_ms;
    c->rx = rx; c->rx_capacity = rx_capacity; c->tx = tx; c->tx_capacity = tx_capacity; c->now = now; c->rx_expected = 4;
    return IAP2_OK;
}
int lockdown_channel_request(lockdown_channel *c, const uint8_t *body, size_t size, uint64_t now) {
    enum usbmux_connection_state state; size_t written; int status;
    if ((!body && size) || !size) return IAP2_ARGUMENT;
    status = check_time(c, now); if (status) return status;
    if (c->state != LOCKDOWN_CHANNEL_IDLE) return LOCKDOWN_CHANNEL_BUSY;
    if (c->next_token == UINT64_MAX) return IAP2_NO_SPACE;
    status = usbmux_dispatcher_state(c->dispatcher, &c->handle, &state);
    if (status || state != USBMUX_CONNECTION_OPEN) return IAP2_END;
    status = lockdown_frame_encode(body, size, c->tx, c->tx_capacity, &written); if (status) return status;
    discard(c); c->tx_size = written; c->started_at = now; c->state = LOCKDOWN_CHANNEL_EXCHANGE; return IAP2_OK;
}
int lockdown_channel_poll(lockdown_channel *c, uint64_t now) {
    int status = check_time(c, now), transport, progress = 0; size_t n, amount;
    if (status) return status;
    transport = usbmux_dispatcher_poll(c->dispatcher, now);
    if (transport != IAP2_OK && transport != IAP2_MORE && transport != USBMUX_DISPATCHER_CONTROL)
        return stop(c, LOCKDOWN_CHANNEL_REASON_TRANSPORT, transport, 0);
    if (c->state == LOCKDOWN_CHANNEL_HELD) return LOCKDOWN_CHANNEL_RESPONSE;
    if (c->state == LOCKDOWN_CHANNEL_EXCHANGE) {
        if (c->tx_offset < c->tx_size) {
            amount = c->tx_size - c->tx_offset; if (amount > LOCKDOWN_CHANNEL_CHUNK) amount = LOCKDOWN_CHANNEL_CHUNK;
            status = usbmux_dispatcher_write(c->dispatcher, &c->handle, c->tx + c->tx_offset, amount, &n, now);
            if (status != IAP2_OK && status != IAP2_MORE && status != USBMUX_DISPATCHER_BUSY)
                return stop(c, LOCKDOWN_CHANNEL_REASON_TRANSPORT, status, status != USBMUX_DISPATCHER_STALE);
            c->tx_offset += n; if (n) progress = 1;
        }
        if (!c->complete) {
            amount = c->rx_expected - c->rx_used; if (amount > LOCKDOWN_CHANNEL_CHUNK) amount = LOCKDOWN_CHANNEL_CHUNK;
            status = usbmux_dispatcher_read(c->dispatcher, &c->handle, c->rx + c->rx_used, amount, &n, now);
            if (status == IAP2_END) return stop(c, LOCKDOWN_CHANNEL_REASON_EOF, status, 1);
            if (status != IAP2_OK && status != IAP2_MORE)
                return stop(c, LOCKDOWN_CHANNEL_REASON_TRANSPORT, status, status != USBMUX_DISPATCHER_STALE);
            c->rx_used += n; if (n) progress = 1;
            if (c->rx_used == 4 && c->rx_expected == 4) {
                size_t total;
                status = lockdown_frame_size(c->rx, 4, &total);
                if (status || total > c->rx_capacity) return stop(c, LOCKDOWN_CHANNEL_REASON_LENGTH, status ? status : IAP2_NO_SPACE, 1);
                c->rx_expected = total;
            }
            if (c->rx_used == c->rx_expected) c->complete = 1;
        }
        if (c->complete && c->tx_offset == c->tx_size) {
            const usbmux_connection *connection = c->dispatcher->connections[c->handle.slot];
            if (!connection->tx_size && !connection->flight_count) {
                c->state = LOCKDOWN_CHANNEL_HELD; c->token = ++c->next_token; c->held_at = now;
                return LOCKDOWN_CHANNEL_RESPONSE;
            }
        }
    }
    if (transport == USBMUX_DISPATCHER_CONTROL) return transport;
    return progress || transport == IAP2_OK ? IAP2_OK : IAP2_MORE;
}
int lockdown_channel_response(const lockdown_channel *c, lockdown_body *body, uint64_t *token) {
    enum usbmux_connection_state state;
    if (body) { body->data = NULL; body->size = 0; }
    if (token) *token = 0;
    if (!initialized(c) || !body || !token) return IAP2_ARGUMENT;
    if (!active(c) || usbmux_dispatcher_state(c->dispatcher, &c->handle, &state) != IAP2_OK) return LOCKDOWN_CHANNEL_CLOSED;
    if (c->state != LOCKDOWN_CHANNEL_HELD) return IAP2_MORE;
    body->data = c->rx + 4; body->size = c->rx_expected - 4; *token = c->token; return LOCKDOWN_CHANNEL_RESPONSE;
}
int lockdown_channel_release(lockdown_channel *c, uint64_t token, uint64_t now) {
    int status;
    if (!initialized(c)) return IAP2_ARGUMENT;
    if (c->state != LOCKDOWN_CHANNEL_HELD || !token || token != c->token) return USBMUX_DISPATCHER_STALE;
    status = check_time(c, now); if (status) return status;
    discard(c); c->state = LOCKDOWN_CHANNEL_IDLE; return IAP2_OK;
}
int lockdown_channel_detach(lockdown_channel *c, usbmux_handle *handle, uint64_t now) {
    int status;
    if (!handle) return IAP2_ARGUMENT;
    status = check_time(c, now); if (status) return status;
    if (c->state != LOCKDOWN_CHANNEL_IDLE) return LOCKDOWN_CHANNEL_BUSY;
    handle->physical = c->handle.physical; handle->connection = c->handle.connection; handle->slot = c->handle.slot;
    discard(c); c->state = LOCKDOWN_CHANNEL_DETACHED; return IAP2_OK;
}
void lockdown_channel_close(lockdown_channel *c) {
    if (initialized(c)) (void)stop(c, LOCKDOWN_CHANNEL_REASON_LOCAL, LOCKDOWN_CHANNEL_CLOSED, 1);
}
uint32_t lockdown_channel_next_delay(const lockdown_channel *c) {
    uint64_t now; uint32_t delay; enum usbmux_connection_state state; const usbmux_connection *connection;
    if (!initialized(c) || !active(c)) return UINT32_MAX;
    if (usbmux_dispatcher_state(c->dispatcher, &c->handle, &state) != IAP2_OK) return 0;
    now = c->now > c->dispatcher->now ? c->now : c->dispatcher->now;
    delay = usbmux_dispatcher_next_delay(c->dispatcher); connection = c->dispatcher->connections[c->handle.slot];
    if (c->state == LOCKDOWN_CHANNEL_EXCHANGE) {
        delay = smaller(delay, remaining(now, c->started_at, c->config.exchange_ms));
        if ((!c->complete && connection->rx_used) || (c->complete && c->tx_offset == c->tx_size && !connection->tx_size && !connection->flight_count)) return 0;
        if (c->tx_offset < c->tx_size && state == USBMUX_CONNECTION_OPEN && !connection->tx_size &&
            connection->flight_count < USBMUX_CONNECTION_FLIGHTS && connection->peer_window > connection->tx_next - connection->tx_una) return 0;
    } else if (c->state == LOCKDOWN_CHANNEL_HELD) delay = smaller(delay, remaining(now, c->held_at, c->config.hold_ms));
    return delay;
}
