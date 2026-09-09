/* SPDX-License-Identifier: GPL-3.0-only */
#include "usbmux_dispatcher.h"
static void clear(void *p, size_t n) { size_t i; for (i = 0; i < n; ++i) ((uint8_t *)p)[i] = 0; }
static void copy(uint8_t *d, const uint8_t *s, size_t n) { size_t i; for (i = 0; i < n; ++i) d[i] = s[i]; }
static uint32_t smaller(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t remaining(uint64_t now, uint64_t at, uint32_t ms) { uint64_t age = now - at; return age >= ms ? 0 : ms - (uint32_t)age; }
static int initialized(const usbmux_dispatcher *d) { return d && d->host && d->count; }
static int can_feed(const usbmux_dispatcher *d) {
    return !d->host->held && (d->host->state == USBMUX_HOST_VERSION_RX || d->host->state == USBMUX_HOST_READY);
}
static void discard(usbmux_dispatcher *d) {
    d->rx_size = d->rx_offset = d->owner_size = 0; d->owner = d->control_pending = d->read_paused = d->write_paused = d->again = 0;
    d->control_token = d->owner_connection = d->read_at = d->write_at = 0; clear(d->rx, sizeof d->rx);
}
static int stop(usbmux_dispatcher *d, enum usbmux_dispatcher_reason reason, int error, unsigned slot) {
    unsigned i;
    if (d->active) {
        d->active = 0; d->reason = reason; d->last_error = error; d->failed_slot = slot;
        d->backend.cancel(d->backend.context, d->generation);
        usbmux_host_close(d->host);
        for (i = 0; i < d->count; ++i) usbmux_connection_close(d->connections[i]);
        discard(d);
    }
    return USBMUX_DISPATCHER_CLOSED;
}
void usbmux_dispatcher_default_config(usbmux_dispatcher_config *config) { if (config) config->retry_ms = 5; }
int usbmux_dispatcher_init(usbmux_dispatcher *d, usbmux_host *host, usbmux_connection *const *connections, unsigned count,
                           const usbmux_backend *backend, const usbmux_dispatcher_config *config) {
    unsigned i, j;
    if (!d || !host || !connections || !count || count > USBMUX_DISPATCHER_SLOTS || !backend || !config ||
        !backend->read || !backend->write || !backend->cancel || !config->retry_ms || config->retry_ms > 1000 ||
        !host->rx.buffer || !host->tx || host->state != USBMUX_HOST_IDLE) return IAP2_ARGUMENT;
    for (i = 0; i < count; ++i) {
        const usbmux_connection *c = connections[i]; size_t required;
        if (!c || !c->rx || !c->tx || c->state != USBMUX_CONNECTION_IDLE) return IAP2_ARGUMENT;
        required = c->rx_capacity + 36; if (required > USBMUX_FRAME_LIMIT) required = USBMUX_FRAME_LIMIT;
        if (host->rx.capacity < required || host->tx_capacity < (size_t)c->config.send_limit + 36) return IAP2_ARGUMENT;
        for (j = 0; j < i; ++j) if (connections[j] == c) return IAP2_ARGUMENT;
    }
    clear(d, sizeof *d); d->host = host; d->count = count; d->config.retry_ms = config->retry_ms;
    for (i = 0; i < count; ++i) d->connections[i] = connections[i];
    d->backend.context = backend->context; d->backend.read = backend->read;
    d->backend.write = backend->write; d->backend.cancel = backend->cancel; d->failed_slot = USBMUX_DISPATCHER_SLOTS;
    return IAP2_OK;
}
int usbmux_dispatcher_start(usbmux_dispatcher *d, uint64_t generation, uint64_t now) {
    unsigned i; int status;
    if (!initialized(d) || d->active || !generation || generation <= d->generation || now < d->now ||
        now < d->host->now || (d->host->state != USBMUX_HOST_IDLE && d->host->state != USBMUX_HOST_DEAD)) return IAP2_ARGUMENT;
    for (i = 0; i < d->count; ++i) {
        const usbmux_connection *c = d->connections[i];
        if (now < c->now || (c->state != USBMUX_CONNECTION_IDLE && c->state != USBMUX_CONNECTION_DEAD)) return IAP2_ARGUMENT;
    }
    status = usbmux_host_start(d->host, generation, now); if (status) return status;
    discard(d); clear(d->used, sizeof d->used); d->generation = generation; d->now = now;
    d->active = d->again = 1; d->next_port = 1; d->round_robin = d->ignored_packets = 0;
    d->reason = USBMUX_DISPATCHER_REASON_NONE; d->last_error = IAP2_OK; d->failed_slot = USBMUX_DISPATCHER_SLOTS;
    return IAP2_OK;
}
void usbmux_dispatcher_close(usbmux_dispatcher *d) {
    if (initialized(d)) (void)stop(d, USBMUX_DISPATCHER_REASON_LOCAL, USBMUX_DISPATCHER_CLOSED, USBMUX_DISPATCHER_SLOTS);
}
/* Check all shared clocks before accepting this time, then enforce all timers.
 * connection_poll may materialize one bounded ACK/FIN packet per connection. */
static int tick(usbmux_dispatcher *d, uint64_t now) {
    unsigned i; int status;
    if (!initialized(d)) return IAP2_ARGUMENT;
    if (!d->active) return USBMUX_DISPATCHER_CLOSED;
    if (now < d->now || now < d->host->now) return IAP2_ARGUMENT;
    for (i = 0; i < d->count; ++i) if (now < d->connections[i]->now) return IAP2_ARGUMENT;
    d->now = now;
    status = usbmux_host_poll(d->host, d->generation, now);
    if (status) return stop(d, USBMUX_DISPATCHER_REASON_HOST, status, USBMUX_DISPATCHER_SLOTS);
    for (i = 0; i < d->count; ++i) if (d->used[i]) {
        status = usbmux_connection_poll(d->connections[i], d->connections[i]->generation, now);
        if (status != IAP2_OK && status != IAP2_MORE && status != IAP2_END)
            return stop(d, USBMUX_DISPATCHER_REASON_CONNECTION, status, i);
    }
    return IAP2_OK;
}
static int result(usbmux_dispatcher *d, const usbmux_io_result *r, size_t maximum) {
    if (r->generation != d->generation) return stop(d, USBMUX_DISPATCHER_REASON_STALE, IAP2_INVALID, USBMUX_DISPATCHER_SLOTS);
    if (r->status < USBMUX_IO_PROGRESS || r->status > USBMUX_IO_FATAL || r->count > maximum ||
        (r->status != USBMUX_IO_PROGRESS && r->count)) return stop(d, USBMUX_DISPATCHER_REASON_RESULT, IAP2_INVALID, USBMUX_DISPATCHER_SLOTS);
    if (r->status == USBMUX_IO_DISCONNECTED) return stop(d, USBMUX_DISPATCHER_REASON_DISCONNECTED, IAP2_END, USBMUX_DISPATCHER_SLOTS);
    if (r->status == USBMUX_IO_FATAL) return stop(d, USBMUX_DISPATCHER_REASON_IO, IAP2_PROVIDER_FAILED, USBMUX_DISPATCHER_SLOTS);
    return IAP2_OK;
}
static int route(usbmux_dispatcher *d) {
    const usbmux_frame *frame; usbmux_tcp tcp; unsigned i; int status;
    if (!d->host->held) return IAP2_OK;
    status = usbmux_host_packet(d->host, &frame);
    if (status != USBMUX_HOST_PACKET) return stop(d, USBMUX_DISPATCHER_REASON_STATE, status, USBMUX_DISPATCHER_SLOTS);
    if (frame->protocol == USBMUX_CONTROL) {
        if (!d->control_pending) {
            if (d->next_control == UINT64_MAX) return stop(d, USBMUX_DISPATCHER_REASON_COUNTER, IAP2_NO_SPACE, USBMUX_DISPATCHER_SLOTS);
            d->control_token = ++d->next_control; d->control_pending = 1;
        }
        return IAP2_OK;
    }
    status = usbmux_tcp_decode(frame->payload, frame->payload_size, &tcp);
    if (frame->protocol != USBMUX_TCP || status) return stop(d, USBMUX_DISPATCHER_REASON_STATE, status ? status : IAP2_INVALID, USBMUX_DISPATCHER_SLOTS);
    for (i = 0; i < d->count; ++i) if (d->used[i] && d->connections[i]->local_port == tcp.destination_port && d->connections[i]->remote_port == tcp.source_port) break;
    if (i < d->count) {
        usbmux_connection *c = d->connections[i];
        status = usbmux_connection_feed(c, frame->payload, frame->payload_size, c->generation, d->now);
        if (status == USBMUX_CONNECTION_BUSY) return IAP2_OK; /* Keep the physical packet until completion unblocks it. */
        if (status != IAP2_OK && status != IAP2_END) return stop(d, USBMUX_DISPATCHER_REASON_CONNECTION, status, i);
        status = usbmux_connection_poll(c, c->generation, d->now);
        if (status != IAP2_OK && status != IAP2_MORE && status != IAP2_END) return stop(d, USBMUX_DISPATCHER_REASON_CONNECTION, status, i);
    } else if (d->ignored_packets != UINT32_MAX) d->ignored_packets++;
    status = usbmux_host_release(d->host, d->generation, d->now);
    if (status) return stop(d, USBMUX_DISPATCHER_REASON_HOST, status, USBMUX_DISPATCHER_SLOTS);
    d->again = 1; return IAP2_OK;
}
static int schedule(usbmux_dispatcher *d) {
    unsigned step, i; const uint8_t *data; size_t size; int status;
    if (d->host->state != USBMUX_HOST_READY || d->host->tx_size) return IAP2_OK;
    if (d->owner) return stop(d, USBMUX_DISPATCHER_REASON_STATE, IAP2_INVALID, d->owner_slot);
    for (step = 0; step < d->count; ++step) {
        i = d->round_robin + step; if (i >= d->count) i -= d->count;
        if (!d->used[i]) continue;
        status = usbmux_connection_output(d->connections[i], &data, &size);
        if (status == IAP2_MORE) continue;
        if (status || d->connections[i]->tx_offset) return stop(d, USBMUX_DISPATCHER_REASON_STATE, status ? status : IAP2_INVALID, i);
        status = usbmux_host_send_tcp(d->host, data, size, d->generation, d->now);
        if (status) return stop(d, USBMUX_DISPATCHER_REASON_HOST, status, i);
        d->owner = 1; d->owner_slot = i; d->owner_size = size; d->owner_connection = d->connections[i]->generation;
        d->owner_mux_sequence = d->host->tx_sequence;
        d->round_robin = i + 1; if (d->round_robin == d->count) d->round_robin = 0;
        d->write_paused = 0; d->again = 1; break;
    }
    return IAP2_OK;
}
int usbmux_dispatcher_poll(usbmux_dispatcher *d, uint64_t now) {
    size_t used, size; const uint8_t *data; int status = tick(d, now);
    if (status) return status;
    d->again = 0;
    if (can_feed(d) && !d->rx_size && (!d->read_paused || now - d->read_at >= d->config.retry_ms)) {
        usbmux_io_result r = {USBMUX_IO_FATAL, 0, 0};
        d->backend.read(d->backend.context, d->generation, d->rx, sizeof d->rx, &r);
        if (result(d, &r, sizeof d->rx)) return USBMUX_DISPATCHER_CLOSED;
        d->rx_size = r.count; d->rx_offset = 0; d->read_at = now; d->read_paused = r.count == 0;
        if (r.count) d->again = 1;
    }
    if (can_feed(d) && d->rx_size) {
        status = usbmux_host_feed(d->host, d->rx + d->rx_offset, d->rx_size - d->rx_offset, &used, d->generation, now);
        if (used > d->rx_size - d->rx_offset) return stop(d, USBMUX_DISPATCHER_REASON_STATE, IAP2_INVALID, USBMUX_DISPATCHER_SLOTS);
        if (status != IAP2_OK && status != IAP2_MORE && status != USBMUX_HOST_PACKET && status != USBMUX_HOST_BUSY)
            return stop(d, USBMUX_DISPATCHER_REASON_HOST, status, USBMUX_DISPATCHER_SLOTS);
        d->rx_offset += used; if (used) d->again = 1;
        if (d->rx_offset == d->rx_size) d->rx_size = d->rx_offset = 0;
    }
    if (route(d) || schedule(d)) return USBMUX_DISPATCHER_CLOSED;
    if (d->host->tx_size && (!d->write_paused || now - d->write_at >= d->config.retry_ms)) {
        usbmux_io_result r = {USBMUX_IO_FATAL, 0, 0};
        status = usbmux_host_output(d->host, &data, &size);
        if (status || !size) return stop(d, USBMUX_DISPATCHER_REASON_STATE, status ? status : IAP2_INVALID, USBMUX_DISPATCHER_SLOTS);
        d->backend.write(d->backend.context, d->generation, data, size, &r);
        if (result(d, &r, size)) return USBMUX_DISPATCHER_CLOSED;
        d->write_at = now; d->write_paused = r.count == 0;
        if (r.count) {
            status = usbmux_host_advance(d->host, r.count, d->generation, now);
            if (status != IAP2_OK && status != IAP2_MORE) return stop(d, USBMUX_DISPATCHER_REASON_HOST, status, USBMUX_DISPATCHER_SLOTS);
            d->again = 1;
            if (!d->host->tx_size && d->owner) {
                usbmux_connection *c = d->connections[d->owner_slot];
                if (c->generation != d->owner_connection || c->tx_offset || c->tx_size != d->owner_size ||
                    d->host->tx_sequence != (uint16_t)(d->owner_mux_sequence + 1u))
                    return stop(d, USBMUX_DISPATCHER_REASON_STATE, IAP2_INVALID, d->owner_slot);
                status = usbmux_connection_advance(c, d->owner_size, c->generation, now);
                if (status) return stop(d, USBMUX_DISPATCHER_REASON_CONNECTION, status, d->owner_slot);
                d->owner = 0; d->owner_size = 0; d->owner_connection = 0;
            }
        }
    }
    return d->control_pending ? USBMUX_DISPATCHER_CONTROL : (d->again ? IAP2_OK : IAP2_MORE);
}
uint32_t usbmux_dispatcher_next_delay(const usbmux_dispatcher *d) {
    uint32_t delay; unsigned i;
    if (!initialized(d) || !d->active) return UINT32_MAX;
    if (d->again) return 0;
    delay = usbmux_host_next_delay(d->host);
    for (i = 0; i < d->count; ++i) if (d->used[i]) {
        const usbmux_connection *c = d->connections[i]; delay = smaller(delay, usbmux_connection_next_delay(c));
        if (d->host->state == USBMUX_HOST_READY && !d->host->tx_size &&
            (c->tx_size || c->ack_pending || (c->fin_requested && !c->fin_sent && !c->flight_count))) return 0;
    }
    if (can_feed(d)) {
        if (d->rx_size) return 0;
        delay = smaller(delay, d->read_paused ? remaining(d->now, d->read_at, d->config.retry_ms) : 0);
    }
    if (d->host->tx_size) delay = smaller(delay, d->write_paused ? remaining(d->now, d->write_at, d->config.retry_ms) : 0);
    return delay;
}
static int handle_check(const usbmux_dispatcher *d, const usbmux_handle *h) {
    if (!initialized(d) || !h) return IAP2_ARGUMENT;
    if (h->physical != d->generation || h->slot >= d->count || !d->used[h->slot] ||
        h->connection != d->connections[h->slot]->generation) return USBMUX_DISPATCHER_STALE;
    return d->active ? IAP2_OK : USBMUX_DISPATCHER_CLOSED;
}
int usbmux_dispatcher_open(usbmux_dispatcher *d, uint16_t remote, uint32_t initial, usbmux_handle *handle, uint64_t now) {
    unsigned i; int status;
    if (!handle || !remote) return IAP2_ARGUMENT;
    status = tick(d, now); if (status) return status;
    if (d->host->state != USBMUX_HOST_READY) return USBMUX_DISPATCHER_BUSY;
    if (d->next_port > UINT16_MAX || d->next_connection == UINT64_MAX) return IAP2_NO_SPACE;
    for (i = 0; i < d->count; ++i) if (!d->used[i] || (d->connections[i]->state == USBMUX_CONNECTION_DRAINED &&
        !d->connections[i]->rx_used && (!d->owner || d->owner_slot != i))) break;
    if (i == d->count) return USBMUX_DISPATCHER_BUSY;
    status = usbmux_connection_start(d->connections[i], (uint16_t)d->next_port, remote, initial, d->next_connection + 1, now);
    if (status) return stop(d, USBMUX_DISPATCHER_REASON_STATE, status, i);
    d->next_port++; d->next_connection++; d->used[i] = d->again = 1;
    handle->physical = d->generation; handle->connection = d->next_connection; handle->slot = i;
    return IAP2_OK;
}
int usbmux_dispatcher_state(const usbmux_dispatcher *d, const usbmux_handle *handle, enum usbmux_connection_state *state) {
    int status;
    if (!state) return IAP2_ARGUMENT;
    status = handle_check(d, handle); if (status) return status;
    *state = d->connections[handle->slot]->state; return IAP2_OK;
}
int usbmux_dispatcher_read(usbmux_dispatcher *d, const usbmux_handle *handle, uint8_t *out, size_t capacity, size_t *read, uint64_t now) {
    const uint8_t *data; size_t size; int status;
    if (read) *read = 0;
    if (!read || (!out && capacity)) return IAP2_ARGUMENT;
    status = handle_check(d, handle); if (status) return status;
    status = tick(d, now); if (status) return status;
    if (!capacity) return IAP2_MORE;
    status = usbmux_connection_input(d->connections[handle->slot], &data, &size); if (status) return status;
    if (size > capacity) size = capacity;
    copy(out, data, size);
    status = usbmux_connection_consume(d->connections[handle->slot], size, handle->connection, now);
    if (status) return stop(d, USBMUX_DISPATCHER_REASON_CONNECTION, status, handle->slot);
    *read = size; d->again = 1; return IAP2_OK;
}
int usbmux_dispatcher_write(usbmux_dispatcher *d, const usbmux_handle *handle, const uint8_t *data, size_t size, size_t *written, uint64_t now) {
    int status;
    if (written) *written = 0;
    if (!written || (!data && size)) return IAP2_ARGUMENT;
    status = handle_check(d, handle); if (status) return status;
    status = tick(d, now); if (status) return status;
    status = usbmux_connection_write(d->connections[handle->slot], data, size, written, handle->connection, now);
    if (status != IAP2_OK && status != IAP2_MORE && status != USBMUX_CONNECTION_BUSY)
        return stop(d, USBMUX_DISPATCHER_REASON_CONNECTION, status, handle->slot);
    if (*written) d->again = 1;
    return status;
}
int usbmux_dispatcher_finish(usbmux_dispatcher *d, const usbmux_handle *handle, uint64_t now) {
    int status = handle_check(d, handle); if (status) return status;
    status = tick(d, now); if (status) return status;
    status = usbmux_connection_finish(d->connections[handle->slot], handle->connection, now);
    if (status != IAP2_OK && status != IAP2_END && status != USBMUX_CONNECTION_BUSY)
        return stop(d, USBMUX_DISPATCHER_REASON_CONNECTION, status, handle->slot);
    if (!status) d->again = 1;
    return status;
}
int usbmux_dispatcher_control(const usbmux_dispatcher *d, const usbmux_frame **frame, uint64_t *token) {
    if (frame) *frame = NULL;
    if (token) *token = 0;
    if (!initialized(d) || !frame || !token) return IAP2_ARGUMENT;
    if (!d->active) return USBMUX_DISPATCHER_CLOSED;
    if (!d->control_pending) return IAP2_MORE;
    *frame = &d->host->packet; *token = d->control_token; return USBMUX_DISPATCHER_CONTROL;
}
int usbmux_dispatcher_release_control(usbmux_dispatcher *d, uint64_t physical, uint64_t token, uint64_t now) {
    int status;
    if (!initialized(d)) return IAP2_ARGUMENT;
    if (physical != d->generation || !d->control_pending || !token || token != d->control_token) return USBMUX_DISPATCHER_STALE;
    status = tick(d, now); if (status) return status;
    status = usbmux_host_release(d->host, d->generation, now);
    if (status) return stop(d, USBMUX_DISPATCHER_REASON_HOST, status, USBMUX_DISPATCHER_SLOTS);
    d->control_pending = 0; d->control_token = 0; d->again = 1; return IAP2_OK;
}
