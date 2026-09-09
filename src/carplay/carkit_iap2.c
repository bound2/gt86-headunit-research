/* SPDX-License-Identifier: GPL-3.0-only */
#include "carkit_iap2.h"
#include <string.h>
static int initialized(const carkit_iap2 *b) { return b && b->channel && b->pump.endpoint; }
static int same_handle(const usbmux_handle *a, const usbmux_handle *b) {
    return a->physical == b->physical && a->connection == b->connection && a->slot == b->slot;
}
static int current(const carkit_iap2 *b) {
    enum usbmux_connection_state state; const carkit *c = b->channel;
    if (!same_handle(&b->handle, &c->handle) || !same_handle(&b->lockdown_handle, &c->client->tls->handle)) return 0;
    return !usbmux_dispatcher_state(c->client->tls->dispatcher, &b->handle, &state) &&
           !usbmux_dispatcher_state(c->client->tls->dispatcher, &b->lockdown_handle, &state);
}
static void discard(carkit_iap2 *b) {
    memset(b->pending, 0, sizeof b->pending); b->pending_size = b->submitted = 0; b->complete = b->again = 0;
}
static void cancel(void *context, uint64_t generation) {
    carkit_iap2 *b = (carkit_iap2 *)context;
    /* Old completion/cancel labels cannot act on a replacement stream. */
    if (generation != b->generation) return;
    if (same_handle(&b->handle, &b->channel->handle) && same_handle(&b->lockdown_handle, &b->channel->client->tls->handle)) {
        /* Let the stale carkit owner free its crypto without ticking/cancelling
         * a newer dispatcher generation. carkit_close is generation-aware. */
        carkit_close(b->channel);
    }
    discard(b);
}
static int stop(carkit_iap2 *b, enum carkit_iap2_reason reason, int error) {
    if (initialized(b) && b->state != CARKIT_IAP2_DEAD) {
        b->state = CARKIT_IAP2_DEAD; b->reason = reason; b->last_error = error;
        if (b->pump.active) iap2_transport_close(&b->pump);
        else { cancel(b, b->generation); iap2_control_close(b->pump.endpoint); }
        discard(b);
    }
    return IAP2_LINK_CLOSED;
}
static int callback_current(carkit_iap2 *b, uint64_t generation, iap2_transport_result *result) {
    result->status = IAP2_TRANSPORT_WOULD_BLOCK; result->count = 0; result->generation = b->generation;
    if (generation != b->generation || b->state != CARKIT_IAP2_ACTIVE || !current(b)) {
        result->status = IAP2_TRANSPORT_FATAL; return 0;
    }
    return 1;
}
static void read_bytes(void *context, uint64_t generation, uint8_t *out, size_t cap, iap2_transport_result *result) {
    carkit_iap2 *b = (carkit_iap2 *)context; size_t n; int status;
    if (!callback_current(b, generation, result)) return;
    status = carkit_read(b->channel, out, cap, &n, b->now);
    if (status != IAP2_OK && status != IAP2_MORE) { result->status = IAP2_TRANSPORT_DISCONNECTED; return; }
    if (n) { result->status = IAP2_TRANSPORT_PROGRESS; result->count = n; }
}
static void write_bytes(void *context, uint64_t generation, const uint8_t *data, size_t size, iap2_transport_result *result) {
    carkit_iap2 *b = (carkit_iap2 *)context;
    if (!callback_current(b, generation, result)) return;
    if (!data || !size || size > sizeof b->pending) { result->status = IAP2_TRANSPORT_FATAL; return; }
    if (b->pending_size) {
        if (size != b->pending_size || memcmp(data, b->pending, size)) { result->status = IAP2_TRANSPORT_FATAL; return; }
        if (b->complete) {
            result->status = IAP2_TRANSPORT_PROGRESS; result->count = size; discard(b); b->again = 1;
        }
        return;
    }
    memcpy(b->pending, data, size); b->pending_size = size; b->submitted = 0; b->complete = 0; b->again = 1;
}
int carkit_iap2_init(carkit_iap2 *b, carkit *channel, iap2_control *endpoint, const iap2_transport_config *config) {
    iap2_transport_backend backend; enum usbmux_connection_state state; int status;
    if (!b || !channel || !channel->client || !channel->client->tls || !channel->service_tls || !endpoint || !config ||
        !config->pending_ms || config->pending_ms > 60000 || !config->retry_ms || config->retry_ms > 1000 || config->retry_ms > config->pending_ms ||
        endpoint->reason != IAP2_CONTROL_REASON_NONE || endpoint->link.state != IAP2_LINK_IDLE) return IAP2_ARGUMENT;
    if (channel->state != CARKIT_OPEN || channel->application_used) return CARKIT_BUSY;
    status = usbmux_dispatcher_state(channel->client->tls->dispatcher, &channel->handle, &state); if (status) return status;
    if (state != USBMUX_CONNECTION_OPEN) return CARKIT_BUSY;
    memset(b, 0, sizeof *b); b->channel = channel; b->handle = channel->handle; b->lockdown_handle = channel->client->tls->handle;
    b->now = channel->now;
    backend.context = b; backend.read = read_bytes; backend.write = write_bytes; backend.cancel = cancel;
    return iap2_transport_init(&b->pump, endpoint, &backend, config);
}
int carkit_iap2_start(carkit_iap2 *b, uint64_t generation, uint64_t now) {
    int status;
    if (!initialized(b) || b->state != CARKIT_IAP2_IDLE || !generation) return IAP2_ARGUMENT;
    if (!current(b)) return stop(b, CARKIT_IAP2_REASON_STALE, USBMUX_DISPATCHER_STALE);
    if (b->pump.endpoint->startup_order == IAP2_CONTROL_IDENTIFICATION_FIRST &&
        b->pump.endpoint->identification.state == IAP2_IDENTIFICATION_DISABLED) return IAP2_ARGUMENT;
    if (now < b->now || now < b->pump.endpoint->link.now || now < b->channel->now || now < b->channel->client->tls->dispatcher->now) return IAP2_ARGUMENT;
    status = carkit_check(b->channel, now); if (status) return stop(b, CARKIT_IAP2_REASON_CARKIT, status);
    status = iap2_transport_start(&b->pump, generation, now); if (status) return status;
    b->generation = generation; b->now = now; b->state = CARKIT_IAP2_ACTIVE; return IAP2_OK;
}
static int advance(carkit_iap2 *b) {
    int status; size_t n;
    if (!b->pending_size || b->complete) return IAP2_OK;
    if (b->submitted < b->pending_size) {
        status = carkit_write(b->channel, b->pending + b->submitted, b->pending_size - b->submitted, &n, b->now);
        if (status != IAP2_OK && status != IAP2_MORE && status != CARKIT_BUSY) return stop(b, CARKIT_IAP2_REASON_CARKIT, status);
        if (n > b->pending_size - b->submitted) return stop(b, CARKIT_IAP2_REASON_RESULT, IAP2_INVALID);
        b->submitted += n; if (n) b->again = 1;
    }
    if (b->submitted == b->pending_size) {
        status = carkit_write_drained(b->channel, b->now);
        if (!status) { b->complete = 1; b->again = 1; }
        else if (status != IAP2_MORE) return stop(b, CARKIT_IAP2_REASON_CARKIT, status);
    }
    return IAP2_OK;
}
int carkit_iap2_poll(carkit_iap2 *b, uint64_t now) {
    int status, lower;
    if (!initialized(b)) return IAP2_ARGUMENT;
    if (b->state != CARKIT_IAP2_ACTIVE) return IAP2_LINK_CLOSED;
    if (!current(b)) return stop(b, CARKIT_IAP2_REASON_STALE, USBMUX_DISPATCHER_STALE);
    if (now < b->now || now < b->pump.now || now < b->pump.endpoint->link.now || now < b->channel->now ||
        now < b->channel->client->tls->dispatcher->now) return IAP2_ARGUMENT;
    b->now = now; b->again = 0;
    status = iap2_transport_check(&b->pump, now); if (status) return stop(b, CARKIT_IAP2_REASON_PUMP, status);
    status = carkit_check(b->channel, now); if (status) return stop(b, CARKIT_IAP2_REASON_CARKIT, status);
    lower = carkit_poll(b->channel, now);
    if (lower != CARKIT_READY) return stop(b, CARKIT_IAP2_REASON_CARKIT, lower);
    status = advance(b); if (status) return status;
    status = iap2_transport_poll(&b->pump, now);
    if (status != IAP2_OK && status != IAP2_MORE && status != IAP2_CONTROL_MESSAGE) return stop(b, CARKIT_IAP2_REASON_PUMP, status);
    if (status == IAP2_CONTROL_MESSAGE) return status;
    return b->again || status == IAP2_OK ? IAP2_OK : IAP2_MORE;
}
void carkit_iap2_close(carkit_iap2 *b) { if (initialized(b)) (void)stop(b, CARKIT_IAP2_REASON_LOCAL, IAP2_LINK_CLOSED); }
uint32_t carkit_iap2_next_delay(const carkit_iap2 *b) {
    uint32_t a, d;
    if (!initialized(b) || b->state != CARKIT_IAP2_ACTIVE) return UINT32_MAX;
    if (!current(b) || b->again || b->channel->now > b->now) return 0;
    a = iap2_transport_next_delay(&b->pump); d = carkit_next_delay(b->channel); return a < d ? a : d;
}
