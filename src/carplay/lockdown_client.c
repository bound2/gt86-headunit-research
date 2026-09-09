/* SPDX-License-Identifier: GPL-3.0-only */
#include "lockdown_client.h"
#include <string.h>
static int initialized(const lockdown_client *c) { return c && c->tls && c->request && c->response; }
static int held(const lockdown_client *c) { return c->state == LOCKDOWN_CLIENT_HELD || c->state == LOCKDOWN_CLIENT_ERROR_HELD; }
static int event_status(const lockdown_client *c) { return c->state == LOCKDOWN_CLIENT_ERROR_HELD ? LOCKDOWN_REPLY_REMOTE_ERROR : LOCKDOWN_CLIENT_REPLY; }
static void discard(lockdown_client *c) {
    memset(&c->document, 0, sizeof c->document); memset(&c->reply, 0, sizeof c->reply);
    c->token = 0; c->used = 0; c->expected_size = 4;
}
static int stop(lockdown_client *c, enum lockdown_client_reason reason, int error) {
    if (initialized(c) && c->state != LOCKDOWN_CLIENT_DEAD) {
        c->state = LOCKDOWN_CLIENT_DEAD; c->reason = reason; c->last_error = error;
        lockdown_tls_close(c->tls); discard(c);
    }
    return LOCKDOWN_CLIENT_CLOSED;
}
int lockdown_client_check(lockdown_client *c, uint64_t now) {
    enum usbmux_connection_state state; int status;
    if (!initialized(c)) return IAP2_ARGUMENT;
    if (c->state == LOCKDOWN_CLIENT_DEAD) return LOCKDOWN_CLIENT_CLOSED;
    status = usbmux_dispatcher_state(c->tls->dispatcher, &c->tls->handle, &state);
    if (status) return stop(c, LOCKDOWN_CLIENT_REASON_TLS, status);
    if (now < c->now || now < c->tls->now || now < c->tls->dispatcher->now) return IAP2_ARGUMENT;
    c->now = now;
    if ((c->state == LOCKDOWN_CLIENT_EXCHANGE && now - c->started_at >= c->config.exchange_ms) ||
        (held(c) && now - c->held_at >= c->config.hold_ms)) return stop(c, LOCKDOWN_CLIENT_REASON_DEADLINE, LOCKDOWN_CLIENT_CLOSED);
    status = lockdown_tls_check(c->tls, now);
    if (status || c->tls->state != LOCKDOWN_TLS_OPEN) return stop(c, LOCKDOWN_CLIENT_REASON_TLS, status ? status : IAP2_INVALID);
    return IAP2_OK;
}
int lockdown_client_init(lockdown_client *c, lockdown_tls *tls, const lockdown_body *label,
                         uint8_t *request, size_t request_capacity, uint8_t *response, size_t response_capacity,
                         const service_plist_storage *storage, const lockdown_channel_config *config, uint64_t now) {
    enum usbmux_connection_state state; size_t i; int status;
    if (!c || !tls || !tls->initialized || !label || !label->data || !label->size || label->size > 64 ||
        !request || !response || request == response || request_capacity < 5 || request_capacity > LOCKDOWN_TLS_WRITE_LIMIT ||
        response_capacity < 5 || response_capacity > LOCKDOWN_FRAME_LIMIT || !storage || !storage->nodes || !storage->bytes ||
        !storage->node_capacity || storage->node_capacity > SERVICE_PLIST_NODES || !storage->byte_capacity || storage->byte_capacity > SERVICE_PLIST_LIMIT ||
        !config || !config->exchange_ms || config->exchange_ms > 60000 || !config->hold_ms || config->hold_ms > 60000) return IAP2_ARGUMENT;
    for (i = 0; i < label->size; ++i) if (label->data[i] < 32 || label->data[i] > 126) return IAP2_ARGUMENT;
    status = usbmux_dispatcher_state(tls->dispatcher, &tls->handle, &state); if (status) return status;
    if (tls->state != LOCKDOWN_TLS_OPEN || tls->application_used || tls->tx_size || tls->rx_size || !tls->session_id_size ||
        state != USBMUX_CONNECTION_OPEN || tls->dispatcher->connections[tls->handle.slot]->peer_fin) return LOCKDOWN_CLIENT_BUSY;
    if (tls->dispatcher->connections[tls->handle.slot]->remote_port != 62078) return IAP2_UNSUPPORTED;
    if (now < tls->now || now < tls->dispatcher->now) return IAP2_ARGUMENT;
    memset(c, 0, sizeof *c); c->tls = tls; c->request = request; c->request_capacity = request_capacity;
    c->response = response; c->response_capacity = response_capacity; c->storage = *storage; c->config = *config;
    memcpy(c->label, label->data, label->size); c->label_size = label->size; c->now = now; c->expected_size = 4;
    return IAP2_OK;
}
static int writable(lockdown_client *c, uint64_t now) {
    int status = lockdown_client_check(c, now); if (status) return status;
    if (c->state != LOCKDOWN_CLIENT_IDLE || c->tls->tx_size) return LOCKDOWN_CLIENT_BUSY;
    if (c->tls->rx_size) return stop(c, LOCKDOWN_CLIENT_REASON_UNEXPECTED, IAP2_INVALID);
    if (c->tls->dispatcher->connections[c->tls->handle.slot]->peer_fin) return stop(c, LOCKDOWN_CLIENT_REASON_TLS, IAP2_END);
    if (c->next_token == UINT64_MAX) return IAP2_NO_SPACE;
    return IAP2_OK;
}
static int queue(lockdown_client *c, size_t size, enum lockdown_reply_command command, enum service_plist_type expected, uint64_t now) {
    int status;
    c->request[0] = (uint8_t)(size >> 24); c->request[1] = (uint8_t)(size >> 16);
    c->request[2] = (uint8_t)(size >> 8); c->request[3] = (uint8_t)size;
    status = lockdown_tls_write(c->tls, c->request, size + 4, now);
    if (status) return status == LOCKDOWN_TLS_CLOSED ? stop(c, LOCKDOWN_CLIENT_REASON_TLS, status) : status;
    discard(c); c->command = command; c->expected_type = expected; c->state = LOCKDOWN_CLIENT_EXCHANGE; c->started_at = now;
    return IAP2_OK;
}
int lockdown_client_get_value(lockdown_client *c, const lockdown_body *key, const lockdown_body *domain, enum service_plist_type expected, uint64_t now) {
    lockdown_body label; size_t size; int status;
    if (expected < SERVICE_PLIST_NULL || expected >= SERVICE_PLIST_KEY) return IAP2_ARGUMENT;
    status = writable(c, now); if (status) return status;
    label.data = c->label; label.size = c->label_size;
    status = lockdown_get_value_encode(&label, key, domain, c->request + 4, c->request_capacity - 4, &size); if (status) return status;
    return queue(c, size, LOCKDOWN_REPLY_GET_VALUE, expected, now);
}
int lockdown_client_start_service(lockdown_client *c, const lockdown_body *service, uint64_t now) {
    size_t size; int status = writable(c, now); if (status) return status;
    status = lockdown_start_service_encode(service, c->request + 4, c->request_capacity - 4, &size); if (status) return status;
    return queue(c, size, LOCKDOWN_REPLY_START_SERVICE, SERVICE_PLIST_NULL, now);
}
int lockdown_client_poll(lockdown_client *c, uint64_t now) {
    size_t n, amount; int status = lockdown_client_check(c, now), transport;
    if (status) return status;
    transport = lockdown_tls_poll(c->tls, now);
    if (transport != IAP2_OK && transport != IAP2_MORE && transport != USBMUX_DISPATCHER_CONTROL) return stop(c, LOCKDOWN_CLIENT_REASON_TLS, transport);
    if (held(c)) return event_status(c);
    if (c->state == LOCKDOWN_CLIENT_IDLE) {
        if (c->tls->rx_size) return stop(c, LOCKDOWN_CLIENT_REASON_UNEXPECTED, IAP2_INVALID);
        return transport;
    }
    if (c->used < c->expected_size) {
        amount = c->expected_size - c->used; if (amount > LOCKDOWN_TLS_CHUNK) amount = LOCKDOWN_TLS_CHUNK;
        status = lockdown_tls_read(c->tls, c->response + c->used, amount, &n, now);
        if (status != IAP2_OK && status != IAP2_MORE) return stop(c, LOCKDOWN_CLIENT_REASON_TLS, status);
        c->used += n;
        if (c->used == 4 && c->expected_size == 4) {
            size_t total; status = lockdown_frame_size(c->response, 4, &total);
            if (status || total > c->response_capacity) return stop(c, LOCKDOWN_CLIENT_REASON_RESPONSE, status ? status : IAP2_NO_SPACE);
            c->expected_size = total;
        }
    }
    if (c->used == c->expected_size && !c->tls->tx_size) {
        const usbmux_connection *conn = c->tls->dispatcher->connections[c->tls->handle.slot];
        if (!conn->tx_size && !conn->flight_count) {
            status = service_plist_decode(c->response + 4, c->expected_size - 4, &c->storage, &c->document);
            if (!status) status = lockdown_reply_validate(&c->document, c->command, c->expected_type, &c->reply);
            if (status && status != LOCKDOWN_REPLY_REMOTE_ERROR) return stop(c, LOCKDOWN_CLIENT_REASON_RESPONSE, status);
            c->state = status ? LOCKDOWN_CLIENT_ERROR_HELD : LOCKDOWN_CLIENT_HELD;
            c->token = ++c->next_token; c->held_at = now; return event_status(c);
        }
    }
    return transport;
}
int lockdown_client_event(const lockdown_client *c, const lockdown_reply **reply, uint64_t *token) {
    enum usbmux_connection_state state;
    if (reply) *reply = NULL; if (token) *token = 0;
    if (!initialized(c) || !reply || !token) return IAP2_ARGUMENT;
    if (c->state == LOCKDOWN_CLIENT_DEAD || c->tls->state != LOCKDOWN_TLS_OPEN ||
        usbmux_dispatcher_state(c->tls->dispatcher, &c->tls->handle, &state)) return LOCKDOWN_CLIENT_CLOSED;
    if (!held(c)) return IAP2_MORE;
    *reply = &c->reply; *token = c->token; return event_status(c);
}
int lockdown_client_release(lockdown_client *c, uint64_t token, uint64_t now) {
    int status;
    if (!initialized(c)) return IAP2_ARGUMENT;
    if (!held(c) || !token || token != c->token) return USBMUX_DISPATCHER_STALE;
    status = lockdown_client_check(c, now); if (status) return status;
    discard(c); c->state = LOCKDOWN_CLIENT_IDLE; return IAP2_OK;
}
void lockdown_client_close(lockdown_client *c) { if (initialized(c)) (void)stop(c, LOCKDOWN_CLIENT_REASON_LOCAL, LOCKDOWN_CLIENT_CLOSED); }
uint32_t lockdown_client_next_delay(const lockdown_client *c) {
    uint64_t now, at, age; uint32_t delay, budget, left;
    if (!initialized(c) || c->state == LOCKDOWN_CLIENT_DEAD) return UINT32_MAX;
    delay = lockdown_tls_next_delay(c->tls);
    if (c->state == LOCKDOWN_CLIENT_IDLE) return delay;
    now = c->now > c->tls->now ? c->now : c->tls->now;
    if (now < c->tls->dispatcher->now) now = c->tls->dispatcher->now;
    at = held(c) ? c->held_at : c->started_at; budget = held(c) ? c->config.hold_ms : c->config.exchange_ms;
    age = now - at; left = age >= budget ? 0 : budget - (uint32_t)age;
    return delay < left ? delay : left;
}
