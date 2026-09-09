/* SPDX-License-Identifier: GPL-3.0-only */
#include "carkit.h"
#include <string.h>
static int initialized(const carkit *c) { return c && c->client && c->service_tls; }
static int same_certificate(const mbedtls_x509_crt *a, const mbedtls_x509_crt *b) {
    return a->raw.len == b->raw.len && !memcmp(a->raw.p, b->raw.p, a->raw.len);
}
static int stop(carkit *c, enum carkit_reason reason, int error) {
    if (initialized(c) && c->state != CARKIT_DEAD) {
        c->state = CARKIT_DEAD; c->reason = reason; c->last_error = error;
        lockdown_tls_close(c->service_tls); lockdown_client_close(c->client);
        memset(&c->credentials, 0, sizeof c->credentials); memset(&c->handle, 0, sizeof c->handle);
        c->port = c->use_tls = c->tls_flag_present = 0;
    }
    return CARKIT_CLOSED;
}
static int tick(carkit *c, uint64_t now) {
    enum usbmux_connection_state state; int status;
    if (!initialized(c)) return IAP2_ARGUMENT;
    if (c->state == CARKIT_DEAD) return CARKIT_CLOSED;
    /* Let the current-generation owner reject stale handles before time. */
    status = usbmux_dispatcher_state(c->client->tls->dispatcher, &c->client->tls->handle, &state);
    if (status) return stop(c, CARKIT_REASON_LOCKDOWN, status);
    if (now < c->now || now < c->client->now || now < c->client->tls->now || now < c->client->tls->dispatcher->now ||
        (c->service_tls->initialized && now < c->service_tls->now)) return IAP2_ARGUMENT;
    c->now = now;
    if (c->state >= CARKIT_REQUEST && c->state <= CARKIT_HANDSHAKE && now - c->started_at >= c->config.startup_ms)
        return stop(c, CARKIT_REASON_DEADLINE, CARKIT_CLOSED);
    status = lockdown_client_check(c->client, now); if (status) return stop(c, CARKIT_REASON_LOCKDOWN, status);
    if (c->state >= CARKIT_PORT && c->state <= CARKIT_OPEN && c->client->state != LOCKDOWN_CLIENT_IDLE)
        return stop(c, CARKIT_REASON_LOCKDOWN, IAP2_INVALID);
    if (c->handle.physical) {
        status = usbmux_dispatcher_state(c->client->tls->dispatcher, &c->handle, &state);
        if (status) return stop(c, CARKIT_REASON_TRANSPORT, status);
        if (c->state >= CARKIT_HANDSHAKE && state != USBMUX_CONNECTION_OPEN) return stop(c, CARKIT_REASON_TRANSPORT, IAP2_END);
    }
    if (c->service_tls->initialized) {
        status = lockdown_tls_check(c->service_tls, now); if (status) return stop(c, CARKIT_REASON_TLS, status);
    }
    return IAP2_OK;
}
void carkit_default_config(carkit_config *cfg) {
    if (cfg) { cfg->policy = CARKIT_REQUIRE_TLS; cfg->startup_ms = 15000; cfg->initial_sequence = 0; lockdown_tls_default_config(&cfg->tls); }
}
int carkit_check(carkit *c, uint64_t now) { return tick(c, now); }
int carkit_write_drained(carkit *c, uint64_t now) {
    const usbmux_connection *conn; int status = tick(c, now); if (status) return status;
    if (c->state != CARKIT_OPEN) return CARKIT_BUSY;
    conn = c->client->tls->dispatcher->connections[c->handle.slot];
    if (conn->peer_fin || conn->fin_requested || conn->fin_sent) return stop(c, CARKIT_REASON_TRANSPORT, IAP2_END);
    return (c->use_tls && c->service_tls->tx_size) || conn->tx_size || conn->flight_count ? IAP2_MORE : IAP2_OK;
}
int carkit_open(carkit *c, lockdown_client *client, lockdown_tls *service_tls,
                const lockdown_tls_credentials *creds, const carkit_config *config, uint64_t now) {
    static const uint8_t name[] = "com.apple.carkit.service";
    const lockdown_body service = {name, sizeof name - 1}; int status;
    if (!c || c->state != CARKIT_UNUSED || !client || !client->tls || !service_tls || service_tls == client->tls || service_tls->initialized ||
        !creds || !creds->random || !creds->root.data || !creds->root.size || creds->root.size > 32768 ||
        !creds->host_certificate.data || !creds->host_certificate.size || creds->host_certificate.size > 32768 ||
        !creds->host_private_key.data || !creds->host_private_key.size || creds->host_private_key.size > 16384 ||
        !creds->device_der.data || !creds->device_der.size || creds->device_der.size > 16384 ||
        !config || config->policy < CARKIT_REQUIRE_TLS || config->policy > CARKIT_ALLOW_PLAIN_IF_REPORTED ||
        !config->startup_ms || config->startup_ms > 60000 || !config->tls.handshake_ms || config->tls.handshake_ms > 60000 ||
        !config->tls.write_ms || config->tls.write_ms > 60000 || !config->tls.hold_ms || config->tls.hold_ms > 60000) return IAP2_ARGUMENT;
    status = lockdown_client_start_service(client, &service, now); if (status) return status;
    memset(c, 0, sizeof *c); c->client = client; c->service_tls = service_tls; c->credentials = *creds; c->config = *config;
    c->now = c->started_at = now; c->state = CARKIT_REQUEST; return IAP2_OK;
}
int carkit_poll(carkit *c, uint64_t now) {
    enum usbmux_connection_state state; int status = tick(c, now), transport;
    usbmux_dispatcher *d;
    if (status) return status;
    d = c->client->tls->dispatcher;
    transport = lockdown_client_poll(c->client, now);
    if (transport == LOCKDOWN_REPLY_REMOTE_ERROR) { c->state = CARKIT_ERROR_HELD; return transport; }
    if (transport != IAP2_OK && transport != IAP2_MORE && transport != USBMUX_DISPATCHER_CONTROL && transport != LOCKDOWN_CLIENT_REPLY)
        return stop(c, CARKIT_REASON_LOCKDOWN, transport);
    if (c->state == CARKIT_REQUEST && transport == LOCKDOWN_CLIENT_REPLY) {
        const lockdown_reply *reply; uint64_t token;
        status = lockdown_client_event(c->client, &reply, &token);
        if (status != LOCKDOWN_CLIENT_REPLY || c->client->command != LOCKDOWN_REPLY_START_SERVICE) return stop(c, CARKIT_REASON_LOCKDOWN, status);
        if (reply->port == 62078 || (!reply->tls_required && c->config.policy == CARKIT_REQUIRE_TLS)) return stop(c, CARKIT_REASON_POLICY, IAP2_AUTH_FAILED);
        c->port = reply->port; c->use_tls = reply->tls_required; c->tls_flag_present = reply->tls_flag_present;
        status = lockdown_client_release(c->client, token, now); if (status) return stop(c, CARKIT_REASON_LOCKDOWN, status);
        c->state = CARKIT_PORT;
    }
    if (c->state == CARKIT_PORT) {
        status = usbmux_dispatcher_open(d, c->port, c->config.initial_sequence, &c->handle, now);
        if (status == USBMUX_DISPATCHER_BUSY || status == IAP2_NO_SPACE) return IAP2_MORE;
        if (status) return stop(c, CARKIT_REASON_TRANSPORT, status);
        c->state = CARKIT_CONNECT;
    }
    if (c->state == CARKIT_CONNECT) {
        status = usbmux_dispatcher_state(d, &c->handle, &state);
        if (status) return stop(c, CARKIT_REASON_TRANSPORT, status);
        if (state == USBMUX_CONNECTION_OPEN) {
            const usbmux_connection *conn = d->connections[c->handle.slot];
            if (conn->peer_fin || conn->fin_requested || conn->fin_sent) return stop(c, CARKIT_REASON_TRANSPORT, IAP2_END);
            if (!c->use_tls) { c->state = CARKIT_OPEN; memset(&c->credentials, 0, sizeof c->credentials); }
            else {
                status = lockdown_tls_init_service(c->service_tls, d, &c->handle, &c->credentials, &c->config.tls, now);
                if (status) return stop(c, CARKIT_REASON_TLS, status);
                if (!same_certificate(&c->service_tls->host_certificate, &c->client->tls->host_certificate) ||
                    !same_certificate(&c->service_tls->device, &c->client->tls->device)) return stop(c, CARKIT_REASON_TLS, IAP2_AUTH_FAILED);
                memset(&c->credentials, 0, sizeof c->credentials); c->state = CARKIT_HANDSHAKE;
            }
        }
    }
    if (c->state == CARKIT_HANDSHAKE || (c->state == CARKIT_OPEN && c->use_tls)) {
        status = lockdown_tls_poll(c->service_tls, now);
        if (status != IAP2_OK && status != IAP2_MORE && status != USBMUX_DISPATCHER_CONTROL) return stop(c, CARKIT_REASON_TLS, status);
        if (c->service_tls->state == LOCKDOWN_TLS_OPEN) c->state = CARKIT_OPEN;
        if (status == USBMUX_DISPATCHER_CONTROL) transport = status;
    }
    if (c->state == CARKIT_OPEN) return CARKIT_READY;
    return transport == USBMUX_DISPATCHER_CONTROL ? transport : IAP2_MORE;
}
int carkit_write(carkit *c, const uint8_t *bytes, size_t size, size_t *accepted, uint64_t now) {
    int status; if (accepted) *accepted = 0;
    if (!bytes || !size || size > LOCKDOWN_TLS_WRITE_LIMIT || !accepted) return IAP2_ARGUMENT;
    status = tick(c, now); if (status) return status;
    if (c->state != CARKIT_OPEN) return CARKIT_BUSY;
    if (c->use_tls) {
        status = lockdown_tls_write(c->service_tls, bytes, size, now);
        if (!status) *accepted = size;
    } else {
        usbmux_dispatcher *d = c->client->tls->dispatcher;
        if (d->connections[c->handle.slot]->peer_fin) return stop(c, CARKIT_REASON_TRANSPORT, IAP2_END);
        status = usbmux_dispatcher_write(d, &c->handle, bytes, size, accepted, now);
    }
    if (*accepted) c->application_used = 1;
    if (status == IAP2_OK || status == IAP2_MORE || status == CARKIT_BUSY) return status;
    return stop(c, c->use_tls ? CARKIT_REASON_TLS : CARKIT_REASON_TRANSPORT, status);
}
int carkit_read(carkit *c, uint8_t *out, size_t capacity, size_t *size, uint64_t now) {
    int status; if (size) *size = 0;
    if (!out || !capacity || !size) return IAP2_ARGUMENT;
    status = tick(c, now); if (status) return status;
    if (c->state != CARKIT_OPEN) return IAP2_MORE;
    status = c->use_tls ? lockdown_tls_read(c->service_tls, out, capacity, size, now) :
        usbmux_dispatcher_read(c->client->tls->dispatcher, &c->handle, out, capacity, size, now);
    if (*size) c->application_used = 1;
    if (status == IAP2_OK || status == IAP2_MORE) return status;
    return stop(c, c->use_tls ? CARKIT_REASON_TLS : CARKIT_REASON_TRANSPORT, status);
}
void carkit_close(carkit *c) { if (initialized(c)) (void)stop(c, CARKIT_REASON_LOCAL, CARKIT_CLOSED); }
uint32_t carkit_next_delay(const carkit *c) {
    uint32_t delay, other; uint64_t now, age;
    if (!initialized(c) || c->state == CARKIT_DEAD) return UINT32_MAX;
    delay = lockdown_client_next_delay(c->client);
    if (c->service_tls->initialized) { other = lockdown_tls_next_delay(c->service_tls); if (other < delay) delay = other; }
    if (c->state >= CARKIT_REQUEST && c->state <= CARKIT_HANDSHAKE) {
        now = c->now > c->client->tls->dispatcher->now ? c->now : c->client->tls->dispatcher->now;
        age = now - c->started_at; other = age >= c->config.startup_ms ? 0 : c->config.startup_ms - (uint32_t)age;
        if (other < delay) delay = other;
    }
    return delay;
}
