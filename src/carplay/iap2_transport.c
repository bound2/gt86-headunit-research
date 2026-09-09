/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "iap2_transport.h"

static void clear(void *out, size_t n) {
    size_t i; for (i = 0; i < n; ++i) ((uint8_t *)out)[i] = 0;
}
static void copy(void *out, const void *in, size_t n) {
    size_t i; for (i = 0; i < n; ++i) ((uint8_t *)out)[i] = ((const uint8_t *)in)[i];
}
static uint32_t smaller(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t remaining(uint64_t now, uint64_t at, uint32_t interval) {
    uint64_t age = now - at;
    return age >= interval ? 0 : interval - (uint32_t)age;
}
static void discard(iap2_transport *p) {
    clear(p->tx, sizeof p->tx); clear(p->rx, sizeof p->rx);
    p->tx_size = p->tx_offset = p->rx_size = p->rx_offset = 0;
    p->tx_at = p->read_at = p->write_at = 0;
    p->read_paused = p->write_paused = p->again = 0;
}
static int stop(iap2_transport *p, enum iap2_transport_reason reason, int error) {
    if (p->active) {
        p->active = 0; p->reason = reason; p->last_error = error;
        p->backend.cancel(p->backend.context, p->generation);
        iap2_control_close(p->endpoint); discard(p);
    }
    return IAP2_LINK_CLOSED;
}
void iap2_transport_default_config(iap2_transport_config *config) {
    if (config) { config->pending_ms = 250; config->retry_ms = 5; }
}
int iap2_transport_init(iap2_transport *p, iap2_control *endpoint,
                        const iap2_transport_backend *backend, const iap2_transport_config *config) {
    if (!p || !endpoint || !backend || !config || !backend->read || !backend->write ||
        !backend->cancel || !config->pending_ms || config->pending_ms > 60000 ||
        !config->retry_ms || config->retry_ms > 1000 || config->retry_ms > config->pending_ms ||
        endpoint->reason != IAP2_CONTROL_REASON_NONE || endpoint->link.state != IAP2_LINK_IDLE)
        return IAP2_ARGUMENT;
    clear(p, sizeof *p); p->endpoint = endpoint;
    copy(&p->backend, backend, sizeof *backend); copy(&p->config, config, sizeof *config);
    return IAP2_OK;
}
int iap2_transport_start(iap2_transport *p, uint64_t generation, uint64_t now) {
    int status;
    if (!p || p->active || !generation || generation <= p->generation || now < p->now ||
        now < p->endpoint->link.now || p->endpoint->reason != IAP2_CONTROL_REASON_NONE ||
        p->endpoint->link.state != IAP2_LINK_IDLE) return IAP2_ARGUMENT;
    status = iap2_control_start(p->endpoint, now); if (status) return status;
    discard(p); p->generation = generation; p->now = now; p->active = 1; p->again = 1;
    p->reason = IAP2_TRANSPORT_REASON_NONE; p->last_error = p->last_feed_error = IAP2_OK;
    return IAP2_OK;
}
void iap2_transport_close(iap2_transport *p) {
    if (p) (void)stop(p, IAP2_TRANSPORT_REASON_LOCAL, IAP2_LINK_CLOSED);
}

/* Ignore output-readiness zeros when a frame is retained, but do not mask hard
 * endpoint deadlines. Read-only coupling to the current bounded control profile. */
static uint32_t hard_delay(const iap2_transport *p) {
    const iap2_control *c = p->endpoint;
    uint32_t d = UINT32_MAX;
    if (c->link.state == IAP2_LINK_DETECT || c->link.state == IAP2_LINK_SYNCHRONIZE)
        d = remaining(p->now, c->link.started_at, c->link.config.handshake_ms);
    if (c->receive_used) d = smaller(d, remaining(p->now, c->message_at, c->message_ms));
    if (c->authentication_timer) d = smaller(d, remaining(p->now, c->authentication_at, c->authentication_ms));
    if (c->identification_timer) d = smaller(d, remaining(p->now, c->identification_at, c->identification_ms));
    if (c->application_reply) d = smaller(d, remaining(p->now, c->reply_at, c->message_ms));
    return d;
}
static uint32_t pending_delay(const iap2_transport *p) {
    const iap2_link *l = &p->endpoint->link;
    uint32_t d;
    unsigned i;
    if (!p->tx_size) return UINT32_MAX;
    d = remaining(p->now, p->tx_at, p->config.pending_ms);
    /* The marker/SYN intervals match iap2_link_output's current local profile. */
    if (l->state == IAP2_LINK_DETECT && l->marker_sent)
        d = smaller(d, remaining(p->now, l->marker_at, 1000));
    if (l->state == IAP2_LINK_SYNCHRONIZE && l->syn_sent)
        d = smaller(d, remaining(p->now, l->syn_at, 500));
    if (l->state == IAP2_LINK_NORMAL) {
        for (i = 0; i < l->tx_sent; ++i) {
            const iap2_link_packet *packet = &l->tx[(l->tx_head + i) % IAP2_LINK_SLOTS];
            d = smaller(d, remaining(p->now, packet->sent_at, l->negotiated.retransmit_ms));
        }
    }
    return d;
}
static int result_check(iap2_transport *p, const iap2_transport_result *r, size_t extent) {
    if (r->generation != p->generation)
        return stop(p, IAP2_TRANSPORT_REASON_STALE, IAP2_INVALID);
    if (r->status < IAP2_TRANSPORT_PROGRESS || r->status > IAP2_TRANSPORT_FATAL ||
        r->count > extent || (r->status != IAP2_TRANSPORT_PROGRESS && r->count))
        return stop(p, IAP2_TRANSPORT_REASON_RESULT, IAP2_INVALID);
    if (r->status == IAP2_TRANSPORT_DISCONNECTED)
        return stop(p, IAP2_TRANSPORT_REASON_DISCONNECTED, IAP2_LINK_CLOSED);
    if (r->status == IAP2_TRANSPORT_FATAL)
        return stop(p, IAP2_TRANSPORT_REASON_IO, IAP2_PROVIDER_FAILED);
    return IAP2_OK;
}
static int endpoint_check(iap2_transport *p, int status) {
    if (p->endpoint->reason != IAP2_CONTROL_REASON_NONE ||
        p->endpoint->link.state == IAP2_LINK_DEAD || p->endpoint->link.state == IAP2_LINK_IDLE)
        return stop(p, IAP2_TRANSPORT_REASON_ENDPOINT,
                    p->endpoint->last_error ? p->endpoint->last_error : status);
    return IAP2_OK;
}
int iap2_transport_poll(iap2_transport *p, uint64_t now) {
    iap2_control *c;
    size_t used;
    int status;
    if (!p) return IAP2_ARGUMENT;
    if (!p->active) return IAP2_LINK_CLOSED;
    c = p->endpoint;
    if (now < p->now || now < c->link.now) return IAP2_ARGUMENT;
    p->now = now; p->again = 0;
    status = iap2_control_feed(c, NULL, 0, &used, now);
    if (endpoint_check(p, status)) return IAP2_LINK_CLOSED;
    if (status) return stop(p, IAP2_TRANSPORT_REASON_ENDPOINT, status);
    if (!pending_delay(p)) return stop(p, IAP2_TRANSPORT_REASON_DEADLINE, IAP2_LINK_CLOSED);

    if (!p->rx_size && (!p->read_paused || now - p->read_at >= p->config.retry_ms)) {
        iap2_transport_result r = { IAP2_TRANSPORT_FATAL, 0, 0 };
        p->backend.read(p->backend.context, p->generation, p->rx, sizeof p->rx, &r);
        if (result_check(p, &r, sizeof p->rx)) return IAP2_LINK_CLOSED;
        p->rx_size = r.count;
        p->read_paused = r.count == 0; p->read_at = now;
        if (r.count) p->again = 1;
    }
    if (p->rx_size) {
        status = iap2_control_feed(c, p->rx + p->rx_offset, p->rx_size - p->rx_offset, &used, now);
        if (endpoint_check(p, status)) return IAP2_LINK_CLOSED;
        if (used > p->rx_size - p->rx_offset)
            return stop(p, IAP2_TRANSPORT_REASON_ENDPOINT, IAP2_INVALID);
        p->rx_offset += used;
        if (status && status != IAP2_INVALID && status != IAP2_UNSUPPORTED && status != IAP2_LINK_BUSY)
            return stop(p, IAP2_TRANSPORT_REASON_ENDPOINT, status);
        if (status) p->last_feed_error = status;
        if (p->rx_offset == p->rx_size) {
            clear(p->rx, sizeof p->rx); p->rx_offset = p->rx_size = 0;
        } else if (used) p->again = 1;
    }
    status = iap2_control_poll(c, now);
    if (endpoint_check(p, status)) return IAP2_LINK_CLOSED;
    if (status != IAP2_OK && status != IAP2_MORE && status != IAP2_LINK_BUSY && status != IAP2_CONTROL_MESSAGE)
        return stop(p, IAP2_TRANSPORT_REASON_ENDPOINT, status);
    if (status == IAP2_OK) p->again = 1;
    /* Input may have changed the negotiated retransmit interval. */
    if (!pending_delay(p)) return stop(p, IAP2_TRANSPORT_REASON_DEADLINE, IAP2_LINK_CLOSED);
    if (!p->tx_size) {
        status = iap2_control_output(c, p->tx, sizeof p->tx, &p->tx_size, now);
        if (endpoint_check(p, status)) return IAP2_LINK_CLOSED;
        if (status != IAP2_OK && status != IAP2_MORE)
            return stop(p, IAP2_TRANSPORT_REASON_ENDPOINT, status);
        if (p->tx_size) { p->tx_at = now; p->write_paused = 0; }
    }
    if (p->tx_size && (!p->write_paused || now - p->write_at >= p->config.retry_ms)) {
        iap2_transport_result r = { IAP2_TRANSPORT_FATAL, 0, 0 };
        p->backend.write(p->backend.context, p->generation, p->tx + p->tx_offset,
                         p->tx_size - p->tx_offset, &r);
        if (result_check(p, &r, p->tx_size - p->tx_offset)) return IAP2_LINK_CLOSED;
        p->tx_offset += r.count;
        p->write_paused = r.count == 0; p->write_at = now;
        if (r.count) p->again = 1;
        if (p->tx_offset == p->tx_size) {
            clear(p->tx, sizeof p->tx); p->tx_size = p->tx_offset = 0; p->tx_at = 0;
        }
    }
    if (c->ready) return IAP2_CONTROL_MESSAGE;
    return p->again ? IAP2_OK : IAP2_MORE;
}
uint32_t iap2_transport_next_delay(const iap2_transport *p) {
    uint32_t d, endpoint;
    if (!p || !p->active) return UINT32_MAX;
    if (p->endpoint->link.now > p->now) return 0; /* Application advanced the shared clock. */
    if (p->again) return 0;
    d = smaller(p->config.retry_ms, hard_delay(p));
    d = smaller(d, pending_delay(p));
    if (p->read_paused) d = smaller(d, remaining(p->now, p->read_at, p->config.retry_ms));
    if (p->write_paused) d = smaller(d, remaining(p->now, p->write_at, p->config.retry_ms));
    endpoint = iap2_control_next_delay(p->endpoint);
    if (endpoint || !p->tx_size) d = smaller(d, endpoint);
    return d;
}
