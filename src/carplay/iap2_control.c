/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "iap2_control.h"

static void clear(uint8_t *p, size_t size) { size_t i; for (i = 0; i < size; ++i) p[i] = 0; }
static void copy(uint8_t *out, const uint8_t *in, size_t size) {
    size_t i; for (i = 0; i < size; ++i) out[i] = in[i];
}
static size_t smaller(size_t a, size_t b) { return a < b ? a : b; }
static void discard(iap2_control *c) {
    c->receive_used = c->receive_expected = c->reply_size = c->reply_offset = 0;
    c->fragment_size = c->fragment_offset = 0;
    c->ready = c->authentication_timer = c->identification_timer = c->application_reply = c->work_pending = 0;
    c->message_at = c->authentication_at = c->identification_at = c->reply_at = 0;
    c->auth.state = IAP2_AUTH_IDLE;
    iap2_identification_reset(&c->identification);
    clear(c->buffers.receive, c->buffers.receive_capacity);
    clear(c->buffers.reply, c->buffers.reply_capacity);
    clear(c->buffers.scratch, c->buffers.scratch_capacity);
    clear(c->fragment, sizeof c->fragment);
}
static int fail(iap2_control *c, enum iap2_control_reason reason, int status) {
    if (c->reason == IAP2_CONTROL_REASON_NONE) {
        c->reason = reason; c->last_error = status;
        iap2_link_close(&c->link); discard(c);
    }
    return status;
}
static int observe(iap2_control *c, int status) {
    if (c->link.state == IAP2_LINK_DEAD)
        return fail(c, IAP2_CONTROL_REASON_LINK, status);
    if (c->application_reply && c->reply_offset == c->reply_size && !c->link.tx_count) {
        c->application_reply = 0; c->reply_at = 0;
    }
    if (c->link.state == IAP2_LINK_NORMAL && !c->authentication_timer &&
        c->auth.state != IAP2_AUTH_ACCEPTED &&
        (c->startup_order == IAP2_CONTROL_AUTHENTICATION_FIRST ||
         c->identification.state == IAP2_IDENTIFICATION_ACCEPTED)) {
        c->authentication_timer = 1; c->authentication_at = c->link.now;
    }
    if (c->link.state == IAP2_LINK_NORMAL && c->identification.state == IAP2_IDENTIFICATION_IDLE &&
        !c->identification_timer && (c->startup_order == IAP2_CONTROL_IDENTIFICATION_FIRST ||
         c->auth.state == IAP2_AUTH_ACCEPTED)) {
        c->identification_timer = 1; c->identification_at = c->link.now;
    }
    return status;
}
static int check_time(iap2_control *c, uint64_t now) {
    if (!c || now < c->link.now) return IAP2_ARGUMENT;
    if (c->reason != IAP2_CONTROL_REASON_NONE) return IAP2_LINK_CLOSED;
    if ((c->receive_used && now - c->message_at >= c->message_ms) ||
        (c->authentication_timer && c->auth.state != IAP2_AUTH_ACCEPTED &&
         now - c->authentication_at >= c->authentication_ms) ||
        (c->identification_timer && now - c->identification_at >= c->identification_ms) ||
        (c->application_reply && now - c->reply_at >= c->message_ms))
        return fail(c, IAP2_CONTROL_REASON_TIMEOUT, IAP2_LINK_CLOSED);
    return IAP2_OK;
}
void iap2_control_default_config(iap2_control_config *config) {
    if (!config) return;
    iap2_link_default_config(&config->link);
    config->message_ms = 5000; config->authentication_ms = 30000;
    config->identification_ms = 30000;
    config->startup_order = IAP2_CONTROL_AUTHENTICATION_FIRST;
}
int iap2_control_init(iap2_control *c, const iap2_control_config *config,
                      const iap2_auth_provider *provider, const iap2_control_buffers *buffers) {
    int status;
    if (!c || !config || !provider || !buffers || !buffers->receive || !buffers->reply ||
        !buffers->scratch || buffers->receive_capacity < 6 ||
        buffers->receive_capacity > IAP2_MAX_FRAME_SIZE || buffers->reply_capacity < 11 ||
        buffers->reply_capacity > IAP2_MAX_FRAME_SIZE || !buffers->scratch_capacity ||
        buffers->scratch_capacity > buffers->reply_capacity - 10 ||
        config->link.offer.session_count != 1 || !config->message_ms || !config->authentication_ms || !config->identification_ms ||
        (config->startup_order != IAP2_CONTROL_AUTHENTICATION_FIRST &&
         config->startup_order != IAP2_CONTROL_IDENTIFICATION_FIRST))
        return IAP2_ARGUMENT;
    /* Link init validates before mutation. It owns the only self-pointer. */
    status = iap2_link_init(&c->link, &config->link); if (status) return status;
    copy((uint8_t *)&c->buffers, (const uint8_t *)buffers, sizeof *buffers);
    c->message_ms = config->message_ms; c->authentication_ms = config->authentication_ms;
    c->identification_ms = config->identification_ms; c->last_identification_rejection = 0;
    c->startup_order = config->startup_order;
    clear((uint8_t *)&c->identification, sizeof c->identification);
    c->reason = IAP2_CONTROL_REASON_NONE; c->last_error = IAP2_OK;
    status = iap2_auth_init(&c->auth, provider, buffers->scratch, buffers->scratch_capacity);
    discard(c);
    return status; /* Cannot fail after the preflight above. */
}
static int enable_identification(iap2_control *c, const iap2_identification_metadata *metadata,
                                 const iap2_identification_wired *wired) {
    iap2_identification candidate;
    int status;
    if (!c || c->reason != IAP2_CONTROL_REASON_NONE || c->link.state != IAP2_LINK_IDLE) return IAP2_ARGUMENT;
    clear((uint8_t *)&candidate, sizeof candidate);
    status = wired ? iap2_identification_init_wired(&candidate, metadata, wired) : iap2_identification_init(&candidate, metadata);
    if (status) return status;
    if (candidate.information_size > c->buffers.reply_capacity) return IAP2_NO_SPACE;
    copy((uint8_t *)&c->identification, (const uint8_t *)&candidate, sizeof candidate);
    return IAP2_OK;
}
int iap2_control_enable_identification(iap2_control *c, const iap2_identification_metadata *metadata) {
    return enable_identification(c, metadata, NULL);
}
int iap2_control_enable_wired_identification(iap2_control *c, const iap2_identification_metadata *metadata,
                                           const iap2_identification_wired *wired) {
    if (!wired) return IAP2_ARGUMENT;
    return enable_identification(c, metadata, wired);
}
int iap2_control_start(iap2_control *c, uint64_t now) {
    int status;
    if (c && c->startup_order == IAP2_CONTROL_IDENTIFICATION_FIRST &&
        c->identification.state == IAP2_IDENTIFICATION_DISABLED) return IAP2_ARGUMENT;
    status = check_time(c, now); if (status) return status;
    return observe(c, iap2_link_start(&c->link, now));
}
void iap2_control_close(iap2_control *c) {
    if (c) (void)fail(c, IAP2_CONTROL_REASON_LOCAL, IAP2_LINK_CLOSED);
}
int iap2_control_feed(iap2_control *c, const uint8_t *data, size_t size, size_t *consumed, uint64_t now) {
    int status;
    if (consumed) *consumed = 0;
    if (!consumed || (!data && size)) return IAP2_ARGUMENT;
    status = check_time(c, now); if (status) return status;
    return observe(c, iap2_link_feed(&c->link, data, size, consumed, now));
}
int iap2_control_output(iap2_control *c, uint8_t *out, size_t capacity, size_t *written, uint64_t now) {
    int status;
    if (written) *written = 0;
    if (!out || !written) return IAP2_ARGUMENT;
    status = check_time(c, now); if (status) return status;
    return observe(c, iap2_link_output(&c->link, out, capacity, written, now));
}
int iap2_control_poll(iap2_control *c, uint64_t now) {
    unsigned work;
    size_t consumed;
    int status = check_time(c, now); if (status) return status;
    if (c->link.state == IAP2_LINK_IDLE) return IAP2_ARGUMENT;
    status = observe(c, iap2_link_feed(&c->link, NULL, 0, &consumed, now)); if (status) return status;
    c->work_pending = 0;
    if (c->link.state != IAP2_LINK_NORMAL) return IAP2_MORE;
    for (work = 0; work < IAP2_CONTROL_POLL_BUDGET; ++work) {
        size_t amount;
        if (c->reply_size) {
            if (c->reply_offset < c->reply_size) {
                amount = smaller(c->reply_size - c->reply_offset, (size_t)c->link.negotiated.packet_size - 10u);
                status = iap2_link_send(&c->link, c->link.negotiated.sessions[0].id,
                    c->buffers.reply + c->reply_offset, amount, now);
                if (status) return observe(c, status);
                c->reply_offset += amount;
                continue;
            }
            if (c->link.tx_count) return IAP2_LINK_BUSY;
            c->reply_size = c->reply_offset = 0;
            c->application_reply = 0; c->reply_at = 0;
            clear(c->buffers.reply, c->buffers.reply_capacity);
        }
        if (c->ready) return IAP2_CONTROL_MESSAGE;
        if (c->receive_used >= 6 && !c->receive_expected) {
            c->receive_expected = ((size_t)c->buffers.receive[2] << 8) | c->buffers.receive[3];
            if (c->buffers.receive[0] != 0x40 || c->buffers.receive[1] != 0x40 || c->receive_expected < 6)
                return fail(c, IAP2_CONTROL_REASON_MESSAGE, IAP2_INVALID);
            if (c->receive_expected > c->buffers.receive_capacity)
                return fail(c, IAP2_CONTROL_REASON_MESSAGE, IAP2_NO_SPACE);
        }
        if (c->receive_expected && c->receive_used == c->receive_expected) {
            iap2_message message;
            status = iap2_message_decode(c->buffers.receive, c->receive_used, &message, &consumed);
            if (status != IAP2_OK || consumed != c->receive_used)
                return fail(c, IAP2_CONTROL_REASON_MESSAGE, IAP2_INVALID);
            if (c->startup_order == IAP2_CONTROL_IDENTIFICATION_FIRST &&
                c->identification.state != IAP2_IDENTIFICATION_ACCEPTED &&
                message.id >= 0xaa00 && message.id <= 0xaa05)
                return fail(c, IAP2_CONTROL_REASON_AUTH, IAP2_AUTH_FAILED);
            status = iap2_auth_handle(&c->auth, c->buffers.receive, c->receive_used,
                c->buffers.reply, c->buffers.reply_capacity, &c->reply_size);
            if (status == IAP2_UNSUPPORTED && c->identification.state != IAP2_IDENTIFICATION_DISABLED &&
                message.id >= 0x1d00 && message.id <= 0x1d03) {
                if (c->startup_order == IAP2_CONTROL_AUTHENTICATION_FIRST &&
                    c->auth.state != IAP2_AUTH_ACCEPTED)
                    return fail(c, IAP2_CONTROL_REASON_IDENTIFICATION, IAP2_AUTH_FAILED);
                status = iap2_identification_handle(&c->identification, c->buffers.receive, c->receive_used,
                    c->buffers.reply, c->buffers.reply_capacity, &c->reply_size);
                if (status) {
                    c->last_identification_rejection = c->identification.rejected_fields;
                    return fail(c, IAP2_CONTROL_REASON_IDENTIFICATION, status);
                }
                if (c->identification.state == IAP2_IDENTIFICATION_ACCEPTED) c->identification_timer = 0;
            }
            if (status == IAP2_UNSUPPORTED) { c->ready = 1; return IAP2_CONTROL_MESSAGE; }
            if (status) return fail(c, IAP2_CONTROL_REASON_AUTH, status);
            c->receive_used = c->receive_expected = 0;
            if (c->auth.state == IAP2_AUTH_ACCEPTED) c->authentication_timer = 0;
            (void)observe(c, IAP2_OK);
            clear(c->buffers.scratch, c->buffers.scratch_capacity);
            continue;
        }
        if (c->fragment_offset == c->fragment_size) {
            uint8_t session;
            status = iap2_link_receive(&c->link, &session, c->fragment, sizeof c->fragment, &c->fragment_size);
            c->fragment_offset = 0;
            if (status) return observe(c, status);
            if (session != c->link.negotiated.sessions[0].id)
                return fail(c, IAP2_CONTROL_REASON_MESSAGE, IAP2_UNSUPPORTED);
            continue;
        }
        if (!c->receive_used) c->message_at = now;
        amount = smaller(c->fragment_size - c->fragment_offset,
            (c->receive_expected ? c->receive_expected : 6u) - c->receive_used);
        copy(c->buffers.receive + c->receive_used, c->fragment + c->fragment_offset, amount);
        c->receive_used += amount; c->fragment_offset += amount;
    }
    c->work_pending = 1;
    return IAP2_OK;
}
int iap2_control_message(const iap2_control *c, const uint8_t **data, size_t *size) {
    if (data) *data = NULL;
    if (size) *size = 0;
    if (!c || !data || !size) return IAP2_ARGUMENT;
    if (c->reason != IAP2_CONTROL_REASON_NONE) return IAP2_LINK_CLOSED;
    if (!c->ready) return IAP2_MORE;
    *data = c->buffers.receive; *size = c->receive_used; return IAP2_OK;
}
int iap2_control_release_message(iap2_control *c) {
    if (!c) return IAP2_ARGUMENT;
    if (c->reason != IAP2_CONTROL_REASON_NONE) return IAP2_LINK_CLOSED;
    if (!c->ready) return IAP2_MORE;
    c->ready = 0; c->receive_used = c->receive_expected = 0; c->work_pending = 1;
    return IAP2_OK;
}
static int queue_application(iap2_control *c, const uint8_t *data, size_t size, uint64_t now, int reply) {
    iap2_message message;
    size_t used;
    int status;
    if (!data) return IAP2_ARGUMENT;
    status = check_time(c, now); if (status) return status;
    if (c->link.state == IAP2_LINK_IDLE) return IAP2_ARGUMENT;
    status = observe(c, iap2_link_feed(&c->link, NULL, 0, &used, now)); if (status) return status;
    if (c->link.state != IAP2_LINK_NORMAL || c->reply_size) return IAP2_LINK_BUSY;
    if (c->auth.state != IAP2_AUTH_ACCEPTED) return IAP2_AUTH_FAILED;
    if (c->identification.state != IAP2_IDENTIFICATION_DISABLED &&
        c->identification.state != IAP2_IDENTIFICATION_ACCEPTED) return IAP2_LINK_BUSY;
    if (reply && !c->ready) return IAP2_MORE;
    status = iap2_message_decode(data, size, &message, &used);
    if (status != IAP2_OK || used != size) return IAP2_INVALID;
    if ((message.id >= 0xaa00 && message.id <= 0xaa05) ||
        (message.id >= 0x1d00 && message.id <= 0x1d03)) return IAP2_UNSUPPORTED;
    if (size > c->buffers.reply_capacity) return IAP2_NO_SPACE;
    copy(c->buffers.reply, data, size); c->reply_size = size; c->reply_offset = 0;
    c->application_reply = 1; c->reply_at = now;
    if (reply) (void)iap2_control_release_message(c);
    else c->work_pending = 1;
    return IAP2_OK;
}
int iap2_control_reply(iap2_control *c, const uint8_t *data, size_t size, uint64_t now) {
    return queue_application(c, data, size, now, 1);
}
int iap2_control_notify(iap2_control *c, const uint8_t *data, size_t size, uint64_t now) {
    return queue_application(c, data, size, now, 0);
}
static uint32_t remaining(uint64_t now, uint64_t at, uint32_t interval) {
    uint64_t age = now - at;
    return age >= interval ? 0 : interval - (uint32_t)age;
}
uint32_t iap2_control_next_delay(const iap2_control *c) {
    uint32_t delay;
    unsigned i;
    if (!c || c->link.state == IAP2_LINK_IDLE || c->reason != IAP2_CONTROL_REASON_NONE) return UINT32_MAX;
    delay = iap2_link_next_delay(&c->link);
    if (c->authentication_timer)
        delay = (uint32_t)smaller(delay, remaining(c->link.now, c->authentication_at, c->authentication_ms));
    if (c->receive_used)
        delay = (uint32_t)smaller(delay, remaining(c->link.now, c->message_at, c->message_ms));
    if (c->identification_timer)
        delay = (uint32_t)smaller(delay, remaining(c->link.now, c->identification_at, c->identification_ms));
    if (c->application_reply)
        delay = (uint32_t)smaller(delay, remaining(c->link.now, c->reply_at, c->message_ms));
    if (c->link.state != IAP2_LINK_NORMAL) return delay;
    if (c->work_pending) return 0;
    if (c->reply_size) {
        if ((c->reply_offset < c->reply_size && c->link.tx_count < IAP2_LINK_SLOTS) ||
            (c->reply_offset == c->reply_size && !c->link.tx_count)) return 0;
        return delay;
    }
    if (c->ready) return delay;
    if (c->fragment_offset < c->fragment_size ||
        (c->receive_used >= 6 && (!c->receive_expected || c->receive_used == c->receive_expected))) return 0;
    for (i = 0; i < IAP2_LINK_SLOTS; ++i)
        if (c->link.rx[i].used && c->link.rx[i].sequence == (uint8_t)(c->link.rx_delivered + 1u)) return 0;
    return delay;
}
