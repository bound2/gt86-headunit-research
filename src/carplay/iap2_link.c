/* SPDX-License-Identifier: GPL-3.0-or-later
 * Protocol reference: pinned LIVI; see third_party/README.md.
 * Independent bounded queue/timer implementation; no runtime or device I/O.
 */
#include "iap2_link.h"

#define SYN 0x80u
#define ACK 0x40u
#define RST 0x10u

static void copy(uint8_t *d, const uint8_t *s, size_t n) {
    size_t i; for (i = 0; i < n; ++i) d[i] = s[i];
}
static uint16_t read16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] * 256u + p[1]); }
static void write16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }
static uint8_t distance(uint8_t a, uint8_t b) { return (uint8_t)(a - b); }

static int valid_lsp(const iap2_lsp *p) {
    unsigned i, j;
    if (!p || !p->window || p->window > 127 || p->packet_size < 10 ||
        !p->retransmit_ms || !p->ack_ms || p->ack_ms >= p->retransmit_ms ||
        !p->retries || !p->max_ack || p->max_ack > p->window ||
        !p->session_count || p->session_count > IAP2_LINK_SESSIONS) return 0;
    for (i = 0; i < p->session_count; ++i) {
        if (!p->sessions[i].id || !p->sessions[i].version) return 0;
        for (j = 0; j < i; ++j) if (p->sessions[j].id == p->sessions[i].id) return 0;
    }
    return 1;
}
int iap2_lsp_decode(const uint8_t *data, size_t size, iap2_lsp *out) {
    iap2_lsp p = {0};
    unsigned i;
    if (!out || (!data && size)) return IAP2_ARGUMENT;
    if (size < 13 || size > IAP2_LINK_LSP_LIMIT || (size - 10) % 3 || data[0] != 1)
        return IAP2_INVALID;
    p.window = data[1]; p.packet_size = read16(data + 2);
    p.retransmit_ms = read16(data + 4); p.ack_ms = read16(data + 6);
    p.retries = data[8]; p.max_ack = data[9]; p.session_count = (uint8_t)((size - 10) / 3);
    for (i = 0; i < p.session_count; ++i) {
        p.sessions[i].id = data[10 + 3*i]; p.sessions[i].kind = data[11 + 3*i];
        p.sessions[i].version = data[12 + 3*i];
    }
    if (!valid_lsp(&p)) return IAP2_INVALID;
    copy((uint8_t *)out, (const uint8_t *)&p, sizeof p); return IAP2_OK;
}
int iap2_lsp_encode(const iap2_lsp *p, uint8_t *out, size_t capacity, size_t *written) {
    unsigned i; size_t n;
    if (written) *written = 0;
    if (!p || !out || !written) return IAP2_ARGUMENT;
    if (!valid_lsp(p)) return IAP2_INVALID;
    n = 10u + 3u*p->session_count;
    if (capacity < n) return IAP2_NO_SPACE;
    out[0] = 1; out[1] = p->window; write16(out + 2, p->packet_size);
    write16(out + 4, p->retransmit_ms); write16(out + 6, p->ack_ms);
    out[8] = p->retries; out[9] = p->max_ack;
    for (i = 0; i < p->session_count; ++i) {
        out[10 + 3*i] = p->sessions[i].id; out[11 + 3*i] = p->sessions[i].kind;
        out[12 + 3*i] = p->sessions[i].version;
    }
    *written = n; return IAP2_OK;
}
static int session_exists(const iap2_lsp *p, uint8_t id) {
    unsigned i; for (i = 0; i < p->session_count; ++i) if (p->sessions[i].id == id) return 1;
    return 0;
}
static int supported_lsp(const iap2_lsp *offer, const iap2_lsp *p) {
    unsigned i, j;
    if (p->window > offer->window || p->packet_size > offer->packet_size) return 0;
    for (i = 0; i < p->session_count; ++i) {
        for (j = 0; j < offer->session_count; ++j)
            if (p->sessions[i].id == offer->sessions[j].id &&
                p->sessions[i].kind == offer->sessions[j].kind &&
                p->sessions[i].version == offer->sessions[j].version) break;
        if (j == offer->session_count) return 0;
    }
    /* This profile requires the offered control session, not only optional data sessions. */
    return session_exists(p, offer->sessions[0].id);
}
static int same_lsp(const iap2_lsp *a, const iap2_lsp *b) {
    uint8_t x[IAP2_LINK_LSP_LIMIT], y[IAP2_LINK_LSP_LIMIT];
    size_t nx, ny, i;
    if (iap2_lsp_encode(a, x, sizeof x, &nx) || iap2_lsp_encode(b, y, sizeof y, &ny) || nx != ny) return 0;
    for (i = 0; i < nx; ++i) if (x[i] != y[i]) return 0;
    return 1;
}
void iap2_link_default_config(iap2_link_config *c) {
    unsigned i;
    if (!c) return;
    c->offer.window = 4; c->offer.packet_size = IAP2_LINK_PACKET_LIMIT;
    c->offer.retransmit_ms = 1000; c->offer.ack_ms = 100;
    c->offer.retries = 3; c->offer.max_ack = 2; c->offer.session_count = 1;
    for (i = 0; i < IAP2_LINK_SESSIONS; ++i) {
        c->offer.sessions[i].id = 0; c->offer.sessions[i].kind = 0; c->offer.sessions[i].version = 0;
    }
    c->offer.sessions[0].id = 10; c->offer.sessions[0].version = 1;
    c->initial_sequence = 99; c->handshake_ms = 10000;
}
int iap2_link_init(iap2_link *l, const iap2_link_config *c) {
    size_t i;
    if (!l || !c || !valid_lsp(&c->offer) || c->offer.window > IAP2_LINK_SLOTS ||
        c->offer.packet_size < IAP2_LINK_LSP_LIMIT + 10 || c->offer.packet_size > IAP2_LINK_PACKET_LIMIT ||
        c->offer.sessions[0].kind != 0 || c->offer.sessions[0].version != 1 ||
        !c->handshake_ms) return IAP2_ARGUMENT;
    /* Explicit byte clear avoids a freestanding libc dependency. */
    for (i = 0; i < sizeof *l; ++i) ((uint8_t *)l)[i] = 0;
    copy((uint8_t *)&l->config, (const uint8_t *)c, sizeof *c);
    copy((uint8_t *)&l->negotiated, (const uint8_t *)&c->offer, sizeof c->offer);
    l->tx_sequence = c->initial_sequence; l->tx_acked = c->initial_sequence;
    return iap2_stream_init(&l->stream, l->rx_storage, c->offer.packet_size);
}
static int clock_update(iap2_link *l, uint64_t now) {
    if (!l || now < l->now) return IAP2_ARGUMENT;
    l->now = now; return IAP2_OK;
}
static void die(iap2_link *l, enum iap2_link_reason reason) {
    unsigned i;
    l->state = IAP2_LINK_DEAD; l->reason = reason;
    l->tx_count = 0; l->tx_sent = 0; l->ack_pending = 0; l->ack_timer = 0;
    l->stream.used = 0;
    for (i = 0; i < IAP2_LINK_SLOTS; ++i) { l->tx[i].used = 0; l->rx[i].used = 0; }
}
void iap2_link_close(iap2_link *l) {
    if (l && l->state != IAP2_LINK_DEAD) die(l, IAP2_LINK_REASON_LOCAL);
}
static int check_time(iap2_link *l, uint64_t now) {
    if (clock_update(l, now)) return IAP2_ARGUMENT;
    if (l->state == IAP2_LINK_DEAD) return IAP2_LINK_CLOSED;
    if ((l->state == IAP2_LINK_DETECT || l->state == IAP2_LINK_SYNCHRONIZE) &&
        now - l->started_at >= l->config.handshake_ms) {
        die(l, IAP2_LINK_REASON_TIMEOUT); return IAP2_LINK_CLOSED;
    }
    return IAP2_OK;
}
int iap2_link_start(iap2_link *l, uint64_t now) {
    if (!l || l->state != IAP2_LINK_IDLE || clock_update(l, now)) return IAP2_ARGUMENT;
    l->started_at = now; l->state = IAP2_LINK_DETECT; return IAP2_OK;
}
static void established(iap2_link *l) {
    if (l->peer_syn && l->our_syn_acked && l->peer_syn_acked) l->state = IAP2_LINK_NORMAL;
}
static iap2_link_packet *rx_find(iap2_link *l, uint8_t seq) {
    unsigned i;
    for (i = 0; i < IAP2_LINK_SLOTS; ++i) if (l->rx[i].used && l->rx[i].sequence == seq) return &l->rx[i];
    return NULL;
}
static int ack_valid(const iap2_link *l, uint8_t ack) {
    uint8_t d = distance(ack, l->tx_acked);
    return d > 127 || d <= l->tx_sent;
}
static void acknowledge(iap2_link *l, uint8_t ack) {
    uint8_t d = distance(ack, l->tx_acked);
    if (d > 127) return; /* Stale ACK: no queue changes. */
    while (d--) {
        l->tx[l->tx_head].used = 0;
        l->tx_head = (uint8_t)((l->tx_head + 1u) % IAP2_LINK_SLOTS);
        --l->tx_count; --l->tx_sent;
    }
    l->tx_acked = ack;
}
static int process(iap2_link *l, const iap2_frame *f) {
    iap2_lsp p;
    unsigned i, advanced = 0;
    iap2_link_packet *slot;
    uint8_t d;
    if (f->control & RST) { die(l, IAP2_LINK_REASON_RESET); return IAP2_LINK_CLOSED; }
    if (f->control & ~(SYN | ACK)) return IAP2_UNSUPPORTED; /* Including EAK. */
    if (f->control & SYN) {
        if (f->session || !f->has_payload || iap2_lsp_decode(f->payload, f->payload_size, &p)) return IAP2_INVALID;
        if (!supported_lsp(&l->config.offer, &p)) return IAP2_UNSUPPORTED;
        if (l->peer_syn && (l->peer_syn_sequence != f->sequence || !same_lsp(&l->negotiated, &p))) {
            die(l, IAP2_LINK_REASON_RESTART); return IAP2_LINK_CLOSED;
        }
        if (!l->peer_syn) {
            copy((uint8_t *)&l->negotiated, (const uint8_t *)&p, sizeof p);
            l->peer_syn = 1; l->peer_syn_sequence = f->sequence;
            l->rx_acked = f->sequence; l->rx_delivered = f->sequence;
        }
        l->ack_pending = 1;
        if (l->state == IAP2_LINK_SYNCHRONIZE && (f->control & ACK) && l->syn_sent &&
            f->acknowledgement == l->config.initial_sequence) l->our_syn_acked = 1;
        return IAP2_OK;
    }
    if (l->state == IAP2_LINK_SYNCHRONIZE) {
        if (f->control != ACK || f->has_payload || f->session || !l->peer_syn || !l->syn_sent ||
            f->acknowledgement != l->config.initial_sequence) return IAP2_INVALID;
        l->our_syn_acked = 1; established(l); return IAP2_OK;
    }
    if (l->state != IAP2_LINK_NORMAL) return IAP2_INVALID;
    if ((!f->has_payload && (f->session || f->control != ACK)) ||
        (f->has_payload && (!f->session || !session_exists(&l->negotiated, f->session)))) return IAP2_UNSUPPORTED;
    if (f->payload_size + (f->has_payload ? 10u : 9u) > l->negotiated.packet_size) return IAP2_INVALID;
    if ((f->control & ACK) && !ack_valid(l, f->acknowledgement)) return IAP2_INVALID;
    if (f->control & ACK) acknowledge(l, f->acknowledgement);
    if (!f->has_payload) return IAP2_OK; /* Pure ACKs must never trigger ACK storms. */
    d = distance(f->sequence, l->rx_acked);
    if (!d || d > l->negotiated.window || rx_find(l, f->sequence)) {
        l->ack_pending = 1; return IAP2_OK; /* Duplicate or outside the receive window. */
    }
    slot = NULL;
    for (i = 0; i < IAP2_LINK_SLOTS; ++i) if (!l->rx[i].used) { slot = &l->rx[i]; break; }
    if (!slot) { l->ack_pending = 1; return IAP2_LINK_BUSY; }
    copy(slot->data, f->payload, f->payload_size);
    slot->size = (uint16_t)f->payload_size; slot->sequence = f->sequence;
    slot->session = f->session; slot->used = 1;
    while (advanced < IAP2_LINK_SLOTS && rx_find(l, (uint8_t)(l->rx_acked + 1u))) {
        ++l->rx_acked; ++advanced;
    }
    if (!advanced) l->ack_pending = 1; /* Repeat cumulative ACK; recover gaps by timeout. */
    else {
        l->ack_count = (uint8_t)(l->ack_count + advanced);
        if (!l->ack_timer) { l->ack_at = l->now; l->ack_timer = 1; }
        if (l->ack_count >= l->negotiated.max_ack) l->ack_pending = 1;
    }
    return IAP2_OK;
}
int iap2_link_feed(iap2_link *l, const uint8_t *data, size_t size, size_t *consumed, uint64_t now) {
    int status;
    if (consumed) *consumed = 0;
    if (!l || !consumed || (!data && size)) return IAP2_ARGUMENT;
    status = check_time(l, now); if (status) return status;
    if (l->state == IAP2_LINK_IDLE) return IAP2_ARGUMENT;
    while (*consumed < size) {
        if (l->state == IAP2_LINK_DETECT) {
            if (data[(*consumed)++] != iap2_detect_marker[l->marker_used++]) {
                die(l, IAP2_LINK_REASON_MARKER); return IAP2_LINK_CLOSED;
            }
            if (l->marker_used == 6) l->state = IAP2_LINK_SYNCHRONIZE;
        } else {
            iap2_frame frame; size_t used;
            status = iap2_stream_push(&l->stream, data + *consumed, size - *consumed, &used, &frame);
            *consumed += used;
            if (status == IAP2_MORE) return IAP2_OK;
            if (status == IAP2_NO_SPACE) { die(l, IAP2_LINK_REASON_OVERSIZE); return IAP2_LINK_CLOSED; }
            if (status) return status;
            status = process(l, &frame); if (status) return status;
        }
    }
    return IAP2_OK;
}
int iap2_link_send(iap2_link *l, uint8_t session, const uint8_t *data, size_t size, uint64_t now) {
    iap2_link_packet *p;
    int status;
    if (!l || (!data && size)) return IAP2_ARGUMENT;
    status = check_time(l, now); if (status) return status;
    if (l->state != IAP2_LINK_NORMAL) return IAP2_LINK_BUSY;
    if (!session_exists(&l->negotiated, session)) return IAP2_UNSUPPORTED;
    if (size > (size_t)l->negotiated.packet_size - 10u) return IAP2_NO_SPACE;
    if (l->tx_count == IAP2_LINK_SLOTS) return IAP2_LINK_BUSY;
    p = &l->tx[(l->tx_head + l->tx_count) % IAP2_LINK_SLOTS];
    copy(p->data, data, size); p->size = (uint16_t)size;
    p->session = session; p->used = 1; p->attempts = 0; ++l->tx_count;
    return IAP2_OK;
}
int iap2_link_receive(iap2_link *l, uint8_t *session, uint8_t *out, size_t capacity, size_t *written) {
    iap2_link_packet *p;
    if (written) *written = 0;
    if (!l || !session || !out || !written) return IAP2_ARGUMENT;
    if (l->state == IAP2_LINK_DEAD) return IAP2_LINK_CLOSED;
    if (l->state != IAP2_LINK_NORMAL || l->rx_delivered == l->rx_acked) return IAP2_MORE;
    p = rx_find(l, (uint8_t)(l->rx_delivered + 1u));
    if (!p) return IAP2_MORE;
    if (capacity < p->size) return IAP2_NO_SPACE;
    copy(out, p->data, p->size); *written = p->size; *session = p->session;
    l->rx_delivered = p->sequence; p->used = 0; return IAP2_OK;
}
static int emit(iap2_link *l, uint8_t control, uint8_t seq, uint8_t session,
                const uint8_t *payload, size_t size, int present, uint8_t *out, size_t capacity, size_t *written) {
    iap2_frame f;
    f.control = control; f.sequence = seq; f.acknowledgement = l->rx_acked;
    f.session = session; f.payload = payload; f.payload_size = size; f.has_payload = present;
    return iap2_frame_encode(&f, out, capacity, written);
}
static void ack_sent(iap2_link *l) {
    l->ack_pending = 0; l->ack_timer = 0; l->ack_count = 0;
    if (l->peer_syn) l->peer_syn_acked = 1;
    if (l->state == IAP2_LINK_SYNCHRONIZE) established(l);
}
int iap2_link_output(iap2_link *l, uint8_t *out, size_t capacity, size_t *written, uint64_t now) {
    int status; unsigned i;
    iap2_link_packet *p;
    if (written) *written = 0;
    if (!l || !out || !written) return IAP2_ARGUMENT;
    status = check_time(l, now); if (status) return status;
    if (l->state == IAP2_LINK_IDLE) return IAP2_MORE;
    if (!l->marker_sent || (l->state == IAP2_LINK_DETECT && now - l->marker_at >= 1000)) {
        if (capacity < 6) return IAP2_NO_SPACE;
        copy(out, iap2_detect_marker, 6); *written = 6;
        l->marker_sent = 1; l->marker_at = now; return IAP2_OK;
    }
    if (l->state == IAP2_LINK_SYNCHRONIZE && (!l->syn_sent || now - l->syn_at >= 500)) {
        uint8_t payload[IAP2_LINK_LSP_LIMIT]; size_t n;
        status = iap2_lsp_encode(&l->config.offer, payload, sizeof payload, &n); if (status) return status;
        status = emit(l, SYN, l->config.initial_sequence, 0, payload, n, 1, out, capacity, written);
        if (!status) { l->syn_sent = 1; l->syn_at = now; }
        return status;
    }
    if (l->state == IAP2_LINK_NORMAL) {
        for (i = 0; i < l->tx_sent; ++i) {
            p = &l->tx[(l->tx_head + i) % IAP2_LINK_SLOTS];
            if (now - p->sent_at < l->negotiated.retransmit_ms) continue;
            if (p->attempts >= l->negotiated.retries) {
                die(l, IAP2_LINK_REASON_TIMEOUT); return IAP2_LINK_CLOSED;
            }
            status = emit(l, ACK, p->sequence, p->session, p->data, p->size, 1, out, capacity, written);
            if (!status) { ++p->attempts; p->sent_at = now; ack_sent(l); }
            return status;
        }
        if (l->tx_sent < l->tx_count && l->tx_sent < l->negotiated.window) {
            p = &l->tx[(l->tx_head + l->tx_sent) % IAP2_LINK_SLOTS];
            status = emit(l, ACK, (uint8_t)(l->tx_sequence + 1u), p->session, p->data, p->size,
                          1, out, capacity, written);
            if (!status) { p->sequence = ++l->tx_sequence; p->sent_at = now; ++l->tx_sent; ack_sent(l); }
            return status;
        }
    }
    if (l->ack_pending || (l->ack_timer && now - l->ack_at >= l->negotiated.ack_ms)) {
        status = emit(l, ACK, l->tx_sequence, 0, NULL, 0, 0, out, capacity, written);
        if (!status) ack_sent(l);
        return status;
    }
    return IAP2_MORE;
}
static uint32_t remaining(uint64_t now, uint64_t at, uint32_t interval) {
    uint64_t age = now - at;
    return age >= interval ? 0 : interval - (uint32_t)age;
}
static uint32_t smaller(uint32_t a, uint32_t b) { return a < b ? a : b; }
uint32_t iap2_link_next_delay(const iap2_link *l) {
    uint32_t delay = UINT32_MAX;
    unsigned i;
    if (!l || l->state == IAP2_LINK_IDLE || l->state == IAP2_LINK_DEAD) return delay;
    if (!l->marker_sent || l->ack_pending) return 0;
    if (l->state == IAP2_LINK_DETECT || l->state == IAP2_LINK_SYNCHRONIZE)
        delay = remaining(l->now, l->started_at, l->config.handshake_ms);
    if (l->state == IAP2_LINK_DETECT) delay = smaller(delay, remaining(l->now, l->marker_at, 1000));
    if (l->state == IAP2_LINK_SYNCHRONIZE) {
        if (!l->syn_sent) return 0;
        delay = smaller(delay, remaining(l->now, l->syn_at, 500));
    }
    if (l->state == IAP2_LINK_NORMAL) {
        if (l->tx_sent < l->tx_count && l->tx_sent < l->negotiated.window) return 0;
        for (i = 0; i < l->tx_sent; ++i) {
            const iap2_link_packet *p = &l->tx[(l->tx_head + i) % IAP2_LINK_SLOTS];
            delay = smaller(delay, remaining(l->now, p->sent_at, l->negotiated.retransmit_ms));
        }
    }
    if (l->ack_timer) delay = smaller(delay, remaining(l->now, l->ack_at, l->negotiated.ack_ms));
    return delay;
}
