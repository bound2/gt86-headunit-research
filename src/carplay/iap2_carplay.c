/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "iap2_carplay.h"

static void clear(void *p, size_t n) { size_t i; for (i = 0; i < n; ++i) ((uint8_t *)p)[i] = 0; }
static void copy(void *d, const void *s, size_t n) {
    size_t i; for (i = 0; i < n; ++i) ((uint8_t *)d)[i] = ((const uint8_t *)s)[i];
}
static void put16(uint8_t *p, size_t n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }
static int valid_text(iap2_carplay_text t, size_t limit, int required) {
    size_t i;
    if (!t.data) return !required && !t.size;
    if (!t.size || t.size > limit) return 0;
    for (i = 0; i < t.size; ++i) if ((uint8_t)t.data[i] < 0x20 || (uint8_t)t.data[i] > 0x7e) return 0;
    return 1;
}
static int text_decode(const iap2_param *p, size_t limit, iap2_carplay_text *t) {
    if (p->size < 2 || p->data[p->size - 1]) return IAP2_INVALID;
    if (p->size - 1 > limit) return IAP2_NO_SPACE;
    t->data = (const char *)p->data; t->size = p->size - 1;
    return valid_text(*t, limit, 1) ? IAP2_OK : IAP2_INVALID;
}
static int message(const uint8_t *data, size_t size, uint16_t id, iap2_message *m) {
    size_t used;
    if (!data) return IAP2_ARGUMENT;
    if (size > IAP2_CARPLAY_MESSAGE_LIMIT) return IAP2_NO_SPACE;
    if (iap2_message_decode(data, size, m, &used) || used != size) return IAP2_INVALID;
    return m->id == id ? IAP2_OK : IAP2_UNSUPPORTED;
}
static int seen_field(uint32_t *seen, uint16_t id, uint16_t maximum) {
    uint32_t bit;
    if (id > maximum) return IAP2_UNSUPPORTED;
    bit = (uint32_t)1u << id;
    if (*seen & bit) return IAP2_INVALID;
    *seen |= bit; return IAP2_OK;
}

typedef struct writer { uint8_t bytes[IAP2_CARPLAY_MESSAGE_LIMIT]; size_t used; } writer;
static void begin(writer *w, uint16_t id) {
    w->used = 6; w->bytes[0] = w->bytes[1] = 0x40; put16(w->bytes + 4, id);
}
static int reserve(writer *w, uint16_t id, size_t size, size_t *payload) {
    if (size > sizeof w->bytes - w->used || sizeof w->bytes - w->used - size < 4) return IAP2_NO_SPACE;
    put16(w->bytes + w->used, size + 4); put16(w->bytes + w->used + 2, id);
    *payload = w->used + 4; w->used += size + 4; return IAP2_OK;
}
static int text_encode(writer *w, uint16_t id, iap2_carplay_text t, size_t limit, int required) {
    size_t offset; int status;
    if (!valid_text(t, limit, required)) return IAP2_ARGUMENT;
    if (!t.data) return IAP2_OK;
    status = reserve(w, id, t.size + 1, &offset); if (status) return status;
    copy(w->bytes + offset, t.data, t.size); w->bytes[offset + t.size] = 0; return IAP2_OK;
}
static int scalar(writer *w, uint16_t id, uint32_t value, size_t size) {
    size_t offset, i; int status = reserve(w, id, size, &offset); if (status) return status;
    for (i = 0; i < size; ++i) w->bytes[offset + size - 1 - i] = (uint8_t)(value >> (i * 8));
    return IAP2_OK;
}
static int finish(writer *w, uint8_t *out, size_t capacity, size_t *written) {
    if (capacity < w->used) return IAP2_NO_SPACE;
    put16(w->bytes + 2, w->used); copy(out, w->bytes, w->used); *written = w->used; return IAP2_OK;
}

int iap2_carplay_transport_ids_decode(const uint8_t *data, size_t size, iap2_carplay_transport_ids *out) {
    iap2_carplay_transport_ids value; iap2_message m; iap2_param p;
    size_t offset = 0; uint32_t seen = 0; int status;
    if (!out) return IAP2_ARGUMENT;
    status = message(data, size, 0x4e0e, &m); if (status) return status;
    clear(&value, sizeof value);
    while ((status = iap2_param_next(&m, &offset, &p)) == IAP2_OK) {
        status = seen_field(&seen, p.id, 1); if (status) return status;
        status = text_decode(&p, IAP2_CARPLAY_TEXT_LIMIT, p.id ? &value.usb : &value.bluetooth);
        if (status) return status;
    }
    if (status != IAP2_END || seen != 3) return IAP2_INVALID;
    copy(out, &value, sizeof value); return IAP2_OK;
}
int iap2_carplay_transport_ids_encode(const iap2_carplay_transport_ids *value, uint8_t *out, size_t capacity, size_t *written) {
    writer w; int status;
    if (written) *written = 0;
    if (!value || !out || !written) return IAP2_ARGUMENT;
    begin(&w, 0x4e0e);
    status = text_encode(&w, 0, value->bluetooth, IAP2_CARPLAY_TEXT_LIMIT, 1); if (status) return status;
    status = text_encode(&w, 1, value->usb, IAP2_CARPLAY_TEXT_LIMIT, 1); if (status) return status;
    return finish(&w, out, capacity, written);
}
int iap2_carplay_wireless_update_decode(const uint8_t *data, size_t size, uint8_t *available) {
    iap2_message m; iap2_param p; size_t offset = 0; uint32_t seen = 0; uint8_t value = 0; int status;
    if (!available) return IAP2_ARGUMENT;
    status = message(data, size, 0x4e0d, &m); if (status) return status;
    while ((status = iap2_param_next(&m, &offset, &p)) == IAP2_OK) {
        status = seen_field(&seen, p.id, 0); if (status) return status;
        if (p.size != 1 || p.data[0] > 1) return IAP2_INVALID;
        value = p.data[0];
    }
    if (status != IAP2_END || !seen) return IAP2_INVALID;
    *available = value; return IAP2_OK;
}
int iap2_carplay_wireless_update_encode(uint8_t available, uint8_t *out, size_t capacity, size_t *written) {
    writer w; int status;
    if (written) *written = 0;
    if (!out || !written || available > 1) return IAP2_ARGUMENT;
    begin(&w, 0x4e0d); status = scalar(&w, 0, available, 1); if (status) return status;
    return finish(&w, out, capacity, written);
}

static int available_decode(const iap2_param *group, iap2_carplay_available_transport *value) {
    iap2_message m; iap2_param p; size_t offset = 0; uint32_t seen = 0; int status;
    if (iap2_params_validate(group->data, group->size)) return IAP2_INVALID;
    m.id = 0; m.params = group->data; m.params_size = group->size; value->present = 1;
    while ((status = iap2_param_next(&m, &offset, &p)) == IAP2_OK) {
        status = seen_field(&seen, p.id, 1); if (status) return status;
        if (!p.id) {
            if (p.size != 1 || p.data[0] > 1) return IAP2_INVALID;
            value->has_available = 1; value->available = p.data[0];
        } else {
            status = text_decode(&p, IAP2_CARPLAY_TEXT_LIMIT, &value->identifier); if (status) return status;
        }
    }
    return status == IAP2_END ? IAP2_OK : IAP2_INVALID;
}
int iap2_carplay_availability_decode(const uint8_t *data, size_t size, iap2_carplay_availability *out) {
    iap2_carplay_availability value; iap2_message m; iap2_param p;
    size_t offset = 0; uint32_t seen = 0; int status;
    if (!out) return IAP2_ARGUMENT;
    status = message(data, size, 0x4300, &m); if (status) return status;
    clear(&value, sizeof value);
    while ((status = iap2_param_next(&m, &offset, &p)) == IAP2_OK) {
        status = seen_field(&seen, p.id, 1); if (status) return status;
        status = available_decode(&p, p.id ? &value.wireless : &value.wired); if (status) return status;
    }
    if (status != IAP2_END) return IAP2_INVALID;
    copy(out, &value, sizeof value); return IAP2_OK;
}
static int available_encode(writer *w, uint16_t id, const iap2_carplay_available_transport *v) {
    size_t start = w->used, payload; int status;
    if (v->present > 1 || v->has_available > 1 || v->available > 1 || (!v->has_available && v->available) ||
        !valid_text(v->identifier, IAP2_CARPLAY_TEXT_LIMIT, 0)) return IAP2_ARGUMENT;
    if (!v->present) return (v->has_available || v->identifier.data) ? IAP2_ARGUMENT : IAP2_OK;
    status = reserve(w, id, 0, &payload); if (status) return status;
    if (v->has_available) { status = scalar(w, 0, v->available, 1); if (status) return status; }
    status = text_encode(w, 1, v->identifier, IAP2_CARPLAY_TEXT_LIMIT, 0); if (status) return status;
    put16(w->bytes + start, w->used - start); return IAP2_OK;
}
int iap2_carplay_availability_encode(const iap2_carplay_availability *value, uint8_t *out, size_t capacity, size_t *written) {
    writer w; int status;
    if (written) *written = 0;
    if (!value || !out || !written) return IAP2_ARGUMENT;
    begin(&w, 0x4300);
    status = available_encode(&w, 0, &value->wired); if (status) return status;
    status = available_encode(&w, 1, &value->wireless); if (status) return status;
    return finish(&w, out, capacity, written);
}

static int addresses_decode(const iap2_param *group, iap2_carplay_wired_start *v) {
    iap2_message m; iap2_param list, p; size_t offset = 0, position = 0; uint32_t seen = 0; int status;
    if (iap2_params_validate(group->data, group->size)) return IAP2_INVALID;
    m.id = 0; m.params = group->data; m.params_size = group->size;
    clear(&list, sizeof list);
    while ((status = iap2_param_next(&m, &offset, &p)) == IAP2_OK) {
        status = seen_field(&seen, p.id, 0); if (status) return status;
        copy(&list, &p, sizeof p);
    }
    if (status != IAP2_END) return IAP2_INVALID;
    if (!seen) return IAP2_OK; /* Present but empty wired group. */
    if (!list.size) return IAP2_INVALID;
    while (position < list.size) {
        size_t start = position; iap2_param item;
        if (v->address_count == IAP2_CARPLAY_ADDRESSES) return IAP2_NO_SPACE;
        while (position < list.size && list.data[position]) ++position;
        if (position == list.size) return IAP2_INVALID;
        item.id = 0; item.data = list.data + start; item.size = ++position - start;
        status = text_decode(&item, IAP2_CARPLAY_ADDRESS_LIMIT, &v->addresses[v->address_count]);
        if (status) return status;
        ++v->address_count;
    }
    return IAP2_OK;
}
int iap2_carplay_wired_start_decode(const uint8_t *data, size_t size, iap2_carplay_wired_start *out) {
    iap2_carplay_wired_start value; iap2_message m; iap2_param p;
    size_t offset = 0, i; uint32_t seen = 0; int status;
    if (!out) return IAP2_ARGUMENT;
    status = message(data, size, 0x4301, &m); if (status) return status;
    clear(&value, sizeof value);
    while ((status = iap2_param_next(&m, &offset, &p)) == IAP2_OK) {
        status = seen_field(&seen, p.id, 5); if (status) return status;
        if (!p.id) { status = addresses_decode(&p, &value); if (status) return status; }
        else if (p.id == 1) return IAP2_UNSUPPORTED; /* No wireless/mixed session fallback. */
        else if (p.id == 2) {
            if (p.size != 4) return IAP2_INVALID;
            value.has_port = 1;
            for (i = 0; i < 4; ++i) value.port = (value.port << 8) | p.data[i];
        } else {
            iap2_carplay_text *target = p.id == 3 ? &value.device_identifier : p.id == 4 ? &value.public_key : &value.source_version;
            status = text_decode(&p, IAP2_CARPLAY_TEXT_LIMIT, target); if (status) return status;
        }
    }
    if (status != IAP2_END || !(seen & 1)) return IAP2_INVALID;
    copy(out, &value, sizeof value); return IAP2_OK;
}
int iap2_carplay_wired_start_encode(const iap2_carplay_wired_start *value, uint8_t *out, size_t capacity, size_t *written) {
    writer w; size_t group, list, payload, bytes = 0, i; int status;
    if (written) *written = 0;
    if (!value || !out || !written || value->address_count > IAP2_CARPLAY_ADDRESSES || value->has_port > 1 ||
        (!value->has_port && value->port)) return IAP2_ARGUMENT;
    begin(&w, 0x4301); group = w.used;
    status = reserve(&w, 0, 0, &payload); if (status) return status;
    for (i = 0; i < value->address_count; ++i) {
        if (!valid_text(value->addresses[i], IAP2_CARPLAY_ADDRESS_LIMIT, 1)) return IAP2_ARGUMENT;
        bytes += value->addresses[i].size + 1;
    }
    if (value->address_count) {
        status = reserve(&w, 0, bytes, &list); if (status) return status;
        for (i = 0; i < value->address_count; ++i) {
            copy(w.bytes + list, value->addresses[i].data, value->addresses[i].size);
            list += value->addresses[i].size; w.bytes[list++] = 0;
        }
    }
    put16(w.bytes + group, w.used - group);
    if (value->has_port) { status = scalar(&w, 2, value->port, 4); if (status) return status; }
    status = text_encode(&w, 3, value->device_identifier, IAP2_CARPLAY_TEXT_LIMIT, 0); if (status) return status;
    status = text_encode(&w, 4, value->public_key, IAP2_CARPLAY_TEXT_LIMIT, 0); if (status) return status;
    status = text_encode(&w, 5, value->source_version, IAP2_CARPLAY_TEXT_LIMIT, 0); if (status) return status;
    return finish(&w, out, capacity, written);
}
int iap2_carplay_reply_wired_start(iap2_control *c, const iap2_carplay_wired_start *value, uint64_t now) {
    iap2_carplay_availability offer; const uint8_t *held; size_t size, written;
    uint8_t reply[IAP2_CARPLAY_MESSAGE_LIMIT]; int status;
    if (!c || !value) return IAP2_ARGUMENT;
    status = iap2_control_message(c, &held, &size); if (status) return status;
    if (c->auth.state != IAP2_AUTH_ACCEPTED) return IAP2_AUTH_FAILED;
    if (c->identification.state != IAP2_IDENTIFICATION_ACCEPTED) return IAP2_LINK_BUSY;
    status = iap2_carplay_availability_decode(held, size, &offer); if (status) return status;
    if (!offer.wired.present || !offer.wired.has_available || !offer.wired.available) return IAP2_UNSUPPORTED;
    if (!value->address_count || !value->has_port || !value->port || value->port > 65535 ||
        !value->device_identifier.data || !value->public_key.data || !value->source_version.data) return IAP2_ARGUMENT;
    status = iap2_carplay_wired_start_encode(value, reply, sizeof reply, &written); if (status) return status;
    return iap2_control_reply(c, reply, written, now);
}
