/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "iap2_identification.h"

static void put16(uint8_t *out, size_t n) { out[0] = (uint8_t)(n >> 8); out[1] = (uint8_t)n; }
static void copy(uint8_t *out, const uint8_t *in, size_t size) {
    size_t i; for (i = 0; i < size; ++i) out[i] = in[i];
}
static int valid_text(const iap2_identification_text *s, size_t limit) {
    size_t i;
    if (!s->data || !s->size || s->size > limit) return 0;
    for (i = 0; i < s->size; ++i)
        if ((uint8_t)s->data[i] < 0x20 || (uint8_t)s->data[i] > 0x7e) return 0;
    return 1;
}
static int equal(const iap2_identification_text *a, const iap2_identification_text *b) {
    size_t i; if (a->size != b->size) return 0;
    for (i = 0; i < a->size; ++i) if (a->data[i] != b->data[i]) return 0;
    return 1;
}
static size_t param(uint8_t *out, uint16_t id, const uint8_t *data, size_t size) {
    put16(out, size + 4); put16(out + 2, id); copy(out + 4, data, size); return size + 4;
}
static size_t string_param(uint8_t *out, uint16_t id, const iap2_identification_text *s) {
    put16(out, s->size + 5); put16(out + 2, id);
    copy(out + 4, (const uint8_t *)s->data, s->size); out[s->size + 4] = 0; return s->size + 5;
}
int iap2_identification_encode(const iap2_identification_metadata *m, uint8_t *out, size_t capacity, size_t *written) {
    const iap2_identification_text *identity[6];
    static const uint8_t sent[] = {0xaa,0x01,0xaa,0x03,0x1d,0x01};
    static const uint8_t received[] = {0xaa,0x00,0xaa,0x02,0xaa,0x04,0xaa,0x05,0x1d,0x00,0x1d,0x02,0x1d,0x03};
    size_t i, j, total = 6 + 4 + sizeof sent + 4 + sizeof received + 5 + 6, offset;
    unsigned matches = 0;
    uint8_t current[2];
    if (written) *written = 0;
    if (!m || !out || !written || m->language_count < 1 || m->language_count > IAP2_IDENTIFICATION_LANGUAGES ||
        (m->power_capability != 0 && m->power_capability != 2) || !valid_text(&m->current_language, 16)) return IAP2_ARGUMENT;
    identity[0] = &m->name; identity[1] = &m->model; identity[2] = &m->manufacturer;
    identity[3] = &m->serial; identity[4] = &m->firmware; identity[5] = &m->hardware;
    for (i = 0; i < 6; ++i) {
        if (!valid_text(identity[i], 127)) return IAP2_ARGUMENT;
        total += identity[i]->size + 5;
    }
    total += m->current_language.size + 5;
    for (i = 0; i < m->language_count; ++i) {
        if (!valid_text(&m->languages[i], 16)) return IAP2_ARGUMENT;
        for (j = 0; j < i; ++j) if (equal(&m->languages[i], &m->languages[j])) return IAP2_ARGUMENT;
        if (equal(&m->current_language, &m->languages[i])) ++matches;
        total += m->languages[i].size + 5;
    }
    if (matches != 1) return IAP2_ARGUMENT;
    if (total > capacity || total > IAP2_IDENTIFICATION_LIMIT) return IAP2_NO_SPACE;
    out[0] = out[1] = 0x40; put16(out + 2, total); put16(out + 4, 0x1d01); offset = 6;
    for (i = 0; i < 6; ++i) offset += string_param(out + offset, (uint16_t)i, identity[i]);
    offset += param(out + offset, 6, sent, sizeof sent);
    offset += param(out + offset, 7, received, sizeof received);
    offset += param(out + offset, 8, &m->power_capability, 1);
    put16(current, m->maximum_current_ma); offset += param(out + offset, 9, current, sizeof current);
    offset += string_param(out + offset, 12, &m->current_language);
    for (i = 0; i < m->language_count; ++i) offset += string_param(out + offset, 13, &m->languages[i]);
    *written = offset; return IAP2_OK;
}
void iap2_identification_reset(iap2_identification *id) {
    if (!id) return;
    id->state = id->information_size ? IAP2_IDENTIFICATION_IDLE : IAP2_IDENTIFICATION_DISABLED;
    id->rejected_fields = 0;
}
int iap2_identification_init(iap2_identification *id, const iap2_identification_metadata *metadata) {
    size_t n;
    int status;
    if (!id) return IAP2_ARGUMENT;
    status = iap2_identification_encode(metadata, id->information, sizeof id->information, &n);
    if (status) return status;
    id->information_size = n; iap2_identification_reset(id); return IAP2_OK;
}
static int reject(iap2_identification *id, int status) { id->state = IAP2_IDENTIFICATION_REJECTED; return status; }
int iap2_identification_handle(iap2_identification *id, const uint8_t *data, size_t size,
                              uint8_t *out, size_t capacity, size_t *written) {
    iap2_message message;
    size_t used, offset = 0;
    int status;
    if (written) *written = 0;
    if (!id || !out || !written) return IAP2_ARGUMENT;
    status = iap2_message_decode(data, size, &message, &used);
    if (status != IAP2_OK || used != size) return reject(id, IAP2_INVALID);
    if (message.id < 0x1d00 || message.id > 0x1d03 || id->state == IAP2_IDENTIFICATION_DISABLED) return IAP2_UNSUPPORTED;
    if (id->state == IAP2_IDENTIFICATION_REJECTED) return IAP2_IDENTIFICATION_FAILED;
    if (message.id == 0x1d00) {
        if (id->state != IAP2_IDENTIFICATION_IDLE || message.params_size) return reject(id, IAP2_INVALID);
        if (!id->information_size || id->information_size > sizeof id->information) return reject(id, IAP2_ARGUMENT);
        if (capacity < id->information_size) return IAP2_NO_SPACE;
        copy(out, id->information, id->information_size); *written = id->information_size;
        id->state = IAP2_IDENTIFICATION_WAIT_RESULT; return IAP2_OK;
    }
    if (message.id == 0x1d01 || id->state != IAP2_IDENTIFICATION_WAIT_RESULT) return reject(id, IAP2_INVALID);
    if (message.id == 0x1d02) {
        if (message.params_size) return reject(id, IAP2_INVALID);
        id->state = IAP2_IDENTIFICATION_ACCEPTED; return IAP2_OK;
    }
    {
        iap2_param p;
        uint32_t fields = 0;
        while ((status = iap2_param_next(&message, &offset, &p)) == IAP2_OK) {
            if (p.id > 31) return reject(id, IAP2_UNSUPPORTED);
            if (p.size || (fields & ((uint32_t)1u << p.id))) return reject(id, IAP2_INVALID);
            fields |= (uint32_t)1u << p.id;
        }
        if (status != IAP2_END) return reject(id, IAP2_INVALID);
        id->rejected_fields = fields;
    }
    return reject(id, IAP2_IDENTIFICATION_FAILED);
}
