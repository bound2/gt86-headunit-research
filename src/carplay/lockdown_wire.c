/* SPDX-License-Identifier: GPL-3.0-only */
#include "lockdown_wire.h"
static void copy(uint8_t *d, const uint8_t *s, size_t n) { size_t i; for (i = 0; i < n; ++i) d[i] = s[i]; }
int lockdown_frame_size(const uint8_t *data, size_t available, size_t *total) {
    uint32_t length;
    if (total) *total = 0;
    if (!total || (!data && available)) return IAP2_ARGUMENT;
    if (available < 4) return IAP2_MORE;
    length = (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3];
    if (!length) return IAP2_INVALID;
    if (length > LOCKDOWN_BODY_LIMIT) return IAP2_NO_SPACE;
    *total = (size_t)length + 4; return IAP2_OK;
}
int lockdown_frame_decode(const uint8_t *data, size_t size, lockdown_body *body, size_t *consumed) {
    size_t total; int status;
    if (consumed) *consumed = 0;
    if (!body || !consumed) return IAP2_ARGUMENT;
    status = lockdown_frame_size(data, size, &total); if (status) return status;
    if (size < total) return IAP2_MORE;
    body->data = data + 4; body->size = total - 4; *consumed = total; return IAP2_OK;
}
int lockdown_frame_encode(const uint8_t *body, size_t size, uint8_t *out, size_t capacity, size_t *written) {
    uint32_t n;
    if (written) *written = 0;
    if (!written || !out || (!body && size)) return IAP2_ARGUMENT;
    if (!size) return IAP2_INVALID;
    if (size > LOCKDOWN_BODY_LIMIT || capacity < size + 4) return IAP2_NO_SPACE;
    n = (uint32_t)size;
    out[0] = (uint8_t)(n >> 24); out[1] = (uint8_t)(n >> 16); out[2] = (uint8_t)(n >> 8); out[3] = (uint8_t)n;
    copy(out + 4, body, size); *written = size + 4; return IAP2_OK;
}
static int valid_text(const lockdown_body *v, size_t minimum, size_t maximum) {
    size_t i;
    if (!v || v->size < minimum || v->size > maximum || (!v->data && v->size)) return 0;
    for (i = 0; i < v->size; ++i) if (v->data[i] < 32 || v->data[i] > 126) return 0;
    return 1;
}
static void literal(uint8_t *out, size_t *at, const char *s) { while (*s) { if (out) out[*at] = (uint8_t)*s; ++*at; ++s; } }
static void escaped(uint8_t *out, size_t *at, const lockdown_body *v) {
    size_t i;
    for (i = 0; i < v->size; ++i) {
        const char *entity = NULL;
        switch (v->data[i]) {
        case '&': entity = "&amp;"; break;
        case '<': entity = "&lt;"; break;
        case '>': entity = "&gt;"; break;
        case '"': entity = "&quot;"; break;
        case '\'': entity = "&apos;"; break;
        default: break;
        }
        if (entity) literal(out, at, entity);
        else { if (out) out[*at] = v->data[i]; ++*at; }
    }
}
static size_t xml(uint8_t *out, const lockdown_body *label, const lockdown_body *key, const lockdown_body *domain) {
    size_t at = 0;
    literal(out, &at, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>");
    escaped(out, &at, label); literal(out, &at, "</string><key>Request</key><string>GetValue</string><key>Key</key><string>");
    escaped(out, &at, key); literal(out, &at, "</string>");
    if (domain) { literal(out, &at, "<key>Domain</key><string>"); escaped(out, &at, domain); literal(out, &at, "</string>"); }
    literal(out, &at, "</dict></plist>\n"); return at;
}
int lockdown_get_value_encode(const lockdown_body *label, const lockdown_body *key, const lockdown_body *domain,
                               uint8_t *out, size_t capacity, size_t *written) {
    size_t size;
    if (written) *written = 0;
    if (!out || !written || !valid_text(label, 1, 64) || !valid_text(key, 1, 128) || (domain && !valid_text(domain, 0, 128))) return IAP2_ARGUMENT;
    size = xml(NULL, label, key, domain);
    if (capacity < size) return IAP2_NO_SPACE;
    *written = xml(out, label, key, domain); return IAP2_OK;
}
