/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "iap2_power.h"

int iap2_power_source_decode(const uint8_t *data, size_t size, iap2_power_source *out) {
    iap2_message message; iap2_param p; iap2_power_source value = {0, 0, 0, 0};
    size_t used, offset = 0; unsigned seen = 0; int status;
    if (!data || !out) return IAP2_ARGUMENT;
    if (size > 1024) return IAP2_NO_SPACE;
    if (iap2_message_decode(data, size, &message, &used) || used != size) return IAP2_INVALID;
    if (message.id != 0xae03) return IAP2_UNSUPPORTED;
    while ((status = iap2_param_next(&message, &offset, &p)) == IAP2_OK) {
        if (p.id > 1) return IAP2_UNSUPPORTED;
        if (seen & (1u << p.id)) return IAP2_INVALID;
        seen |= 1u << p.id;
        if (!p.id) {
            if (p.size != 2) return IAP2_INVALID;
            value.has_available_current = 1;
            value.available_current_ma = (uint16_t)((uint16_t)p.data[0] * 256u + p.data[1]);
        } else {
            if (p.size != 1 || p.data[0] > 1) return IAP2_INVALID;
            value.has_should_charge = 1; value.should_charge = p.data[0];
        }
    }
    if (status != IAP2_END) return IAP2_INVALID;
    *out = value; return IAP2_OK;
}
int iap2_power_source_encode(const iap2_power_source *value, uint8_t *out, size_t capacity, size_t *written) {
    uint8_t current[2]; iap2_param params[2]; size_t count = 0;
    if (written) *written = 0;
    if (!value || !out || !written || value->has_available_current > 1 || value->has_should_charge > 1 ||
        value->should_charge > 1 || (!value->has_available_current && value->available_current_ma) ||
        (!value->has_should_charge && value->should_charge)) return IAP2_ARGUMENT;
    if (value->has_available_current) {
        current[0] = (uint8_t)(value->available_current_ma >> 8); current[1] = (uint8_t)value->available_current_ma;
        params[count].id = 0; params[count].data = current; params[count++].size = 2;
    }
    if (value->has_should_charge) {
        params[count].id = 1; params[count].data = &value->should_charge; params[count++].size = 1;
    }
    return iap2_message_encode(0xae03, params, count, out, capacity, written);
}
int iap2_power_source_notify(iap2_control *c, const iap2_power_source *value, uint64_t now) {
    uint8_t out[17]; size_t written; int status;
    if (!c || !value) return IAP2_ARGUMENT;
    if (c->reason != IAP2_CONTROL_REASON_NONE) return IAP2_LINK_CLOSED;
    if (c->auth.state != IAP2_AUTH_ACCEPTED) return IAP2_AUTH_FAILED;
    if (c->identification.state != IAP2_IDENTIFICATION_ACCEPTED) return IAP2_LINK_BUSY;
    if (!c->identification.wired_carplay) return IAP2_UNSUPPORTED;
    if (value->has_available_current != 1 || value->has_should_charge != 1) return IAP2_ARGUMENT;
    status = iap2_power_source_encode(value, out, sizeof out, &written); if (status) return status;
    return iap2_control_notify(c, out, written, now);
}
