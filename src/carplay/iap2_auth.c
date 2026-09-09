/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "iap2_auth.h"

int iap2_auth_init(iap2_auth *auth, const iap2_auth_provider *provider,
                    uint8_t *scratch, size_t scratch_capacity) {
    if (!auth || !provider || !scratch || !scratch_capacity ||
        scratch_capacity > IAP2_MAX_FRAME_SIZE - 10u) return IAP2_ARGUMENT;
    auth->state = IAP2_AUTH_IDLE; auth->provider = *provider;
    auth->scratch = scratch; auth->scratch_capacity = scratch_capacity;
    return IAP2_OK;
}

static int reject(iap2_auth *auth, int code) {
    auth->state = IAP2_AUTH_REJECTED;
    return code;
}

int iap2_auth_handle(iap2_auth *auth, const uint8_t *data, size_t size,
                     uint8_t *reply, size_t capacity, size_t *written) {
    iap2_message message;
    iap2_param param;
    size_t consumed, offset = 0, produced = 0;
    uint16_t response_id;
    enum iap2_auth_state next;
    int status;
    if (written) *written = 0;
    if (!auth || !reply || !written || !auth->scratch || !auth->scratch_capacity ||
        auth->scratch_capacity > IAP2_MAX_FRAME_SIZE - 10u) return IAP2_ARGUMENT;
    status = iap2_message_decode(data, size, &message, &consumed);
    if (status != IAP2_OK || consumed != size) return reject(auth, IAP2_INVALID);
    if (message.id != 0xaa00 && message.id != 0xaa02 &&
        message.id != 0xaa04 && message.id != 0xaa05) return IAP2_UNSUPPORTED;
    if (auth->state == IAP2_AUTH_REJECTED) return IAP2_AUTH_FAILED;
    if (message.id == 0xaa04) return reject(auth, IAP2_AUTH_FAILED);
    if (message.id == 0xaa05) {
        if (auth->state != IAP2_AUTH_WAIT_RESULT || message.params_size)
            return reject(auth, IAP2_INVALID);
        auth->state = IAP2_AUTH_ACCEPTED;
        return IAP2_OK;
    }
    if (message.id == 0xaa00) {
        if (auth->state != IAP2_AUTH_IDLE || message.params_size)
            return reject(auth, IAP2_INVALID);
        if (!auth->provider.certificate) return reject(auth, IAP2_PROVIDER_FAILED);
        status = auth->provider.certificate(auth->provider.context, auth->scratch,
                                            auth->scratch_capacity, &produced);
        response_id = 0xaa01; next = IAP2_AUTH_WAIT_CHALLENGE;
    } else {
        if (auth->state != IAP2_AUTH_WAIT_CHALLENGE ||
            iap2_param_next(&message, &offset, &param) != IAP2_OK || param.id != 0 ||
            offset != message.params_size || !param.size || param.size > 128)
            return reject(auth, IAP2_INVALID);
        if (!auth->provider.sign) return reject(auth, IAP2_PROVIDER_FAILED);
        status = auth->provider.sign(auth->provider.context, param.data, param.size,
                                    auth->scratch, auth->scratch_capacity, &produced);
        response_id = 0xaa03; next = IAP2_AUTH_WAIT_RESULT;
    }
    if (status != IAP2_OK || !produced || produced > auth->scratch_capacity)
        return reject(auth, IAP2_PROVIDER_FAILED);
    param.id = 0; param.data = auth->scratch; param.size = produced;
    status = iap2_message_encode(response_id, &param, 1, reply, capacity, written);
    if (status != IAP2_OK) return reject(auth, status);
    auth->state = next;
    return IAP2_OK;
}
