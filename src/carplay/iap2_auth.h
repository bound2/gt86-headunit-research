/* SPDX-License-Identifier: GPL-3.0-or-later
 * Message IDs and fields reference LIVI (see third_party/README.md).
 */
#ifndef GT86_IAP2_AUTH_H
#define GT86_IAP2_AUTH_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif

enum iap2_auth_state {
    IAP2_AUTH_IDLE, IAP2_AUTH_WAIT_CHALLENGE, IAP2_AUTH_WAIT_RESULT,
    IAP2_AUTH_ACCEPTED, IAP2_AUTH_REJECTED
};

/* Callbacks must use the actual accessory-authentication provider. A provider
 * returns IAP2_OK and sets written on success. It may not write past capacity.
 * Neither callback exports private keys; sign requests a challenge response.
 * There is no default signer and no authentication emulation in this library.
 */
typedef struct iap2_auth_provider {
    void *context;
    int (*certificate)(void *, uint8_t *, size_t, size_t *);
    int (*sign)(void *, const uint8_t *, size_t, uint8_t *, size_t, size_t *);
} iap2_auth_provider;

typedef struct iap2_auth {
    enum iap2_auth_state state;
    iap2_auth_provider provider;
    uint8_t *scratch;
    size_t scratch_capacity;
} iap2_auth;

int iap2_auth_init(iap2_auth *auth, const iap2_auth_provider *provider,
                    uint8_t *scratch, size_t scratch_capacity);
/* One complete CSM in, at most one reply out. Input, output and scratch must
 * not overlap. Only an in-sequence phone AuthenticationSucceeded notification
 * advances to ACCEPTED; that means accessory auth, not a running CarPlay session.
 * A handled result notification returns OK with written=0. Unknown message IDs
 * return UNSUPPORTED without changing state. Any handled auth failure requires
 * reinitialization for a new session. Link disconnect/timeout must also reset.
 */
int iap2_auth_handle(iap2_auth *auth, const uint8_t *message, size_t size,
                     uint8_t *reply, size_t capacity, size_t *written);

#ifdef __cplusplus
}
#endif
#endif
