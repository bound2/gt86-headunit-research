/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PAIR_VERIFY_H
#define GT86_PAIR_VERIFY_H
#include "pair_crypto.h"
#include "pair_tlv.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PAIR_VERIFY_RESPONSE 11
#define PAIR_VERIFY_KEYS 12
#define PAIR_VERIFY_CLOSED (-7)
#define PAIR_VERIFY_BUSY 3
#define PAIR_VERIFY_MAX_BODY 1024u
/* Trusted, read-only lookup: OK fills exactly 32 public-key bytes, END means
 * unknown controller, other results fail. No TOFU, Pair or save operation.
 * Synchronous callback must not block/reenter or retain borrowed pointers.
 */
typedef int (*pair_lookup_fn)(void *,const uint8_t *,size_t,uint8_t public_key[32]);
typedef struct pair_verify_config { uint32_t exchange_ms,hold_ms; } pair_verify_config;
enum pair_verify_state { PAIR_VERIFY_M1,PAIR_VERIFY_M2_HELD,PAIR_VERIFY_M3,
    PAIR_VERIFY_M4_HELD,PAIR_VERIFY_KEYS_READY,PAIR_VERIFY_DETACHED,PAIR_VERIFY_DEAD };
enum pair_verify_reason { PAIR_VERIFY_REASON_NONE,PAIR_VERIFY_REASON_LOCAL,
    PAIR_VERIFY_REASON_PROTOCOL,PAIR_VERIFY_REASON_AUTH,PAIR_VERIFY_REASON_PROVIDER,PAIR_VERIFY_REASON_DEADLINE };
typedef struct pair_session_keys {
    uint8_t read_key[32],write_key[32],shared_secret[32],controller_id[PAIR_ID_MAX];
    size_t controller_id_size;
} pair_session_keys;
typedef struct pair_verify {
    const pair_identity *identity;
    pair_random_fn random;
    void *random_context;
    pair_lookup_fn lookup;
    void *lookup_context;
    pair_verify_config config;
    uint64_t generation,token,now,started_at,held_at;
    uint8_t our_ephemeral[32],peer_ephemeral[32],encrypt_key[32];
    pair_session_keys keys; /* Internal, not exposed until take; caller read-only. */
    uint8_t output[PAIR_VERIFY_MAX_BODY];
    size_t output_size;
    enum pair_verify_state state;
    enum pair_verify_reason reason;
    int last_error;
} pair_verify;
/* One-shot responder for an explicitly provisioned identity and known trusted
 * controller. Fresh nonzero generation, borrowed immutable identity/provider
 * contexts through take/close. No heap, transport, default identity/RNG/store,
 * advertising, retries, pair-setup or MFi authentication. All storage disjoint,
 * no copying/reentry/concurrency; initialize once per lifetime. Config defaults
 * exchange10s/hold5s, each 1..60000ms. Overall exchange starts at init and is
 * never renewed; callbacks are synchronous and cannot be preempted here.
 */
void pair_verify_default_config(pair_verify_config *);
int pair_verify_init(pair_verify *,const pair_identity *,pair_random_fn,void *,pair_lookup_fn,void *,
                      const pair_verify_config *,uint64_t generation,uint64_t now_ms);
int pair_verify_check(pair_verify *,uint64_t generation,uint64_t now_ms);
/* One complete TLV8 body after outer RTSP validation. M1 requires state1/key32;
 * M3 requires state3/sealed-data. Unique other fields are retained by the codec
 * but ignored here; duplicate fields and separators reject in this handshake.
 * Wrong phase/body/auth/provider failure closes/wipes the exchange, no fake
 * success or automatic failure reply. Caller closes transport or sends its
 * explicit error. Wrong generation/decreasing clock are transactional.
 */
int pair_verify_request(pair_verify *,uint64_t generation,const uint8_t *,size_t,uint64_t now_ms);
/* Borrow a complete M2/M4 response until release/close; outputs zero if absent.
 * Release is caller attestation that the entire plaintext outer response has
 * been drained by its downstream transport. It is not inferred from a copy.
 * M2 release enables M3; M4 release enables key handoff, never plaintext resume.
 */
int pair_verify_response(const pair_verify *,const uint8_t **body,size_t *size,uint64_t *token);
int pair_verify_release(pair_verify *,uint64_t generation,uint64_t token,uint64_t now_ms);
/* Only after M3 signature/known-key verification AND explicit M4 release.
 * Copies session keys once, then wipes responder secrets and detaches. Caller
 * owns clearing its copy and must bind it to the same connection lifetime.
 * No API can mark a failed/unverified session secure. A matching generation /
 * response token is mandatory; errors leave key output unchanged.
 */
int pair_verify_take(pair_verify *,uint64_t generation,uint64_t token,pair_session_keys *,uint64_t now_ms);
void pair_verify_close(pair_verify *);
uint32_t pair_verify_next_delay(const pair_verify *);
#ifdef __cplusplus
}
#endif
#endif
