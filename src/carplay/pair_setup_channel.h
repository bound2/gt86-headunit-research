/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PAIR_SETUP_CHANNEL_H
#define GT86_PAIR_SETUP_CHANNEL_H
#include "pair_setup.h"
#include "projection_control.h"
#ifdef __cplusplus
extern "C" {
#endif
enum pair_setup_channel_state { PAIR_SETUP_CHANNEL_ACTIVE,PAIR_SETUP_CHANNEL_DRAINED,
    PAIR_SETUP_CHANNEL_DETACHED,PAIR_SETUP_CHANNEL_DEAD };
enum pair_setup_channel_reason { PAIR_SETUP_CHANNEL_REASON_NONE,PAIR_SETUP_CHANNEL_REASON_LOCAL,
    PAIR_SETUP_CHANNEL_REASON_SETUP,PAIR_SETUP_CHANNEL_REASON_RTSP,PAIR_SETUP_CHANNEL_REASON_ROUTE,PAIR_SETUP_CHANNEL_REASON_EOF };
typedef struct pair_setup_channel_config { pair_setup_config setup;rtsp_channel_config rtsp; } pair_setup_channel_config;
typedef struct pair_setup_channel {
    pair_setup setup;rtsp_channel rtsp;rtsp_channel_key key;
    const pair_identity *identity;pair_random_fn random;void *random_context;pair_lookup_fn lookup;void *lookup_context;
    uint64_t generation,now,pair_token;
    enum pair_setup_channel_state state;enum pair_setup_channel_reason reason;int last_error;
} pair_setup_channel;
/* Owning, serial, plaintext enrollment route. No attaching existing children
 * or direct external child calls; all fields read-only, noncopyable, no reentry/
 * concurrency, disjoint objects/buffers. Explicit enrollment mode only, NOT a
 * dispatcher for known controllers or capability routes. Identity/RNG/lookup
 * remain borrowed through take/close; commit contract is pair_setup's.
 * Defaults: setup60s/hold10s/approval30s; RTSP reply30s/output10s, ordinary idle/
 * receive defaults. Minimum of applicable absolute deadlines always applies.
 */
void pair_setup_channel_default_config(pair_setup_channel_config *);
int pair_setup_channel_init(pair_setup_channel *,const pair_identity *,pair_random_fn,void *,pair_setup_commit_fn,void *,
    pair_lookup_fn,void *,const pair_setup_channel_config *,uint8_t *rx,size_t,uint8_t *tx,size_t,uint64_t generation,uint64_t now_ms);
int pair_setup_channel_authorize(pair_setup_channel *,uint64_t generation,uint64_t authorization,uint64_t now_ms);
int pair_setup_channel_check(pair_setup_channel *,uint64_t generation,uint64_t now_ms);
/* No bytes consumed before local authorization or while approval/reply/drain
 * is held. Only exact POST /pair-setup, one application/pairing+tlv8 type.
 * Stops at one complete request, preserving any following wire bytes outside.
 */
int pair_setup_channel_feed(pair_setup_channel *,uint64_t generation,const uint8_t *,size_t,size_t *,uint64_t now_ms);
int pair_setup_channel_pending(const pair_setup_channel *,pair_setup_candidate *,rtsp_channel_key *);
int pair_setup_channel_decide(pair_setup_channel *,rtsp_channel_key,int approve,uint64_t now_ms);
int pair_setup_channel_output(pair_setup_channel *,uint64_t generation,rtsp_slice *,rtsp_channel_key *,uint64_t now_ms);
int pair_setup_channel_consume(pair_setup_channel *,rtsp_channel_key,size_t count,uint64_t now_ms);
/* Exact-request downstream-drain attestation, never inferred from copied
 * bytes. M6 release returns PAIR_SETUP_COMPLETE, not secure control readiness.
 */
int pair_setup_channel_release(pair_setup_channel *,rtsp_channel_key,uint64_t now_ms);
/* Only after committed M6 has drained. Initializes fresh projection_control
 * for the SAME transport's next pair-verify exchange, then detaches this owner.
 * New nonzero generation MUST differ; final enrollment key remains required.
 * RX/TX may transfer their exact buffers or use disjoint new storage; borrowed
 * identity/provider contexts must outlive the receiving owner.
 * Validates destination/config first; failure does not retire source. Does not
 * consume following wire or mark secure. Old-owner close cannot wipe new data.
 */
int pair_setup_channel_take(pair_setup_channel *,rtsp_channel_key,projection_control *,const projection_control_config *,
                             const projection_control_storage *,uint64_t next_generation,uint64_t now_ms);
int pair_setup_channel_eof(pair_setup_channel *,uint64_t generation,uint64_t now_ms);
void pair_setup_channel_close(pair_setup_channel *);
uint32_t pair_setup_channel_next_delay(const pair_setup_channel *);
#ifdef __cplusplus
}
#endif
#endif
