/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_CONTROL_H
#define GT86_PROJECTION_CONTROL_H
#include "pair_verify.h"
#include "control_cipher.h"
#include "rtsp_channel.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_CONTROL_SECURE 15
#define PROJECTION_CONTROL_CLOSED (-7)
enum projection_control_state { PROJECTION_CONTROL_PAIRING,PROJECTION_CONTROL_ENCRYPTED,PROJECTION_CONTROL_DEAD };
enum projection_control_reason { PROJECTION_CONTROL_REASON_NONE,PROJECTION_CONTROL_REASON_LOCAL,
    PROJECTION_CONTROL_REASON_PAIRING,PROJECTION_CONTROL_REASON_FRAMING,PROJECTION_CONTROL_REASON_CIPHER,
    PROJECTION_CONTROL_REASON_ROUTE,PROJECTION_CONTROL_REASON_EOF };
typedef struct projection_control_config {
    pair_verify_config pairing;
    rtsp_channel_config rtsp;
    control_cipher_config cipher;
} projection_control_config;
typedef struct projection_control_storage {
    uint8_t *request,*response,*cipher_rx,*plain,*cipher_tx;
    size_t request_capacity,response_capacity,cipher_rx_capacity,plain_capacity,cipher_tx_capacity;
} projection_control_storage;
typedef struct projection_control {
    pair_verify pairing;
    rtsp_channel rtsp;
    control_cipher cipher;
    rtsp_channel_key key;
    uint64_t generation,now,pair_token;
    uint8_t shared_secret[32],controller_id[PAIR_ID_MAX];
    size_t controller_id_size;
    enum projection_control_state state;
    enum projection_control_reason reason;
    int last_error;
} projection_control;
/* Owns fresh children from init through close; no attaching unrelated sessions,
 * external calls on children, copies, restart, concurrency or reentry. Children
 * and all fields are read-only to caller. Immutable identity/provider lifetime
 * and disjoint storage follow pair_verify/rtsp_channel/control_cipher contracts.
 * Invalid init leaves destination/storage unchanged; no I/O or provider calls.
 * Known-controller branch only: plaintext POST /pair-verify, exactly one
 * Content-Type: application/pairing+tlv8. Other plaintext routes close without
 * success. No enrollment, listener, auth-setup, capability/media handlers.
 */
void projection_control_default_config(projection_control_config *);
int projection_control_init(projection_control *,const pair_identity *,pair_random_fn,void *,pair_lookup_fn,void *,
                             const projection_control_config *,const projection_control_storage *,uint64_t generation,uint64_t now_ms);
int projection_control_check(projection_control *,uint64_t generation,uint64_t now_ms);
/* At most one cipher record and one RTSP message per call. Stops before any
 * plaintext/ciphertext tail at handshake or held-request boundaries. An
 * authenticated frame's unconsumed plaintext is retained across replies;
 * feed(NULL,0) processes that tail after release (or feed the unconsumed wire).
 * MORE/count0 may mean internal plaintext progressed, not a transport read.
 * REQUEST means encrypted application request held; OUTPUT means internal M2/
 * M4 reply ready. BUSY/count0 while a reply/request awaits application/drain.
 */
int projection_control_feed(projection_control *,uint64_t generation,const uint8_t *,size_t,size_t *consumed,uint64_t now_ms);
int projection_control_request(const projection_control *,rtsp_message *,rtsp_channel_key *);
int projection_control_respond(projection_control *,rtsp_channel_key,const rtsp_response *,uint64_t now_ms);
/* Output is plaintext only during verified handshake, ciphertext thereafter.
 * Each call creates at most one frame, retaining the same ciphertext across
 * partial writes. key identifies the enclosing request, not a transport job.
 * Calls/views are synchronous; consume acknowledges only the current prefix.
 * OUTPUT_DONE means all queues retired, not physically drained. release is an
 * explicit downstream-drain attestation for this exact response/lifetime.
 * M4 release is the ONLY transition to encryption and returns SECURE; it takes
 * keys once from the internally correlated pairing exchange. No raw-key bind.
 */
int projection_control_output(projection_control *,uint64_t generation,rtsp_slice *,rtsp_channel_key *,uint64_t now_ms);
int projection_control_consume(projection_control *,rtsp_channel_key,size_t count,uint64_t now_ms);
int projection_control_release(projection_control *,rtsp_channel_key,uint64_t now_ms);
int projection_control_eof(projection_control *,uint64_t generation,uint64_t now_ms);
void projection_control_close(projection_control *);
uint32_t projection_control_next_delay(const projection_control *);
#ifdef __cplusplus
}
#endif
#endif
