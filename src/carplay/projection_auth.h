/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_AUTH_H
#define GT86_PROJECTION_AUTH_H
#include "projection_control.h"
#include "mfi_sap.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_AUTH_CLOSED (-7)
enum projection_auth_state { PROJECTION_AUTH_ACTIVE,PROJECTION_AUTH_DEAD };
enum projection_auth_reason { PROJECTION_AUTH_REASON_NONE,PROJECTION_AUTH_REASON_LOCAL,
    PROJECTION_AUTH_REASON_CONTROL,PROJECTION_AUTH_REASON_ROUTE,PROJECTION_AUTH_REASON_MFI };
typedef struct projection_auth_config { projection_control_config control;uint32_t auth_hold_ms; } projection_auth_config;
typedef struct projection_auth {
    projection_control control;
    mfi_sap auth;
    uint64_t generation,now;
    enum projection_auth_state state;enum projection_auth_reason reason;int last_error;
    uint8_t internal_reply;
} projection_auth;
/* Owns FRESH pairing/control and MFiSAP children from init through close. No
 * attaching an unrelated authenticated stream or raw session keys. Use only
 * these wrapper APIs, not child APIs; internals read-only/noncopyable, no
 * concurrency/reentry. Identity, RNG and provider contexts must outlive owner.
 * All arguments/storage disjoint as for projection_control. Init no I/O.
 * Output storage >= MFI_SAP_REPLY_MAX+256 ensures worst-case internal response
 * capacity before any chip call. auth hold default5s, independent absolute budget.
 * Initially only known-controller /pair-verify; /auth-setup handled ONLY after
 * real verification and plaintext M4 drain activate encrypted control. Plaintext
 * auth requests cannot call chip/RNG. No enrollment/initial-mode router yet.
 */
void projection_auth_default_config(projection_auth_config *);
int projection_auth_init(projection_auth *,const pair_identity *,pair_random_fn,void *,pair_lookup_fn,void *,
                           const mfi_sap_provider *,const projection_auth_config *,const projection_control_storage *,uint64_t,uint64_t);
int projection_auth_check(projection_auth *,uint64_t,uint64_t);
/* Exact POST /auth-setup with one application/octet-stream Content-Type is an
 * internal one-shot route. Malformed/repeated auth closes, never a permissive
 * success. Other encrypted requests remain HELD for explicit application policy
 * and replies; this module does NOT claim capabilities, start media or enforce
 * the future session-command state machine. No automatic 200 for unknown routes.
 * Retained tails, record limits and byte accounting follow projection_control.
 */
int projection_auth_feed(projection_auth *,uint64_t,const uint8_t *,size_t,size_t *,uint64_t);
int projection_auth_request(const projection_auth *,rtsp_message *,rtsp_channel_key *);
int projection_auth_respond(projection_auth *,rtsp_channel_key,const rtsp_response *,uint64_t);
int projection_auth_output(projection_auth *,uint64_t,rtsp_slice *,rtsp_channel_key *,uint64_t);
int projection_auth_consume(projection_auth *,rtsp_channel_key,size_t,uint64_t);
/* Exact full encrypted reply drain returns MFI_SAP_DRAINED and clears auth
 * output/provider state. Not Apple/phone acceptance or active CarPlay. Otherwise
 * forwards normal pairing/application release status. No raw keys are exposed.
 */
int projection_auth_release(projection_auth *,rtsp_channel_key,uint64_t);
int projection_auth_eof(projection_auth *,uint64_t,uint64_t);
void projection_auth_close(projection_auth *);
uint32_t projection_auth_next_delay(const projection_auth *);
#ifdef __cplusplus
}
#endif
#endif
