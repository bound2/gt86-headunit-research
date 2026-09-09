/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PAIR_SETUP_H
#define GT86_PAIR_SETUP_H
#include "pair_srp.h"
#include "pair_tlv.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PAIR_SETUP_RESPONSE 16
#define PAIR_SETUP_APPROVAL 17
#define PAIR_SETUP_COMPLETE 18
#define PAIR_SETUP_CLOSED (-7)
#define PAIR_SETUP_BUSY 3
#define PAIR_SETUP_MAX_BODY 1024u
enum pair_setup_state { PAIR_SETUP_WAIT_AUTH,PAIR_SETUP_M1,PAIR_SETUP_M2_HELD,
    PAIR_SETUP_M3,PAIR_SETUP_M4_HELD,PAIR_SETUP_M5,PAIR_SETUP_PENDING,
    PAIR_SETUP_M6_HELD,PAIR_SETUP_DONE,PAIR_SETUP_DEAD };
enum pair_setup_reason { PAIR_SETUP_REASON_NONE,PAIR_SETUP_REASON_LOCAL,PAIR_SETUP_REASON_PROTOCOL,
    PAIR_SETUP_REASON_AUTH,PAIR_SETUP_REASON_PROVIDER,PAIR_SETUP_REASON_DEADLINE,PAIR_SETUP_REASON_DENIED };
typedef struct pair_setup_config { uint32_t exchange_ms,hold_ms,approval_ms; } pair_setup_config;
typedef struct pair_setup_candidate {
    uint8_t identifier[PAIR_ID_MAX],public_key[32];size_t identifier_size;
} pair_setup_candidate;
/* Trusted synchronous store provider, invoked ONCE only after verified M5 and
 * explicit candidate approval. OK must mean an acknowledged durable insert,
 * or the exact same ID/key already durably present. Never overwrite a different
 * key for an existing ID. Validation/conflict failures leave storage unchanged;
 * physical I/O failure can instead be INDETERMINATE (e.g. PAIR_STORE_UNCERTAIN).
 * Such a provider must stop serving trust until explicitly reopened/validated.
 * All failures suppress M6; no retry, rollback or deletion here. last_error
 * preserves the provider result. Provider owns locking, permissions, durability
 * and execution policy; synchronous OS I/O has no hard latency bound, so callers
 * must isolate it from real-time work. No reentry or pointer retention.
 */
typedef int (*pair_setup_commit_fn)(void *,uint64_t generation,uint64_t authorization,
                                    const uint8_t *identifier,size_t,const uint8_t public_key[32]);
typedef struct pair_setup {
    pair_srp srp;
    const pair_identity *identity;
    pair_random_fn random;void *random_context;
    pair_setup_commit_fn commit;void *commit_context;
    pair_setup_config config;
    pair_setup_candidate candidate;
    uint8_t session_key[64],output[PAIR_SETUP_MAX_BODY];size_t output_size;
    uint64_t generation,authorization,token,now,started_at,held_at;
    enum pair_setup_state state;enum pair_setup_reason reason;int last_error;
    uint8_t committed; /* Acknowledged commit only; false does NOT prove no disk write.
                        * Survives close; true does not mean peer received M6. */
} pair_setup;
/* Fresh immutable borrowed identity, explicit RNG/store; init once, noncopyable
 * read-only internals, no reentry/concurrency, all storage/arguments disjoint.
 * No I/O, automatic identity/store generation, SRP bypass or MFi auth. The
 * public fixed code is NOT identity authorization. Starts WAIT_AUTH. Exchange
 * deadline starts at init, defaults60s; response holds10s, candidate approval30s;
 * all values1..60000. No deadline is renewed by malformed/partial traffic.
 */
void pair_setup_default_config(pair_setup_config *);
int pair_setup_init(pair_setup *,const pair_identity *,pair_random_fn,void *,pair_setup_commit_fn,void *,
                      const pair_setup_config *,uint64_t generation,uint64_t now_ms);
/* Local authorization to attempt enrollment, caller-issued nonzero audit ID.
 * Must represent explicit user/administrative permission, not just USB presence.
 * One attempt; cannot reopen a failed/completed exchange or authorize via wire.
 */
int pair_setup_authorize(pair_setup *,uint64_t generation,uint64_t authorization,uint64_t now_ms);
int pair_setup_check(pair_setup *,uint64_t generation,uint64_t now_ms);
/* Complete validated outer body: M1 method0/state1 (flags absent or zero),
 * M3 A384/proof64/state3, M5 authenticated signed Ed25519 key exchange/state5.
 * Duplicate dictionary fields/separators reject. Unique unknown fields ignored.
 * Transient, MFi-method and alternate SRP byte profiles unsupported, no fallback.
 */
int pair_setup_request(pair_setup *,uint64_t generation,const uint8_t *,size_t,uint64_t now_ms);
int pair_setup_response(const pair_setup *,const uint8_t **,size_t *,uint64_t *token);
/* Immutable candidate copied only while approval pending; no M6 response yet.
 * Token identifies this verified candidate. It is not proof that the candidate
 * is the owner's intended phone. Caller must authenticate its enrollment intent.
 */
int pair_setup_pending(const pair_setup *,pair_setup_candidate *,uint64_t *token);
/* Decision0 denies/closes without write. Decision1 calls trusted commit once;
 * M6 becomes available ONLY if it returns OK. No "saved despite error" success.
 * Stale generation/token, wrong phase/decision/clock do not call the provider.
 */
int pair_setup_decide(pair_setup *,uint64_t generation,uint64_t token,int approve,uint64_t now_ms);
/* Caller attests the whole matching plaintext outer reply has drained. M2/M4
 * releases enable M3/M5. M6 release wipes/detaches and returns COMPLETE, NOT
 * encrypted control readiness. A separate pair-verify exchange is still needed.
 * Closing after successful commit does not delete/rollback the stored trust.
 */
int pair_setup_release(pair_setup *,uint64_t generation,uint64_t token,uint64_t now_ms);
void pair_setup_close(pair_setup *);
uint32_t pair_setup_next_delay(const pair_setup *);
#ifdef __cplusplus
}
#endif
#endif
