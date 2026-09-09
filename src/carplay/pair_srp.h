/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PAIR_SRP_H
#define GT86_PAIR_SRP_H
#include "pair_crypto.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PAIR_SRP_PUBLIC_SIZE 384u
#define PAIR_SRP_SALT_SIZE 16u
#define PAIR_SRP_HASH_SIZE 64u
enum pair_srp_state { PAIR_SRP_NEW,PAIR_SRP_WAIT_PROOF,PAIR_SRP_DEAD };
typedef struct pair_srp {
    uint8_t secret[32],verifier[384],public_key[384],salt[16];
    enum pair_srp_state state;
    int last_error;
} pair_srp;
/* Memory-only, one-shot SRP-6a server: RFC5054 group3072/g5, SHA512,
 * username Pair-Setup, public compatibility code 3939. This is NOT authority
 * to enroll a controller. pair_setup supplies separate enrollment/approval.
 * Byte profile explicitly matches pinned LIVI: k/u use padded384 integers;
 * K hashes minimal unsigned S; proofs hash padded384 A/B. No fallback profile.
 * Optional hosted dependency: Mbed TLS 3.6.7 MPI allocates/free-wipes temporaries.
 * All storage/arguments disjoint, noncopyable read-only internals, init once,
 * no I/O, reentry or concurrency. init/clear have no allocations/provider calls.
 */
void pair_srp_init(pair_srp *);
/* RNG called for exactly salt16 then secret32. Zero secret rejected, no retry.
 * On success public_key/salt are available, secret/verifier remain private.
 */
int pair_srp_start(pair_srp *,pair_random_fn,void *);
/* A exactly384/proof exactly64 checked by enclosing TLV owner. Reject A outside
 * 2..N-2 and degenerate shared base/secret, u=0. Constant-time proof comparison.
 * Valid request consumes server once on success OR failure and wipes it.
 * Success writes K64/server_proof64; failure wipes both outputs; argument/state
 * errors leave them unchanged. No deadline here: owner checks before calling.
 * This research adapter is not a target side-channel/allocator safety proof.
 */
int pair_srp_verify(pair_srp *,const uint8_t client_public[384],const uint8_t proof[64],
                     uint8_t session_key[64],uint8_t server_proof[64]);
void pair_srp_clear(pair_srp *);
#ifdef __cplusplus
}
#endif
#endif
