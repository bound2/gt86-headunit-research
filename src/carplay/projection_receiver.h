/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_RECEIVER_H
#define GT86_PROJECTION_RECEIVER_H
#include "pair_setup_channel.h"
#include "projection_auth.h"
#include "projection_info.h"
#include "projection_session.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_RECEIVER_AUTHORIZE 21
#define PROJECTION_RECEIVER_CLOSED (-7)
enum projection_receiver_state {
    PROJECTION_RECEIVER_ROUTING, PROJECTION_RECEIVER_WAIT_AUTH,
    PROJECTION_RECEIVER_SETUP, PROJECTION_RECEIVER_AUTH, PROJECTION_RECEIVER_DEAD,
    PROJECTION_RECEIVER_DISCOVERY
};
enum projection_receiver_reason {
    PROJECTION_RECEIVER_REASON_NONE, PROJECTION_RECEIVER_REASON_LOCAL,
    PROJECTION_RECEIVER_REASON_INITIAL, PROJECTION_RECEIVER_REASON_ROUTE,
    PROJECTION_RECEIVER_REASON_SETUP, PROJECTION_RECEIVER_REASON_AUTH,
    PROJECTION_RECEIVER_REASON_TOKEN, PROJECTION_RECEIVER_REASON_EOF,
    PROJECTION_RECEIVER_REASON_INFO, PROJECTION_RECEIVER_REASON_SESSION
};
typedef struct projection_receiver_config {
    rtsp_channel_config initial;
    pair_setup_channel_config setup;
    projection_auth_config auth;
    uint8_t enrollment_enabled; /* Default 0. Enabling does NOT authorize a phone. */
} projection_receiver_config;
typedef struct projection_receiver_storage {
    uint8_t *initial; size_t initial_capacity;
    projection_control_storage control;
} projection_receiver_storage;
typedef struct projection_receiver_providers {
    const pair_identity *identity;
    pair_random_fn random; void *random_context;
    pair_lookup_fn lookup; void *lookup_context;
    pair_setup_commit_fn commit; void *commit_context;
    mfi_sap_provider mfi;
} projection_receiver_providers;
typedef struct projection_receiver_info_config {
    const projection_info_profile *profile;
    /* Trusted synchronous runtime check: attest ALL described capabilities,
     * descriptors, modes, formats and flags have available backend support.
     * No reentry, mutation of profile, pointer retention or unbounded I/O.
     * This is not an MFi provider; no implementation is supplied by default. */
    int (*available)(void *,uint64_t connection_generation,const projection_info_profile *);
    void *context;
    uint8_t *buffer; size_t capacity;
    uint32_t initial_ms; /* 1..60000, absolute from receiver init. */
    uint8_t initial_limit,allow_initial; /* 1..16 replies; explicit plaintext opt-in. */
} projection_receiver_info_config;
typedef struct projection_receiver {
    rtsp_channel initial;
    pair_setup_channel setup;
    projection_auth auth;
    projection_receiver_config config;
    projection_receiver_storage storage;
    projection_receiver_providers providers;
    projection_receiver_info_config info;
    projection_session session;
    rtsp_channel_key key, child_key;
    uint64_t generation, verify_generation, next_token, authorization, now,started_at;
    size_t info_size;
    enum projection_receiver_state state;
    enum projection_receiver_reason reason;
    int last_error;
    uint8_t enrolled; /* Acknowledged trust commit, never proof of phone acceptance. */
    uint8_t info_pending,initial_info_count;
} projection_receiver;
/* Fresh serial noncopyable owner. All internals read-only; no external child
 * calls, attach, reentry or concurrency. Identity/provider bindings immutable;
 * mutable provider contexts borrowed until close. No listener, automatic approval, trust creation,
 * credential, default capabilities, media handler or real chip access.
 *
 * Distinct nonzero connection and verification generations must be reserved by
 * the caller and never reused for another live/replacement owner. Public calls
 * and keys ALWAYS use connection generation; commit sees it, MFi sees verification
 * generation. Public request tokens are monotonic across all child phases.
 *
 * All storage/arguments disjoint; initial storage is a separate first-request
 * staging buffer (64..control.request_capacity), not extra network read-ahead.
 * Active children share control buffers only after prior owner drains/detaches.
 * The initial parser borrows response storage; only explicitly enabled info
 * replies may use it before selection, and must drain before another request.
 * Init validates enabled branches without I/O or changing destination/storage.
 */
void projection_receiver_default_config(projection_receiver_config *);
int projection_receiver_init(projection_receiver *, const projection_receiver_providers *,
    const projection_receiver_config *, const projection_receiver_storage *,
    uint64_t connection_generation, uint64_t verification_generation, uint64_t now_ms);
int projection_receiver_check(projection_receiver *, uint64_t, uint64_t);
/* Optional /info route, disabled at receiver init. Enable ONCE before any
 * initial input/provider work, while ROUTING. Validates/measures profile and
 * response capacity, no I/O or provider call. Profile and referenced data stay
 * immutable; provider context and separate writable scratch stay alive/disjoint
 * until close. Provider bindings stay immutable. No generic
 * attach or caller-supplied opaque successful response. Invalid config leaves
 * owner/buffers/time unchanged. defaults: initial disabled, 60s total, 4 replies.
 *
 * Exact GET (empty body) or POST /info; nonempty POST requires unique binary
 * plist content type and a bounded <=32768-byte/640-node decoded dictionary,
 * including finite binary reals; the stricter Lockdown parser is unchanged.
 * Decoded text/data use the separate info scratch buffer (capacity capped at
 * 32768 for decoding), then are cleared. Caller request/staging/scratch capacity
 * may impose a smaller bound; insufficient space closes, never a partial reply.
 * Request selectors are not implemented; full profile returned, as in reference.
 * Calls availability once per complete valid request, closes on failure. Reply
 * copied into normal owned output, scratch cleared. Caller refreshes monotonic
 * time after synchronous check. Replies do not authenticate or allocate media.
 * Pre-pairing plaintext discovery additionally requires allow_initial=1; no
 * such route in the middle of setup/verify. Absolute initial_ms/initial_limit
 * prevent endless discovery from renewing the initial connection lifetime.
 */
void projection_receiver_info_default_config(projection_receiver_info_config *);
int projection_receiver_enable_info(projection_receiver *,uint64_t,const projection_receiver_info_config *,uint64_t);
/* Optional typed SETUP/RECORD/TEARDOWN, disabled at init. Enable once while
 * ROUTING, after enabling info and before input. Uses that same immutable
 * capability profile/availability binding and scratch. Requires explicit real
 * resource provider; no default ports/backend. Only verified encrypted control
 * AFTER local MFi reply drain may allocate resources. No phone acceptance claim.
 * Sessions own transferred leases through close, deadline/EOF and reply failures.
 * Callback time must be refreshed before subsequent output/transport work.
 * See projection_session.h for schemas, key lifetime and drain/start contract. */
int projection_receiver_enable_session(projection_receiver *,uint64_t,const projection_session_config *,uint64_t);
/* Optional local one-attempt authorization ID, not supplied by the wire. May be
 * granted while ROUTING or after AUTHORIZE event; never renewed/replaced. When
 * waiting it processes the already held initial request, possibly returning
 * OUTPUT. Separate verified-candidate decide is still REQUIRED before commit.
 * Denial is explicit close; no implicit permission from enrollment_enabled.
 */
int projection_receiver_authorize(projection_receiver *, uint64_t, uint64_t authorization, uint64_t now_ms);
/* Parse exactly one initial complete plaintext request, then select only exact
 * POST /pair-setup or /pair-verify with unique pairing+tlv8 content type. Other
 * initial routes fail closed unless explicitly enabled /info handles discovery.
 * Setup without local authorization returns
 * AUTHORIZE and holds without RNG/store/chip calls. No following wire consumed.
 * Once selected there is no route fallback or mode restart. Later wire/events
 * follow the owned setup/auth children, including authenticated retained tails.
 * Initial idle/receive/authorization-hold budgets are absolute per phase;
 * selected setup/verification budgets start at selection/transfer, not renewed
 * by fragmentation. No automatic polling, rate limiting or approval UI.
 */
int projection_receiver_feed(projection_receiver *, uint64_t, const uint8_t *, size_t, size_t *, uint64_t);
int projection_receiver_pending(const projection_receiver *, pair_setup_candidate *, rtsp_channel_key *);
int projection_receiver_decide(projection_receiver *, rtsp_channel_key, int approve, uint64_t);
int projection_receiver_request(const projection_receiver *, rtsp_message *, rtsp_channel_key *);
int projection_receiver_respond(projection_receiver *, rtsp_channel_key, const rtsp_response *, uint64_t);
int projection_receiver_output(projection_receiver *, uint64_t, rtsp_slice *, rtsp_channel_key *, uint64_t);
int projection_receiver_consume(projection_receiver *, rtsp_channel_key, size_t, uint64_t);
/* Explicit exact-response downstream-drain attestation. Final M6 drain returns
 * PAIR_SETUP_COMPLETE and atomically transfers into fresh verification/MFi on
 * the SAME connection; no caller-managed handoff or raw keys. Public generation
 * stays stable, old tokens expire. M4 drain alone activates encrypted control;
 * MFI_SAP_DRAINED means local auth reply drained, not Apple/phone acceptance.
 */
int projection_receiver_release(projection_receiver *, rtsp_channel_key, uint64_t);
int projection_receiver_eof(projection_receiver *, uint64_t, uint64_t);
void projection_receiver_close(projection_receiver *);
uint32_t projection_receiver_next_delay(const projection_receiver *);
#ifdef __cplusplus
}
#endif
#endif
