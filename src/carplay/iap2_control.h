/* SPDX-License-Identifier: GPL-3.0-or-later
 * CSM format reference: LIVI, Copyright (C) 2025 Lasse Heitgres.
 * Experimental local stream/serialization policy; not Apple conformance.
 */
#ifndef GT86_IAP2_CONTROL_H
#define GT86_IAP2_CONTROL_H
#include "iap2_link.h"
#include "iap2_auth.h"
#include "iap2_identification.h"
#ifdef __cplusplus
extern "C" {
#endif

#define IAP2_CONTROL_MESSAGE 4
#define IAP2_CONTROL_POLL_BUDGET 8u
enum iap2_control_reason { IAP2_CONTROL_REASON_NONE, IAP2_CONTROL_REASON_LOCAL,
    IAP2_CONTROL_REASON_LINK, IAP2_CONTROL_REASON_MESSAGE,
    IAP2_CONTROL_REASON_AUTH, IAP2_CONTROL_REASON_TIMEOUT,
    IAP2_CONTROL_REASON_IDENTIFICATION };
enum iap2_control_startup_order {
    IAP2_CONTROL_AUTHENTICATION_FIRST = 0, /* Existing experimental default. */
    IAP2_CONTROL_IDENTIFICATION_FIRST = 1 /* Pinned LIVI runtime ordering. */
};

typedef struct iap2_control_config {
    iap2_link_config link; /* Exactly one control session, kind 0/version 1. */
    uint32_t message_ms; /* Assembly + hold per CSM; also separate application TX-to-ACK budget. */
    uint32_t authentication_ms; /* Eligible phase start to accepted, including backpressure. */
    uint32_t identification_ms; /* Eligible phase start to accepted, if enabled. */
    enum iap2_control_startup_order startup_order;
} iap2_control_config;

/* Caller owns these three distinct, nonoverlapping buffers for the entire
 * endpoint lifetime. RX/reply capacities: 6..65535 / 11..65535 respectively.
 * scratch: 1..reply_capacity-10. No allocation or assumed certificate size.
 */
typedef struct iap2_control_buffers {
    uint8_t *receive, *reply, *scratch;
    size_t receive_capacity, reply_capacity, scratch_capacity;
} iap2_control_buffers;

/* Treat ALL fields (including link/auth) as read-only. Only the control API
 * may operate the owned link: reinitializing it separately is prohibited.
 * Noncopyable after init; no overlapping arguments/storage, concurrent calls,
 * or reentrant provider calls. No transport/device I/O or built-in signer.
 */
typedef struct iap2_control {
    iap2_link link;
    iap2_auth auth;
    iap2_identification identification;
    iap2_control_buffers buffers;
    enum iap2_control_reason reason;
    int last_error;
    uint32_t message_ms, authentication_ms, identification_ms;
    enum iap2_control_startup_order startup_order;
    uint32_t last_identification_rejection; /* Preserved across closure, reset by init. */
    uint64_t message_at, authentication_at, identification_at, reply_at;
    size_t receive_used, receive_expected, reply_size, reply_offset;
    size_t fragment_size, fragment_offset;
    uint8_t ready, authentication_timer, identification_timer, application_reply, work_pending; /* application_reply covers notifications too. */
    uint8_t fragment[IAP2_LINK_PAYLOAD_LIMIT];
} iap2_control;

void iap2_control_default_config(iap2_control_config *);
/* Copies config/provider/buffer descriptors. Reinit discards old connection
 * state; stop physical transport and discard externally retained TX tails
 * first. Invalid config leaves the existing endpoint unchanged. */
int iap2_control_init(iap2_control *, const iap2_control_config *,
                      const iap2_auth_provider *, const iap2_control_buffers *);
/* Optional, only before start. Copies explicit metadata and preflights reply
 * capacity. Init disables identification; every new init needs a new enable.
 * Order is explicit in config; IDENTIFICATION_FIRST requires this enable before
 * start and forbids auth messages/provider work until identification ACCEPTED.
 * AUTHENTICATION_FIRST retains the original auth-before-identification policy.
 * Both wait for reply ACK before results and fail closed on rejected/out-of-order
 * identification. No automatic fallback or phase restart after failure.
 * No transport components or CarPlay flags are advertised. */
int iap2_control_enable_identification(iap2_control *, const iap2_identification_metadata *);
/* IDENTIFICATION_FIRST without enabled metadata returns ARGUMENT without
 * starting the link or accepting the clock. Phase one starts at NORMAL; phase
 * two starts when poll processes phase-one acceptance, not when bytes arrive.
 * Both phases have separate total budgets; neither restarts on partial work. */
int iap2_control_start(iap2_control *, uint64_t now_ms);
/* EOF, local failure or cancellation. Clears partial/reply/provider scratch
 * contents and resets auth to IDLE. Not a secure memory-erasure guarantee. */
void iap2_control_close(iap2_control *);

/* feed/output retain the link API's consumed/written and physical-tail rules.
 * They NEVER invoke the provider or automatically drain control messages.
 * Honor recoverable link errors (including BUSY with consumed bytes); poll
 * to free receive space and continue servicing output/ACKs even while busy.
 * All timed calls use the same monotonically nondecreasing millisecond clock.
 * Any terminal link error resets auth and control state immediately. */
int iap2_control_feed(iap2_control *, const uint8_t *, size_t, size_t *consumed, uint64_t now_ms);
int iap2_control_output(iap2_control *, uint8_t *, size_t, size_t *written, uint64_t now_ms);

/* Bounded work, synchronous explicit provider callbacks ONLY here. Reassembles
 * length-delimited CSMs across opaque link payloads, preserving coalesced tails.
 * Malformed/oversize CSM or auth failure closes the endpoint; no resync scan.
 * Replies are fragmented to negotiated MTU and retained through queue pressure.
 * Processing subsequent CSMs waits until the WHOLE reply is cumulatively ACKed;
 * this is local serialization, not evidence of peer authentication/ordering.
 * Call after start (IDLE returns ARGUMENT without accepting the clock value).
 * OK: work budget exhausted, poll again. MORE: waiting for input/handshake.
 * BUSY: waiting for TX space/ACK; service transport, do not busy-spin.
 * MESSAGE: one valid, non-auth CSM is held for the application. Inspect/release
 * it. Enabled identification is handled internally; other messages are not
 * implicitly CarPlay commands. Auth may still be IDLE for a held message.
 * Negative status: inspect reason/link.state; last_error preserves terminal
 * cause after later calls return CLOSED. Provider callbacks must be bounded;
 * caller-time budgets cannot interrupt a blocking callback.
 */
int iap2_control_poll(iap2_control *, uint64_t now_ms);
/* A read-only view, valid until release/close/reinit or a timed call that closes
 * the endpoint. Does not advance time. Release explicitly consumes this CSM. */
int iap2_control_message(const iap2_control *, const uint8_t **data, size_t *size);
int iap2_control_release_message(iap2_control *);
/* Atomically copy one complete non-auth/non-identification CSM reply and release
 * the held application request. Requires NORMAL, auth ACCEPTED, and (if enabled)
 * identification ACCEPTED. No implied application handler.
 * IDLE returns ARGUMENT (call start first). BUSY: negotiation, prior reply or
 * identification pending; MORE: no held request.
 * Invalid/oversize/reserved messages leave the request and reply queue intact.
 * On OK caller can release input storage; poll fragments the retained copy.
 * The total application reply-to-ACK budget is message_ms, including stalled
 * transport. Continue output/poll and check next_delay; OK is not peer receipt.
 * Timed call rules apply; input must not overlap endpoint/buffer storage. */
int iap2_control_reply(iap2_control *, const uint8_t *, size_t, uint64_t now_ms);
/* Explicit unsolicited application CSM. Same gates, validation, owned-copy,
 * queue/backpressure and TX-to-ACK deadline as reply, but no request is needed
 * and any held/partially assembled input is preserved. Never resets its hold
 * deadline. Reserved auth/identification messages cannot bypass the sequencers.
 * No automatic send, capability advertisement or provider callback. Caller
 * must declare supported messages in its actual identification profile.
 * Call between pump polls; OK means queued, not received or acted upon. */
int iap2_control_notify(iap2_control *, const uint8_t *, size_t, uint64_t now_ms);
/* Minimum link/adapter timer or immediate runnable work, from last supplied
 * time. A held MESSAGE is a caller event, not a perpetual zero-delay timer.
 * Always service output for link retry exhaustion as well as poll for CSMs. */
uint32_t iap2_control_next_delay(const iap2_control *);

#ifdef __cplusplus
}
#endif
#endif
