/* SPDX-License-Identifier: GPL-3.0-or-later
 * CSM format reference: LIVI, Copyright (C) 2025 Lasse Heitgres.
 * Experimental local stream/serialization policy; not Apple conformance.
 */
#ifndef GT86_IAP2_CONTROL_H
#define GT86_IAP2_CONTROL_H
#include "iap2_link.h"
#include "iap2_auth.h"
#ifdef __cplusplus
extern "C" {
#endif

#define IAP2_CONTROL_MESSAGE 4
#define IAP2_CONTROL_POLL_BUDGET 8u
enum iap2_control_reason { IAP2_CONTROL_REASON_NONE, IAP2_CONTROL_REASON_LOCAL,
    IAP2_CONTROL_REASON_LINK, IAP2_CONTROL_REASON_MESSAGE,
    IAP2_CONTROL_REASON_AUTH, IAP2_CONTROL_REASON_TIMEOUT };

typedef struct iap2_control_config {
    iap2_link_config link; /* Exactly one control session, kind 0/version 1. */
    uint32_t message_ms; /* Total assembly + application-hold budget per CSM. */
    uint32_t authentication_ms; /* NORMAL to accepted, including backpressure. */
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
    iap2_control_buffers buffers;
    enum iap2_control_reason reason;
    int last_error;
    uint32_t message_ms, authentication_ms;
    uint64_t message_at, authentication_at;
    size_t receive_used, receive_expected, reply_size, reply_offset;
    size_t fragment_size, fragment_offset;
    uint8_t ready, authentication_timer, work_pending;
    uint8_t fragment[IAP2_LINK_PAYLOAD_LIMIT];
} iap2_control;

void iap2_control_default_config(iap2_control_config *);
/* Copies config/provider/buffer descriptors. Reinit discards old connection
 * state; stop physical transport and discard externally retained TX tails
 * first. Invalid config leaves the existing endpoint unchanged. */
int iap2_control_init(iap2_control *, const iap2_control_config *,
                      const iap2_auth_provider *, const iap2_control_buffers *);
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
 * it; not implicitly an identification/CarPlay handler. Auth may still be IDLE.
 * Negative status: inspect reason/link.state; last_error preserves terminal
 * cause after later calls return CLOSED. Provider callbacks must be bounded;
 * caller-time budgets cannot interrupt a blocking callback.
 */
int iap2_control_poll(iap2_control *, uint64_t now_ms);
/* A read-only view, valid until release/close/reinit or a timed call that closes
 * the endpoint. Does not advance time. Release explicitly consumes this CSM. */
int iap2_control_message(const iap2_control *, const uint8_t **data, size_t *size);
int iap2_control_release_message(iap2_control *);
/* Minimum link/adapter timer or immediate runnable work, from last supplied
 * time. A held MESSAGE is a caller event, not a perpetual zero-delay timer.
 * Always service output for link retry exhaustion as well as poll for CSMs. */
uint32_t iap2_control_next_delay(const iap2_control *);

#ifdef __cplusplus
}
#endif
#endif
