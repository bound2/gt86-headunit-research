/* SPDX-License-Identifier: GPL-3.0-or-later
 * Link-format reference: LIVI, Copyright (C) 2025 Lasse Heitgres.
 * See third_party/README.md. Experimental bounded profile, not MFi certification.
 */
#ifndef GT86_IAP2_LINK_H
#define GT86_IAP2_LINK_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif

#define IAP2_LINK_SLOTS 8u
#define IAP2_LINK_PACKET_LIMIT 1024u
#define IAP2_LINK_PAYLOAD_LIMIT (IAP2_LINK_PACKET_LIMIT - 10u)
#define IAP2_LINK_SESSIONS 3u
#define IAP2_LINK_LSP_LIMIT (10u + 3u * IAP2_LINK_SESSIONS)
#define IAP2_LINK_BUSY 3
#define IAP2_LINK_CLOSED (-7)

enum iap2_link_state { IAP2_LINK_IDLE, IAP2_LINK_DETECT, IAP2_LINK_SYNCHRONIZE,
                       IAP2_LINK_NORMAL, IAP2_LINK_DEAD };
enum iap2_link_reason { IAP2_LINK_REASON_NONE, IAP2_LINK_REASON_LOCAL,
    IAP2_LINK_REASON_MARKER, IAP2_LINK_REASON_TIMEOUT, IAP2_LINK_REASON_RESET,
    IAP2_LINK_REASON_RESTART, IAP2_LINK_REASON_OVERSIZE };

typedef struct iap2_link_session { uint8_t id, kind, version; } iap2_link_session;
typedef struct iap2_lsp {
    uint8_t window, retries, max_ack, session_count;
    uint16_t packet_size, retransmit_ms, ack_ms;
    iap2_link_session sessions[IAP2_LINK_SESSIONS];
} iap2_lsp;

/* Strict version-1 LSP codec: exact triplets, unique nonzero session IDs,
 * positive bounded windows/timers, no zero-ACK profile. Decode is transactional.
 * Input/output must not overlap. Engine-specific capacity checks happen later.
 */
int iap2_lsp_decode(const uint8_t *, size_t, iap2_lsp *);
int iap2_lsp_encode(const iap2_lsp *, uint8_t *, size_t, size_t *written);

typedef struct iap2_link_config {
    iap2_lsp offer;
    uint8_t initial_sequence;
    uint32_t handshake_ms; /* Total detection + negotiation budget. */
} iap2_link_config;

typedef struct iap2_link_packet {
    uint8_t used, sequence, session, attempts;
    uint16_t size;
    uint64_t sent_at;
    uint8_t data[IAP2_LINK_PAYLOAD_LIMIT];
} iap2_link_packet;

/* Caller-owned storage. Treat fields as read-only outside this implementation.
 * Fixed TX/RX queues, no heap, OS calls, callbacks or global mutable state.
 */
typedef struct iap2_link {
    enum iap2_link_state state;
    enum iap2_link_reason reason;
    iap2_link_config config;
    iap2_lsp negotiated;
    uint64_t now, started_at, marker_at, syn_at, ack_at;
    uint8_t marker_used, marker_sent, syn_sent, peer_syn, peer_syn_sequence;
    uint8_t our_syn_acked, peer_syn_acked, ack_pending, ack_timer, ack_count;
    uint8_t tx_head, tx_count, tx_sent, tx_sequence, tx_acked;
    uint8_t rx_acked, rx_delivered;
    uint8_t rx_storage[IAP2_LINK_PACKET_LIMIT];
    iap2_stream stream;
    iap2_link_packet tx[IAP2_LINK_SLOTS], rx[IAP2_LINK_SLOTS];
} iap2_link;

/* Default: 4-packet window, 1024 bytes/frame, 1000-ms retransmit, 100-ms ACK,
 * 3 retransmissions AFTER the initial send, cumulative ACK every 2 payloads,
 * control session 10/version 1 only. Other sessions require explicit offers
 * and application handlers. Config/session data is copied; link is noncopyable
 * after init because its stream points into its own storage. No overlapping
 * input/output/config/storage, concurrent calls, or external field mutation.
 */
void iap2_link_default_config(iap2_link_config *);
int iap2_link_init(iap2_link *, const iap2_link_config *);
int iap2_link_start(iap2_link *, uint64_t now_ms);
void iap2_link_close(iap2_link *); /* EOF/transport failure: discard all state. */

/* All time-bearing calls require monotonically nondecreasing milliseconds.
 * feed processes bytes until exhausted or a recoverable error. Always honor
 * consumed: a bad checksummed frame or RX-full packet may already be consumed.
 * RX-full returns BUSY and does not advance the ACK for the new payload;
 * that packet is dropped for peer retransmission after the app drains receive.
 * Garbage/bad headers are scanned by iap2_stream. Bad bodies are rejected;
 * valid headers exceeding offered capacity terminate the link. EAK and other
 * unimplemented controls are rejected before ACK/queue changes.
 */
int iap2_link_feed(iap2_link *, const uint8_t *, size_t, size_t *consumed, uint64_t now_ms);
/* Queues one opaque session payload. BUSY means not accepted; no hidden queue.
 * Only negotiated IDs are accepted. No CSM/EA fragmentation or parsing here.
 */
int iap2_link_send(iap2_link *, uint8_t session, const uint8_t *, size_t, uint64_t now_ms);
/* Copies one IN-ORDER received payload. MORE means none ready. NO_SPACE keeps
 * the payload queued, written=0. Session is set only on success. */
int iap2_link_receive(iap2_link *, uint8_t *session, uint8_t *, size_t, size_t *written);
/* Produces at most one marker/frame. MORE means no output now. NO_SPACE does
 * not consume pending output or retry budget. Call only when the transport can
 * accept/retain the whole returned frame; retain any partially written tail
 * outside this engine, or close on failure. This is not a USB write function.
 * Drain repeatedly until MORE (or transport backpressure) to service pending
 * control traffic as well as data. Check state/reason on every error; reset the
 * authentication/session layers whenever this link closes or is reinitialized.
 * Retransmission clocks start here, not at send(). Payloads are retained until
 * valid cumulative ACKs. Returned data may carry a current piggyback ACK.
 */
int iap2_link_output(iap2_link *, uint8_t *, size_t, size_t *written, uint64_t now_ms);
/* Delay from last supplied time until output/timeout needs polling; 0 means
 * immediate. UINT32_MAX means no timer/output pending. No wall clock is read. */
uint32_t iap2_link_next_delay(const iap2_link *);

#ifdef __cplusplus
}
#endif
#endif
