/* SPDX-License-Identifier: GPL-3.0-or-later
 * Local bounded byte-stream pump. No USB profile or native device implementation.
 */
#ifndef GT86_IAP2_TRANSPORT_H
#define GT86_IAP2_TRANSPORT_H
#include "iap2_control.h"
#ifdef __cplusplus
extern "C" {
#endif

enum iap2_transport_io { IAP2_TRANSPORT_PROGRESS, IAP2_TRANSPORT_WOULD_BLOCK,
    IAP2_TRANSPORT_DISCONNECTED, IAP2_TRANSPORT_FATAL };
typedef struct iap2_transport_result {
    int status; /* One iap2_transport_io value; other integers are rejected. */
    size_t count;
    uint64_t generation;
} iap2_transport_result;

/* Nonblocking, synchronous callbacks. Fill EVERY result field. PROGRESS accepts
 * 0..requested bytes; zero is treated as WOULD_BLOCK. Every other status MUST
 * have count=0. Successful writes mean byte acceptance, never an iAP2 ACK.
 * Report any later failure on the next call; terminal results discard the
 * connection, including bytes that cannot safely be accounted for.
 *
 * Echo the generation of the operation actually completed, not blindly the
 * current argument. Stale results close the connection without feeding RX or
 * advancing TX. All descriptors, completion validation, USB/HID framing and
 * DMA buffers belong to the backend, not this byte-stream pump.
 *
 * Never retain/access these buffers or the result pointer after return. A
 * native async backend must use its own storage and bridge completions into
 * these synchronous calls. cancel must synchronously quiesce that generation
 * before returning. No reentry, concurrent callbacks, or buffer overlap.
 * Callback bounds/lifetimes are caller obligations, not a memory sandbox;
 * the pump cannot interrupt blocking callbacks or prevent a backend overrun.
 */
typedef struct iap2_transport_backend {
    void *context;
    void (*read)(void *, uint64_t, uint8_t *, size_t, iap2_transport_result *);
    void (*write)(void *, uint64_t, const uint8_t *, size_t, iap2_transport_result *);
    void (*cancel)(void *, uint64_t);
} iap2_transport_backend;

typedef struct iap2_transport_config {
    uint32_t pending_ms; /* 1..60000, total retained-output budget; not reset by progress. */
    uint32_t retry_ms;   /* 1..1000, <= pending_ms: polling backoff after no progress. */
} iap2_transport_config;
enum iap2_transport_reason { IAP2_TRANSPORT_REASON_NONE, IAP2_TRANSPORT_REASON_LOCAL,
    IAP2_TRANSPORT_REASON_DISCONNECTED, IAP2_TRANSPORT_REASON_IO,
    IAP2_TRANSPORT_REASON_RESULT, IAP2_TRANSPORT_REASON_STALE,
    IAP2_TRANSPORT_REASON_DEADLINE, IAP2_TRANSPORT_REASON_ENDPOINT };

/* Caller-owned, noncopyable, no heap/OS calls. Treat all fields as read-only.
 * init once per lifetime; never reinitialize an active pump. Keep the endpoint,
 * its buffers, backend context and pump alive until close/cancel returns.
 */
typedef struct iap2_transport {
    iap2_control *endpoint;
    iap2_transport_backend backend;
    iap2_transport_config config;
    uint64_t generation, now, tx_at, read_at, write_at;
    size_t tx_size, tx_offset, rx_size, rx_offset;
    enum iap2_transport_reason reason;
    int last_error, last_feed_error;
    uint8_t active, read_paused, write_paused, again;
    uint8_t tx[IAP2_LINK_PACKET_LIMIT], rx[IAP2_LINK_PACKET_LIMIT];
} iap2_transport;

void iap2_transport_default_config(iap2_transport_config *);
/* Endpoint must already be initialized and IDLE; invalid init is transactional.
 * The pump/endpoint and their storage must not overlap config/backend arguments. */
int iap2_transport_init(iap2_transport *, iap2_control *,
                        const iap2_transport_backend *, const iap2_transport_config *);
/* Starts the endpoint without opening a device. generation must be nonzero and
 * strictly greater than the last successful start. No wrap/reuse. On reconnect,
 * close first, reinitialize the SAME endpoint (identification disabled again),
 * then start a new generation. Do not reset the pump to bypass this rule.
 */
int iap2_transport_start(iap2_transport *, uint64_t generation, uint64_t now_ms);
/* Cancels exactly once per active generation, closes endpoint and clears tails.
 * Idempotent. Diagnostic reasons survive closure until the next start.
 * Memory clearing is not a secure-erasure guarantee. */
void iap2_transport_close(iap2_transport *);

/* At most one backend read, one buffered feed, one control poll, one output
 * production and one backend write per call. Partial output is never replaced
 * or interleaved. Input remains serviced while output is blocked. Bad checksums,
 * unsupported frames and RX queue pressure follow the link's consumed-count
 * policy; last_feed_error retains the latest recoverable error until start.
 *
 * A pending tail closes at pending_ms OR when it would block an existing link
 * retransmission deadline. Control/handshake timeouts are checked before I/O.
 * These are conservative local policies, not Apple-required USB timing.
 *
 * OK: more bounded work may be runnable. MORE: wait for next_delay. MESSAGE:
 * service the endpoint's held application message, but keep polling transport.
 * CLOSED: inspect reason/last_error. ARGUMENT: no state/time change.
 * All timed calls share a monotonic clock. While active, ONLY this pump calls
 * endpoint start/feed/output/poll/close; application view/release/reply remains
 * allowed between polls, using the same clock. Configure identification before
 * start. Never reinitialize the endpoint while the pump is active.
 */
int iap2_transport_poll(iap2_transport *, uint64_t now_ms);
/* Deadline preflight used by layered transports before performing lower-layer
 * I/O. Advances shared endpoint clocks with an empty feed; no provider, output
 * production or read/write callbacks. Expiry may invoke synchronous cancel.
 * Retained-output deadlines are unchanged and are checked again by poll.
 */
int iap2_transport_check(iap2_transport *, uint64_t now_ms);
/* Delay from the last supplied time. Polling design, no readiness callback:
 * idle/no-progress I/O is retried within retry_ms. Zero is runnable bounded
 * work, not merely a blocked write or an unhandled application message.
 * UINT32_MAX means inactive. Service the application between pump calls.
 */
uint32_t iap2_transport_next_delay(const iap2_transport *);

#ifdef __cplusplus
}
#endif
#endif
