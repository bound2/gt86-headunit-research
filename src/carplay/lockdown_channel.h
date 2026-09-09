/* SPDX-License-Identifier: GPL-3.0-only
 * Bounded serial plist-service exchange on an explicitly owned dispatcher stream.
 * Plain service bytes only: no TLS, plist semantics, pairing or automatic request.
 */
#ifndef GT86_LOCKDOWN_CHANNEL_H
#define GT86_LOCKDOWN_CHANNEL_H
#include "lockdown_wire.h"
#include "usbmux_dispatcher.h"
#ifdef __cplusplus
extern "C" {
#endif
#define LOCKDOWN_CHANNEL_RESPONSE 6
#define LOCKDOWN_CHANNEL_CLOSED (-7)
#define LOCKDOWN_CHANNEL_BUSY 3
#define LOCKDOWN_CHANNEL_CHUNK 512u
enum lockdown_channel_state { LOCKDOWN_CHANNEL_IDLE, LOCKDOWN_CHANNEL_EXCHANGE,
    LOCKDOWN_CHANNEL_HELD, LOCKDOWN_CHANNEL_DETACHED, LOCKDOWN_CHANNEL_DEAD };
enum lockdown_channel_reason { LOCKDOWN_CHANNEL_REASON_NONE, LOCKDOWN_CHANNEL_REASON_LOCAL,
    LOCKDOWN_CHANNEL_REASON_STALE, LOCKDOWN_CHANNEL_REASON_TRANSPORT, LOCKDOWN_CHANNEL_REASON_DEADLINE,
    LOCKDOWN_CHANNEL_REASON_LENGTH, LOCKDOWN_CHANNEL_REASON_EOF };
typedef struct lockdown_channel_config { uint32_t exchange_ms, hold_ms; /* 1..60000; defaults 5000/5000. */ } lockdown_channel_config;
/* Read-only fields, noncopyable caller-owned object. Separate frame buffers
 * 5..65540 bytes each include their four-byte prefix. Initialize once per
 * lifetime; no overlapping arguments/storage, concurrency or reentry. While
 * bound, ONLY this channel uses its stream's read/write/finish APIs. Other
 * dispatcher streams/control handling remain available to the application.
 */
typedef struct lockdown_channel {
    usbmux_dispatcher *dispatcher;
    usbmux_handle handle;
    lockdown_channel_config config;
    uint8_t *rx, *tx;
    size_t rx_capacity, tx_capacity, rx_used, rx_expected, tx_size, tx_offset;
    uint64_t now, started_at, held_at, next_token, token;
    enum lockdown_channel_state state;
    enum lockdown_channel_reason reason;
    int last_error;
    uint8_t complete;
} lockdown_channel;
void lockdown_channel_default_config(lockdown_channel_config *);
/* Bind an OPEN, TX-drained dispatcher stream at a known service-frame boundary.
 * No callbacks/requests at init. Stale/invalid init is transactional. Existing
 * unread bytes may remain at that known boundary; this layer cannot establish
 * protocol identity or determine whether an earlier TLS upgrade is required.
 */
int lockdown_channel_init(lockdown_channel *, usbmux_dispatcher *, const usbmux_handle *,
                          const lockdown_channel_config *, uint8_t *rx, size_t rx_capacity,
                          uint8_t *tx, size_t tx_capacity, uint64_t now_ms);
/* One explicit opaque request body, copied and framed transactionally. Does not
 * parse plist data or restrict generic request semantics; typed callers must
 * validate before use. No automatic retries, pairing or identity selection.
 */
int lockdown_channel_request(lockdown_channel *, const uint8_t *, size_t, uint64_t now_ms);
/* Check channel deadlines BEFORE a dispatcher poll; then at most one bounded
 * stream write and one exact-needed read (<=512 bytes each). Read only four
 * prefix bytes, then the declared body: never consume the following message or
 * possible TLS bytes. RX is serviced while request output remains pending.
 * RESPONSE only after a complete frame AND all request bytes are physically sent
 * and TCP-acknowledged. It does not mean a successful/valid plist response.
 * CONTROL is propagated when there is no held response; inspect dispatcher
 * control events independently when both exist. Keep polling while held.
 * Timed request/poll/release/detach operations check shared deadlines after
 * validating arguments and handle lifetime. Checks do not read/write backend
 * bytes, but can queue ACK/FIN output or cancel an expired shared generation.
 */
int lockdown_channel_poll(lockdown_channel *, uint64_t now_ms);
/* Untimed body view, borrowed until release/detach/closure. Error/MORE zero all
 * outputs. Release requires the current response token; stale release cannot
 * consume a later response or advance time. The application validates plist,
 * Request/Error fields and security requirements before beginning another RPC.
 */
int lockdown_channel_response(const lockdown_channel *, lockdown_body *, uint64_t *token);
int lockdown_channel_release(lockdown_channel *, uint64_t token, uint64_t now_ms);
/* IDLE only: return the original handle and relinquish framing without reading
 * any extra bytes, closing the stream or initiating TLS. Cancel/close after
 * detach is a no-op. A TLS implementation must take over explicitly afterward.
 */
int lockdown_channel_detach(lockdown_channel *, usbmux_handle *, uint64_t now_ms);
/* Abort a still-current owned stream by closing/cancelling its SHARED dispatcher.
 * A stale channel only clears its local state; it never closes a newer slot or
 * physical generation. No callback/buffer erasure guarantees beyond the existing
 * dispatcher contract. Reasons survive closure; no implicit rebind/reconnect.
 */
void lockdown_channel_close(lockdown_channel *);
/* Minimum of dispatcher readiness/deadlines and this operation/hold budget.
 * Uses the latest supplied channel/dispatcher time. No spin on a held response
 * or peer zero window; UINT32_MAX if detached/dead/uninitialized.
 */
uint32_t lockdown_channel_next_delay(const lockdown_channel *);
#ifdef __cplusplus
}
#endif
#endif
