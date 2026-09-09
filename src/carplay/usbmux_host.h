/* SPDX-License-Identifier: GPL-3.0-only
 * Bounded raw USBmux v2 host; no USB I/O, TCP connection or phone trust pairing.
 * Pinned references and local policy differences: reports/usbmux-transport.md.
 */
#ifndef GT86_USBMUX_HOST_H
#define GT86_USBMUX_HOST_H
#include "usbmux_wire.h"
#ifdef __cplusplus
extern "C" {
#endif

#define USBMUX_HOST_BUSY 3
#define USBMUX_HOST_PACKET 4
#define USBMUX_HOST_CLOSED (-7)

enum usbmux_host_state { USBMUX_HOST_IDLE, USBMUX_HOST_VERSION_TX,
    USBMUX_HOST_VERSION_RX, USBMUX_HOST_SETUP_TX, USBMUX_HOST_READY, USBMUX_HOST_DEAD };
enum usbmux_host_sequence { USBMUX_HOST_USBMUXD, USBMUX_HOST_LIVI };
enum usbmux_host_reason { USBMUX_HOST_REASON_NONE, USBMUX_HOST_REASON_LOCAL,
    USBMUX_HOST_REASON_DEADLINE, USBMUX_HOST_REASON_STALE, USBMUX_HOST_REASON_RESULT,
    USBMUX_HOST_REASON_VERSION, USBMUX_HOST_REASON_PROTOCOL };
typedef struct usbmux_host_config {
    enum usbmux_host_sequence sequence;
    uint32_t handshake_ms; /* Total version TX/RX + setup TX, 1..60000. */
    uint32_t write_ms;     /* Total per-packet completion budget, 1..60000. */
    uint32_t receive_ms;   /* Total assembly + application hold, 1..60000. */
} usbmux_host_config;

/* Caller-owned, noncopyable state; ALL fields read-only outside this module.
 * Initialize once per lifetime, not to bypass generation/clock rules. RX/TX
 * storage must be separate, 36..65536 bytes each, and outlive this object.
 * No overlapping state/config/storage/output arguments, concurrency or reentry.
 * No allocation, callbacks, device access, blocking or hidden clock.
 */
typedef struct usbmux_host {
    usbmux_host_config config;
    usbmux_stream rx;
    usbmux_frame packet;
    usbmux_version peer_version;
    uint8_t *tx;
    size_t tx_capacity, tx_size, tx_offset;
    uint64_t generation, now, started_at, tx_at, rx_at;
    uint16_t tx_sequence, rx_sequence;
    enum usbmux_host_state state;
    enum usbmux_host_reason reason;
    int last_error;
    uint8_t held, rx_timer;
} usbmux_host;

/* Defaults: usbmuxd sequence convention, 2000/250/5000 ms local budgets.
 * usbmuxd: setup RX slot=ffff, then copy the incoming SECOND sequence slot.
 * LIVI: outgoing RX slot always zero. Both start TX slot=0 and wrap u16.
 * Explicit configuration, no automatic profile fallback or peer-magic check.
 */
void usbmux_host_default_config(usbmux_host_config *);
int usbmux_host_init(usbmux_host *, const usbmux_host_config *,
                     uint8_t *rx, size_t rx_capacity, uint8_t *tx, size_t tx_capacity);
/* Queue initial VERSION 2.0.0, without opening a device. Require IDLE/DEAD,
 * nonzero generation strictly greater than the last successful start and a
 * nondecreasing clock. No generation/clock wrap or reuse. Invalid start/init
 * is transactional. Before close/restart the caller MUST synchronously quiesce
 * old I/O and stop using borrowed views; this module cannot cancel a backend.
 */
int usbmux_host_start(usbmux_host *, uint64_t generation, uint64_t now_ms);
/* Idempotent local close. Discard partial/held RX and pending TX, not securely
 * erase backing storage. Preserve reason/error/peer version until next start.
 * Signal EOF/backend failure by closing; zero-byte feed is NOT EOF.
 */
void usbmux_host_close(usbmux_host *);

/* All timed operations check deadlines BEFORE progress. Partial/zero progress,
 * blocked input/output and repeated views do not renew budgets. A stale
 * generation closes the active host without accepting its clock or bytes.
 * With the current generation, decreasing time/basic ARGUMENT changes neither
 * state nor clock. Other local
 * payload/capacity errors preserve queues but may advance the supplied clock.
 * Terminal errors return CLOSED; inspect reason/last_error for details.
 * poll checks time only; it neither performs I/O nor reports backend readiness.
 */
int usbmux_host_poll(usbmux_host *, uint64_t generation, uint64_t now_ms);
/* Borrow the pending physical-write tail, or MORE/null/zero if absent.
 * View APIs do not check time: poll before initiating I/O. Views last until
 * advance/close/start. Serialize completions and report only bytes ACTUALLY
 * completed from the current tail. Copying/submitting a buffer is not a
 * completion. Async backends need their own storage/completion accounting.
 */
int usbmux_host_output(const usbmux_host *, const uint8_t **data, size_t *size);
int usbmux_host_advance(usbmux_host *, size_t completed, uint64_t generation, uint64_t now_ms);
/* Feed one packet. Preserve any unconsumed coalesced tail at the caller.
 * BUSY/consumed=0 during VERSION_TX/SETUP_TX or while a packet is held.
 * VERSION_RX accepts exactly a version-2 reply; minor/padding are preserved,
 * not restricted. Version 1 has no fallback. READY begins only after setup's
 * complete physical write; it means mux configured, NOT paired/TCP connected.
 * READY accepts CONTROL or minimal TCP, returning PACKET and a held view;
 * unexpected VERSION/SETUP, malformed or over-capacity input closes the host.
 */
int usbmux_host_feed(usbmux_host *, const uint8_t *, size_t, size_t *consumed,
                     uint64_t generation, uint64_t now_ms);
/* Held packet borrows RX storage until release/close/start. Sending/output
 * completion never releases it. Releasing an incomplete packet is not allowed.
 * These view outputs are null on MORE/CLOSED/ARGUMENT.
 */
int usbmux_host_packet(const usbmux_host *, const usbmux_frame **);
int usbmux_host_release(usbmux_host *, uint64_t generation, uint64_t now_ms);
/* Queue one complete encoded minimal TCP header+payload, copied into owned TX.
 * Only READY and no pending TX; otherwise BUSY. Input cannot overlap TX/state,
 * but may borrow held RX storage. It is not retained after return. Malformed
 * local TCP/capacity errors do not close the host or consume a sequence slot.
 * No TCP routing, SYN/ACK validation, window enforcement, retransmission or
 * connection tracking. Caller must provide those before real transport use.
 */
int usbmux_host_send_tcp(usbmux_host *, const uint8_t *, size_t,
                         uint64_t generation, uint64_t now_ms);
/* Minimum hard-deadline delay from last accepted time; UINT32_MAX means none.
 * Not an I/O scheduler: callers also wait on backend readiness/application work.
 * Idle READY need not wake until those events. Never wrap the caller clock.
 */
uint32_t usbmux_host_next_delay(const usbmux_host *);
#ifdef __cplusplus
}
#endif
#endif
