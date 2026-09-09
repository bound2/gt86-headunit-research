/* SPDX-License-Identifier: GPL-3.0-only
 * Local bounded USBmux host/connection dispatcher and byte-stream API.
 * No native USB backend, Lockdown, trust pairing, TLS or CarPlay media supplied.
 */
#ifndef GT86_USBMUX_DISPATCHER_H
#define GT86_USBMUX_DISPATCHER_H
#include "usbmux_host.h"
#include "usbmux_connection.h"
#ifdef __cplusplus
extern "C" {
#endif
#define USBMUX_DISPATCHER_SLOTS 4u
#define USBMUX_DISPATCHER_READ_CHUNK 1024u
#define USBMUX_DISPATCHER_BUSY 3
#define USBMUX_DISPATCHER_CONTROL 4
#define USBMUX_DISPATCHER_CLOSED (-7)
#define USBMUX_DISPATCHER_STALE (-8)
enum usbmux_io_status { USBMUX_IO_PROGRESS, USBMUX_IO_WOULD_BLOCK, USBMUX_IO_DISCONNECTED, USBMUX_IO_FATAL };
typedef struct usbmux_io_result { int status; size_t count; uint64_t generation; } usbmux_io_result;
/* Nonblocking synchronous callbacks; fill ALL result fields. PROGRESS count is
 * 0..requested; zero means no progress. Other statuses require count=0. write
 * counts only physically completed bytes from this tail, not copied/submitted
 * bytes. Echo the actual operation's generation. No pointer/result retention,
 * overlap, reentry or concurrent mutation. Async backends need their own memory
 * and completion accounting. cancel MUST synchronously quiesce that generation.
 * These are caller obligations, not a memory sandbox or USB-driver implementation.
 */
typedef struct usbmux_backend {
    void *context;
    void (*read)(void *, uint64_t, uint8_t *, size_t, usbmux_io_result *);
    void (*write)(void *, uint64_t, const uint8_t *, size_t, usbmux_io_result *);
    void (*cancel)(void *, uint64_t);
} usbmux_backend;
typedef struct usbmux_dispatcher_config { uint32_t retry_ms; /* 1..1000, default 5. */ } usbmux_dispatcher_config;
typedef struct usbmux_handle { uint64_t physical, connection; unsigned slot; } usbmux_handle;
enum usbmux_dispatcher_reason { USBMUX_DISPATCHER_REASON_NONE, USBMUX_DISPATCHER_REASON_LOCAL,
    USBMUX_DISPATCHER_REASON_HOST, USBMUX_DISPATCHER_REASON_CONNECTION, USBMUX_DISPATCHER_REASON_IO,
    USBMUX_DISPATCHER_REASON_DISCONNECTED, USBMUX_DISPATCHER_REASON_RESULT,
    USBMUX_DISPATCHER_REASON_STALE, USBMUX_DISPATCHER_REASON_STATE, USBMUX_DISPATCHER_REASON_COUNTER };
/* Caller-owned/noncopyable; ALL fields read-only. init once per lifetime.
 * While owned, only this dispatcher mutates the host/connections; applications
 * use the handle APIs below. Objects, buffers and backend context must outlive
 * close/cancel. No allocation, hidden clock, OS APIs or global mutable state.
 */
typedef struct usbmux_dispatcher {
    usbmux_host *host;
    usbmux_connection *connections[USBMUX_DISPATCHER_SLOTS];
    usbmux_backend backend;
    usbmux_dispatcher_config config;
    uint64_t generation, now, next_connection, next_control, control_token, read_at, write_at;
    uint64_t owner_connection;
    size_t rx_size, rx_offset, owner_size;
    uint32_t next_port, ignored_packets;
    unsigned count, round_robin, owner_slot, failed_slot;
    uint16_t owner_mux_sequence;
    enum usbmux_dispatcher_reason reason;
    int last_error;
    uint8_t used[USBMUX_DISPATCHER_SLOTS], active, owner, control_pending, read_paused, write_paused, again;
    uint8_t rx[USBMUX_DISPATCHER_READ_CHUNK];
} usbmux_dispatcher;
void usbmux_dispatcher_default_config(usbmux_dispatcher_config *);
/* Host and 1..4 distinct connections must already be initialized and IDLE.
 * Host TX must fit every send_limit+36; RX must fit min(rx_capacity+36,65536),
 * so the connection never advertises a larger receivable packet than the host.
 * Invalid init leaves existing state untouched. Arguments/storage cannot overlap.
 */
int usbmux_dispatcher_init(usbmux_dispatcher *, usbmux_host *, usbmux_connection *const *, unsigned,
                           const usbmux_backend *, const usbmux_dispatcher_config *);
/* Caller establishes a fresh physical byte stream first. Nonzero generation
 * strictly increases; no reuse/wrap, no decreasing clock. Queues version but
 * performs no I/O. Previous generation must have been closed/cancelled. */
int usbmux_dispatcher_start(usbmux_dispatcher *, uint64_t generation, uint64_t now_ms);
/* Cancels exactly once per active generation before clearing host/connection
 * queues. Any terminal connection error conservatively closes the shared mux;
 * there is no isolated local abort/RST scheduler. Reasons survive until start.
 */
void usbmux_dispatcher_close(usbmux_dispatcher *);
/* At most one backend read, one buffered feed/held-frame dispatch, one TCP
 * submission and one backend write per poll. Check all hard deadlines first.
 * Round-robin complete-packet scheduling; no interleaving. Account a connection
 * packet only after the entire containing mux packet is physically completed.
 * Unmatched/retired TCP is discarded, not anonymously reset. CONTROL is held
 * for explicit handling; TX continues but subsequent RX is backpressured.
 * OK: bounded work may remain; MORE: wait next_delay; CONTROL: service the held
 * event while continuing to poll; CLOSED: inspect reason/failed_slot/last_error.
 */
int usbmux_dispatcher_poll(usbmux_dispatcher *, uint64_t now_ms);
/* Timers only: check all shared clocks/deadlines without backend reads/writes.
 * May queue bounded ACK/FIN output; deadline failure cancels the current shared
 * generation exactly once. Does NOT route buffered input or complete output.
 * Callers holding a stream handle must validate its generation BEFORE this
 * physical-session-wide operation; an old owner must not tick a newer session.
 */
int usbmux_dispatcher_check(usbmux_dispatcher *, uint64_t now_ms);
/* Polling backoff + hard deadlines. Zero means bounded work, not a repeatedly
 * blocked write or unhandled CONTROL. UINT32_MAX means inactive. */
uint32_t usbmux_dispatcher_next_delay(const usbmux_dispatcher *);
/* READY host required. Allocate fresh local port 1..65535, never reused within
 * a physical generation. Reuse a slot only after graceful close AND RX drain.
 * Both local and remote port routing remain enforced. Output unchanged on error.
 * Handle includes physical/connection generations; old handles return STALE
 * without changing time/state or closing a newer connection. No counter wrap.
 */
int usbmux_dispatcher_open(usbmux_dispatcher *, uint16_t remote_port, uint32_t initial_sequence,
                           usbmux_handle *, uint64_t now_ms);
int usbmux_dispatcher_state(const usbmux_dispatcher *, const usbmux_handle *, enum usbmux_connection_state *);
/* Byte-stream prefix operations. read copies at most one contiguous RX view;
 * MORE is no data, END is drained peer FIN. write copies a bounded prefix and
 * may return BUSY/accepted=0. Neither claims a peer ACK or TLS/service success.
 * Call poll after application progress. Basic invalid pointer/count arguments
 * and stale handles leave time/state unchanged. Timed operations otherwise
 * enforce all shared deadlines even when the requested stream would block.
 */
int usbmux_dispatcher_read(usbmux_dispatcher *, const usbmux_handle *, uint8_t *, size_t, size_t *, uint64_t now_ms);
int usbmux_dispatcher_write(usbmux_dispatcher *, const usbmux_handle *, const uint8_t *, size_t, size_t *, uint64_t now_ms);
int usbmux_dispatcher_finish(usbmux_dispatcher *, const usbmux_handle *, uint64_t now_ms);
/* Untimed opaque CONTROL view and token, null/zero when absent/error. Borrowed
 * until release/closure; never log/execute these bytes automatically. Wrong
 * physical generation/token returns STALE without releasing a newer event.
 * Failure to service it within host.receive_ms closes the shared transport.
 */
int usbmux_dispatcher_control(const usbmux_dispatcher *, const usbmux_frame **, uint64_t *token);
int usbmux_dispatcher_release_control(usbmux_dispatcher *, uint64_t physical, uint64_t token, uint64_t now_ms);
#ifdef __cplusplus
}
#endif
#endif
