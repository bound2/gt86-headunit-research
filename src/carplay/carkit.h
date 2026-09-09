/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_CARKIT_H
#define GT86_CARKIT_H
#include "lockdown_client.h"
#ifdef __cplusplus
extern "C" {
#endif
#define CARKIT_READY 7
#define CARKIT_CLOSED (-7)
#define CARKIT_BUSY 3
enum carkit_policy { CARKIT_REQUIRE_TLS, CARKIT_ALLOW_PLAIN_IF_REPORTED };
enum carkit_state { CARKIT_UNUSED, CARKIT_REQUEST, CARKIT_PORT, CARKIT_CONNECT,
    CARKIT_HANDSHAKE, CARKIT_OPEN, CARKIT_ERROR_HELD, CARKIT_DEAD };
enum carkit_reason { CARKIT_REASON_NONE, CARKIT_REASON_LOCAL, CARKIT_REASON_LOCKDOWN,
    CARKIT_REASON_POLICY, CARKIT_REASON_TRANSPORT, CARKIT_REASON_TLS, CARKIT_REASON_DEADLINE };
typedef struct carkit_config {
    enum carkit_policy policy;
    uint32_t startup_ms, initial_sequence;
    lockdown_tls_config tls;
} carkit_config;
/* Zero initialize. Noncopyable/exclusive owner of client and service_tls after
 * successful open; caller still handles unrelated dispatcher streams/CONTROL.
 * All fields/read views are read-only, storage distinct, no reentry/concurrency.
 * Credentials are borrowed (no key copies/record lookup) until service TLS init;
 * their byte buffers and RNG context MUST remain unchanged/alive through close.
 * Use the same selected pairing identity as the authenticated Lockdown session.
 * Parsed host and device certificates must match that session before the service
 * handshake emits any bytes; a different supplied identity is not a fallback.
 */
typedef struct carkit {
    lockdown_client *client; lockdown_tls *service_tls;
    lockdown_tls_credentials credentials; carkit_config config; usbmux_handle handle;
    uint64_t now, started_at;
    uint16_t port; uint8_t use_tls, tls_flag_present, application_used;
    enum carkit_state state; enum carkit_reason reason; int last_error;
} carkit;
void carkit_default_config(carkit_config *);
/* Explicitly queue com.apple.carkit.service on an IDLE protected RPC client.
 * Fresh zero-initialized service TLS storage required even if plain is allowed.
 * No backend I/O at open; successful queue begins the absolute startup budget.
 * Default REQUIRE_TLS refuses absent/false service SSL before opening a port.
 * Explicit ALLOW_PLAIN honors absent/false, but never falls back after TLS error.
 * The returned port is validated as 1..65535 and cannot be Lockdown's own 62078.
 */
int carkit_open(carkit *, lockdown_client *, lockdown_tls *service_tls,
                const lockdown_tls_credentials *, const carkit_config *, uint64_t now_ms);
/* One protected-client poll and, once needed, one service-TLS poll: at most two
 * physical backend reads/writes per carkit poll. No service app bytes until
 * CARKIT_READY; a TLS-required service must complete its own real handshake.
 * REMOTE_ERROR is a held error from the owned client; inspect via client_event,
 * do not externally release/retry/mutate it. Close or its hold timer terminates.
 */
int carkit_poll(carkit *, uint64_t now_ms);
/* Timers/lifetimes only, no backend or crypto I/O. */
int carkit_check(carkit *, uint64_t now_ms);
/* OPEN only: OK means service TLS's pending plaintext is empty AND its USBmux
 * connection has no physical output or unacknowledged data. MORE means pending.
 * This is a transport drain barrier, not an iAP2 ACK. Caller must exclusively
 * own service writes to associate the barrier with its submitted byte prefix.
 */
int carkit_write_drained(carkit *, uint64_t now_ms);
/* Raw iAP2 byte prefixes, NOT four-byte plist frames. TLS copies one whole write
 * <=4096 or BUSY; plaintext accepts a transport-limited prefix. accepted is not
 * physical completion, peer ACK or CarPlay success. Poll for forward progress.
 * Timed reads/writes check both service and retained Lockdown lifetimes first.
 */
int carkit_write(carkit *, const uint8_t *, size_t, size_t *accepted, uint64_t now_ms);
int carkit_read(carkit *, uint8_t *, size_t, size_t *, uint64_t now_ms);
/* Abort both streams via the shared mux; not StopSession/graceful shutdown.
 * Stale owners cannot cancel newer generations. Idempotent, releases TLS heap.
 */
void carkit_close(carkit *);
uint32_t carkit_next_delay(const carkit *);
#ifdef __cplusplus
}
#endif
#endif
