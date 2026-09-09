/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_LOCKDOWN_TLS_H
#define GT86_LOCKDOWN_TLS_H
#include "lockdown_bootstrap.h"
#include <mbedtls/ssl.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#ifdef __cplusplus
extern "C" {
#endif
#define LOCKDOWN_TLS_CHUNK 512u
#define LOCKDOWN_TLS_WRITE_LIMIT 4096u
#define LOCKDOWN_TLS_CLOSED (-7)
#define LOCKDOWN_TLS_BUSY 3
enum lockdown_tls_state { LOCKDOWN_TLS_UNUSED, LOCKDOWN_TLS_HANDSHAKE, LOCKDOWN_TLS_OPEN, LOCKDOWN_TLS_DEAD };
enum lockdown_tls_reason { LOCKDOWN_TLS_REASON_NONE, LOCKDOWN_TLS_REASON_LOCAL,
    LOCKDOWN_TLS_REASON_STALE, LOCKDOWN_TLS_REASON_TRANSPORT, LOCKDOWN_TLS_REASON_DEADLINE,
    LOCKDOWN_TLS_REASON_CRYPTO, LOCKDOWN_TLS_REASON_PEER_CLOSE, LOCKDOWN_TLS_REASON_TRUNCATED };
typedef struct lockdown_tls_credentials {
    /* PEM including terminating NUL, or DER. Bounds apply before parsing.
     * Root/host cert <=32768, private key <=16384, device DER <=16384.
     * Device pin is exactly one DER leaf certificate from the selected record.
     * No filesystem lookup, Pair, generation, credential logging or defaults.
     */
    lockdown_body root, host_certificate, host_private_key, device_der;
    /* Production requires a seeded CSPRNG, returning 0 only after filling all
     * bytes. Callback/context outlive TLS, synchronous/nonblocking/nonreentrant.
     * The library cannot prove the quality of a caller's randomness provider.
     */
    int (*random)(void *, unsigned char *, size_t);
    void *random_context;
} lockdown_tls_credentials;
typedef struct lockdown_tls_config { uint32_t handshake_ms, write_ms, hold_ms; } lockdown_tls_config;
/* Zero initialize before init. Noncopyable, exclusive owner; all fields are
 * read-only. No overlapping arguments, concurrent access or callback reentry.
 * Uses Mbed TLS heap allocations, system certificate time and caller RNG.
 * Fixed app buffers and per-call BIO budgets are NOT a total crypto heap/CPU
 * bound. Dispatcher/backend lifetime extends through close/free.
 */
typedef struct lockdown_tls {
    usbmux_dispatcher *dispatcher; usbmux_handle handle;
    mbedtls_ssl_context ssl; mbedtls_ssl_config ssl_config;
    mbedtls_x509_crt root, host_certificate, device;
    mbedtls_pk_context host_key;
    lockdown_tls_config config;
    uint64_t now, started_at, write_at, held_at;
    uint8_t session_id[256]; size_t session_id_size;
    size_t tx_size, rx_size, rx_offset;
    uint8_t tx[LOCKDOWN_TLS_WRITE_LIMIT], rx[LOCKDOWN_TLS_CHUNK];
    unsigned send_budget, receive_budget;
    enum lockdown_tls_state state; enum lockdown_tls_reason reason;
    int last_error, initialized, transport_error, truncated, peer_matched, again;
} lockdown_tls;
void lockdown_tls_default_config(lockdown_tls_config *);
/* Consumes/zeroes handoff only on successful init. Failure frees partial crypto
 * state, leaves handoff/transport intact, and returns ARGUMENT/BUSY/stale or a
 * Mbed TLS error. Caller must abort the handed-off stream if abandoning TLS.
 * Performs local parse/key-pair checks but NO backend I/O or handshake.
 * TLS 1.2 only, ECDHE RSA/ECDSA + AES-GCM; required CA validation AND exact DER
 * pin, no DNS name (USB identity is pinned), no verification-flag clearing,
 * resumption, renegotiation, legacy SSL or plaintext fallback.
 */
int lockdown_tls_init(lockdown_tls *, lockdown_tls_handoff *, const lockdown_tls_credentials *,
                      const lockdown_tls_config *, uint64_t now_ms);
/* At most one dispatcher poll and one TLS handshake step / write / read.
 * BIO does at most one <=512-byte dispatcher read and write per poll. Crypto
 * operations themselves may be expensive. OPEN is set only after real verified
 * handshake completion. Keep polling for deadlines and unrelated mux traffic.
 * CONTROL remains available via the dispatcher even if TLS makes progress.
 */
int lockdown_tls_poll(lockdown_tls *, uint64_t now_ms);
/* OPEN only. Copy one whole 1..4096-byte write into stable owned retry storage.
 * No physical I/O. tx_size==0 after poll means TLS accepted plaintext, NOT peer
 * ACK/application success. Cannot queue another write until that point.
 * Read consumes a prefix of held verified plaintext; size>0 required. Neither
 * method processes ciphertext. Invalid arguments reject before time changes.
 */
int lockdown_tls_write(lockdown_tls *, const uint8_t *, size_t, uint64_t now_ms);
int lockdown_tls_read(lockdown_tls *, uint8_t *, size_t, size_t *, uint64_t now_ms);
/* Abort only, not TLS close_notify/StopSession/graceful service shutdown.
 * Fatal error and close cancel the shared mux once, only if still its owner.
 * Free crypto and zero app buffers. Original caller credentials remain caller's
 * responsibility; OS copies, swap and caller memory are not securely erased.
 */
void lockdown_tls_close(lockdown_tls *);
uint32_t lockdown_tls_next_delay(const lockdown_tls *);
#ifdef __cplusplus
}
#endif
#endif
