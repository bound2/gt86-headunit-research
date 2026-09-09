/* SPDX-License-Identifier: GPL-3.0-only
 * Explicit pre-TLS Lockdown client. No pairing fallback or TLS implementation.
 */
#ifndef GT86_LOCKDOWN_BOOTSTRAP_H
#define GT86_LOCKDOWN_BOOTSTRAP_H
#include "lockdown_reply.h"
#ifdef __cplusplus
extern "C" {
#endif
#define LOCKDOWN_BOOTSTRAP_VALUE 6
#define LOCKDOWN_BOOTSTRAP_TLS 7
#define LOCKDOWN_BOOTSTRAP_CLOSED (-7)
#define LOCKDOWN_BOOTSTRAP_BUSY 3
#define LOCKDOWN_BOOTSTRAP_REQUEST_LIMIT 4096u
enum lockdown_bootstrap_state { LOCKDOWN_BOOTSTRAP_IDLE, LOCKDOWN_BOOTSTRAP_PENDING,
    LOCKDOWN_BOOTSTRAP_VALUE_HELD, LOCKDOWN_BOOTSTRAP_ERROR_HELD, LOCKDOWN_BOOTSTRAP_TLS_HELD,
    LOCKDOWN_BOOTSTRAP_DETACHED, LOCKDOWN_BOOTSTRAP_DEAD };
enum lockdown_bootstrap_reason { LOCKDOWN_BOOTSTRAP_REASON_NONE, LOCKDOWN_BOOTSTRAP_REASON_LOCAL,
    LOCKDOWN_BOOTSTRAP_REASON_STALE, LOCKDOWN_BOOTSTRAP_REASON_CHANNEL,
    LOCKDOWN_BOOTSTRAP_REASON_STATE, LOCKDOWN_BOOTSTRAP_REASON_RESPONSE };
typedef struct lockdown_tls_handoff {
    usbmux_dispatcher *dispatcher;
    usbmux_handle handle;
    uint8_t session_id[256]; size_t session_id_size;
} lockdown_tls_handoff;
/* Caller-owned/noncopyable/read-only fields. Initialize once. Exclusive owner
 * of the supplied channel until detach/closure; other dispatcher streams and
 * CONTROL handling remain available. All objects, request scratch and parser
 * storage must be separate and outlive this object/views. No argument overlap,
 * concurrent calls, reentry, implicit clock or secure-erasure guarantee.
 */
typedef struct lockdown_bootstrap {
    lockdown_channel *channel;
    service_plist_storage storage;
    service_plist_document document;
    lockdown_reply reply;
    uint8_t *request; size_t request_capacity;
    uint8_t label[64]; size_t label_size;
    uint64_t now, token;
    enum lockdown_reply_command command;
    enum service_plist_type expected;
    enum lockdown_bootstrap_state state;
    enum lockdown_bootstrap_reason reason;
    int last_error;
} lockdown_bootstrap;
/* Bind an unused IDLE channel on a fresh OPEN TCP 62078 stream, with no
 * application data sent/received. label: caller supplied 1..64 printable ASCII.
 * Request scratch: 1..4096 bytes; each encoded request must also fit channel TX.
 * Parser storage follows service_plist limits. No callback, request, pair-record
 * access or phone identity is inferred at init. Invalid init is transactional.
 */
int lockdown_bootstrap_init(lockdown_bootstrap *, lockdown_channel *, const lockdown_body *label,
                            uint8_t *request, size_t, const service_plist_storage *, uint64_t now_ms);
/* IDLE only. Encode/copy one explicit request; physical I/O happens on poll.
 * GetValue's expected type must match the selected key. StartSession identities
 * must come from the caller's selected pairing record; only public HostID and
 * SystemBUID are serialized, never private keys. No UUID/record is generated.
 * A rejected session is an explicit held error, not automatic Pair or retry.
 */
int lockdown_bootstrap_get_value(lockdown_bootstrap *, const lockdown_body *key, const lockdown_body *domain,
                                 enum service_plist_type expected, uint64_t now_ms);
int lockdown_bootstrap_start_session(lockdown_bootstrap *, const lockdown_body *host_id,
                                     const lockdown_body *system_buid, uint64_t now_ms);
/* One channel poll, then decode/validate a newly held response at most once.
 * VALUE, REMOTE_ERROR or TLS means a held event; keep polling for deadlines and
 * unrelated traffic. Malformed/mismatched responses close the shared dispatcher.
 * TLS means VALIDATED TLS HANDOFF REQUIRED, not TLS established/trust granted.
 * CONTROL remains independently inspectable when a held event takes precedence.
 */
int lockdown_bootstrap_poll(lockdown_bootstrap *, uint64_t now_ms);
/* Untimed view of owned decoded storage; valid until release/handoff/closure.
 * Output null/zero on MORE/error. A generation/token mismatch never exposes an
 * old event. Caller must poll first; this view does not advance clocks.
 */
int lockdown_bootstrap_event(const lockdown_bootstrap *, const lockdown_reply **, uint64_t *token);
/* Release VALUE/REMOTE_ERROR explicitly back to IDLE. Wrong token returns STALE
 * without time/state changes. TLS cannot be released back into plaintext mode.
 * No automatic retry even after the application acknowledges a remote error.
 */
int lockdown_bootstrap_release(lockdown_bootstrap *, uint64_t token, uint64_t now_ms);
/* TLS_HELD only, exact token, live OPEN stream without peer/send FIN.
 * Check all channel/shared deadlines, release/detach and copy session metadata
 * into caller output without backend reads/writes. Coalesced following bytes
 * remain unread. Caller MUST install/run a TLS engine on the returned stream
 * before any further plist/service request. No resume/mark-secure bypass API
 * exists. This object is terminal after handoff; close then is a no-op.
 * Errors zero the entire output; malformed/expired/stale owners cannot hand off.
 */
int lockdown_bootstrap_take_tls(lockdown_bootstrap *, uint64_t token, lockdown_tls_handoff *, uint64_t now_ms);
void lockdown_bootstrap_close(lockdown_bootstrap *);
uint32_t lockdown_bootstrap_next_delay(const lockdown_bootstrap *);
#ifdef __cplusplus
}
#endif
#endif
