/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_LOCKDOWN_REPLY_H
#define GT86_LOCKDOWN_REPLY_H
#include "service_plist.h"
#include "lockdown_channel.h"
#ifdef __cplusplus
extern "C" {
#endif
#define LOCKDOWN_REPLY_REMOTE_ERROR (-9)
enum lockdown_reply_command { LOCKDOWN_REPLY_GET_VALUE, LOCKDOWN_REPLY_START_SESSION,
    LOCKDOWN_REPLY_START_SERVICE, LOCKDOWN_REPLY_PAIR };
typedef struct lockdown_reply {
    const service_plist_node *value, *session_id, *escrow_bag;
    const service_plist_node *error, *error_string, *error_description;
    uint16_t port;
    uint8_t tls_required, tls_flag_present;
} lockdown_reply;
/* Validate a complete decoded dictionary from the owned, expected RPC.
 * Exact Request string required; a mismatched response is never accepted.
 * GetValue requires Value of the explicitly expected type (not KEY).
 * Other commands require expected_value_type=NULL (unused).
 * StartSession requires a nonempty <=256-byte printable-ASCII SessionID and
 * boolean EnableSessionSSL=true; false returns AUTH_FAILED (no downgrade).
 * StartService requires an integer Port in 1..65535 BEFORE narrowing. Its
 * EnableServiceSSL may be absent (false) but, when present, MUST be boolean.
 * Pair optionally carries an opaque data EscrowBag. No key generation/storage.
 *
 * Error presence always prevents success; nonempty <=256-byte string or integer
 * errors return REMOTE_ERROR, with optional bounded string error metadata.
 * All other failures zero the entire result. REMOTE_ERROR publishes ONLY error
 * fields. Unknown dictionary fields are allowed after the parser has validated
 * their supported types/structure; duplicate keys are rejected by the parser.
 * Results borrow caller plist storage and expire when that storage is reused.
 * OK means VALIDATED RESPONSE METADATA, not trusted/paired/TLS-established,
 * successful carkit connection, or permission to release/continue a live RPC.
 * No I/O, channel mutation, TLS handoff, retry or phone state change occurs.
 */
int lockdown_reply_validate(const service_plist_document *, enum lockdown_reply_command,
                            enum service_plist_type expected_value_type, lockdown_reply *);
/* Untimed explicit bridge from a HELD channel response through decode/validate.
 * Caller must poll first and supply the command/type belonging to this RPC.
 * OK/REMOTE_ERROR publish the owned document, reply and current release token.
 * All other statuses zero those outputs (scratch storage may change). Does NOT
 * release, retry, close or advance the channel; malformed input leaves it held
 * for explicit application failure handling and its existing bounded deadline.
 * All argument/storage regions must be disjoint. Repeated reads into the same
 * storage invalidate earlier document/reply views. Keep polling while held.
 */
int lockdown_reply_read(const lockdown_channel *, const service_plist_storage *,
                        enum lockdown_reply_command, enum service_plist_type,
                        service_plist_document *, lockdown_reply *, uint64_t *token);
#ifdef __cplusplus
}
#endif
#endif
