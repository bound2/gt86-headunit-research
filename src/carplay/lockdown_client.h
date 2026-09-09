/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_LOCKDOWN_CLIENT_H
#define GT86_LOCKDOWN_CLIENT_H
#include "lockdown_tls.h"
#ifdef __cplusplus
extern "C" {
#endif
#define LOCKDOWN_CLIENT_REPLY 6
#define LOCKDOWN_CLIENT_CLOSED (-7)
#define LOCKDOWN_CLIENT_BUSY 3
enum lockdown_client_state { LOCKDOWN_CLIENT_IDLE, LOCKDOWN_CLIENT_EXCHANGE,
    LOCKDOWN_CLIENT_HELD, LOCKDOWN_CLIENT_ERROR_HELD, LOCKDOWN_CLIENT_DEAD };
enum lockdown_client_reason { LOCKDOWN_CLIENT_REASON_NONE, LOCKDOWN_CLIENT_REASON_LOCAL,
    LOCKDOWN_CLIENT_REASON_TLS, LOCKDOWN_CLIENT_REASON_DEADLINE, LOCKDOWN_CLIENT_REASON_RESPONSE,
    LOCKDOWN_CLIENT_REASON_UNEXPECTED, LOCKDOWN_CLIENT_REASON_STATE };
/* Initialize once. Noncopyable/exclusive owner of a new, authenticated Lockdown
 * TLS session (no prior application I/O). Objects/storage are separate and stay
 * alive; all fields/views are read-only. No overlap, reentry or concurrency.
 * Request scratch 5..4096, response frame 5..65540; existing plist storage caps.
 * Only explicit GetValue and StartService. No opaque RPC, Pair or retry fallback.
 */
typedef struct lockdown_client {
    lockdown_tls *tls;
    uint8_t *request, *response; size_t request_capacity, response_capacity, used, expected_size;
    uint8_t label[64]; size_t label_size;
    service_plist_storage storage; service_plist_document document; lockdown_reply reply;
    lockdown_channel_config config;
    uint64_t now, started_at, held_at, token, next_token;
    enum lockdown_reply_command command; enum service_plist_type expected_type;
    enum lockdown_client_state state; enum lockdown_client_reason reason; int last_error;
} lockdown_client;
int lockdown_client_init(lockdown_client *, lockdown_tls *, const lockdown_body *label,
                         uint8_t *request, size_t, uint8_t *response, size_t,
                         const service_plist_storage *, const lockdown_channel_config *, uint64_t now_ms);
int lockdown_client_get_value(lockdown_client *, const lockdown_body *key, const lockdown_body *domain,
                              enum service_plist_type, uint64_t now_ms);
int lockdown_client_start_service(lockdown_client *, const lockdown_body *service, uint64_t now_ms);
/* One TLS/dispatcher poll, one exact-needed plaintext prefix read <=512, then
 * at most one decode/validation. Reply held only after the request is accepted
 * by TLS AND drained/ACKed by the TCP-style connection. No following frame bytes
 * are consumed. Unexpected buffered data before a new request is fatal.
 * Valid remote errors are held, never automatically retried or paired.
 */
int lockdown_client_poll(lockdown_client *, uint64_t now_ms);
int lockdown_client_check(lockdown_client *, uint64_t now_ms);
/* Untimed views: poll first, views expire on release/close. Exact-token release
 * checks deadlines without physical I/O; wrong token does not advance time.
 */
int lockdown_client_event(const lockdown_client *, const lockdown_reply **, uint64_t *token);
int lockdown_client_release(lockdown_client *, uint64_t token, uint64_t now_ms);
void lockdown_client_close(lockdown_client *);
uint32_t lockdown_client_next_delay(const lockdown_client *);
#ifdef __cplusplus
}
#endif
#endif
