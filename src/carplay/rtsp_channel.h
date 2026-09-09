/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_RTSP_CHANNEL_H
#define GT86_RTSP_CHANNEL_H
#include "rtsp_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define RTSP_CHANNEL_REQUEST 8
#define RTSP_CHANNEL_OUTPUT 9
#define RTSP_CHANNEL_OUTPUT_DONE 10
#define RTSP_CHANNEL_CLOSED (-7)
enum rtsp_channel_state { RTSP_CHANNEL_RECEIVING, RTSP_CHANNEL_HELD,
    RTSP_CHANNEL_SENDING, RTSP_CHANNEL_SENT, RTSP_CHANNEL_DEAD };
enum rtsp_channel_reason { RTSP_CHANNEL_REASON_NONE, RTSP_CHANNEL_REASON_LOCAL,
    RTSP_CHANNEL_REASON_DEADLINE, RTSP_CHANNEL_REASON_PROTOCOL, RTSP_CHANNEL_REASON_EOF };
typedef struct rtsp_channel_config { uint32_t idle_ms, receive_ms, reply_ms, output_ms; } rtsp_channel_config;
typedef struct rtsp_channel_key { uint64_t generation, token; } rtsp_channel_key;
typedef struct rtsp_channel {
    rtsp_stream input;
    uint8_t *tx;
    size_t tx_capacity, tx_size, tx_offset;
    rtsp_channel_config config;
    uint64_t generation, next_token, token, now, phase_at;
    enum rtsp_channel_state state;
    enum rtsp_channel_reason reason;
    int last_error;
} rtsp_channel;
/* A serial plaintext request/explicit response owner, not a network transport
 * or authentication state machine. No I/O, automatic response, retry, key
 * activation, route dispatch or default receiver identity. Caller-owned,
 * noncopyable, read-only internals; initialize once per lifetime with a fresh
 * nonzero caller generation, never reused for a replacement connection. Arguments,
 * object and RX/TX storage disjoint, except response data may borrow held RX.
 * Config values 1..60000 ms; defaults idle30s/receive10s/reply5s/output5s.
 */
void rtsp_channel_default_config(rtsp_channel_config *);
int rtsp_channel_init(rtsp_channel *, const rtsp_channel_config *, uint8_t *rx, size_t rx_capacity,
                       uint8_t *tx, size_t tx_capacity, uint64_t generation, uint64_t now_ms);
/* Generation/key validation precedes clock/deadline acceptance. Decreasing time
 * rejects without mutation. Receiving a first byte starts an absolute receive
 * budget; fragmentation cannot renew it. One complete request becomes HELD.
 * No subsequent bytes are consumed while HELD/SENDING/SENT. Caller retains all
 * tail bytes, especially ciphertext after a pair-verify boundary. No internal
 * resynchronization after malformed input; terminal errors zero retained data.
 */
int rtsp_channel_check(rtsp_channel *, uint64_t generation, uint64_t now_ms);
int rtsp_channel_feed(rtsp_channel *, uint64_t generation, const uint8_t *, size_t,
                      size_t *consumed, uint64_t now_ms);
/* Untimed borrowed request view and exact lifetime token, valid only while HELD.
 * Errors/MORE zero both outputs. No automatic routing or permissive 200 ACK.
 */
int rtsp_channel_request(const rtsp_channel *, rtsp_message *, rtsp_channel_key *);
/* Transactionally validate/copy one final response (status>=200). Protocol and
 * CSeq are taken from the held request, never caller overrides. Invalid
 * arguments/insufficient output capacity do not consume token or advance time.
 * Unsupported handlers must explicitly reply with an error or close.
 */
int rtsp_channel_respond(rtsp_channel *, rtsp_channel_key, const rtsp_response *, uint64_t now_ms);
/* Borrow remaining response bytes; consume only bytes the caller's exclusive
 * downstream owner has accepted. Partial retirement never renews output budget.
 * OUTPUT_DONE means this plaintext queue is empty, NOT physically written,
 * TCP-acknowledged, cipher-authenticated or accepted by the peer. No implicit
 * return to RECEIVING: caller must drain its downstream owner, perform any
 * verified cipher handoff, then release. SENT shares the original output budget.
 * Wrong token/count cannot retire data or advance time. Views expire at the
 * next consume/release/close; downstream must copy before reporting acceptance.
 */
int rtsp_channel_output(rtsp_channel *, rtsp_channel_key, rtsp_slice *, uint64_t now_ms);
int rtsp_channel_consume(rtsp_channel *, rtsp_channel_key, size_t count, uint64_t now_ms);
int rtsp_channel_release(rtsp_channel *, rtsp_channel_key, uint64_t now_ms);
int rtsp_channel_eof(rtsp_channel *, uint64_t generation, uint64_t now_ms);
void rtsp_channel_close(rtsp_channel *);
/* Until the next applicable absolute deadline; UINT32_MAX if closed/uninitialized.
 * Held events do not cause a zero-delay busy loop. No backend timer is hidden.
 */
uint32_t rtsp_channel_next_delay(const rtsp_channel *);
#ifdef __cplusplus
}
#endif
#endif
