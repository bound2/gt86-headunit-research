/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_TIMING_H
#define GT86_PROJECTION_TIMING_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_TIMING_REPLY 22
#define PROJECTION_TIMING_SAMPLE 23
#define PROJECTION_TIMING_CLOSED (-7)
typedef struct projection_timing_config { uint32_t interval_ms,response_ms,sync_ms,max_rtt_ms; } projection_timing_config;
typedef struct projection_timing {
    projection_timing_config config;
    uint64_t now_ns,mono_origin,ntp_origin,opened_ns,last_sync_ns,last_sent_ns,pending_t1,pending_ns;
    uint64_t delays[8],pick_rtt,pick_offset;
    uint32_t samples,timeouts;
    uint8_t active,pending,sent,synced,picks,delay_count,delay_index;
} projection_timing;
/* Pure bounded RTCP-style timing/clock engine. No socket, DNS, I/O, OS clock
 * changes, thread, authentication or wall-clock default. Caller pins peer IP/port
 * before feed. Exactly 32 bytes, version byte 0x80, type210/211, length7. Header
 * bytes4..7 are ignored, not invented as mandatory zero. NTP64 wraps modulo2^64.
 * All storage disjoint; serial noncopyable owner, internals read-only.
 * Monotonic ns and initial NTP anchor explicit; nondecreasing ns required.
 * One in-flight probe, exact originate match, nonnegative bounded RTT, two-sample
 * minimum followed by an eight-group delay window; first/large phase step,
 * small residual gain1/8. Signed phase arithmetic uses unsigned modular math,
 * no float, signed overflow or conversion of negative values to unsigned time.
 * Offset is local only, not a trusted/authenticated measurement of phone time.
 */
void projection_timing_default_config(projection_timing_config *);
int projection_timing_init(projection_timing *,const projection_timing_config *,uint64_t mono_ns,uint64_t ntp);
int projection_timing_check(projection_timing *,uint64_t now_ns);
uint64_t projection_timing_now(const projection_timing *,uint64_t now_ns);
/* Make a probe without committing it; MORE when not due. On successful atomic
 * datagram send call sent with the SAME time/value. On would-block discard it
 * and make a fresh timestamp later. No pending probe before send acceptance. */
int projection_timing_probe(projection_timing *,uint64_t now_ns,uint8_t out[32]);
int projection_timing_sent(projection_timing *,uint64_t now_ns,uint64_t t1);
/* One datagram. receive<=transmit times use same ns clock; request replies stamp
 * both explicitly. Invalid/stale/duplicate responses do not renew sync deadline.
 * Matched invalid RTT retires that probe, not the previous clock estimate.
 * REPLY writes32 bytes; SAMPLE means clock updated; OK/MORE no reply. Malformed
 * packet returns INVALID but is not a fatal socket error. Wrong clock is ARG.
 * Output untouched except REPLY. Sync expiry closes; no restart in place. */
int projection_timing_feed(projection_timing *,const uint8_t *,size_t,uint64_t receive_ns,uint64_t transmit_ns,uint8_t reply[32]);
uint32_t projection_timing_next_delay(const projection_timing *);
void projection_timing_close(projection_timing *);
#ifdef __cplusplus
}
#endif
#endif
