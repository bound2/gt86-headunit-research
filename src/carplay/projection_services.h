/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_SERVICES_H
#define GT86_PROJECTION_SERVICES_H
#include "projection_session.h"
#include "projection_timing.h"
#include "control_cipher.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_SERVICES_CLOSED (-7)
typedef struct projection_ip { uint8_t bytes[16],family; uint32_t scope; } projection_ip;
typedef struct projection_services_storage {
    uint8_t *cipher_rx,*plain,*cipher_tx,*network;
    size_t cipher_rx_size,plain_size,cipher_tx_size,network_size;
} projection_services_storage;
typedef struct projection_services_config {
    projection_ip local,peer; /* Explicit control connection addresses, never DNS/wildcard. */
    uint64_t (*clock_ns)(void *); void *clock_context; /* Trusted bounded monotonic ns. */
    uint64_t mono_origin_ns,ntp_origin; /* Explicit initial local NTP mapping. */
    projection_timing_config timing;
    control_cipher_config event;
    uint32_t accept_ms,poll_ms;
    uint8_t enabled_features; /* Explicit supported runtime features; no defaults. */
    projection_session_provider media; /* Optional real media provider, no fallback. */
} projection_services_config;
typedef struct projection_services_media { uint64_t lease,child; uint32_t type; } projection_services_media;
typedef struct projection_services {
    projection_services_config config; projection_services_storage storage;
    projection_timing timing; control_cipher event;
    projection_services_media media[PROJECTION_SESSION_STREAMS]; size_t media_count;
    uintptr_t timing_socket,keep_socket,listener,event_socket; /* Internal Win32 handles, never caller I/O. */
    uint64_t generation,next_lease,event_lease,opened_ns,now_ns;
    size_t network_used,network_offset;
    uint16_t peer_timing_port;
    uint32_t keep_received;
    uint8_t ready,opened,wsa,failed,connected,started,finalized;
    int last_error;
} projection_services;
/* Actual Windows Winsock backend, not a QNX/portable socket implementation.
 * Init fresh noncopyable serial context, no sockets/WSA/clock callback yet.
 * IPv4 uses first4 bytes/restzero/scope0; IPv6 rejects unspecified/multicast/
 * mapped-v4, requires scope for link-local and zero scope otherwise. Explicit
 * local/peer same family. No interface discovery, DNS, wildcard, SO_REUSEADDR,
 * inherited listening handles, background threads, default credentials or ports.
 * Disjoint caller storage/context/config and borrowed contexts live until close;
 * cfg/bindings immutable; buffers exclusively owned, no external child calls.
 *
 * Provider open(type0) creates nonblocking exclusive ephemeral UDP timing,
 * TCP event and optional UDP keepalive; no lease is returned until all succeed.
 * Event keys come only from that typed provider call; actual receiver integration
 * supplies its verified key derivation. TCP accepts ONE matching control peer,
 * then closes listener. Wrong peer attempts cannot renew accept deadline.
 * UDP timing pins both peer address/port; low-power consumes only matching peer
 * address, does not extend control/sync deadlines or implement sleep/wake policy.
 * Events are encrypted from byte1; EOF/tag failure closes sockets, never reconnects
 * with reset counters. Matched IP is not cryptographic UDP timing authentication.
 *
 * Other stream types delegate explicitly to media. Leases are remapped uniquely
 * (never guessed from port numbers). No media provider => UNSUPPORTED, not a
 * dummy listener/success. Features must match explicit config; nonzero features
 * require a media provider whose real support is attested by /info availability.
 * Delegate contexts obey session provider contracts, including cleanup on error.
 *
 * poll performs at most4 timing receives,1 keepalive receive,1 accept,1 TCP
 * read/write and1 cipher feed per call, plus one bounded delegate poll. Queued
 * network tails are retained under application backpressure. Calls refresh the
 * supplied ns clock before I/O and enforce timing/accept/cipher budgets; no
 * protocol/lifetime budget is renewed by unrelated traffic. Clock failures are
 * terminal. Event APIs take that same ns clock explicitly; wrong key/count/gen
 * is transactional. next_delay includes a bounded polling cadence (1..1000ms).
 */
void projection_services_default_config(projection_services_config *);
int projection_services_init(projection_services *,const projection_services_config *,const projection_services_storage *,uint64_t);
projection_session_provider projection_services_provider(projection_services *);
int projection_services_poll(projection_services *,uint64_t);
uint32_t projection_services_next_delay(const projection_services *,uint64_t);
/* Low-level authenticated event records, NOT an event RTSP/command sequencer.
 * Frontend must frame/classify/correlate messages explicitly, never auto-200.
 * unsolicited1 requires completed provider start (outer RECORD drain); replies
 * may be queued earlier. Caller may not mislabel a command as a reply. Accepted
 * TCP writes mean kernel ownership, NOT phone ACK, processing or playback.
 */
int projection_services_event_peek(const projection_services *,uint64_t,rtsp_slice *,control_cipher_key *);
int projection_services_event_consume(projection_services *,control_cipher_key,size_t,uint64_t now_ns);
int projection_services_event_queue(projection_services *,uint64_t,const uint8_t *,size_t,int unsolicited,uint64_t now_ns);
void projection_services_close(projection_services *); /* Final explicit cleanup, no restart. */
#ifdef __cplusplus
}
#endif
#endif
