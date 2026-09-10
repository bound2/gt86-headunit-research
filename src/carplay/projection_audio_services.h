/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_AUDIO_SERVICES_H
#define GT86_PROJECTION_AUDIO_SERVICES_H
#include "projection_services.h"
#include "projection_audio.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct projection_audio_sink {
    void *context;
    /* Explicit real codec/output backend, no default. Same bounded synchronous,
     * non-reentrant/no-retention contract as session providers. open validates
     * ACTUAL codec/format/device support, prepares (never plays), returns unique
     * nonzero child lease. Any nonzero lease on any result transfers cleanup.
     * Zero on failure means all partial resources already cleaned. */
    int (*open)(void *,uint64_t,const projection_session_resource *,const projection_audio_format *,uint64_t *);
    int (*start)(void *,uint64_t,uint64_t);
    /* Atomic full packet copy/accept: OK consumed, MORE consumed nothing. No
     * retained payload pointer. Compressed input is a raw AAC AU/Opus packet;
     * PCM is S16BE. Use packet timestamps/counter gaps, not unprotected sequence
     * as authority. Implement decoding, pacing, resampling and loss handling;
     * submission is NOT playback. Peer-supplied payload is untrusted media. */
    int (*submit)(void *,uint64_t,uint64_t,const projection_audio_format *,const projection_audio_packet *);
    int (*poll)(void *,uint64_t,uint64_t,uint64_t now_ns); /* OK/MORE; bounded device/decoder work. */
    int (*playback)(void *,uint64_t,uint64_t,projection_playback_position *);
    void (*close)(void *,uint64_t,uint64_t);
    /* Optional two-phase FLUSH, same stop/clear then reply-drained resume
     * contract as session provider. No nonce reset or inferred played samples. */
    int (*flush)(void *,uint64_t,uint64_t,const projection_audio_flush_request *);
} projection_audio_sink;
typedef struct projection_audio_services_config {
    projection_ip local,peer;
    uint64_t (*clock_ns)(void *); void *clock_context;
    projection_audio_config audio; /* format ignored here; each SETUP selects it. */
    projection_audio_sink sink;
    uint32_t poll_ms; /* 1..1000 */
} projection_audio_services_config;
typedef struct projection_audio_services_slot {
    projection_audio audio;
    uint64_t lease,child,opened_ns,started_ns;
    uintptr_t data_socket,control_socket;
    uint32_t type,control_received;
    uint16_t peer_port;
    uint8_t occupied,started,flushing;
} projection_audio_services_slot;
typedef struct projection_audio_services {
    projection_audio_services_config config;
    projection_audio_services_slot slots[3];
    uint8_t *storage,*network; size_t stream_bytes,network_size,count;
    uint64_t generation,next_lease,now_ns;
    uint8_t ready,failed,wsa,finalized; int last_error;
} projection_audio_services;
/* Real Windows nonblocking audio UDP provider, types100/101/102 only. Supply
 * it as projection_services_config.media BEFORE root services init. It does not
 * replace root timing/event services or claim screen/iAP/microphone support.
 * peer_data_port/has_write (mic requests) currently UNSUPPORTED, never silently
 * accepted. /info availability must attest exactly the supplied real sink.
 * Native target/QNX, output devices and compressed decoders remain separate.
 *
 * Fresh serial noncopyable owner, immutable config/provider bindings, borrowed
 * disjoint storage alive until final close. init does no I/O/clock callback and
 * changes nothing on invalid input. storage >=3*slots*payload_capacity, network
 * >=payload_capacity+36 (only those extents owned/wiped); no heap/thread/default
 * device, DNS, wildcard bind, SO_REUSEADDR or inherited socket handles.
 * Explicit local/peer IPv4 or IPv6, same family. Data source port pins only after
 * first authenticated accepted datagram; thereafter exact peer IP/port.
 * Control UDP currently bounded drain only from pinned peer IP: no RTCP parser,
 * retransmission, sync/flush handler or automatic success response.
 * Authenticated session-control FLUSH is separate, exposed only if sink.flush
 * is supplied: stop/clear first, preserve sockets/keys/replay/source pinning,
 * then resume on encrypted reply drain. New packets may queue while suspended;
 * neither submit nor sink poll runs until resume. Generic start cannot bypass it.
 *
 * Prepare sink + two actual exclusive ports, then start only on RECORD/SETUP
 * reply drain. poll performs at most one data/control receive and one atomic
 * sink submit per live stream, plus one sink poll. Full queues stop data reads;
 * kernel/UDP loss remains possible, and exact gap is exposed by packet counters.
 * Receiver checks control deadlines first; this provider samples its explicit
 * ns clock before/after callbacks and closes on reversal/held expiry/failure.
 * Bad UDP packets/peers are drops, not session-killing authentication oracles.
 * Terminal errors close this owner's ALL streams; root receiver poll/close
 * must retire its remaining resources immediately (no reentry into the parent).
 *
 * Playback comes only from the sink and must use this clock domain and format's
 * RTP clock rate. Future/pre-open/pre-start positions and invalid output close,
 * including timestamps from before that stream's start invocation.
 * No received/submitted packet counter is ever exposed as played audio.
 */
int projection_audio_services_init(projection_audio_services *,const projection_audio_services_config *,uint8_t *,size_t,uint8_t *,size_t,uint64_t);
projection_session_provider projection_audio_services_provider(projection_audio_services *);
int projection_audio_services_poll(projection_audio_services *,uint64_t);
uint32_t projection_audio_services_next_delay(const projection_audio_services *,uint64_t);
void projection_audio_services_close(projection_audio_services *);
#ifdef __cplusplus
}
#endif
#endif
