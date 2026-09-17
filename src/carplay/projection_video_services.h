/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_VIDEO_SERVICES_H
#define GT86_PROJECTION_VIDEO_SERVICES_H
#include "projection_services.h"
#include "projection_video.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_VIDEO_SERVICES_CLOSED (-7)
typedef struct projection_video_services projection_video_services;
typedef struct projection_video_sink {
    void *context;
    /* Synchronous bounded serial callbacks: no reentry, exceptions or retained
     * argument pointers. open validates actual resource/output support and
     * prepares, never presents. Any nonzero child on ANY result transfers close
     * responsibility. Child leases must be nonzero and unique while live. */
    int (*open)(void *,uint64_t,const projection_session_resource *,uint64_t *child);
    int (*start)(void *,uint64_t,uint64_t child);
    /* May precede start. Synchronously invalidate all old-epoch output before
     * returning OK; no MORE here. Configuration is explicitly unauthenticated. */
    int (*configure)(void *,uint64_t,uint64_t,const projection_video_configuration *);
    /* Borrowed tight I420 view, valid ONLY during this call. OK means atomic
     * copy/accept, MORE means nothing accepted; neither means displayed. A sink
     * retaining output must own its copy, bound its queue, and invalidate it on
     * configure/close. No guessed presentation time or implicit A/V clock. */
    int (*submit)(void *,uint64_t,uint64_t,const projection_h264_view *,const projection_video_metadata *);
    int (*poll)(void *,uint64_t,uint64_t,uint64_t now_ns); /* OK/MORE; only after start. */
    void (*close)(void *,uint64_t,uint64_t); /* Invalidate output/cancel work, cannot fail. */
} projection_video_sink;
typedef struct projection_video_services_config {
    projection_ip local,peer; /* Explicit addresses of authenticated control transport. */
    uint64_t (*clock_ns)(void *); void *clock_context;
    projection_video_config video;
    projection_video_sink sink;
    uint32_t accept_ms,poll_ms; /* 1..60000 / 1..1000; no defaults. */
    uint8_t enabled_features; /* Explicit session contract; HEVC is unsupported. */
    /* Optional non-video media provider (e.g. real audio). Immutable binding;
     * leases remapped into this owner's namespace, including playback/FLUSH.
     * Its clock must use this exact ns domain. Its clock callback is not used;
     * the enclosing root supplies timing. No fallback for screen requests. */
    projection_session_provider other;
} projection_video_services_config;
/* Optional Windows Winsock service for screen types110/111, not a QNX backend.
 * Heap-owning noncopyable serial owner. Create does no I/O or clock callback.
 * Install returned provider as root projection_services_config.media BEFORE
 * root init; use other to retain audio support. Never call it concurrently or
 * access children directly. Bindings/borrowed contexts outlive destroy.
 *
 * Session owner must supply only verified resource keys, fresh stream IDs and
 * the same generation; its lifetime ID ledger prevents key/nonce reuse. Explicit
 * /info availability must attest a REAL sink; no default display/capabilities.
 * All sockets use exclusive ephemeral binding, no wildcard/DNS/reuse, no handle
 * inheritance. Accept exactly one matching control IP, close listener, never
 * reconnect under that key. IP matching is NOT config authentication.
 * Wrong peers cannot renew accept deadline. Observed EOF/error is terminal (no
 * subsequent presentation/drain); all this owner's video/delegate leases close.
 * Output can be delivered before recv observes an EOF already in the socket.
 *
 * Each poll performs <=1 accept, <=1 read (16KiB), <=1 record feed, <=1 sink
 * submit and <=1 sink poll per screen, plus <=1 delegate poll. Coalesced tails
 * remain owned. Staged network tails have an absolute receive_ms budget from
 * recv, independent of child fragment/queue budgets. A held sink frame uses
 * received_ms+hold_ms, never a refreshed backpressure timeout. Callbacks/codec
 * work are followed by clock checks. This is not a hard wall-time/heap bound.
 * Output is gated by provider start (outer RECORD/SETUP reply drain), not TCP
 * connect/decryption. Configuration changes retire held output before callback.
 * next_delay is pure; caller must poll. Terminal result requires immediate
 * receiver close/poll to retire root timing/event/control resources too.
 */
int projection_video_services_create(const projection_video_services_config *,uint64_t,projection_video_services **);
projection_session_provider projection_video_services_provider(projection_video_services *);
int projection_video_services_poll(projection_video_services *,uint64_t);
uint32_t projection_video_services_next_delay(const projection_video_services *,uint64_t);
int projection_video_services_error(const projection_video_services *);
void projection_video_services_close(projection_video_services *);
void projection_video_services_destroy(projection_video_services *);
#ifdef __cplusplus
}
#endif
#endif
