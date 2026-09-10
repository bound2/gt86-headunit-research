/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_DECODE_SINK_H
#define GT86_PROJECTION_DECODE_SINK_H
#include "projection_audio_services.h"
#include "projection_decode.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct projection_decode_sink projection_decode_sink;
typedef struct projection_decode_sink_config {
    projection_audio_sink pcm; /* Explicit real PCM renderer, e.g. WASAPI. */
    uint64_t (*clock_ns)(void *); void *clock_context;
    uint32_t hold_ms; /* 1..60000, absolute decoded-output backpressure budget. */
} projection_decode_sink_config;
/* Owning codec adapter between authenticated audio services and a PCM sink.
 * Fresh serial, non-reentrant owner, same thread/lifetime as the supplied sink.
 * No device, clock or codec fallback. Creation does no I/O or clock callback.
 * One owned decoder per type100..102; open prepares actual decoder + downstream
 * PCM resource. Downstream SETUP format is mapped to PCM at the SAME RTP clock
 * rate/channels, with frames_per_packet=0 because decoded blocks may split.
 *
 * start forwards authorization; submit accepts/decode-copies one entire packet
 * or MORE consumes none while decoded output remains. poll calls the renderer
 * once, then submits at most one <=8192-byte S16BE chunk. Chunks retain the
 * authenticated packet counter (it may repeat across chunks), not a fabricated
 * authentication identity. Their sample timestamps advance by exact decoded
 * frames. Priming/empty inputs produce no dummy PCM. No view is borrowed from
 * the upstream packet after submit returns. Pending PCM has an absolute deadline
 * sampled around work/callbacks; trickle consumption cannot renew it. Backend
 * calls/decodes are finite, synchronous work, not a hard CPU time guarantee.
 *
 * Playback delegates only actual downstream device observations at the original
 * format's rate. Decoder output does not become a played position. Any decoder,
 * output, clock or held-output failure closes/wipes all this adapter's resources;
 * the enclosing audio/root owners must propagate failure and retire the session.
 * Optional downstream pcm.flush exposes two-phase stop/clear and reply-drained
 * resume: discard pending PCM and recreate the codec at its original format,
 * retaining the PCM lease. The enclosing audio owner MUST preserve replay/key
 * state and fence incoming timestamps; codec reset grants no nonce reset.
 * AAC re-primes; generic start cannot bypass the held flush. Unsignaled codec
 * discontinuities still fail closed. Full jitter/loss/buffered flush/pacing and
 * actual phone validation remain work.
 *
 * Destroy after closing the borrowing audio provider and before destroying the
 * downstream PCM owner. Destroy consumes the non-NULL owner exactly once.
 */
int projection_decode_sink_create(const projection_decode_sink_config *,uint64_t,projection_decode_sink **);
projection_audio_sink projection_decode_sink_provider(projection_decode_sink *);
void projection_decode_sink_destroy(projection_decode_sink *);
#ifdef __cplusplus
}
#endif
#endif
