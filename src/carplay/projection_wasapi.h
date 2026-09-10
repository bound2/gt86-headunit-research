/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_WASAPI_H
#define GT86_PROJECTION_WASAPI_H
#include "projection_audio_services.h"
#include <wchar.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct projection_wasapi projection_wasapi;
typedef struct projection_wasapi_config {
    const wchar_t *endpoint_id; /* Explicit IMMDevice ID, copied; no default. */
    uint32_t buffer_ms; /* 40..500, requested shared-mode buffer capacity. */
    uint32_t startup_ms; /* 0..500, wait after first queued packet for prefill. */
} projection_wasapi_config;
/* Windows-only PCM16 output, types 100..102, one stream of each type. Creates
 * an STA COM scope on this thread (fails if already in an incompatible MTA).
 * ALL sink calls and destroy MUST remain serial on this same thread; no reentry,
 * pointer retention, hidden worker, sleep, default endpoint, capture or volume
 * changes. Sink callbacks make a bounded number of synchronous OS calls, not a
 * hard real-time guarantee. Caller must poll promptly, normally every 2..5 ms.
 * Device invalidation fails closed, never silently switches output devices.
 *
 * create initializes COM and a heap owner, but opens no stream. sink.open
 * validates the explicit active render endpoint and actually initializes S16LE
 * shared-mode output with Windows PCM sample-rate/channel conversion. AAC/Opus,
 * mic and non-audio requests are unsupported. start arms output after RECORD;
 * the device starts only after actual PCM has been prefilled. 65536 owned queue
 * bytes per stream; submit copies a whole <=8192-byte PCM16BE packet or MORE
 * consumes none. Empty packets are no-ops. Within a continuous run, timestamps
 * must be contiguous modulo 2^32; gaps/overlaps are UNSUPPORTED, not guessed.
 * A new timestamp origin is allowed only after the device drains and queue is
 * empty. No adaptive jitter, loss concealment, negotiated latency, NTP pacing,
 * flush/focus semantics or compressed decoding is claimed by this backend.
 *
 * Low buffer headroom stops appending: drain known frames, Stop/Reset, then
 * prefill a new epoch. This can cause an audible gap, not a false clock anchor.
 * Transfers delayed beyond one device period fail closed. Playback uses only
 * accurate IAudioClock position/QPC pairs inside released media, never padding,
 * receipt counts, queued samples or wall-clock extrapolation. Position zero,
 * delayed/inaccurate readings and drained epochs report no position.
 *
 * Use projection_wasapi_clock_ns as the EXACT ns clock for enclosing audio and
 * timing services; anchor their origin using it as well. It is absolute QPC ns,
 * not GetTickCount or time since init. Returns UINT64_MAX on clock failure.
 * No capability is advertised automatically. Keep owner alive until its audio
 * provider closes; destroy then closes remaining devices, wipes queues and
 * balances COM. Failed create leaves *out=NULL. destroy(NULL) is harmless;
 * otherwise destroy takes ownership and must be called exactly once.
 */
int projection_wasapi_create(const projection_wasapi_config *,uint64_t generation,projection_wasapi **out);
projection_audio_sink projection_wasapi_sink(projection_wasapi *);
uint64_t projection_wasapi_clock_ns(void *unused);
int projection_wasapi_destroy(projection_wasapi *);
#ifdef __cplusplus
}
#endif
#endif
