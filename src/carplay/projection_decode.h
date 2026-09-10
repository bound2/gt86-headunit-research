/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_DECODE_H
#define GT86_PROJECTION_DECODE_H
#include "projection_audio.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_DECODE_FRAMES 5760u
#define PROJECTION_DECODE_SAMPLES (PROJECTION_DECODE_FRAMES*2u)
typedef struct projection_decode projection_decode;
typedef struct projection_decoded_audio {
    const int16_t *samples; /* Interleaved native-endian PCM16, decoder-owned. */
    uint32_t frames,duration,sample_time; /* Per channel; duration includes AAC priming. */
    uint8_t channels,priming;
} projection_decoded_audio;
/* Explicit optional Opus/FAAD2 source build. No device, socket, file, clock,
 * worker or synthetic success fallback. Heap-owning, serial, non-reentrant,
 * generation-bound decoder; one per stream. Input must already be authenticated
 * and ordered by the audio owner. Payload <=8192 bytes, fixed negotiated format.
 * PCM is S16BE; Opus is a raw mono packet at 48 kHz, <=120 ms; AAC is one raw
 * AAC-LC stereo AU, 1024 samples at 44.1/48 kHz, configured by the exact ASC.
 * No ADTS/ADIF/LATM/Ogg demux, HE-AAC, channel changes, PLC/FEC, reset/seek or
 * automatic concealment. Nonempty packets need increasing counters and
 * contiguous sample timestamps modulo 2^32; a discontinuity closes the decoder.
 * Empty transport packets are no-ops, NOT an Opus loss-concealment request.
 * SBR is disabled, but FAAD may skip unknown fill extensions and decode the LC
 * core; this is not a complete AAC extension/conformance validator.
 *
 * Decode owns its PCM view until next decode, discard or destroy. Never retain
 * a view while accepting another packet. FAAD's first valid AAC AU can report
 * zero output: priming=1, duration=1024, frames=0, no fabricated samples. Later
 * PCM is labelled with that AU's own sample timestamp; no container pre-skip or
 * guessed encoder-delay adjustment. Actual phone timing still needs validation.
 * Invalid peer media/decoder errors close and wipe our wire/PCM buffers; backend
 * opaque allocations are released (FAAD internal heap wiping is not promised).
 * Bad local arguments/stale generation do not alter the owner. All outputs are
 * cleared on errors. Destroy consumes a non-NULL owner exactly once.
 */
int projection_decode_create(uint32_t format,uint64_t generation,projection_decode **out);
int projection_decode_packet(projection_decode *,uint64_t,const projection_audio_packet *,projection_decoded_audio *);
int projection_decode_discard(projection_decode *,uint64_t);
int projection_decode_pcm_format(uint32_t,projection_audio_format *);
void projection_decode_destroy(projection_decode *);
#ifdef __cplusplus
}
#endif
#endif
