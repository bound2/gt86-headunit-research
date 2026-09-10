/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_AUDIO_H
#define GT86_PROJECTION_AUDIO_H
#include "pair_crypto.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_AUDIO_SLOTS 64u
#define PROJECTION_AUDIO_PAYLOAD 8192u
#define PROJECTION_AUDIO_PACKET 24
#define PROJECTION_AUDIO_DROPPED 25
#define PROJECTION_AUDIO_BUSY 26
#define PROJECTION_AUDIO_CLOSED (-7)
enum projection_audio_codec { PROJECTION_AUDIO_PCM16=1,PROJECTION_AUDIO_AAC_LC,PROJECTION_AUDIO_OPUS };
typedef struct projection_audio_format {
    uint32_t bit,clock_rate,input_rate;
    uint8_t codec,channels;
    uint16_t aac_config;
} projection_audio_format;
typedef struct projection_audio_config { uint32_t format,reorder_ms,hold_ms; size_t slots,payload_capacity; } projection_audio_config;
typedef struct projection_audio_key { uint64_t generation,token; } projection_audio_key;
typedef struct projection_audio_packet {
    const uint8_t *data; size_t size;
    uint64_t counter,received_ns,skipped_packets;
    uint32_t sample_time,ssrc,frames;
    uint16_t sequence; uint8_t payload_type,marker;
} projection_audio_packet;
typedef struct projection_audio_slot { projection_audio_packet packet; uint8_t occupied; } projection_audio_slot;
typedef struct projection_audio {
    projection_audio_config config; projection_audio_format format;
    projection_audio_slot slots[PROJECTION_AUDIO_SLOTS];
    uint8_t *storage; size_t storage_size,count,held;
    uint8_t key[32];
    uint64_t generation,next_token,token,now_ns,held_ns,highest,seen,last;
    uint32_t ssrc,flush_sample; uint8_t ready,started,received,delivered,dead,fenced;
    int last_error;
} projection_audio;
/* Single-format encrypted RTP/UDP child, no socket, decoder, playback clock,
 * allocation, callbacks or default key. Fresh serial noncopyable owner; all
 * buffers/arguments disjoint and internals read-only. Bind ONLY the directional
 * key from the owning verified session resource. No reconnect/nonce reset under
 * a reused key; media flush preserves cryptographic history. Caller pins peer IP
 * and pins source port only after
 * PACKET success. No default format; supported bits are explicit, never guessed.
 * PCM16 is interleaved big endian; AAC is one raw access unit; Opus is one raw
 * packet with a 48k RTP/decode clock even for 16k/24k negotiated input rates.
 * Format support does not mean a decoder/output device exists.
 *
 * Fixed 12-byte RTP v2 header, dynamic payload type 96..127, no CSRC/extension/
 * padding. Tail=16-byte tag then 8-byte LE nonce, zero-extended to IETF nonce.
 * ONLY timestamp/SSRC bytes4..11 and payload are authenticated. Prefix fields
 * (including sequence) are diagnostic, NOT identity/order/replay authority.
 * This profile requires increasing uint64 nonce counters with a 64-packet
 * replay window; no wrapping/reset. After authentication, first SSRC binds.
 * Malformed, failed tags, duplicate/too-old counters and changed SSRC DROP;
 * they never advance replay/order state or refresh an application deadline.
 *
 * Queue order uses authenticated nonce counters, not unprotected RTP sequence.
 * Initial/gapped output waits reorder_ms (0..1000) from oldest candidate's
 * receipt; contiguous output is immediate. Queued arrivals before start cannot
 * be exposed until RECORD drain enables start. Missing packet counts are
 * explicit; no retransmission, concealment, playout pacing or estimated played
 * samples. A decoder/output backend must use timestamps and handle gaps.
 * Full queue returns BUSY without consuming a datagram; UDP/kernel loss under
 * backpressure remains possible. Caller-owned slots*payload_capacity bytes.
 * Reorder is bounded, not a complete adaptive jitter buffer for buffered audio.
 *
 * peek borrows one packet until exact token release, entire packet consumed by
 * caller first. Absolute hold_ms (1..60000) closes/wipes on expiry. Partial
 * consumer copies cannot renew it. No stream idle timeout: silence is legal.
 * All timed calls need nondecreasing explicit monotonic ns; next_delay is pure.
 * Init/invalid local arguments leave destination/storage/time unchanged.
 */
int projection_audio_format_get(uint32_t,projection_audio_format *);
void projection_audio_default_config(projection_audio_config *); /* Format remains 0. */
int projection_audio_init(projection_audio *,const projection_audio_config *,uint8_t *,size_t,const uint8_t key[32],uint64_t,uint64_t);
int projection_audio_check(projection_audio *,uint64_t,uint64_t);
int projection_audio_start(projection_audio *,uint64_t,uint64_t);
/* Explicit authenticated-control flush: clear owned queue/held view, suspend
 * delivery and fence strictly before sample_time. Preserve key, SSRC, highest
 * nonce/replay window, lifetime tokens. Floor delivery at highest received nonce
 * so discarded packets cannot return, including queued packets beyond the fence.
 * New arrivals may queue while suspended: admit only equal/forward timestamps
 * in the unambiguous half-range until first release after projection_audio_start;
 * then nonce ordering protects that new epoch. Whole packets, no partial-frame
 * trimming or selective buffered-range preservation. No RTP sequence authority. */
int projection_audio_flush(projection_audio *,uint64_t,uint32_t sample_time,uint64_t);
int projection_audio_feed(projection_audio *,uint64_t,const uint8_t *,size_t,uint64_t);
int projection_audio_peek(projection_audio *,uint64_t,projection_audio_packet *,projection_audio_key *,uint64_t);
int projection_audio_release(projection_audio *,projection_audio_key,uint64_t);
uint32_t projection_audio_next_delay(const projection_audio *);
void projection_audio_close(projection_audio *);
/* Explicit PCM16BE -> PCM16LE conversion, no resampling or volume change.
 * Validate full format/alignment/capacity before output. Disjoint buffers.
 * Compressed codecs are UNSUPPORTED; no fake decoder or silent passthrough. */
int projection_audio_pcm16le(const projection_audio_format *,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
#ifdef __cplusplus
}
#endif
#endif
